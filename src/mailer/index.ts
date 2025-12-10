import {sha256, switcher, tryCatch, parseJson, fromPairs, textEncoder} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {RELAYS, getPubkey, getTagValue} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, prepAndSign, publishRelays, rpcSend} from '../lib/index.js'
import type {IStorageFactory, IStorage} from '../lib/index.js'

export enum ValidationStatus {
  Ok = "ok",
  Error = "error",
  Pending = "pending",
}

export type ValidationState = {
  email: string
  clientPubkey: string
  signerPubkeys: string[]
  status: ValidationStatus
}

const getValidationKey = (email: string, clientPubkey: string) => `${email}:${clientPubkey}`

export type RecoveryState = {}

export type LoginState = {}

export type EmailProvider = {
  sendValidationEmail: (email: string, clientPubkey: string) => Promise<void>
  sendRecoveryEmail: () => Promise<void>
  sendLoginEmail: () => Promise<void>
}

export type MailerOptions = {
  secret: string
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
  storage: IStorageFactory
  provider: EmailProvider
}

export class Mailer {
  private abortController = new AbortController()
  private validations: IStorage<ValidationState>

  constructor(private options: MailerOptions) {
    this.validations = options.storage('validations')
  }

  publishRelays() {
    return publishRelays({
      secret: this.options.secret,
      signal: this.abortController.signal,
      relays: [...this.options.indexerRelays, ...this.options.outboxRelays],
      outboxRelays: this.options.outboxRelays,
      inboxRelays: this.options.inboxRelays,
    })
  }

  listenForEvents() {
    return request({
      signal: this.abortController.signal,
      relays: this.options.inboxRelays,
      filters: [{
        kinds: [
          Kinds.ValidateEmail,
          Kinds.ReleaseShard,
          Kinds.SendOTP,
        ],
        '#p': [getPubkey(this.options.secret)],
      }],
      onEvent: (event: TrustedEvent) => {
        switch (event.kind) {
          case Kinds.ValidateEmail: return this.handleValidateEmail(event)
          case Kinds.ReleaseShard: return this.handleReleaseShard(event)
          case Kinds.SendOTP: return this.handleSendOTP(event)
        }
      },
    })
  }

  async start() {
    await this.publishRelays()
    this.listenForEvents()
  }

  stop() {
    this.abortController.abort()
  }

  // Email Validation

  async handleValidateEmail(event: TrustedEvent) {
    const {secret, provider} = this.options

    const tags: string[][] = parseJson(await nip44.decrypt(event.pubkey, secret, event.content))

    if (!Array.isArray(tags)) throw new Error("Invalid event private tags")

    const clientPubkey = getTagValue('client_pubkey', tags)
    const emailCiphertext = getTagValue('email_ciphertext', tags)

    if (!clientPubkey) throw new Error("client_pubkey was not provided")
    if (!emailCiphertext) throw new Error("email_ciphertext was not provided")

    const email = await tryCatch(() => nip44.decrypt(clientPubkey, secret, emailCiphertext))

    if (!email) throw new Error("Failed to decrypt email address")
    if (!email?.includes('@')) throw new Error("Invalid email address provided")

    const key = getValidationKey(email, clientPubkey)
    const validation = await this.validations.get(key)

    if (!validation) {
      await this.validations.set(key, {
        email,
        clientPubkey,
        signerPubkeys: [event.pubkey],
        status: ValidationStatus.Pending,
      })

      await provider.sendValidationEmail(email, clientPubkey)
    } else {
      if (validation.status === ValidationStatus.Ok) {
        await this.sendValidateEmailACK(event.pubkey, clientPubkey, ValidationStatus.Ok)
      }

      if (validation.status === ValidationStatus.Error) {
        await this.sendValidateEmailACK(event.pubkey, clientPubkey, ValidationStatus.Error)
      }

      if (validation.status === ValidationStatus.Pending) {
        validation.signerPubkeys.push(event.pubkey)
        await this.validations.set(key, validation)
        await this.sendValidateEmailACK(event.pubkey, clientPubkey, ValidationStatus.Pending)
      }
    }
  }

  async sendValidateEmailACK(signerPubkey: string, clientPubkey: string, status: ValidationStatus) {
    const {secret, indexerRelays} = this.options

    const message = switcher(status, {
      [ValidationStatus.Ok]: "Successfully validated user email.",
      [ValidationStatus.Error]: "Failed to validate user email.",
      [ValidationStatus.Pending]: "User email validation pending.",
    })

    await rpcSend({
      signal: this.abortController.signal,
      authorSecret: this.options.secret,
      indexerRelays: this.options.indexerRelays,
      recipientPubkey: signerPubkey,
      requestKind: Kinds.ValidateEmailACK,
      requestContent: [
        ["status", status],
        ["message", message],
        ["client", clientPubkey],
      ],
    })
  }

  async completeEmailValidation(email: string, clientPubkey: string) {
    const key = getValidationKey(email, clientPubkey)
    const validation = await this.validations.get(key)

    if (validation) {
      await this.validations.set(key, {...validation, status: ValidationStatus.Ok})

      for (const signerPubkey of validation.signerPubkeys) {
        await this.sendValidateEmailACK(signerPubkey, clientPubkey, ValidationStatus.Ok)
      }
    }
  }

  async failEmailValidation(email: string, clientPubkey: string) {
    const key = getValidationKey(email, clientPubkey)
    const validation = await this.validations.get(key)

    if (validation) {
      await this.validations.set(key, {...validation, status: ValidationStatus.Error})

      for (const signerPubkey of validation.signerPubkeys) {
        await this.sendValidateEmailACK(signerPubkey, clientPubkey, ValidationStatus.Error)
      }
    }
  }

  // Key Recovery

  async handleReleaseShard(event: TrustedEvent) {
  }

  // Login

  async handleSendOTP(event: TrustedEvent) {
  }
}
