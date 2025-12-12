import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {RPC, makeValidateResult, Status, isValidateRequest} from "../lib/index.js"
import type {IStorageFactory, IStorage, ValidateRequest} from "../lib/index.js"

export type ValidationState = {
  email: string
  status: Status
  peers: string[]
  client: string
}

const getValidationKey = (email: string, client: string) => `${email}:${client}`

export type EmailProvider = {
  sendValidationEmail: (email: string, client: string) => Promise<void>
  sendRecoveryEmail: () => Promise<void>
  sendLoginEmail: () => Promise<void>
}

export type MailerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
  provider: EmailProvider
}

export class Mailer {
  rpc: RPC
  pubkey: string
  validations: IStorage<ValidationState>
  stop: () => void

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.validations = options.storage("validations")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe((message, event) => {
      if (isValidateRequest(message)) this.handleValidateRequest(message, event)
    })
  }

  async handleValidateRequest(message: ValidateRequest, event: TrustedEvent) {
    const client = message.payload.client
    const email = tryCatch(() => this.rpc.decrypt(client, message.payload.email_ciphertext))

    const cb = (status: Status, message: string) =>
      this.rpc.channel(event.pubkey).send(makeValidateResult({client, status, message}))

    if (!email) return cb(Status.Error, "Failed to decrypt email address")
    if (!email?.includes("@")) return cb(Status.Error, "Invalid email address provided")

    const key = getValidationKey(email, client)
    const validation = await this.validations.get(key)

    if (!validation) {
      await this.validations.set(key, {
        email,
        client,
        peers: [event.pubkey],
        status: Status.Pending,
      })

      await this.options.provider.sendValidationEmail(email, client)
    } else {
      if (validation.status === Status.Ok) {
        await cb(Status.Ok, "Successfully validated user email")
      }

      if (validation.status === Status.Error) {
        await cb(Status.Error, "Failed to validate user email")
      }

      if (validation.status === Status.Pending) {
        validation.peers.push(event.pubkey)
        await this.validations.set(key, validation)
        await cb(Status.Pending, "User email validation pending")
      }
    }
  }

  async completeEmailValidation(email: string, client: string) {
    const key = getValidationKey(email, client)
    const validation = await this.validations.get(key)

    if (validation) {
      await this.validations.set(key, {...validation, status: Status.Ok})

      for (const peer of validation.peers) {
        this.rpc.channel(peer).send(
          makeValidateResult({
            client,
            status: Status.Ok,
            message: "Successfully validated user email",
          }),
        )
      }
    }
  }

  async failEmailValidation(email: string, client: string) {
    const key = getValidationKey(email, client)
    const validation = await this.validations.get(key)

    if (validation) {
      await this.validations.set(key, {...validation, status: Status.Error})

      for (const peer of validation.peers) {
        this.rpc.channel(peer).send(
          makeValidateResult({
            client,
            status: Status.Ok,
            message: "Successfully validated user email",
          }),
        )
      }
    }
  }
}
