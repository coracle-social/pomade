import {fromPairs, parseJson} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {RELAYS, makeSecret, getPubkey, getTagValues} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, makeRPCEvent, prepAndSign} from '../lib/index.js'
import type {IStorageFactory, IStorage} from '../lib/index.js'

export type SignerOptions = {
  secret: string
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
  storage: IStorageFactory
}

export class Signer {
  private abortController = new AbortController()
  private pendingRegistrations: IStorage<TrustedEvent>

  constructor(private options: SignerOptions) {
    this.pendingRegistrations = options.storage("pending_registrations")
  }

  publishRelays() {
    return publish({
      signal: this.abortController.signal,
      relays: [...this.options.indexerRelays, ...this.options.outboxRelays],
      event: prepAndSign(this.options.secret, {
        kind: RELAYS,
        content: "",
        tags: [
          ...this.options.outboxRelays.map(url => ["r", url, "write"]),
          ...this.options.inboxRelays.map(url => ["r", url, "read"]),
        ]
      })
    })
  }

  listenForEvents() {
    return request({
      signal: this.abortController.signal,
      relays: this.options.inboxRelays,
      filters: [{
        kinds: [
          Kinds.Register,
          Kinds.ValidateEmailACK,
          Kinds.CommitRequest,
          Kinds.CommitGroup,
          Kinds.Unregister,
          Kinds.RecoverShard,
          Kinds.RequestOTP,
          Kinds.OTPLogin,
        ],
        '#p': [getPubkey(this.options.secret)],
      }],
      onEvent: (event: TrustedEvent) => {
        switch (event.kind) {
          case Kinds.Register: return this.handleRegister(event)
          case Kinds.ValidateEmailACK: return this.handleValidateEmailACK(event)
          case Kinds.CommitRequest: return this.handleCommitRequest(event)
          case Kinds.CommitGroup: return this.handleCommitGroup(event)
          case Kinds.Unregister: return this.handleUnregister(event)
          case Kinds.RecoverShard: return this.handleRecoverShard(event)
          case Kinds.RequestOTP: return this.handleRequestOTP(event)
          case Kinds.OTPLogin: return this.handleOTPLogin(event)
        }
      },
    })
  }

  start() {
    this.publishRelays()
    this.listenForEvents()
  }

  stop() {
    this.abortController.abort()
  }

  async handleRegister(event: TrustedEvent) {
    const cb = (status: string, message: string) =>
      publish({
        signal: this.abortController.signal,
        relays: this.options.outboxRelays,
        event: makeRPCEvent({
          authorSecret: this.options.secret,
          recipientPubkey: event.pubkey,
          kind: Kinds.RegisterACK,
          content: [
            ["status", status],
            ["message", message],
          ],
          tags: [
            ["e", event.id],
          ],
        })
      })

    const tags: string[][] = parseJson(await nip44.decrypt(event.pubkey, this.options.secret, event.content))

    if (!Array.isArray(tags)) {
      return cb("error", "Failed to parse encrypted tags.")
    }

    const meta = fromPairs(tags)

    if (!meta.email_service) {
      return cb("error", "No email service was specified.")
    }

    if (!meta.email_hash) {
      return cb("error", "No recovery email was provided.")
    }

    if (!meta.email_ciphertext) {
      return cb("error", "No recovery email ciphertext was provided.")
    }

    if (!["reject", "replace"].includes(meta.email_collision_policy)) {
      return cb("error", `Invalid email collision policy: ${meta.email_collision_policy}.`)
    }

    const [emailServiceRelayList] = await request({
      autoClose: true,
      signal: this.abortController.signal,
      relays: this.options.indexerRelays,
      filters: [{kinds: [RELAYS], authors: [meta.email_service!]}],
    })

    if (!emailServiceRelayList) {
      return cb("error", "Failed to fetch email service relay selections.")
    }

    const emailServiceRelays = getTagValues("r", emailServiceRelayList.tags)

    if (emailServiceRelays.length === 0) {
      return cb("error", "No relay selections found for selected email service.")
    }

    this.pendingRegistrations.set(event.pubkey, event)

    await cb("pending", "Please check your email to confirm your registration.")
  }

  async handleValidateEmailACK(event: TrustedEvent) {
  }

  async handleCommitRequest(event: TrustedEvent) {
  }

  async handleCommitGroup(event: TrustedEvent) {
  }

  async handleUnregister(event: TrustedEvent) {
  }

  async handleRecoverShard(event: TrustedEvent) {
  }

  async handleRequestOTP(event: TrustedEvent) {
  }

  async handleOTPLogin(event: TrustedEvent) {
  }
}
