import {call, tryCatch, fromPairs, parseJson} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {RELAYS, makeSecret, getPubkey, getTagValues} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, RPC, RPCMethod, prepAndSign, publishRelays, fetchRelays} from '../lib/index.js'
import type {IStorageFactory, IStorage} from '../lib/index.js'
import {Lib, PackageEncoder} from '@frostr/bifrost'
import type {GroupPackage, SharePackage} from '@frostr/bifrost'

export type SignerOptions = {
  secret: string
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
  storage: IStorageFactory
}

export type SignerSession = {
  event: TrustedEvent
  share: SharePackage
  group: GroupPackage
  status: "pending" | "active"
}

export class Signer {
  private abortController = new AbortController()
  private sessions: IStorage<SignerSession>

  constructor(private options: SignerOptions) {
    this.sessions = options.storage("sessions")
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

  async start() {
    await this.publishRelays()
    this.listenForEvents()
  }

  stop() {
    this.abortController.abort()
  }

  async handleRegister(event: TrustedEvent) {
    const rpc = new RPC({
      other: event.pubkey,
      secret: this.options.secret
      indexerRelays: this.options.indexerRelays,
    })

    const cb = (status: string, message: string) =>
      rpc.send({
        signal: this.abortController.signal,
        method: RPCMethod.RegisterResult,
        requestContent: [
          ["status", status],
          ["message", message],
          ["e", event.id],
        ],
      })

    const tags: string[][] = parseJson(await nip44.decrypt(event.pubkey, this.options.secret, event.content))

    if (!Array.isArray(tags)) return cb("error", "Failed to parse encrypted tags.")

    const meta = fromPairs(tags)

    if (!meta.share)                               return cb("error", "No share was provided.")
    if (!meta.group)                               return cb("error", "No group was provided.")
    if (!meta.email_hash)                          return cb("error", "No email hash was provided.")
    if (!meta.email_ciphertext)                    return cb("error", "No email ciphertext was provided.")
    if (meta.email_service?.length !== 64)         return cb("error", "Invalid email service pubkey.")

    const share = tryCatch(() => PackageEncoder.share.deserialize(Buffer.from(meta.share, 'hex')))
    const group = tryCatch(() => PackageEncoder.group.deserialize(Buffer.from(meta.group, 'hex')))

    if (!share)                                    return cb("error", `Failed to deserialize share package.`)
    if (!group)                                    return cb("error", `Failed to deserialize group package.`)
    if (!Lib.is_group_member(group, share))        return cb("error", "Share does not belong to the provided group.")
    if (group.threshold <= 0)                      return cb("error", "Group threshold must be greater than zero.")
    if (group.threshold > group.commits.length)    return cb("error", "Invalid group threshold.")

    const indices = new Set(group.commits.map(c => c.idx))
    const commit = group.commits.find(c => c.idx === share.idx)

    if (indices.size !== group.commits.length)     return cb("error", "Group contains duplicate member indices.")
    if (!commit)                                   return cb("error", "Share index not found in group commits.")
    if (commit.pubkey !== getPubkey(share.seckey)) return cb("error", "Share public key does not match group commit.")
    if (await this.sessions.has(event.pubkey))     return cb("error", "Client key has already been used.")

    await this.sessions.set(event.pubkey, {event, share, group, status: "pending"})

    // Validate the email asynchronously
    rpcSend({
      authorSecret: this.options.secret,
      indexerRelays: this.options.indexerRelays,
      recipientPubkey: meta.email_service,
      requestKind: Kinds.ValidateEmail,
      requestContent: [
        ["client", event.pubkey],
        ["email_ciphertext", meta.email_ciphertext],
      ],
    })

    return cb("pending", "Please check your email to confirm your registration.")
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
