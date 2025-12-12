import {Lib, PackageEncoder} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {RPC, Status, makeRegisterResult, isRegisterRequest, isSignRequest, makeSignResult} from "../lib/index.js"
import type {IStorageFactory, IStorage, RegisterRequest, SignRequest} from "../lib/index.js"

export type SignerRegistration = {
  share: SharePackage
  group: GroupPackage
  event: TrustedEvent
}

export type SignerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
}

export class Signer {
  rpc: RPC
  pubkey: string
  registrations: IStorage<SignerRegistration>
  stop: () => void

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.registrations = options.storage("registrations")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe((message, event) => {
      if (isRegisterRequest(message)) this.handleRegisterRequest(message, event)
      if (isSignRequest(message)) this.handleSignRequest(message, event)
    })
  }

  async handleRegisterRequest({payload}: RegisterRequest, event: TrustedEvent) {
    const channel = this.rpc.channel(event.pubkey)
    const share = tryCatch(() => PackageEncoder.share.decode(payload.share))
    const group = tryCatch(() => PackageEncoder.group.decode(payload.group))
    const cb = (status: Status, message: string) =>
      channel.send(makeRegisterResult({status, message}))

    if (!share) return cb(Status.Error, `Failed to deserialize share package.`)
    if (!group) return cb(Status.Error, `Failed to deserialize group package.`)

    const isMember = Lib.is_group_member(group, share)

    if (!isMember) return cb(Status.Error, "Share does not belong to the provided group.")
    if (group.threshold <= 0) return cb(Status.Error, "Group threshold must be greater than zero.")
    if (group.threshold > group.commits.length) return cb(Status.Error, "Invalid group threshold.")

    const indices = new Set(group.commits.map(c => c.idx))
    const commit = group.commits.find(c => c.idx === share.idx)

    if (indices.size !== group.commits.length)
      return cb(Status.Error, "Group contains duplicate member indices.")
    if (!commit) return cb(Status.Error, "Share index not found in group commits.")
    if (await this.registrations.has(event.pubkey))
      return cb(Status.Error, "Client key has already been used.")

    await this.registrations.set(event.pubkey, {event, share, group})

    return cb(Status.Ok, "Your key has been registered")
  }

  async handleSignRequest({payload}: SignRequest, event: TrustedEvent) {
    const channel = this.rpc.channel(event.pubkey)
    const registration = await this.registrations.get(event.pubkey)

    if (!registration) {
      return channel.send(
        makeSignResult({
          status: Status.Error,
          message: "No registration found for client",
        })
      )
    }

    const ctx = Lib.get_session_ctx(registration.group, payload.session)
    const psig = Lib.create_psig_pkg(ctx, registration.share)

    channel.send(
      makeSignResult({
        psig,
        status: Status.Ok,
        message: "Successfully signed event",
      })
    )
  }
}
