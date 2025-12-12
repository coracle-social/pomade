import {not, sortBy, first, last, isDefined, sha256, sample, textEncoder} from "@welshman/lib"
import {hash, own, makeSecret} from "@welshman/util"
import type {SignedEvent, StampedEvent} from "@welshman/util"
import {Schema, Lib, PackageEncoder} from "@frostr/bifrost"
import type {GroupPackage, PartialSigPackage} from "@frostr/bifrost"
import {
  RPC,
  Status,
  context,
  makeRegisterRequest,
  isRegisterResult,
  makeSetEmailRequest,
  isSetEmailResult,
  makeSignRequest,
  isSignResult,
} from "../lib/index.js"

export type ClientOptions = {
  group: GroupPackage
  secret: string
  peers: string[]
}

export class Client {
  rpc: RPC
  peers: string[]
  group: GroupPackage

  constructor(options: ClientOptions) {
    this.rpc = new RPC(options.secret)
    this.peers = options.peers
    this.group = options.group
  }

  static async register(threshold: number, n: number, userSecret: string) {
    if (context.signerPubkeys.length < n) {
      throw new Error("Not enough signers available")
    }

    if (threshold <= 0) {
      throw new Error("Threshold must be greater than 0")
    }

    const secret = makeSecret()
    const rpc = new RPC(secret)
    const deal = Lib.generate_dealer_pkg(threshold, n, [userSecret])
    const group = PackageEncoder.group.encode(deal.group)
    const remainingSignerPubkeys = Array.from(context.signerPubkeys)
    const errorsByPeer = new Map<string, string>()
    const peersByIndex = new Map<number, string>()

    await Promise.all(
      deal.shares.map(async (rawShare, i) => {
        const share = PackageEncoder.share.encode(rawShare)

        while (remainingSignerPubkeys.length > 0 && !peersByIndex.has(i)) {
          const channel = rpc.channel(remainingSignerPubkeys.shift()!)

          channel.send(makeRegisterRequest({threshold, share, group}))

          await channel.receive((message, event, done) => {
            if (isRegisterResult(message)) {
              if (message.payload.status === Status.Ok) {
                peersByIndex.set(i, event.pubkey)
                done()
              }

              if (message.payload.status === Status.Error) {
                errorsByPeer.set(event.pubkey, message.payload.message)
                done()
              }
            }
          })
        }
      }),
    )

    // Check if we have enough successful registrations
    if (peersByIndex.size < n) {
      const errors = Array.from(errorsByPeer.entries())
        .map(([pubkey, error]) => `${pubkey}: ${error}`)
        .join("\n")

      throw new Error(`Failed to register all shards:\n${errors}`)
    }

    return new Client({group, secret, peers: sortBy(first, peersByIndex).map(last)})
  }

  async setEmail(email: string, emailService: string, otp?: string) {
    const emailHash = await sha256(textEncoder.encode(email))
    const emailCiphertext = this.rpc.encrypt(emailService, email)

    const errors = await Promise.all(
      this.peers.map(async (peer, i) => {
        const channel = this.rpc.channel(peer)

        channel.send(
          makeSetEmailRequest({
            email_hash: emailHash,
            email_service: emailService,
            email_ciphertext: emailCiphertext,
          }),
        )

        return channel.receive<string>((message, event, resolve) => {
          if (isSetEmailResult(message)) {
            if (message.payload.status === "ok") {
              resolve()
            }

            if (message.payload.status === "error") {
              resolve(message.payload.message)
            }
          }
        })
      }),
    )

    for (const error of errors) {
      if (error) {
        throw new Error(error)
      }
    }
  }

  async sign(stampedEvent: StampedEvent) {
    const {group_pk, threshold, commits} = this.group
    const event = hash(own(stampedEvent, group_pk))
    const members = sample(threshold, commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to build signing template")

    const pkg = Lib.create_session_pkg(this.group, template)

    const psigs = await Promise.all(
      members.map(async i => {
        const peer = this.peers[i]!
        const channel = this.rpc.channel(peer)

        channel.send(makeSignRequest({pkg, event}))

        return channel.receive<PartialSigPackage>((message, event, resolve) => {
          if (isSignResult(message)) {
            resolve(Schema.sign.psig_pkg.parse(message.payload.psig))
          }
        })
      }),
    )

    if (psigs.every(isDefined)) {
      const ctx = Lib.get_session_ctx(this.group, pkg)
      const sig = Lib.combine_signature_pkgs(ctx, psigs)[0]?.[2]

      if (!sig) throw new Error("Failed to combine signatures")

      return {...event, sig} as SignedEvent
    }
  }
}
