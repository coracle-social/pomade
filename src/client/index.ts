import {not, isDefined, sha256, sample, call, thrower, parseJson, spec, textEncoder} from '@welshman/lib'
import {publish, request, PublishStatus} from '@welshman/net'
import {prep, hash, own, makeSecret, getPubkey, getTagValue} from '@welshman/util'
import type {TrustedEvent, SignedEvent, EventTemplate, StampedEvent} from '@welshman/util'
import {Schema, Lib, PackageEncoder} from '@frostr/bifrost'
import type {GroupPackage, PartialSigPackage} from '@frostr/bifrost'
import {RPC, Status, Method, context, makeRegisterRequest, isRegisterResult, makeSetEmailRequest, isSetEmailResult, makeSignRequest, isSignResult} from '../lib/index.js'

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

  static async register(total: number, threshold: number, userSecret: string) {
    if (context.signerPubkeys.length < total) {
      throw new Error('Not enough signers to meet threshold')
    }

    if (threshold <= 0) {
      throw new Error('Threshold must be greater than 0')
    }

    const secret = makeSecret()
    const rpc = new RPC(secret)
    const userPubkey = getPubkey(userSecret)
    const {group, shares} = Lib.generate_dealer_pkg(threshold, total, [userSecret])
    const hexGroup = Buffer.from(PackageEncoder.group.encode(group)).toString('hex')
    const remainingSignerPubkeys = Array.from(context.signerPubkeys)
    const errorsBySignerPubkey = new Map<string, string>()
    const peers = new Array(0).fill("")

    await Promise.all(
      shares.map(async (share, i) => {
        const hexShare = Buffer.from(PackageEncoder.share.encode(share)).toString('hex')

        while (remainingSignerPubkeys.length > 0 && !peers[i]) {
          const channel = rpc.channel(remainingSignerPubkeys.shift()!)

          channel.send(makeRegisterRequest({threshold, share: hexShare, group: hexGroup}))

          await channel.receive((message, event, done) => {
            if (isRegisterResult(message)) {
              if (message.payload.status === Status.Ok) {
                peers[i] = event.pubkey
                done()
              }

              if (message.payload.status === Status.Error) {
                errorsBySignerPubkey.set(event.pubkey, message.payload.message)
                done()
              }
            }
          })
        }
      }),
    )

    // Check if we have enough successful registrations
    if (peers.some(not)) {
      const errors = Array.from(errorsBySignerPubkey.entries())
        .map(([pubkey, error]) => `${pubkey}: ${error}`)
        .join('\n')

      throw new Error(`Failed to register all shards:\n${errors}`)
    }

    return new Client({group, secret, peers})
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
          })
        )

        return channel.receive<string>((message, event, resolve) => {
          if (isSetEmailResult(message)) {
            if (message.payload.status === "ok") {
              resolve()
            }

            if (message.payload.status === 'error') {
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
      })
    )

    if (psigs.every(isDefined)) {
      const ctx = Lib.get_session_ctx(this.group, pkg)
      const sig = Lib.combine_signature_pkgs(ctx, psigs)[0]?.[2]

      if (!sig) throw new Error('Failed to combine signatures')

      return {...event, sig} as SignedEvent
    }
  }
}
