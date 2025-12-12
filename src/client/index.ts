import {not, sha256, sample, call, thrower, parseJson, spec, textEncoder} from '@welshman/lib'
import {publish, request, PublishStatus} from '@welshman/net'
import {prep, makeSecret, getPubkey, getTagValue} from '@welshman/util'
import type {TrustedEvent, SignedEvent, EventTemplate, StampedEvent} from '@welshman/util'
import {Schema, Lib, PackageEncoder} from '@frostr/bifrost'
import type {GroupPackage, PartialSigPackage} from '@frostr/bifrost'

import {RPC, Method} from '../lib/index.js'

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

          await new Promise(resolve => {
            setTimeout(resolve, 30_000)

            channel.subscribe(message => {
              if (isRegisterResult(message)) {
                if (message.payload.status === "ok") {
                  peers[i] = message.peer
                  resolve()
                }

                if (message.payload.status === 'error') {
                  errorsBySignerPubkey.set(message.peer, message.payload.message)
                  resolve()
                }
              }
            })
          })

          channel.close()
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
        const channel = rpc.channel(peer)

        channel.send(
          makeSetEmailRequest({
            email_hash: emailHash,
            email_service: emailService,
            email_ciphertext: emailCiphertext,
          })
        )

        await new Promise(resolve => {
          setTimeout(resolve, 30_000)

          channel.subscribe(message => {
            if (isSetEmailResult(message)) {
              if (payload.status === "ok") {
                resolve()
              }

              if (payload.status === 'error') {
                resolve(payload.message)
              }
            }
          })
        })
      }),
    )

    for (const error of errors) {
      if (error) {
        throw new Error(error)
      }
    }
  }

  async sign(event: StampedEvent) {
    const {group_pk, threshold, commits} = this.group

    if (event.pubkey !== group_pk) throw new Error("Event author does not match signer pubkey")

    const members = sample(group.threshold, group.commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to build signing template")

    const pkg = Lib.create_session_pkg(group, template)

    const psigs = await Promise.all(
      members.map(async i => {
        const peer = this.peers[i]!
        const channel = this.rpc.channel(peer)

        channel.send(makeSignRequest({pkg, event}))

        const message = await channel.receive(Method.SignResult)

        return Schema.sign.psig_pkg.parse(message.payload.psig)
      })
    )

    const ctx = Lib.get_session_ctx(group, pkg)
    const sig = Lib.combine_signature_pkgs(ctx, psigs)[0]?.[2]

    if (!sig) throw new Error('Failed to combine signatures')

    return {...event, sig} as SignedEvent
  }
}
