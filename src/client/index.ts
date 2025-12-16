import {
  sortBy,
  fromPairs,
  uniq,
  first,
  last,
  isDefined,
  sha256,
  sample,
  textEncoder,
} from "@welshman/lib"
import {extract} from "@noble/hashes/hkdf.js"
import {sha256 as sha256Hash} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"
import {hash, own, makeSecret} from "@welshman/util"
import type {SignedEvent, StampedEvent} from "@welshman/util"
import {Schema, Lib, PackageEncoder} from "@frostr/bifrost"
import type {GroupPackage, ECDHPackage} from "@frostr/bifrost"
import {
  context,
  isEcdhResult,
  isLoginFinalizeResult,
  isLoginRequestResult,
  isRegisterResult,
  isSetEmailFinalizeResult,
  isSetEmailRequestResult,
  isSignResult,
  LoginFinalizeResultMessage,
  LoginRequestResultMessage,
  makeEcdhRequest,
  makeLoginFinalize,
  makeLoginRequest,
  makeRegisterRequest,
  makeSetEmailFinalize,
  makeSetEmailRequest,
  makeSignRequest,
  parseChallenge,
  RPC,
  SetEmailFinalizeResultMessage,
  SetEmailRequestResultMessage,
  SignResultMessage,
  Status,
  WithEvent,
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
    const {group, shares} = Lib.generate_dealer_pkg(threshold, n, [userSecret])
    const remainingSignerPubkeys = Array.from(context.signerPubkeys)
    const errorsByPeer = new Map<string, string>()
    const peersByIndex = new Map<number, string>()

    await Promise.all(
      shares.map(async (share, i) => {
        while (remainingSignerPubkeys.length > 0 && !peersByIndex.has(i)) {
          const channel = rpc.channel(remainingSignerPubkeys.shift()!)

          channel.send(makeRegisterRequest({threshold, share, group}))

          await channel.receive((message, resolve) => {
            if (isRegisterResult(message)) {
              if (message.payload.status === Status.Ok) {
                peersByIndex.set(i, message.event.pubkey)
                resolve()
              }

              if (message.payload.status === Status.Error) {
                errorsByPeer.set(message.event.pubkey, message.payload.message)
                resolve()
              }
            }
          })
        }
      }),
    )

    rpc.stop()

    // Check if we have enough successful registrations
    if (peersByIndex.size < n) {
      const errors = Array.from(errorsByPeer.entries())
        .map(([pubkey, error]) => `${pubkey}: ${error}`)
        .join("\n")

      throw new Error(`Failed to register all shards:\n${errors}`)
    }

    return new Client({
      secret,
      group,
      peers: sortBy(first, peersByIndex).map(last) as string[],
    })
  }

  static async loginRequest(secret: string, email: string, pubkey?: string) {
    const rpc = new RPC(secret)
    const emailHash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      context.signerPubkeys.map(async (peer, i) => {
        const channel = rpc.channel(peer)

        channel.send(makeLoginRequest({email_hash: emailHash}))

        return channel.receive<LoginRequestResultMessage>((message, resolve) => {
          if (isLoginRequestResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    rpc.stop()

    return {
      messages,
      ok: messages.every(m => m?.payload.status === Status.Ok),
      options: uniq(messages.flatMap(m => m?.payload.options || [])),
    }
  }

  static async loginFinalize(secret: string, email: string, challenge: string) {
    const rpc = new RPC(secret)
    const emailHash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      parseChallenge(challenge).map(async ([peer, otp]) => {
        const channel = rpc.channel(peer)

        channel.send(makeLoginFinalize({otp, email_hash: emailHash}))

        return channel.receive<WithEvent<LoginFinalizeResultMessage>>((message, resolve) => {
          if (isLoginFinalizeResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.status === Status.Ok), messages}
  }

  async setEmailRequest(email: string, emailService: string) {
    const emailHash = await sha256(textEncoder.encode(email))
    const emailCiphertext = this.rpc.encrypt(emailService, email)

    const messages = await Promise.all(
      this.peers.map(async (peer, i) => {
        const channel = this.rpc.channel(peer)

        channel.send(
          makeSetEmailRequest({
            email_hash: emailHash,
            email_service: emailService,
            email_ciphertext: emailCiphertext,
          }),
        )

        return channel.receive<WithEvent<SetEmailRequestResultMessage>>((message, resolve) => {
          if (isSetEmailRequestResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    return {ok: messages.every(m => m?.payload.status === Status.Ok), messages}
  }

  async setEmailFinalize(email: string, emailService: string, challenge: string) {
    const emailHash = await sha256(textEncoder.encode(email))
    const otpsByPeer = fromPairs(parseChallenge(challenge))

    const messages = await Promise.all(
      this.peers.map(async (peer, i) => {
        const channel = this.rpc.channel(peer)

        channel.send(
          makeSetEmailFinalize({
            email_hash: emailHash,
            otp: otpsByPeer[peer] || "",
          }),
        )

        return channel.receive<WithEvent<SetEmailFinalizeResultMessage>>((message, resolve) => {
          if (isSetEmailFinalizeResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    return {ok: messages.every(m => m?.payload.status === Status.Ok), messages}
  }

  async sign(stampedEvent: StampedEvent) {
    const {group_pk, threshold, commits} = this.group
    const event = hash(own(stampedEvent, group_pk.slice(2)))
    const members = sample(threshold, commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to create signing template")

    const session = Lib.create_session_pkg(this.group, template)

    const messages = await Promise.all(
      members.map(async idx => {
        const peer = this.peers[idx - 1]!
        const channel = this.rpc.channel(peer)

        channel.send(makeSignRequest({session}))

        return channel.receive<WithEvent<SignResultMessage>>((message, resolve) => {
          if (isSignResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    if (messages.every(m => m?.payload.status === Status.Ok)) {
      const ctx = Lib.get_session_ctx(this.group, session)
      const pkgs = messages.map(m => Schema.sign.psig_pkg.parse(m!.payload.result))
      const sig = Lib.combine_signature_pkgs(ctx, pkgs)[0]?.[2]

      if (sig) {
        return {ok: true, messages, event: {...event, sig} as SignedEvent}
      }
    }

    return {ok: false, messages}
  }

  async getConversationKey(ecdh_pk: string) {
    const {threshold, commits} = this.group
    const members = sample(threshold, commits).map(c => c.idx)

    const results = await Promise.all(
      members.map(async idx => {
        const peer = this.peers[idx - 1]!
        const channel = this.rpc.channel(peer)

        channel.send(makeEcdhRequest({idx, members, ecdh_pk}))

        return channel.receive<ECDHPackage>((message, resolve) => {
          if (isEcdhResult(message)) {
            resolve(message.payload.result)
          }
        })
      }),
    )

    if (results.every(isDefined)) {
      return bytesToHex(
        extract(
          sha256Hash,
          hexToBytes(Lib.combine_ecdh_pkgs(results).slice(2)),
          textEncoder.encode("nip44-v2"),
        ),
      )
    }
  }
}
