import {
  Maybe,
  pushToMapKey,
  tryCatch,
  shuffle,
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
import {prep, makeSecret, getPubkey, makeHttpAuth} from "@welshman/util"
import type {SignedEvent, StampedEvent} from "@welshman/util"
import {Schema, Lib} from "@frostr/bifrost"
import type {SharePackage, GroupPackage, ECDHPackage} from "@frostr/bifrost"
import {
  context,
  Method,
  ClientListResultMessage,
  isClientListResult,
  isEcdhResult,
  isLoginFinalizeResult,
  isLoginRequestResult,
  isRecoverFinalizeResult,
  isRecoverRequestResult,
  isRegisterResult,
  isSetEmailFinalizeResult,
  isSetEmailRequestResult,
  isSignResult,
  isUnregisterResult,
  LoginFinalizeResultMessage,
  LoginRequestResultMessage,
  RecoverFinalizeResultMessage,
  RecoverRequestResultMessage,
  makeClientListRequest,
  makeEcdhRequest,
  makeLoginFinalize,
  makeLoginRequest,
  makeRecoverFinalize,
  makeRecoverRequest,
  makeRegisterRequest,
  makeSetEmailFinalize,
  makeSetEmailRequest,
  makeSignRequest,
  makeUnregisterRequest,
  parseChallenge,
  RPC,
  SetEmailFinalizeResultMessage,
  SetEmailRequestResultMessage,
  SignResultMessage,
  Status,
  UnregisterResultMessage,
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
  pubkey: string
  userPubkey: string

  constructor(options: ClientOptions) {
    this.rpc = new RPC(options.secret)
    this.peers = options.peers
    this.group = options.group
    this.pubkey = getPubkey(options.secret)
    this.userPubkey = this.group.group_pk.slice(2)
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
    const remainingSignerPubkeys = shuffle(context.signerPubkeys)
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
    const email_hash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      context.signerPubkeys.map(async (peer, i) => {
        const channel = rpc.channel(peer)

        channel.send(makeLoginRequest({email_hash, pubkey}))

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
    const email_hash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      parseChallenge(challenge).map(async ([peer, otp]) => {
        const channel = rpc.channel(peer)

        channel.send(makeLoginFinalize({otp, email_hash}))

        return channel.receive<WithEvent<LoginFinalizeResultMessage>>((message, resolve) => {
          if (isLoginFinalizeResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    rpc.stop()

    let group: Maybe<GroupPackage> = undefined
    const peers: string[] = []

    for (const m of messages) {
      if (m?.payload.status !== Status.Ok || !m.payload.group) {
        continue
      }

      if (group && m.payload.group.group_pk !== group.group_pk) {
        continue
      }

      group = m.payload.group
      peers.push(m.event.pubkey)
    }

    if (group && peers.length >= group.threshold) {
      return {ok: true, group, peers, messages}
    }

    return {ok: false, messages}
  }

  static async recoverRequest(secret: string, email: string, pubkey?: string) {
    const rpc = new RPC(secret)
    const email_hash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      context.signerPubkeys.map(async (peer, i) => {
        const channel = rpc.channel(peer)

        channel.send(makeRecoverRequest({email_hash, pubkey}))

        return channel.receive<RecoverRequestResultMessage>((message, resolve) => {
          if (isRecoverRequestResult(message)) {
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

  static async recoverFinalize(secret: string, email: string, challenge: string) {
    const rpc = new RPC(secret)
    const email_hash = await sha256(textEncoder.encode(email))

    const messages = await Promise.all(
      parseChallenge(challenge).map(async ([peer, otp]) => {
        const channel = rpc.channel(peer)

        channel.send(makeRecoverFinalize({otp, email_hash}))

        return channel.receive<WithEvent<RecoverFinalizeResultMessage>>((message, resolve) => {
          if (isRecoverFinalizeResult(message)) {
            resolve(message)
          }
        })
      }),
    )

    rpc.stop()

    let group: Maybe<GroupPackage> = undefined
    const peers: string[] = []
    const shares: SharePackage[] = []

    for (const m of messages) {
      if (m?.payload.status !== Status.Ok || !m.payload.group || !m.payload.share) {
        continue
      }

      if (group && m.payload.group.group_pk !== group.group_pk) {
        continue
      }

      group = m.payload.group
      peers.push(m.event.pubkey)
      shares.push(m.payload.share)
    }

    const userSecret = tryCatch(() => Lib.recover_secret_key(group!, shares))

    if (userSecret) {
      return {ok: true, secret: userSecret, messages}
    }

    return {ok: false, messages}
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
    const {threshold, commits} = this.group
    const event = prep(stampedEvent, this.userPubkey)
    const members = sample(threshold, commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to create signing template")

    const session = Lib.create_session_pkg(this.group, template)

    const messages = await Promise.all(
      members.map(async idx => {
        const peer = this.peers[idx - 1]!
        const channel = this.rpc.channel(peer)

        const pub = channel.send(makeSignRequest({session}))

        return channel.receive<WithEvent<SignResultMessage>>((message, resolve) => {
          if (isSignResult(message) && message.payload.prev === pub.event.id) {
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

  async listClients() {
    const messages = await Promise.all(
      context.signerPubkeys.map(async (peer, i) => {
        const channel = this.rpc.channel(peer)
        const {event: auth} = await this.sign(await makeHttpAuth(peer, Method.ClientListRequest))

        if (auth) {
          const pub = channel.send(makeClientListRequest({auth}))

          return channel.receive<WithEvent<ClientListResultMessage>>((message, resolve) => {
            if (isClientListResult(message) && message.payload.prev === pub.event.id) {
              resolve(message)
            }
          })
        }
      }),
    )

    const resultsByClient = new Map<string, {peer: string; email_hash: string}[]>()

    for (const message of messages) {
      if (!message) continue

      for (const {client, email_hash} of message.payload.clients) {
        pushToMapKey(resultsByClient, client, {peer: message.event.pubkey, email_hash})
      }
    }

    return resultsByClient
  }

  async unregister(client: string, peers: string[]) {
    const messages = await Promise.all(
      peers.map(async (peer, i) => {
        const channel = this.rpc.channel(peer)
        const {event: auth} = await this.sign(await makeHttpAuth(peer, Method.UnregisterRequest))

        if (auth) {
          const pub = channel.send(makeUnregisterRequest({client, auth}))

          return channel.receive<WithEvent<UnregisterResultMessage>>((message, resolve) => {
            if (isUnregisterResult(message) && message.payload.prev === pub.event.id) {
              resolve(message)
            }
          })
        }
      }),
    )

    return {ok: messages.every(m => m?.payload.status === Status.Ok), messages}
  }
}
