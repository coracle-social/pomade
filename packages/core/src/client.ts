import * as b58 from "base58-js"
import {
  tryCatch,
  textDecoder,
  removeUndefined,
  splitAt,
  shuffle,
  sortBy,
  first,
  last,
  isDefined,
  identity,
  sample,
  textEncoder,
} from "@welshman/lib"
import {extract} from "@noble/hashes/hkdf.js"
import {sha256} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"
import {prep, makeSecret, getPubkey, makeHttpAuth} from "@welshman/util"
import type {SignedEvent, StampedEvent} from "@welshman/util"
import {Lib} from "@frostr/bifrost"
import type {GroupPackage, ECDHPackage} from "@frostr/bifrost"
import {Method} from "./schema.js"
import {context, hashArgon} from "./util.js"
import {RPC, WithEvent} from "./rpc.js"
import {
  isEcdhResult,
  isLoginOptions,
  isLoginResult,
  isRecoveryOptions,
  isRecoveryResult,
  isRecoveryMethodInitResult,
  isRegisterResult,
  isSessionDeleteResult,
  isSessionListResult,
  isSignResult,
  makeChallengeRequest,
  makeEcdhRequest,
  makeLoginStart,
  makeLoginSelect,
  makeRecoveryStart,
  makeRecoverySelect,
  makeRecoveryMethodInit,
  makeRegisterRequest,
  makeSessionDelete,
  makeSessionList,
  makeSignRequest,
  LoginOptions,
  LoginResult,
  RecoveryOptions,
  RecoveryResult,
  RecoveryMethodInitResult,
  RegisterResult,
  SessionDeleteResult,
  SessionListResult,
  SignResult,
} from "./message.js"

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

  stop() {
    this.rpc.stop()
  }

  static getKnownPeers() {
    if (context.signerPubkeys.length === 0) {
      console.log("[pomade]: You can configure available signer pubkeys using setSignerPubkeys")
      throw new Error("No signer pubkeys available")
    }

    return context.signerPubkeys
  }

  // Register

  static async register(threshold: number, n: number, userSecret: string, recovery = true) {
    if (context.signerPubkeys.length < n) {
      console.log("[pomade]: You can configure available signer pubkeys using setSignerPubkeys")
      throw new Error("Not enough signer pubkeys available")
    }

    if (threshold <= 0) {
      throw new Error("Threshold must be greater than 0")
    }

    const secret = makeSecret()
    const rpc = new RPC(secret)
    const {group, shares} = Lib.generate_dealer_pkg(threshold, n, [userSecret])
    const remainingSignerPubkeys = shuffle(context.signerPubkeys)
    const peersByIndex = new Map<number, string>()

    const messages = await Promise.all(
      shares.map(async (share, i) => {
        while (remainingSignerPubkeys.length > 0) {
          const messages = await rpc
            .channel(remainingSignerPubkeys.shift()!)
            .send(makeRegisterRequest({share, group, recovery}))
            .receive<RegisterResult>((message, resolve) => {
              if (isRegisterResult(message)) {
                if (message.payload.ok) {
                  peersByIndex.set(i, message.event.pubkey)
                }

                resolve(message)
              }
            })

          if (peersByIndex.has(i)) {
            return messages
          }
        }
      }),
    )

    rpc.stop()

    const ok = peersByIndex.size === n
    const peers = sortBy(first, peersByIndex).map(last) as string[]

    return {
      ok,
      messages,
      clientOptions: {
        peers,
        group,
        secret,
      },
    }
  }

  // Recovery setup

  async initializeRecoveryMethod(email: string, userPassword: string) {
    const messages = await Promise.all(
      this.peers.map(async (peer, i) => {
        const password = await hashArgon(userPassword, peer)

        return this.rpc
          .channel(peer)
          .send(makeRecoveryMethodInit({email, password}))
          .receive<WithEvent<RecoveryMethodInitResult>>((message, resolve) => {
            if (isRecoveryMethodInitResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
  }

  // Challenge

  static async requestChallenge(email: string) {
    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const oks = await Promise.all(
      Client.getKnownPeers().map(async (peer, i) => {
        const email_hash = await hashArgon(email, peer)

        return rpc.channel(peer).send(makeChallengeRequest({email_hash})).ok
      }),
    )

    rpc.stop()

    return {ok: oks.every(identity)}
  }

  // Login

  static async loginWithPassword(email: string, userPassword: string) {
    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      Client.getKnownPeers().map(async (peer, i) => {
        const auth = {
          email_hash: await hashArgon(email, peer),
          password: await hashArgon(userPassword, peer),
        }

        return rpc
          .channel(peer)
          .send(makeLoginStart({auth}))
          .receive<LoginOptions>((message, resolve) => {
            if (isLoginOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async loginWithChallenge(email: string, challenges: string[]) {
    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      challenges.map(async base58 => {
        const challenge = textDecoder.decode(b58.base58_to_binary(base58))
        const peer = challenge.slice(0, 64)
        const otp = challenge.slice(64)
        const email_hash = await hashArgon(email, peer)
        const auth = {email_hash, otp}

        return rpc
          .channel(peer)
          .send(makeLoginStart({auth}))
          .receive<LoginOptions>((message, resolve) => {
            if (isLoginOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async selectLogin(clientSecret: string, client: string, peers: string[]) {
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      peers.map((peer, i) => {
        return rpc
          .channel(peer)
          .send(makeLoginSelect({client}))
          .receive<LoginResult>((message, resolve) => {
            if (isLoginResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    const group = messages.find(m => m?.payload.group)?.payload.group

    return {ok: messages.every(m => m?.payload.ok), messages, group, clientSecret}
  }

  // Recovery

  static async recoverWithPassword(email: string, userPassword: string) {
    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      Client.getKnownPeers().map(async (peer, i) => {
        const auth = {
          email_hash: await hashArgon(email, peer),
          password: await hashArgon(userPassword, peer),
        }

        return rpc
          .channel(peer)
          .send(makeRecoveryStart({auth}))
          .receive<RecoveryOptions>((message, resolve) => {
            if (isRecoveryOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async recoverWithChallenge(email: string, challenges: string[]) {
    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      challenges.map(async base58 => {
        const challenge = textDecoder.decode(b58.base58_to_binary(base58))
        const peer = challenge.slice(0, 64)
        const otp = challenge.slice(64)
        const email_hash = await hashArgon(email, peer)
        const auth = {email_hash, otp}

        return rpc
          .channel(peer)
          .send(makeRecoveryStart({auth}))
          .receive<RecoveryOptions>((message, resolve) => {
            if (isRecoveryOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async selectRecovery(clientSecret: string, client: string, peers: string[]) {
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      peers.map(peer => {
        return rpc
          .channel(peer)
          .send(makeRecoverySelect({client}))
          .receive<WithEvent<RecoveryResult>>((message, resolve) => {
            if (isRecoveryResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    const group = messages.find(m => m?.payload.group)?.payload.group
    const shares = removeUndefined(messages.map(m => m?.payload.share))
    const userSecret = tryCatch(() => Lib.recover_secret_key(group!, shares))

    return {ok: Boolean(userSecret), messages, userSecret}
  }

  async sign(stampedEvent: StampedEvent) {
    // TODO: optimize this so that all signers are asked, but only the fastest results get used
    const {threshold, commits} = this.group
    const event = prep(stampedEvent, this.userPubkey)
    const members = sample(threshold, commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to create signing template")

    const request = Lib.create_session_pkg(this.group, template)

    const messages = await Promise.all(
      members.map(idx => {
        const peer = this.peers[idx - 1]!

        return this.rpc
          .channel(peer)
          .send(makeSignRequest({request}))
          .receive<WithEvent<SignResult>>((message, resolve) => {
            if (isSignResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    if (messages.every(m => m?.payload.ok)) {
      const ctx = Lib.get_session_ctx(this.group, request)
      const pkgs = messages.map(m => m!.payload.result!)
      const sig = Lib.combine_signature_pkgs(ctx, pkgs)[0]?.[2]

      if (sig) {
        return {ok: true, messages, event: {...event, sig} as SignedEvent}
      }
    }

    return {ok: false, messages}
  }

  async getConversationKey(ecdh_pk: string) {
    // TODO: optimize this so that all signers are asked, but only the fastest results get used
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
          sha256,
          hexToBytes(Lib.combine_ecdh_pkgs(results).slice(2)),
          textEncoder.encode("nip44-v2"),
        ),
      )
    }
  }

  async listSessions() {
    const messages = await Promise.all(
      Client.getKnownPeers().map(async (peer, i) => {
        const {event: auth} = await this.sign(await makeHttpAuth(peer, Method.SessionList))

        if (auth) {
          return this.rpc
            .channel(peer)
            .send(makeSessionList({auth}))
            .receive<WithEvent<SessionListResult>>((message, resolve) => {
              if (isSessionListResult(message)) {
                resolve(message)
              }
            })
        }
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
  }

  async deleteSession(client: string, peers: string[]) {
    const messages = await Promise.all(
      peers.map(async (peer, i) => {
        const {event: auth} = await this.sign(await makeHttpAuth(peer, Method.SessionDelete))

        if (auth) {
          return this.rpc
            .channel(peer)
            .send(makeSessionDelete({client, auth}))
            .receive<WithEvent<SessionDeleteResult>>((message, resolve) => {
              if (isSessionDeleteResult(message)) {
                resolve(message)
              }
            })
        }
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
  }
}
