import * as z from "zod"
import {
  tryCatch,
  removeUndefined,
  pushToMapKey,
  shuffle,
  sortBy,
  fromPairs,
  first,
  last,
  isDefined,
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
import {Schema, Method, RecoveryType} from "./schema.js"
import {parseChallenge, context} from "./util.js"
import {RPC, WithEvent} from "./rpc.js"
import {
  isEcdhResult,
  isRecoveryFinalizeResult,
  isRecoveryMethodFinalizeResult,
  isRecoveryMethodSetResult,
  isRecoveryStartResult,
  isRegisterResult,
  isSessionDeleteResult,
  isSessionListResult,
  isSignResult,
  makeEcdhRequest,
  makeRecoveryFinalize,
  makeRecoveryMethodFinalize,
  makeRecoveryMethodSet,
  makeRecoveryStart,
  makeRegisterRequest,
  makeSessionDelete,
  makeSessionList,
  makeSignRequest,
  RecoveryFinalizeResult,
  RecoveryMethodFinalizeResult,
  RecoveryMethodSetResult,
  RecoveryStartResult,
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

  static async startRecovery(inbox: string, callback_url?: string, pubkey?: string) {
    if (context.signerPubkeys.length === 0) {
      console.log("[pomade]: You can configure available signer pubkeys using setSignerPubkeys")
      throw new Error("No signer pubkeys available")
    }

    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      context.signerPubkeys.map((peer, i) => {
        return rpc
          .channel(peer)
          .send(makeRecoveryStart({type: RecoveryType.Recovery, inbox, callback_url, pubkey}))
          .receive<RecoveryStartResult>((message, resolve) => {
            if (isRecoveryStartResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async finalizeRecovery(clientSecret: string, challenge: string) {
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      parseChallenge(challenge).map(([peer, otp]) => {
        return rpc
          .channel(peer)
          .send(makeRecoveryFinalize({otp}))
          .receive<WithEvent<RecoveryFinalizeResult>>((message, resolve) => {
            if (isRecoveryFinalizeResult(message)) {
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

  static async startLogin(inbox: string, callback_url?: string, pubkey?: string) {
    if (context.signerPubkeys.length === 0) {
      console.log("[pomade]: You can configure available signer pubkeys using setSignerPubkeys")
      throw new Error("No signer pubkeys available")
    }

    const clientSecret = makeSecret()
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      context.signerPubkeys.map((peer, i) => {
        return rpc
          .channel(peer)
          .send(makeRecoveryStart({type: RecoveryType.Login, inbox, callback_url, pubkey}))
          .receive<RecoveryStartResult>((message, resolve) => {
            if (isRecoveryStartResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return {ok: messages.every(m => m?.payload.ok), messages, clientSecret}
  }

  static async finalizeLogin(clientSecret: string, challenge: string) {
    const rpc = new RPC(clientSecret)

    const messages = await Promise.all(
      parseChallenge(challenge).map(([peer, otp]) => {
        return rpc
          .channel(peer)
          .send(makeRecoveryFinalize({otp}))
          .receive<WithEvent<RecoveryFinalizeResult>>((message, resolve) => {
            if (isRecoveryFinalizeResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    const group = messages.find(m => m?.payload.group)?.payload.group
    const peers = removeUndefined(messages.map(m => m?.event.pubkey))

    return {
      messages,
      ok: messages.every(m => m?.payload.ok),
      clientOptions: {
        secret: clientSecret,
        group: group!,
        peers,
      },
    }
  }

  async setRecoveryMethod(inbox: string, mailer: string, callback_url?: string) {
    const messages = await Promise.all(
      this.peers.map((peer, i) => {
        return this.rpc
          .channel(peer)
          .send(makeRecoveryMethodSet({inbox, mailer, callback_url}))
          .receive<WithEvent<RecoveryMethodSetResult>>((message, resolve) => {
            if (isRecoveryMethodSetResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
  }

  async finalizeRecoveryMethod(challenge: string) {
    const otpsByPeer = fromPairs(parseChallenge(challenge))

    const messages = await Promise.all(
      this.peers.map((peer, i) => {
        const otp = otpsByPeer[peer] || ""

        if (otp) {
          return this.rpc
            .channel(peer)
            .send(makeRecoveryMethodFinalize({otp}))
            .receive<WithEvent<RecoveryMethodFinalizeResult>>((message, resolve) => {
              if (isRecoveryMethodFinalizeResult(message)) {
                resolve(message)
              }
            })
        }
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
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
      context.signerPubkeys.map(async (peer, i) => {
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

    const sessionsByClient = new Map<
      string,
      z.infer<typeof Schema.sessionItem> & {peer: string}[]
    >()

    for (const message of messages) {
      if (!message) continue

      for (const sessionItem of message.payload.sessions) {
        pushToMapKey(sessionsByClient, sessionItem.client, {
          peer: message.event.pubkey,
          ...sessionItem,
        })
      }
    }

    return sessionsByClient
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
