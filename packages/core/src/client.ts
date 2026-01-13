import {
  Maybe,
  tryCatch,
  groupBy,
  removeUndefined,
  shuffle,
  randomId,
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
import {prep, makeSecret, makeHttpAuth} from "@welshman/util"
import type {SignedEvent, StampedEvent} from "@welshman/util"
import {Lib} from "@frostr/bifrost"
import type {GroupPackage, ECDHPackage} from "@frostr/bifrost"
import {Method} from "./schema.js"
import {context, hashEmail, hashPassword} from "./util.js"
import {RPC, WithEvent} from "./rpc.js"
import {
  isEcdhResult,
  isLoginOptions,
  isLoginResult,
  isRecoveryOptions,
  isRecoveryResult,
  isRecoverySetupResult,
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
  makeRecoverySetup,
  makeRegisterRequest,
  makeSessionDelete,
  makeSessionList,
  makeSignRequest,
  LoginOptions,
  LoginResult,
  RecoveryOptions,
  RecoveryResult,
  RecoverySetupResult,
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

export type ClientOptionsResult<T> = {
  ok: boolean
  options: [string, string[]][]
  messages: Maybe<T>[]
  clientSecret: string
}

export class Client {
  rpc: RPC
  peers: string[]
  group: GroupPackage
  userPubkey: string

  constructor(options: ClientOptions) {
    this.rpc = RPC.fromSecret(options.secret)
    this.peers = options.peers
    this.group = options.group
    this.userPubkey = this.group.group_pk.slice(2)
  }

  stop() {
    this.rpc.stop()
  }

  getPubkey() {
    return this.rpc.signer.getPubkey()
  }

  static _buildOptions<T extends WithEvent<LoginOptions | RecoveryOptions>>(
    clientSecret: string,
    messages: Maybe<T>[],
    threshold: "total" | "threshold",
  ): ClientOptionsResult<T> {
    // Extract all items with their metadata
    const items = messages.flatMap(
      m =>
        m?.payload.items?.map(item => ({
          client: item.client,
          peer: m.event.pubkey,
          idx: item.idx,
          total: item.total,
          threshold: item.threshold,
        })) || [],
    )

    // Group by client
    const itemsByClient = Array.from(groupBy(item => item.client, items))

    // Build options, filtering out incomplete sets
    const options: [string, string[]][] = []

    for (const [client, clientItems] of itemsByClient) {
      // Get the expected total (should be the same for all items of this client)
      const total = clientItems[0]?.[threshold]
      if (!total || clientItems.length < total) continue

      // Check that we have all indices from 1 to total
      const idxSet = new Set(clientItems.map(item => item.idx))
      const hasAllIndices = Array.from({length: total}, (_, i) => i + 1).every(idx =>
        idxSet.has(idx),
      )

      if (!hasAllIndices) continue

      // Sort by idx and map to peers
      const peers = sortBy(item => item.idx, clientItems).map(item => item.peer)
      options.push([client, peers])
    }

    const ok = messages.some(m => m?.payload.ok) && options.length > 0

    return {ok, options, messages, clientSecret}
  }

  static _getKnownPeers() {
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
    const rpc = RPC.fromSecret(secret)
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

  async setupRecovery(email: string, password: string) {
    const messages = await Promise.all(
      this.peers.map(async (peer, i) => {
        const password_hash = await hashPassword(email, password, peer)

        return this.rpc
          .channel(peer)
          .send(makeRecoverySetup({email, password_hash}))
          .receive<WithEvent<RecoverySetupResult>>((message, resolve) => {
            if (isRecoverySetupResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    return {ok: messages.every(m => m?.payload.ok), messages}
  }

  // Challenge

  static async requestChallenge(email: string, peers = Client._getKnownPeers()) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)
    const peersByPrefix = new Map<string, string>()

    const oks = await Promise.all(
      peers.map(async (peer, i) => {
        let prefix = randomId().slice(-2)
        while (peersByPrefix.has(prefix)) {
          prefix = randomId().slice(-2)
        }

        peersByPrefix.set(prefix, peer)

        const email_hash = await hashEmail(email, peer)

        return rpc.channel(peer).send(makeChallengeRequest({prefix, email_hash})).ok
      }),
    )

    rpc.stop()

    return {ok: oks.every(identity), peersByPrefix}
  }

  // Login

  static async loginWithPassword(email: string, password: string) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      Client._getKnownPeers().map(async (peer, i) => {
        const email_hash = await hashEmail(email, peer)
        const password_hash = await hashPassword(email, password, peer)
        const auth = {email_hash, password_hash}

        return rpc
          .channel(peer)
          .send(makeLoginStart({auth}))
          .receive<WithEvent<LoginOptions>>((message, resolve) => {
            if (isLoginOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return this._buildOptions(clientSecret, messages, "total")
  }

  static async loginWithChallenge(
    email: string,
    peersByPrefix: Map<string, string>,
    otps: string[],
  ) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      otps.map(async otp => {
        const peer = peersByPrefix.get(otp.slice(0, 2))

        if (peer) {
          const email_hash = await hashEmail(email, peer)
          const auth = {email_hash, otp}

          return rpc
            .channel(peer)
            .send(makeLoginStart({auth}))
            .receive<WithEvent<LoginOptions>>((message, resolve) => {
              if (isLoginOptions(message)) {
                resolve(message)
              }
            })
        }
      }),
    )

    rpc.stop()

    return this._buildOptions(clientSecret, messages, "total")
  }

  static async selectLogin(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      peers.map((peer, i) => {
        return rpc
          .channel(peer)
          .send(makeLoginSelect({client}))
          .receive<WithEvent<LoginResult>>((message, resolve) => {
            if (isLoginResult(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    const group = messages.find(m => m?.payload.group)?.payload.group
    const ok = Boolean(group && messages.every(m => m?.payload.ok))
    const clientOptions = ok ? ({group, peers, secret: clientSecret} as ClientOptions) : undefined

    return {ok, messages, clientOptions}
  }

  // Recovery

  static async recoverWithPassword(email: string, password: string) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      Client._getKnownPeers().map(async (peer, i) => {
        const email_hash = await hashEmail(email, peer)
        const password_hash = await hashPassword(email, password, peer)
        const auth = {email_hash, password_hash}

        return rpc
          .channel(peer)
          .send(makeRecoveryStart({auth}))
          .receive<WithEvent<RecoveryOptions>>((message, resolve) => {
            if (isRecoveryOptions(message)) {
              resolve(message)
            }
          })
      }),
    )

    rpc.stop()

    return this._buildOptions(clientSecret, messages, "threshold")
  }

  static async recoverWithChallenge(
    email: string,
    peersByPrefix: Map<string, string>,
    otps: string[],
  ) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      otps.map(async otp => {
        const peer = peersByPrefix.get(otp.slice(0, 2))

        if (peer) {
          const email_hash = await hashEmail(email, peer)
          const auth = {email_hash, otp}

          return rpc
            .channel(peer)
            .send(makeRecoveryStart({auth}))
            .receive<WithEvent<RecoveryOptions>>((message, resolve) => {
              if (isRecoveryOptions(message)) {
                resolve(message)
              }
            })
        }
      }),
    )

    rpc.stop()

    return this._buildOptions(clientSecret, messages, "threshold")
  }

  static async selectRecovery(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

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
      members.map(idx => {
        const peer = this.peers[idx - 1]!
        const channel = this.rpc.channel(peer)

        return channel
          .send(makeEcdhRequest({idx, members, ecdh_pk}))
          .receive<ECDHPackage>((message, resolve) => {
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
      Client._getKnownPeers().map(async (peer, i) => {
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
