import {
  tryCatch,
  groupBy,
  removeUndefined,
  shuffle,
  randomId,
  sortBy,
  first,
  last,
  isDefined,
  indexBy,
  textEncoder,
  identity,
} from "@welshman/lib"
import {extract} from "@noble/hashes/hkdf.js"
import {sha256} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"
import {prep, makeSecret} from "@welshman/util"
import type {StampedEvent, SignedEvent} from "@welshman/util"
import {Lib} from "@frostr/bifrost"
import type {CommitPackage, GroupPackage} from "@frostr/bifrost"
import {context, hashEmail, hashPassword, permutations, delay} from "./util.js"
import {RPC} from "./rpc.js"
import {PomadeSigner} from "./pomade-signer.js"
import {
  Message,
  ChallengeResponse,
  LoginStartResponse,
  RecoveryStartResponse,
  LoginSelectResponse,
  RecoverySelectResponse,
  RecoverySetupResponse,
  RegisterResponse,
  SessionDeactivateResponse,
  SessionDeleteResponse,
  SessionListResponse,
  SignCommitResponse,
  SignCompleteResponse,
  EcdhResponse,
} from "./message.js"

export type ClientOptions = {
  group: GroupPackage
  secret: string
  peers: string[]
}

export type AccountOption = {
  pubkey: string
  client: string
  peers: string[]
}

export type ClientOptionsResult<T> = {
  ok: boolean
  options: AccountOption[]
  messages: Message<T>[]
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

  getPubkey() {
    return this.rpc.signer.getPubkey()
  }

  static _buildAccountOptions<T extends LoginStartResponse | RecoveryStartResponse>(
    clientSecret: string,
    messages: Message<T>[],
  ): ClientOptionsResult<T> {
    const items = messages.flatMap(
      m =>
        m.res?.items?.map(item => ({
          pubkey: item.pubkey,
          client: item.client,
          url: m.url,
          idx: item.idx,
          total: item.total,
          threshold: item.threshold,
        })) || [],
    )

    const options: AccountOption[] = []

    for (const [, groupItems] of groupBy(item => `${item.pubkey}:${item.client}`, items)) {
      const required = groupItems[0]?.threshold

      if (!required || groupItems.length < required) continue

      const {pubkey, client, total} = groupItems[0]
      const peers: string[] = new Array(total).fill("")
      for (const item of groupItems) {
        peers[item.idx - 1] = item.url
      }

      options.push({pubkey, client, peers})
    }

    const ok = messages.some(m => m.res?.ok) && options.length > 0

    return {ok, options, messages, clientSecret}
  }

  static _getKnownPeers() {
    if (context.signerUrls.length === 0) {
      console.log("[pomade]: You can configure available signer URLs using setSignerUrls")
      throw new Error("No signer URLs available")
    }

    return context.signerUrls
  }

  static async register(threshold: number, n: number, userSecret: string, recovery = true) {
    if (context.signerUrls.length < n) {
      console.log("[pomade]: You can configure available signer URLs using setSignerUrls")
      throw new Error("Not enough signer URLs available")
    }

    if (threshold <= 0) {
      throw new Error("Threshold must be greater than 0")
    }

    const secret = makeSecret()
    const rpc = RPC.fromSecret(secret)
    const {group, shares} = Lib.generate_dealer_pkg(threshold, n, [userSecret])
    const remainingSignerUrls = shuffle(context.signerUrls)
    const peersByIndex = new Map<number, string>()

    const messages = await Promise.all(
      shares.map(async (share, i) => {
        while (remainingSignerUrls.length > 0) {
          const url = remainingSignerUrls.shift()!
          const message = await rpc.post<RegisterResponse>(
            url,
            "/register",
            {share, group, recovery},
            {pow: context.registerPow},
          )

          if (message.res?.ok) {
            peersByIndex.set(i, url)
            return message
          }
        }
      }),
    )

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

  async setupRecovery(email: string, password: string) {
    const messages = await Promise.all(
      this.peers.map(async url => {
        const password_hash = await hashPassword(email, password, url)

        return this.rpc.post<RecoverySetupResponse>(url, "/recovery/setup", {email, password_hash})
      }),
    )

    return {ok: messages.every(m => m.res?.ok), messages}
  }

  static async requestChallenge(email: string, peers = Client._getKnownPeers()) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)
    const peersByPrefix = new Map<string, string>()

    const results = await Promise.all(
      peers.map(async url => {
        let prefix = randomId().slice(-2)
        while (peersByPrefix.has(prefix)) {
          prefix = randomId().slice(-2)
        }

        peersByPrefix.set(prefix, url)

        const email_hash = await hashEmail(email, url)

        return rpc.post<ChallengeResponse>(url, "/challenge", {prefix, email_hash})
      }),
    )

    return {ok: results.every(r => r.res?.ok), peersByPrefix}
  }

  static async loginWithPassword(email: string, password: string) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      Client._getKnownPeers().map(async url => {
        const email_hash = await hashEmail(email, url)
        const password_hash = await hashPassword(email, password, url)
        const auth = {email_hash, password_hash}

        return rpc.post<LoginStartResponse>(url, "/login/start", {auth})
      }),
    )

    return this._buildAccountOptions(clientSecret, messages)
  }

  static async loginWithChallenge(
    email: string,
    peersByPrefix: Map<string, string>,
    otps: string[],
  ) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = removeUndefined(
      await Promise.all(
        otps.map(async otp => {
          const url = peersByPrefix.get(otp.slice(0, 2))

          if (url) {
            const email_hash = await hashEmail(email, url)
            const auth = {email_hash, otp}

            return rpc.post<LoginStartResponse>(url, "/login/start", {auth})
          }
        }),
      ),
    )

    return this._buildAccountOptions(clientSecret, messages)
  }

  static async selectLogin(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      peers
        .filter(identity)
        .map(url => rpc.post<LoginSelectResponse>(url, "/login/select", {client})),
    )

    const group = messages.find(m => m.res?.group)?.res?.group
    const successCount = messages.filter(m => m.res?.ok).length
    const ok = Boolean(group && successCount >= (group?.threshold || messages.length))
    const clientOptions = ok ? ({group, peers, secret: clientSecret} as ClientOptions) : undefined

    return {ok, messages, clientOptions}
  }

  static async recoverWithPassword(email: string, password: string) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      Client._getKnownPeers().map(async url => {
        const email_hash = await hashEmail(email, url)
        const password_hash = await hashPassword(email, password, url)
        const auth = {email_hash, password_hash}

        return rpc.post<RecoveryStartResponse>(url, "/recovery/start", {auth})
      }),
    )

    return this._buildAccountOptions(clientSecret, messages)
  }

  static async recoverWithChallenge(
    email: string,
    peersByPrefix: Map<string, string>,
    otps: string[],
  ) {
    const clientSecret = makeSecret()
    const rpc = RPC.fromSecret(clientSecret)

    const messages = removeUndefined(
      await Promise.all(
        otps.map(async otp => {
          const url = peersByPrefix.get(otp.slice(0, 2))

          if (url) {
            const email_hash = await hashEmail(email, url)
            const auth = {email_hash, otp}

            return rpc.post<RecoveryStartResponse>(url, "/recovery/start", {auth})
          }
        }),
      ),
    )

    return this._buildAccountOptions(clientSecret, messages)
  }

  static async selectRecovery(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      peers
        .filter(identity)
        .map(url => rpc.post<RecoverySelectResponse>(url, "/recovery/select", {client})),
    )

    const group = messages.find(m => m.res?.group)?.res?.group
    const shares = removeUndefined(messages.map(m => m.res?.share))
    const userSecret = tryCatch(() => Lib.recover_secret_key(group!, shares))

    return {ok: Boolean(userSecret), messages, userSecret}
  }

  async racePermutations<T>(
    fn: (selectedCommits: CommitPackage[], signal: AbortSignal) => Promise<T>,
  ): Promise<T | undefined> {
    const {threshold, commits} = this.group
    const availableCommits = commits.filter(c => this.peers[c.idx - 1])

    if (availableCommits.length < threshold) {
      throw new Error("Not enough available peers")
    }

    const controller = new AbortController()

    const attempts = permutations(availableCommits, threshold).map(async (commit, i) => {
      if (i > 0) {
        await delay(i * 1000, controller.signal)
      }

      return fn(commit, controller.signal)
    })

    try {
      const result = await Promise.any(attempts)
      controller.abort()
      return result
    } catch {
      return undefined
    }
  }

  async sign(stampedEvent: StampedEvent) {
    const event = prep(stampedEvent, this.userPubkey)
    const allMessages: Message<SignCompleteResponse>[] = []

    const result = await this.racePermutations(async (selectedCommits, signal) => {
      const members = selectedCommits.map(c => c.idx)

      // Round 1: collect a fresh public nonce from every member.
      const commitMessages = await Promise.all(
        members.map(idx =>
          this.rpc.post<SignCommitResponse>(
            this.peers[idx - 1]!,
            "/sign/commit",
            {members},
            {signal},
          ),
        ),
      )

      if (!commitMessages.every(m => m.res?.ok)) throw new Error("Round 1 failure")

      const template = Lib.create_session_template(members, event.id)

      if (!template) throw new Error("Failed to create signing template")

      const request = Lib.create_session_pkg(this.group, template)
      const commits = commitMessages.map(m => m.res!.result!)
      const commitIdByIdx = indexBy(c => c.idx, commits)
      const pnonces = commits.map(c => ({
        idx: c.idx,
        hidden_pn: c.hidden_pn,
        binder_pn: c.binder_pn,
      }))

      const completeRequest = {
        content: request.content,
        hash: request.hashes[0]!,
        members: request.members,
        stamp: request.stamp,
        type: request.type,
        gid: request.gid,
        sid: request.sid,
      }

      const messages = await Promise.all(
        members.map(idx =>
          this.rpc.post<SignCompleteResponse>(
            this.peers[idx - 1]!,
            "/sign/complete",
            {commit_id: commitIdByIdx.get(idx)!.commit_id, request: completeRequest, pnonces},
            {signal},
          ),
        ),
      )

      allMessages.push(...messages)

      if (!messages.every(m => m.res?.ok)) throw new Error("Round 2 failure")

      const registrationByIdx = indexBy(c => c.idx, this.group.commits)

      // Build the signing context from the fresh round-1 pnonces rather than the
      // registration-time group.commits, applying the same additive per-sighash
      // tweak as Lib.get_session_ctx via the substituted commit set.
      const ctx = Lib.get_session_ctx(
        {
          ...this.group,
          commits: pnonces.map(pn => ({
            idx: pn.idx,
            hidden_pn: pn.hidden_pn,
            binder_pn: pn.binder_pn,
            pubkey: registrationByIdx.get(pn.idx)!.pubkey,
          })),
        },
        request,
      )
      const pkgs = messages.map(m => {
        const {idx, psig, pubkey, sid} = m.res!.result!

        return {idx, psigs: [psig], pubkey, sid}
      })
      const sig = Lib.combine_signature_pkgs(ctx, pkgs)[0]?.[2]

      if (!sig) throw new Error("Failed to combine signatures")

      return {messages, event: {...event, sig} as SignedEvent}
    })

    if (result) return {ok: true as const, ...result}

    return {ok: false as const, messages: allMessages}
  }

  async getConversationKey(ecdh_pk: string) {
    return this.racePermutations(async (selectedCommits, signal) => {
      const members = selectedCommits.map(c => c.idx)

      const results = await Promise.all(
        members.map(idx =>
          this.rpc
            .post<EcdhResponse>(this.peers[idx - 1]!, "/ecdh", {idx, members, ecdh_pk}, {signal})
            .then(r => r.res?.result),
        ),
      )

      if (!results.every(isDefined)) throw new Error("Signer failure")

      return bytesToHex(
        extract(
          sha256,
          hexToBytes(Lib.combine_ecdh_pkgs(results).slice(2)),
          textEncoder.encode("nip44-v2"),
        ),
      )
    })
  }

  async listSessions() {
    const userRpc = new RPC(new PomadeSigner(this))

    const messages = await Promise.all(
      Client._getKnownPeers().map(url =>
        userRpc.post<SessionListResponse>(url, "/session/list", {}),
      ),
    )

    return {ok: messages.every(m => m.res?.ok), messages}
  }

  async deactivateSession(client: string, peers: string[]) {
    const userRpc = new RPC(new PomadeSigner(this))

    // Sign auth before sending since we might be deactivating our own session
    const requests = await Promise.all(
      peers.map(url => userRpc.prep(url, "/session/deactivate", {client})),
    )

    const messages = await Promise.all(
      requests.map(request => userRpc.send<SessionDeactivateResponse>(request)),
    )

    return {ok: messages.every(m => m.res?.ok), messages}
  }

  async deleteSession(client: string, peers: string[]) {
    const userRpc = new RPC(new PomadeSigner(this))

    // Sign auth before sending since we might be deleting our own session
    const requests = await Promise.all(
      peers.map(url => userRpc.prep(url, "/session/delete", {client})),
    )

    const messages = await Promise.all(
      requests.map(request => userRpc.send<SessionDeleteResponse>(request)),
    )

    return {ok: messages.every(m => m.res?.ok), messages}
  }
}
