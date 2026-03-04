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
  sample,
  textEncoder,
} from "@welshman/lib"
import {extract} from "@noble/hashes/hkdf.js"
import {sha256} from "@noble/hashes/sha2.js"
import {hexToBytes, bytesToHex} from "@noble/hashes/utils.js"
import {prep, makeSecret} from "@welshman/util"
import type {StampedEvent, SignedEvent} from "@welshman/util"
import {Lib} from "@frostr/bifrost"
import type {GroupPackage} from "@frostr/bifrost"
import {context, hashEmail, hashPassword} from "./util.js"
import {RPC} from "./rpc.js"
import {PomadeSigner} from "./pomade-signer.js"
import {validateAttestation} from "./attestation.js"
import type {AttestationResult} from "./attestation.js"
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
  SignResponse,
  EcdhResponse,
} from "./message.js"

export type ClientOptions = {
  group: GroupPackage
  secret: string
  peers: string[]
}

export type ClientOptionsResult<T> = {
  ok: boolean
  options: [string, string[]][]
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

  static _buildOptions<T extends LoginStartResponse | RecoveryStartResponse>(
    clientSecret: string,
    messages: Message<T>[],
    threshold: "total" | "threshold",
  ): ClientOptionsResult<T> {
    // Extract all items with their metadata
    const items = messages.flatMap(
      m =>
        m.res?.items?.map(item => ({
          client: item.client,
          url: m.url,
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
      const peers = sortBy(item => item.idx, clientItems).map(item => item.url)

      options.push([client, peers])
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
            context.registerPow,
          )

          if (message.res?.ok) {
            peersByIndex.set(i, url)
          }

          return message
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

    return this._buildOptions(clientSecret, messages, "total")
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

    return this._buildOptions(clientSecret, messages, "total")
  }

  static async selectLogin(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      peers.map(url => rpc.post<LoginSelectResponse>(url, "/login/select", {client})),
    )

    const group = messages.find(m => m.res?.group)?.res?.group
    const ok = Boolean(group && messages.every(m => m.res?.ok))
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

    return this._buildOptions(clientSecret, messages, "threshold")
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

    return this._buildOptions(clientSecret, messages, "threshold")
  }

  static async selectRecovery(clientSecret: string, client: string, peers: string[]) {
    const rpc = RPC.fromSecret(clientSecret)

    const messages = await Promise.all(
      peers.map(url => rpc.post<RecoverySelectResponse>(url, "/recovery/select", {client})),
    )

    const group = messages.find(m => m.res?.group)?.res?.group
    const shares = removeUndefined(messages.map(m => m.res?.share))
    const userSecret = tryCatch(() => Lib.recover_secret_key(group!, shares))

    return {ok: Boolean(userSecret), messages, userSecret}
  }

  async sign(stampedEvent: StampedEvent) {
    const {threshold, commits} = this.group
    const event = prep(stampedEvent, this.userPubkey)
    const members = sample(threshold, commits).map(c => c.idx)
    const template = Lib.create_session_template(members, event.id)

    if (!template) throw new Error("Failed to create signing template")

    const request = Lib.create_session_pkg(this.group, template)

    const messages = await Promise.all(
      members.map(idx => {
        const url = this.peers[idx - 1]!

        return this.rpc.post<SignResponse>(url, "/sign", {request})
      }),
    )

    if (messages.every(m => m.res?.ok)) {
      const ctx = Lib.get_session_ctx(this.group, request)
      const pkgs = messages.map(m => m.res!.result!)
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
      members.map(idx => {
        const url = this.peers[idx - 1]!

        return this.rpc
          .post<EcdhResponse>(url, "/ecdh", {idx, members, ecdh_pk})
          .then(r => r.res?.result)
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
    const userRpc = new RPC(new PomadeSigner(this))

    const messages = await Promise.all(
      Client._getKnownPeers().map(url =>
        userRpc.post<SessionListResponse>(url, "/session/list", {}),
      ),
    )

    return {ok: messages.every(m => m.res?.ok), messages}
  }

  /**
   * Fetch and validate the attestation document from a signer peer.
   *
   * Verifies the COSE_Sign1 signature and the full certificate chain up to the
   * AWS Nitro root CA. On success, returns the parsed document so the caller
   * can inspect PCR values against a known-good build.
   *
   * A random nonce is generated internally and embedded in the attestation
   * document, preventing replay attacks.
   *
   * @param url - The signer peer URL to attest.
   */
  static async validateAttestation(url: string): Promise<AttestationResult> {
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    const res = await fetch(`${url}/attest`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({nonce}),
    })

    if (!res.ok) {
      return {ok: false, error: `HTTP ${res.status} from ${url}/attest`}
    }

    const json = (await res.json()) as {ok: boolean; document?: string; message?: string}

    if (!json.ok || !json.document) {
      return {ok: false, error: json.message ?? "No document in response"}
    }

    return validateAttestation(json.document)
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
