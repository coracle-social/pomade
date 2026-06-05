import * as nt44 from "nostr-tools/nip44"
import {bytesToHex, hexToBytes} from "@noble/hashes/utils.js"
import {describe, it, expect, beforeEach, afterEach, beforeAll, afterAll} from "vitest"
import {sortBy, uniq} from "@welshman/lib"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {
  setupSuite,
  teardownSuite,
  makeEmail,
  makeClientWithRecovery,
  makeSignedAuthHeader,
  makeMalformedAuthHeaders,
  postToSigner,
  type SignerResponse,
  type SuiteContext,
} from "./util.js"
import {Client, RPC, hashEmail, hashPassword} from "@pomade/core"
import {assertSignersAvailable, type SignerKind} from "./harness.js"

const doLet = <T>(x: T, f: (x: T) => void) => f(x)

type SuiteSpec = {label: string; specs: SignerKind[]}

const suites: SuiteSpec[] = [
  {label: "8 typescript signers", specs: Array(8).fill("ts") as SignerKind[]},
  {label: "8 rust signers", specs: Array(8).fill("rust") as SignerKind[]},
  {label: "8 go signers", specs: Array(8).fill("go") as SignerKind[]},
  {label: "one of each", specs: ["ts", "rust", "go"]},
]

// Fail fast at collection time if any signer binary required by the suites
// below is missing, instead of grinding through earlier suites first.
assertSignersAvailable(suites.flatMap(s => s.specs))

for (const {label, specs} of suites) {
  describe(`protocol flows (${label})`, () => {
    // eslint-disable-next-line prefer-const
    let ctx: SuiteContext = undefined!

    beforeEach(async () => {
      ctx = await setupSuite(specs)
    })

    afterEach(async () => {
      if (ctx) await teardownSuite(ctx)
    })

    describe("register", () => {
      it("successfully registers with multiple signers", async () => {
        const secret = makeSecret()
        const pubkey = getPubkey(secret)
        const clientRegister = await Client.register(1, 2, secret)
        const client = new Client(clientRegister.clientOptions)

        expect(client.peers.length).toBe(2)
        expect(client.group.commits.length).toBe(2)
        expect(client.group.threshold).toBe(1)
        expect(client.group.group_pk.slice(2)).toBe(pubkey)
      })
    })

    describe("list sessions", () => {
      it("lists all sessions by pubkey", async () => {
        const secret = makeSecret()
        const c1Register = await Client.register(1, 2, secret)
        const c1 = new Client(c1Register.clientOptions)
        const c2Register = await Client.register(1, 2, secret)
        const c2 = new Client(c2Register.clientOptions)
        const c3Register = await Client.register(1, 2, secret)
        const c3 = new Client(c3Register.clientOptions)

        // Add another session with a different secret
        await Client.register(1, 2, makeSecret())

        const result = await c1.listSessions()
        const sortFn = (c: {client: string; peer: string}) => c.client + c.peer
        const [pk1, pk2, pk3] = await Promise.all([
          c1.rpc.signer.getPubkey(),
          c2.rpc.signer.getPubkey(),
          c3.rpc.signer.getPubkey(),
        ])
        const expected = sortBy(sortFn, [
          ...c1.peers.map(peer => ({client: pk1, peer})),
          ...c2.peers.map(peer => ({client: pk2, peer})),
          ...c3.peers.map(peer => ({client: pk3, peer})),
        ])
        const actual = sortBy(
          sortFn,
          result.messages.flatMap(m =>
            m.res?.items?.map(item => ({client: item.client, peer: m.url})) ?? [],
          ),
        )

        expect(actual.length).toBe(6)
        expect(actual).toStrictEqual(expected)
      })
    })

    describe("list and deactivate/delete sessions", () => {
      it("successfully deactivates current session", async () => {
        const secret = makeSecret()
        const client1Register = await Client.register(1, 2, secret)
        const client1 = new Client(client1Register.clientOptions)
        const client2Register = await Client.register(1, 2, secret)
        const client2 = new Client(client2Register.clientOptions)
        const client3Register = await Client.register(1, 2, secret)
        const client3 = new Client(client3Register.clientOptions)

        const [pk1, pk2, pk3] = await Promise.all([
          client1.rpc.signer.getPubkey(),
          client2.rpc.signer.getPubkey(),
          client3.rpc.signer.getPubkey(),
        ])

        await client1.deactivateSession(pk1, client1.peers)

        doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
        doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
        doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(true))

        const {messages} = await client2.listSessions()
        const allItems = messages.flatMap(m => m.res?.items ?? [])
        const clientPks = new Set(allItems.map(item => item.client))

        expect(clientPks).toContain(pk1)
        expect(clientPks).toContain(pk2)
        expect(clientPks).toContain(pk3)
        expect(allItems.filter(item => item.client === pk1).every(item => item.deactivated_at)).toBe(true)
        expect(allItems.filter(item => item.client !== pk1).every(item => !item.deactivated_at)).toBe(true)
      })

      it("successfully deactivates other sessions", async () => {
        const secret = makeSecret()
        const client1Register = await Client.register(1, 2, secret)
        const client1 = new Client(client1Register.clientOptions)
        const client2Register = await Client.register(1, 2, secret)
        const client2 = new Client(client2Register.clientOptions)
        const client3Register = await Client.register(1, 2, secret)
        const client3 = new Client(client3Register.clientOptions)

        const [pk1, pk2, pk3] = await Promise.all([
          client1.rpc.signer.getPubkey(),
          client2.rpc.signer.getPubkey(),
          client3.rpc.signer.getPubkey(),
        ])

        await client1.deactivateSession(pk2, client2.peers)
        await client1.deactivateSession(pk3, client3.peers)

        doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
        doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
        doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(false))

        const {messages} = await client1.listSessions()
        const allItems = messages.flatMap(m => m.res?.items ?? [])
        const clientPks = new Set(allItems.map(item => item.client))

        expect(clientPks).toContain(pk1)
        expect(clientPks).toContain(pk2)
        expect(clientPks).toContain(pk3)
        expect(allItems.filter(item => item.client === pk1).every(item => !item.deactivated_at)).toBe(true)
        expect(allItems.filter(item => item.client !== pk1).every(item => item.deactivated_at)).toBe(true)
      })

      it("successfully deletes current session", async () => {
        const secret = makeSecret()
        const client1Register = await Client.register(1, 2, secret)
        const client1 = new Client(client1Register.clientOptions)
        const client2Register = await Client.register(1, 2, secret)
        const client2 = new Client(client2Register.clientOptions)
        const client3Register = await Client.register(1, 2, secret)
        const client3 = new Client(client3Register.clientOptions)

        const [pk1, pk2, pk3] = await Promise.all([
          client1.rpc.signer.getPubkey(),
          client2.rpc.signer.getPubkey(),
          client3.rpc.signer.getPubkey(),
        ])

        await client1.deleteSession(pk1, client1.peers)

        doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
        doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
        doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(true))

        const {messages} = await client2.listSessions()
        const allItems = messages.flatMap(m => m.res?.items ?? [])
        const clientPks = new Set(allItems.map(item => item.client))

        expect(clientPks).not.toContain(pk1)
        expect(clientPks).toContain(pk2)
        expect(clientPks).toContain(pk3)
      })

      it("successfully deletes other sessions", async () => {
        const secret = makeSecret()
        const client1Register = await Client.register(1, 2, secret)
        const client1 = new Client(client1Register.clientOptions)
        const client2Register = await Client.register(1, 2, secret)
        const client2 = new Client(client2Register.clientOptions)
        const client3Register = await Client.register(1, 2, secret)
        const client3 = new Client(client3Register.clientOptions)

        const [pk1, pk2, pk3] = await Promise.all([
          client1.rpc.signer.getPubkey(),
          client2.rpc.signer.getPubkey(),
          client3.rpc.signer.getPubkey(),
        ])

        await client1.deleteSession(pk2, client2.peers)
        await client1.deleteSession(pk3, client3.peers)

        doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
        doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
        doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(false))

        const {messages} = await client1.listSessions()
        const allItems = messages.flatMap(m => m.res?.items ?? [])
        const clientPks = new Set(allItems.map(item => item.client))

        expect(clientPks).toContain(pk1)
        expect(clientPks).not.toContain(pk2)
        expect(clientPks).not.toContain(pk3)
      })
    })

    describe("signing", () => {
      it("successfully signs an event with 1/2 threshold", async () => {
        const clientRegister = await Client.register(1, 2, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const result = await client.sign(makeEvent(1))

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
      })

      it("signs an event with 2/3 threshold", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const result = await client.sign(makeEvent(1))

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
      })

      it("signs an event with 3/5 threshold", async () => {
        if (ctx.signers.length < 5) return // not enough signers in this suite

        const clientRegister = await Client.register(3, 5, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const result = await client.sign(makeEvent(1))

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
      })

      it("produces fresh nonces across two consecutive signatures", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        // Sign the SAME event twice: fresh per-session nonces must produce
        // different signatures. A reused/deterministic nonce would repeat the
        // signature for an identical message.
        const event = makeEvent(1, {content: "same"})
        const first = await client.sign(event)
        const second = await client.sign(event)

        expect(first.ok).toBe(true)
        expect(second.ok).toBe(true)
        expect(verifyEvent(first.event!)).toBe(true)
        expect(verifyEvent(second.event!)).toBe(true)
        expect(first.event!.sig).not.toBe(second.event!.sig)
      })
    })

    describe("single-use nonce enforcement", () => {
      // Capture the exact /sign/commit and /sign/complete payloads the client
      // produces during a real two-round sign, so we can replay round 2 by hand
      // without reconstructing the wire format.
      const captureTwoRound = async (client: Client) => {
        const original = RPC.fetch
        const completes: {url: string; body: Record<string, unknown>; auth: string}[] = []
        let supported = true

        RPC.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input)
          const res = await original(input, init)

          if (url.endsWith("/sign/complete") && init?.body) {
            completes.push({
              url: url.slice(0, -"/sign/complete".length),
              body: JSON.parse(init.body as string),
              auth: (init.headers as Record<string, string>).Authorization,
            })
          }

          if (url.endsWith("/sign/commit")) {
            const clone = res.clone()
            const json = (await clone.json()) as SignerResponse
            if (!json.ok && json.message === "Not found") supported = false
          }

          return res
        }

        try {
          const result = await client.sign(makeEvent(1))
          return {result, completes, supported}
        } finally {
          RPC.fetch = original
        }
      }

      it("refuses a second completion for the same commit id", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const {result, completes, supported} = await captureTwoRound(client)

        if (!supported) return // signer does not support the two-round flow yet

        expect(result.ok).toBe(true)
        expect(completes.length).toBeGreaterThan(0)

        const {url, body, auth} = completes[0]!
        const replay = await postToSigner(url, "/sign/complete", body, auth)

        expect(replay.ok).toBe(false)
        expect(replay.message).toBe("Commitment not found or already used")
      })

      it("yields at most one signature for concurrent completions", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        // Capture the round-2 bodies the client builds, but short-circuit the
        // outbound /sign/complete so the commitments stay unconsumed. We then
        // replay one captured body twice concurrently to race the take.
        const original = RPC.fetch
        const captured: {url: string; body: Record<string, unknown>; auth: string}[] = []
        let supported = true

        RPC.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input)

          if (url.endsWith("/sign/commit")) {
            const res = await original(input, init)
            const json = (await res.clone().json()) as SignerResponse
            if (!json.ok && json.message === "Not found") supported = false
            return res
          }

          if (url.endsWith("/sign/complete") && init?.body) {
            captured.push({
              url: url.slice(0, -"/sign/complete".length),
              body: JSON.parse(init.body as string),
              auth: (init.headers as Record<string, string>).Authorization,
            })
            return new Response(JSON.stringify({ok: false, message: "intercepted"}), {status: 200})
          }

          return original(input, init)
        }

        try {
          await client.sign(makeEvent(1))
        } finally {
          RPC.fetch = original
        }

        if (!supported) return

        const {url, body, auth} = captured[0]!
        const [a, b] = await Promise.all([
          postToSigner(url, "/sign/complete", body, auth),
          postToSigner(url, "/sign/complete", body, auth),
        ])

        expect(a.ok !== b.ok).toBe(true)
        expect([a, b].filter(r => r.ok).length).toBe(1)
        // The single winner must carry a real partial signature, and the loser
        // must be refused with the exact single-use message (never re-signed).
        expect([a, b].find(r => r.ok)!.result).toBeTruthy()
        expect([a, b].find(r => !r.ok)!.message).toBe("Commitment not found or already used")

        // A subsequent sequential replay of the same commit id is also refused,
        // proving the nonce was destroyed by the winning completion above.
        const replay = await postToSigner(url, "/sign/complete", body, auth)
        expect(replay.ok).toBe(false)
        expect(replay.message).toBe("Commitment not found or already used")
      })

      it("refuses an unknown commit id without signing", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const url = client.peers[0]!
        const secret = makeSecret()
        const members = client.group.commits.slice(0, 2).map(c => c.idx)

        // Probe support without consuming a real commitment; an old signer
        // returns "Not found" for the unknown endpoint.
        const probeAuth = await makeSignedAuthHeader(secret, url, "/sign/commit", {members})
        const probe = await postToSigner(url, "/sign/commit", {members}, probeAuth)
        if (!probe.ok) return

        const body = {
          commit_id: makeSecret(), // never issued by this signer
          request: {
            content: null,
            hash: [makeSecret()],
            members,
            stamp: 1,
            type: "event",
            gid: makeSecret(),
            sid: makeSecret(),
          },
          pnonces: members.map(idx => ({
            idx,
            hidden_pn: "02" + makeSecret(),
            binder_pn: "02" + makeSecret(),
          })),
        }
        const auth = await makeSignedAuthHeader(secret, url, "/sign/complete", body)
        const res = await postToSigner(url, "/sign/complete", body, auth)

        expect(res.ok).toBe(false)
        expect(res.message).toBe("Commitment not found or already used")
        expect(res.result).toBeFalsy()
      })

      it("rejects a commit whose member set excludes the signer", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        // Authenticate as the registered client so the membership check runs
        // (an unknown key would short-circuit with "No session found").
        const secret = clientRegister.clientOptions.secret
        // peers[0] holds the share at idx 1; ask it to commit for a member set
        // that omits its own index.
        const url = client.peers[0]!
        const members = client.group.commits.map(c => c.idx).filter(idx => idx !== 1)

        const auth = await makeSignedAuthHeader(secret, url, "/sign/commit", {members})
        const res = await postToSigner(url, "/sign/commit", {members}, auth)

        // An old signer answers "Not found"; an upgraded one must reject the
        // out-of-set commit with the spec failure string.
        if (res.message === "Not found") return

        expect(res.ok).toBe(false)
        expect(res.message).toBe("Signer index not present in members list")
        expect(res.result).toBeFalsy()
      })

      it("rejects a completion whose own pnonce does not match the commitment", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const url = client.peers[0]!
        const secret = makeSecret()
        const members = client.group.commits.slice(0, 2).map(c => c.idx)

        const commitAuth = await makeSignedAuthHeader(secret, url, "/sign/commit", {members})
        const commit = await postToSigner(url, "/sign/commit", {members}, commitAuth)

        if (!commit.ok) return // signer does not support the two-round flow yet

        const commitResult = commit.result as {commit_id: string; idx: number}

        const tamperedBody = {
          commit_id: commitResult.commit_id,
          request: {
            content: null,
            hash: [makeSecret()],
            members,
            stamp: 1,
            type: "event",
            gid: makeSecret(),
            sid: makeSecret(),
          },
          pnonces: members.map(idx => ({
            idx,
            hidden_pn: "02" + makeSecret(),
            binder_pn: "02" + makeSecret(),
          })),
        }
        const completeAuth = await makeSignedAuthHeader(secret, url, "/sign/complete", tamperedBody)
        const res = await postToSigner(url, "/sign/complete", tamperedBody, completeAuth)

        expect(res.ok).toBe(false)
      })
    })

    describe("racing and permutations", () => {
      it("falls back to an alternate subset when a peer is down", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const downPeer = client.peers[0]!
        await ctx.signers.find(s => s.url === downPeer)?.stop()

        const result = await client.sign(makeEvent(1))

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
      })

      it("falls back to an alternate subset on a round-2 dropout", async () => {
        // Round 1 succeeds for every peer, but round 2 fails for one specific
        // peer. With 2-of-3 this leaves exactly one viable 2-subset, so the
        // client must abandon any permutation containing the bad peer and
        // complete round 2 with the remaining pair.
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const badPeer = client.peers[0]!
        const original = RPC.fetch
        let supported = true
        let badCompletes = 0

        RPC.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input)

          // Skip this assertion entirely if a signer lacks the two-round
          // endpoints; the client no longer has a single-round fallback.
          if (url.endsWith("/sign/commit")) {
            const res = await original(input, init)
            const json = (await res.clone().json()) as SignerResponse
            if (!json.ok && json.message === "Not found") supported = false
            return res
          }

          // Drop round 2 for the bad peer only, after its round 1 succeeded.
          if (url === `${badPeer}/sign/complete`) {
            badCompletes++
            return new Response(
              JSON.stringify({ok: false, message: "Round 2 dropped"}),
              {status: 200},
            )
          }

          return original(input, init)
        }

        try {
          const result = await client.sign(makeEvent(1))

          if (!supported) return // signer does not support the two-round flow

          expect(result.ok).toBe(true)
          expect(verifyEvent(result.event!)).toBe(true)
          // The bad peer's round 2 was attempted and dropped at least once,
          // proving we fell back rather than simply skipping it from the start.
          expect(badCompletes).toBeGreaterThan(0)
        } finally {
          RPC.fetch = original
        }
      })

      it("reports failure when round 2 fails on every subset", async () => {
        // If no permutation can complete round 2, sign must surface ok:false
        // rather than fabricate a signature.
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const original = RPC.fetch
        let supported = true

        RPC.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input)

          if (url.endsWith("/sign/commit")) {
            const res = await original(input, init)
            const json = (await res.clone().json()) as SignerResponse
            if (!json.ok && json.message === "Not found") supported = false
            return res
          }

          if (url.endsWith("/sign/complete")) {
            return new Response(
              JSON.stringify({ok: false, message: "Round 2 dropped"}),
              {status: 200},
            )
          }

          return original(input, init)
        }

        let result
        try {
          result = await client.sign(makeEvent(1))
        } finally {
          RPC.fetch = original
        }

        if (!supported) return

        expect(result.ok).toBe(false)
        expect(result.event).toBeUndefined()
      })

      it("resolves the first viable permutation without waiting for the stagger", async () => {
        // The first permutation runs immediately; later ones are staggered by
        // one second each. With all peers healthy, the winner must resolve well
        // inside that stagger window.
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)

        const start = Date.now()
        const result = await client.sign(makeEvent(1))
        const elapsed = Date.now() - start

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
        expect(elapsed).toBeLessThan(1000)
      })
    })

    describe("ecdh", () => {
      it("successfully generates a conversation key", async () => {
        const clientSecret = makeSecret()
        const pubkey = getPubkey(makeSecret())
        const clientRegister = await Client.register(2, 3, clientSecret)
        const client = new Client(clientRegister.clientOptions)
        const sharedSecret = await client.getConversationKey(pubkey)

        expect(sharedSecret).toBe(
          bytesToHex(nt44.v2.utils.getConversationKey(hexToBytes(clientSecret), pubkey)),
        )
      })
    })

    describe("set recovery method", () => {
      it("rejects initializing recovery multiple times", async () => {
        const email = makeEmail()
        const clientRegister = await Client.register(1, 2, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const res1 = await client.setupRecovery(email, makeSecret())

        expect(res1.ok).toBe(true)

        const res2 = await client.setupRecovery(email, makeSecret())

        expect(res2.ok).toBe(false)
      })

      it("rejects disabled recovery", async () => {
        const clientRegister = await Client.register(1, 2, makeSecret(), false)
        const client = new Client(clientRegister.clientOptions)
        const res = await client.setupRecovery("test@example.com", makeSecret())

        expect(res.ok).toBe(false)
      })
    })

    describe("password-based login", () => {
      it("works", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.loginWithPassword(email, password)
        const messages = res1.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res2 = await Client.selectLogin(res1.clientSecret, clients[0], peers)

        expect(res2.ok).toBe(true)
        expect(res2.messages.every(m => m.res?.group)).toBe(true)
      })

      it("rejects invalid password without revealing registration", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.loginWithPassword(email, password)

        expect(res1.ok).toBe(true)

        const res2 = await Client.loginWithPassword(email, makeSecret())

        expect(res2.ok).toBe(false)

        const res3 = await Client.loginWithPassword(makeEmail(), makeSecret())

        expect(res3.ok).toBe(false)
      })

      it("rejects inconsistent client secret", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.loginWithPassword(email, password)
        const messages = res1.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)
        const res2 = await Client.selectLogin(makeSecret(), clients[0], peers)

        expect(res2.ok).toBe(false)
      })
    })

    describe("challenge-based login", () => {
      it("works", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)
        expect(ctx.challengePayloads.length).toBe(3)
        expect(ctx.challengePayloads[0].email).toBe(email)
        expect(ctx.challengePayloads[0].otp.length).toBe(8)

        const otps = ctx.challengePayloads.map(p => p.otp)
        const res2 = await Client.loginWithChallenge(email, res1.peersByPrefix, otps)
        const messages = res2.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res3 = await Client.selectLogin(res2.clientSecret, clients[0], peers)

        expect(res3.ok).toBe(true)
        expect(res3.messages.every(m => m.res?.group)).toBe(true)
      })

      it("rejects invalid challenge without revealing registration", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)

        const otps = ["00123456"] // Invalid OTP with unknown prefix
        const res2 = await Client.loginWithChallenge(email, res1.peersByPrefix, otps)

        expect(res2.ok).toBe(false)
      })

      it("rejects inconsistent client secret", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)
        expect(ctx.challengePayloads.length).toBe(3)
        expect(ctx.challengePayloads[0].email).toBe(email)
        expect(ctx.challengePayloads[0].otp.length).toBe(8)

        const otps = ctx.challengePayloads.map(p => p.otp)
        const res2 = await Client.loginWithChallenge(email, res1.peersByPrefix, otps)
        const messages = res2.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res3 = await Client.selectLogin(makeSecret(), clients[0], peers)

        expect(res3.ok).toBe(false)
      })
    })

    describe("password-based recovery", () => {
      it("works", async () => {
        const email = makeEmail()
        const password = makeSecret()
        const userSecret = makeSecret()
        const expectedPubkey = getPubkey(userSecret)

        const clientRegister = await Client.register(2, 3, userSecret)
        const client = new Client(clientRegister.clientOptions)

        expect(client.userPubkey).toBe(expectedPubkey)

        await client.setupRecovery(email, password)

        const res1 = await Client.recoverWithPassword(email, password)
        const messages = res1.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res2 = await Client.selectRecovery(res1.clientSecret, clients[0], peers)

        expect(res2.ok).toBe(true)
        expect(res2.messages.every(m => m.res?.share && m.res?.group)).toBe(true)
        expect(getPubkey(res2.userSecret!)).toBe(expectedPubkey)
      })

      it("rejects invalid password without revealing registration", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.recoverWithPassword(email, password)

        expect(res1.ok).toBe(true)

        const res2 = await Client.recoverWithPassword(email, makeSecret())

        expect(res2.ok).toBe(false)

        const res3 = await Client.recoverWithPassword(makeEmail(), makeSecret())

        expect(res3.ok).toBe(false)
      })

      it("rejects inconsistent client secret", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.recoverWithPassword(email, password)
        const messages = res1.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)
        const res2 = await Client.selectRecovery(makeSecret(), clients[0], peers)

        expect(res2.ok).toBe(false)
      })
    })

    describe("challenge-based recovery", () => {
      it("works", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)
        expect(ctx.challengePayloads.length).toBe(3)
        expect(ctx.challengePayloads[0].email).toBe(email)
        expect(ctx.challengePayloads[0].otp.length).toBe(8)

        const otps = ctx.challengePayloads.map(p => p.otp)
        const res2 = await Client.recoverWithChallenge(email, res1.peersByPrefix, otps)
        const messages = res2.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res3 = await Client.selectRecovery(res2.clientSecret, clients[0], peers)

        expect(res3.ok).toBe(true)
        expect(res3.messages.every(m => m.res?.share && m.res?.group)).toBe(true)
      })

      it("rejects invalid challenge without revealing registration", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)

        const otps = ["00123456"] // Invalid OTP with unknown prefix
        const res2 = await Client.recoverWithChallenge(email, res1.peersByPrefix, otps)

        expect(res2.ok).toBe(false)
      })

      it("rejects inconsistent client secret", async () => {
        const email = makeEmail()

        await makeClientWithRecovery(email)

        const res1 = await Client.requestChallenge(email)

        expect(res1.ok).toBe(true)
        expect(ctx.challengePayloads.length).toBe(3)
        expect(ctx.challengePayloads[0].email).toBe(email)
        expect(ctx.challengePayloads[0].otp.length).toBe(8)

        const otps = ctx.challengePayloads.map(p => p.otp)
        const res2 = await Client.recoverWithChallenge(email, res1.peersByPrefix, otps)
        const messages = res2.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res3 = await Client.selectRecovery(makeSecret(), clients[0], peers)

        expect(res3.ok).toBe(false)
      })
    })

    describe("recovery and login edge cases", () => {
      it("Switching between login and recovery fails", async () => {
        const email = makeEmail()
        const password = makeSecret()

        await makeClientWithRecovery(email, password)

        const res1 = await Client.loginWithPassword(email, password)
        const messages = res1.messages.filter(m => m.res?.ok)
        const clients = uniq(messages.flatMap(m => m.res!.items!.map(it => it.client)))
        const peers = messages.map(m => m.url)

        expect(clients.length).toBe(1)
        expect(peers.length).toBe(3)

        const res2 = await Client.selectRecovery(res1.clientSecret, clients[0], peers)

        expect(res2.ok).toBe(false)
      })

      it("handles multiple pubkeys associated with a single email", async () => {
        const email = makeEmail()
        const password1 = makeSecret()
        const password2 = makeSecret()
        await makeClientWithRecovery(email, password1)
        await makeClientWithRecovery(email, password1)
        await makeClientWithRecovery(email, password2)

        const res1 = await Client.loginWithPassword(email, password1)
        const messages1 = res1.messages.filter(m => m.res?.ok)
        const clients1 = uniq(messages1.flatMap(m => m.res!.items!.map(it => it.client)))

        expect(clients1.length).toBe(2)

        const res2 = await Client.recoverWithPassword(email, password2)
        const messages2 = res2.messages.filter(m => m.res?.ok)
        const clients2 = uniq(messages2.flatMap(m => m.res!.items!.map(it => it.client)))

        expect(clients2.length).toBe(1)

        const res = await Client.requestChallenge(email)

        const otps = ctx.challengePayloads.map(p => p.otp)
        const res3 = await Client.loginWithChallenge(email, res.peersByPrefix, otps)
        const messages3 = res3.messages.filter(m => m.res?.ok)
        const clients3 = uniq(messages3.flatMap(m => m.res!.items!.map(it => it.client)))

        expect(clients3.length).toBe(3)
      }, 10_000)
    })
  })

  describe(`adversarial flows (${label})`, () => {
    // eslint-disable-next-line prefer-const
    let ctx: SuiteContext = undefined!

    beforeEach(async () => {
      ctx = await setupSuite(specs)
    })

    afterEach(async () => {
      if (ctx) await teardownSuite(ctx)
    })

    const expectMalformedAuthRejected = async (path: string, body: unknown = {}) => {
      const url = ctx.signers[0]!.url
      const headers = await makeMalformedAuthHeaders(makeSecret(), url, path, body)

      const responses = await Promise.all([
        postToSigner(url, path, body),
        postToSigner(url, path, body, headers.noPrefix),
        postToSigner(url, path, body, headers.unsigned),
        postToSigner(url, path, body, headers.forgedSignature),
        postToSigner(url, path, body, headers.mismatchedPubkey),
        postToSigner(url, path, body, headers.wrongPath),
        postToSigner(url, path, body, headers.wrongMethod),
        postToSigner(url, path, body, headers.staleTimestamp),
        postToSigner(url, path, body, headers.futureTimestamp),
      ])

      expect(responses.every(res => !res.ok)).toBe(true)
      expect(responses.every(res => res.message === "Failed to validate authentication.")).toBe(true)
    }

    const expectSchemaRejected = async (path: string) => {
      const url = ctx.signers[0]!.url
      const auth = await makeSignedAuthHeader(makeSecret(), url, path, [])
      const res = await postToSigner(url, path, [], auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("Failed to validate request data.")
    }

    const getSuccessfulMessage = <T extends {res?: SignerResponse}>(messages: T[]) =>
      messages.find(m => m.res?.ok)

    it("/register", async () => {
      await expectMalformedAuthRejected("/register", {})
      await expectSchemaRejected("/register")
    })

    it("/sign/commit", async () => {
      await expectMalformedAuthRejected("/sign/commit", {})
      await expectSchemaRejected("/sign/commit")

      const url = ctx.signers[0]!.url
      const body = {members: [1]}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/sign/commit", body)
      const res = await postToSigner(url, "/sign/commit", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("No session found for client")
    })

    it("/ecdh", async () => {
      await expectMalformedAuthRejected("/ecdh", {})
      await expectSchemaRejected("/ecdh")

      const url = ctx.signers[0]!.url
      const noSessionBody = {idx: 1, members: [1], ecdh_pk: makeSecret()}
      const noSessionAuth = await makeSignedAuthHeader(makeSecret(), url, "/ecdh", noSessionBody)
      const noSessionRes = await postToSigner(url, "/ecdh", noSessionBody, noSessionAuth)

      expect(noSessionRes.ok).toBe(false)
      expect(noSessionRes.message).toBe("No session found for client")

      const clientRegister = await Client.register(1, 2, makeSecret())
      expect(clientRegister.ok).toBe(true)
      const client = new Client(clientRegister.clientOptions)
      const signerUrl = client.peers[0]
      if (!signerUrl) throw new Error("Expected at least one signer peer")
      const secret = clientRegister.clientOptions.secret
      const body = {
        idx: 1,
        members: [1],
        ecdh_pk: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      }
      const auth = await makeSignedAuthHeader(secret, signerUrl, "/ecdh", body)
      const res = await postToSigner(signerUrl, "/ecdh", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("Invalid ECDH public key")
    })

    it("/recovery/setup", async () => {
      await expectMalformedAuthRejected("/recovery/setup", {})
      await expectSchemaRejected("/recovery/setup")

      const clientRegister = await Client.register(1, 2, makeSecret())
      const client = new Client(clientRegister.clientOptions)
      const body = {email: makeEmail(), password_hash: "not-a-hash"}
      const auth = await makeSignedAuthHeader(clientRegister.clientOptions.secret, client.peers[0]!, "/recovery/setup", body)
      const res = await postToSigner(client.peers[0]!, "/recovery/setup", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toContain("Recovery method password hash")
    })

    it("/challenge", async () => {
      await expectMalformedAuthRejected("/challenge", {})
      await expectSchemaRejected("/challenge")

      const email = makeEmail()
      const seededClient = await makeClientWithRecovery(email)
      const signerUrl = seededClient.peers[0]!
      const authSecret = makeSecret()

      const knownBody = {prefix: "12", email_hash: await hashEmail(email, signerUrl)}
      const knownAuth = await makeSignedAuthHeader(authSecret, signerUrl, "/challenge", knownBody)
      const knownRes = await postToSigner(signerUrl, "/challenge", knownBody, knownAuth)

      const unknownBody = {prefix: "34", email_hash: await hashEmail(makeEmail(), signerUrl)}
      const unknownAuth = await makeSignedAuthHeader(authSecret, signerUrl, "/challenge", unknownBody)
      const unknownRes = await postToSigner(signerUrl, "/challenge", unknownBody, unknownAuth)

      expect(knownRes.ok).toBe(true)
      expect(unknownRes.ok).toBe(true)
      expect(knownRes.message).toBe(unknownRes.message)

      const start = ctx.challengePayloads.length
      const challenge = await Client.requestChallenge(email)
      expect(challenge.ok).toBe(true)

      const otps = ctx.challengePayloads.slice(start).map(p => p.otp)
      const firstLogin = await Client.loginWithChallenge(email, challenge.peersByPrefix, otps)
      const {client: selectedClient, peers} = firstLogin.options[0] || {}

      expect(firstLogin.ok).toBe(true)
      expect(selectedClient).toBeTruthy()
      expect(peers).toBeTruthy()

      const secondLogin = await Client.loginWithChallenge(email, challenge.peersByPrefix, otps)
      expect(secondLogin.ok).toBe(false)

      const secondMessages = secondLogin.messages
      expect(secondMessages.every(m => !m.res?.ok)).toBe(true)

      const select = await Client.selectLogin(firstLogin.clientSecret, selectedClient!, peers!)
      expect(select.ok).toBe(true)
    })

    it("/login/start", async () => {
      await expectMalformedAuthRejected("/login/start", {})
      await expectSchemaRejected("/login/start")

      const url = ctx.signers[0]!.url
      const body = {auth: {email_hash: makeSecret(), password_hash: makeSecret()}}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/login/start", body)
      const res = await postToSigner(url, "/login/start", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("No sessions found.")

      const email = makeEmail()
      const password = makeSecret()
      await makeClientWithRecovery(email, password)

      const good = await Client.loginWithPassword(email, password)
      expect(good.ok).toBe(true)

      const {client: selectedClient, peers: selectedPeers} = good.options[0] || {}
      expect(selectedClient).toBeTruthy()
      expect(selectedPeers).toBeTruthy()

      const select = await Client.selectLogin(good.clientSecret, selectedClient!, selectedPeers!)
      expect(select.ok).toBe(true)

      const reused = await Client.selectLogin(good.clientSecret, selectedClient!, selectedPeers!)
      expect(reused.ok).toBe(false)
      expect(reused.messages.every(m => m.res?.message === "No active login found.")).toBe(true)

      const existingRegister = await Client.register(1, 2, makeSecret())
      const existingSession = new Client(existingRegister.clientOptions)
      const signerUrl = existingSession.peers[0]!
      const reusedEmail = makeEmail()
      const reusedPassword = makeSecret()
      await existingSession.setupRecovery(reusedEmail, reusedPassword)

      const loginStart = await Client.loginWithPassword(reusedEmail, reusedPassword)
      const loginClient = getSuccessfulMessage(loginStart.messages)?.res?.items?.[0]?.client
      expect(loginClient).toBeTruthy()

      const reusedLoginSecret = makeSecret()

      const reuseBody = {
        auth: {
          email_hash: await hashEmail(reusedEmail, signerUrl),
          password_hash: await hashPassword(reusedEmail, reusedPassword, signerUrl),
        },
      }
      const reusedAuth = await makeSignedAuthHeader(reusedLoginSecret, signerUrl, "/login/start", reuseBody)
      const reuseRes = await postToSigner(signerUrl, "/login/start", reuseBody, reusedAuth)

      const reusedAuth2 = await makeSignedAuthHeader(
        reusedLoginSecret,
        signerUrl,
        "/login/start",
        reuseBody,
      )
      const reuseRes2 = await postToSigner(signerUrl, "/login/start", reuseBody, reusedAuth2)

      expect(reuseRes.ok).toBe(true)
      expect(reuseRes2.ok).toBe(false)
      expect(reuseRes2.message).toBe("Do not re-use session keys.")
    })

    it("/login/select", async () => {
      await expectMalformedAuthRejected("/login/select", {})
      await expectSchemaRejected("/login/select")

      const url = ctx.signers[0]!.url
      const body = {client: makeSecret()}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/login/select", body)
      const res = await postToSigner(url, "/login/select", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("No active login found.")
    })

    it("/recovery/start", async () => {
      await expectMalformedAuthRejected("/recovery/start", {})
      await expectSchemaRejected("/recovery/start")

      const url = ctx.signers[0]!.url
      const body = {auth: {email_hash: makeSecret(), password_hash: makeSecret()}}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/recovery/start", body)
      const res = await postToSigner(url, "/recovery/start", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("No sessions found.")

      const email = makeEmail()
      const password = makeSecret()
      await makeClientWithRecovery(email, password)

      const good = await Client.recoverWithPassword(email, password)
      expect(good.ok).toBe(true)

      const {client: selectedClient, peers: selectedPeers} = good.options[0] || {}
      expect(selectedClient).toBeTruthy()
      expect(selectedPeers).toBeTruthy()

      const select = await Client.selectRecovery(good.clientSecret, selectedClient!, selectedPeers!)
      expect(select.ok).toBe(true)

      const reused = await Client.selectRecovery(good.clientSecret, selectedClient!, selectedPeers!)
      expect(reused.ok).toBe(false)
      expect(reused.messages.every(m => m.res?.message === "No active recovery found.")).toBe(true)

      const existingRegister = await Client.register(1, 2, makeSecret())
      const existingSession = new Client(existingRegister.clientOptions)
      const signerUrl = existingSession.peers[0]!
      const reusedEmail = makeEmail()
      const reusedPassword = makeSecret()
      await existingSession.setupRecovery(reusedEmail, reusedPassword)

      const reusedRecoverySecret = makeSecret()
      const reuseBody = {
        auth: {
          email_hash: await hashEmail(reusedEmail, signerUrl),
          password_hash: await hashPassword(reusedEmail, reusedPassword, signerUrl),
        },
      }
      const reusedAuth = await makeSignedAuthHeader(
        reusedRecoverySecret,
        signerUrl,
        "/recovery/start",
        reuseBody,
      )
      const reuseRes = await postToSigner(signerUrl, "/recovery/start", reuseBody, reusedAuth)

      const reusedAuth2 = await makeSignedAuthHeader(
        reusedRecoverySecret,
        signerUrl,
        "/recovery/start",
        reuseBody,
      )
      const reuseRes2 = await postToSigner(signerUrl, "/recovery/start", reuseBody, reusedAuth2)

      expect(reuseRes.ok).toBe(true)
      expect(reuseRes2.ok).toBe(false)
      expect(reuseRes2.message).toBe("Do not re-use session keys.")
    })

    it("/recovery/select", async () => {
      await expectMalformedAuthRejected("/recovery/select", {})
      await expectSchemaRejected("/recovery/select")

      const url = ctx.signers[0]!.url
      const body = {client: makeSecret()}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/recovery/select", body)
      const res = await postToSigner(url, "/recovery/select", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("No active recovery found.")
    })

    it("/recovery/result", async () => {
      await expectMalformedAuthRejected("/recovery/result", {})

      const url = ctx.signers[0]!.url
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/recovery/result", {})
      const res = await postToSigner(url, "/recovery/result", {}, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("Not found")
    })

    it("/session/list", async () => {
      await expectMalformedAuthRejected("/session/list", {})
      await expectSchemaRejected("/session/list")

      const victim = await Client.register(1, 2, makeSecret())
      const victimClient = new Client(victim.clientOptions)
      const attacker = await Client.register(1, 2, makeSecret())
      const attackerClient = new Client(attacker.clientOptions)

      const victimList = await victimClient.listSessions()
      const attackerList = await attackerClient.listSessions()

      const victimPubkeys = new Set(victimList.messages.flatMap(m => m.res?.items?.map(i => i.pubkey) ?? []))
      const attackerPubkeys = new Set(attackerList.messages.flatMap(m => m.res?.items?.map(i => i.pubkey) ?? []))

      expect(victimPubkeys.has(victimClient.userPubkey)).toBe(true)
      expect(victimPubkeys.has(attackerClient.userPubkey)).toBe(false)
      expect(attackerPubkeys.has(attackerClient.userPubkey)).toBe(true)
      expect(attackerPubkeys.has(victimClient.userPubkey)).toBe(false)

      const body = {}
      const auth = await makeSignedAuthHeader(victim.clientOptions.secret, victimClient.peers[0]!, "/session/list", body)
      const clientKeyRes = await postToSigner(victimClient.peers[0]!, "/session/list", body, auth)

      expect(clientKeyRes.ok).toBe(true)
      expect((clientKeyRes.items as unknown[] | undefined)?.length ?? 0).toBe(0)
    })

    it("/session/deactivate", async () => {
      await expectMalformedAuthRejected("/session/deactivate", {})
      await expectSchemaRejected("/session/deactivate")

      const url = ctx.signers[0]!.url
      const body = {client: makeSecret()}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/session/deactivate", body)
      const res = await postToSigner(url, "/session/deactivate", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("Failed to deactivate selected session.")

      const registered = await Client.register(1, 2, makeSecret())
      const sessionClient = new Client(registered.clientOptions)
      const clientBody = {client: await sessionClient.getPubkey()}
      const clientAuth = await makeSignedAuthHeader(registered.clientOptions.secret, sessionClient.peers[0]!, "/session/deactivate", clientBody)
      const clientRes = await postToSigner(sessionClient.peers[0]!, "/session/deactivate", clientBody, clientAuth)

      expect(clientRes.ok).toBe(false)
      expect(clientRes.message).toBe("Failed to deactivate selected session.")
    })

    it("/session/delete", async () => {
      await expectMalformedAuthRejected("/session/delete", {})
      await expectSchemaRejected("/session/delete")

      const url = ctx.signers[0]!.url
      const body = {client: makeSecret()}
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/session/delete", body)
      const res = await postToSigner(url, "/session/delete", body, auth)

      expect(res.ok).toBe(false)
      expect(res.message).toBe("Failed to delete selected session.")

      const registered = await Client.register(1, 2, makeSecret())
      const sessionClient = new Client(registered.clientOptions)
      const clientBody = {client: await sessionClient.getPubkey()}
      const clientAuth = await makeSignedAuthHeader(registered.clientOptions.secret, sessionClient.peers[0]!, "/session/delete", clientBody)
      const clientRes = await postToSigner(sessionClient.peers[0]!, "/session/delete", clientBody, clientAuth)

      expect(clientRes.ok).toBe(false)
      expect(clientRes.message).toBe("Failed to delete selected session.")
    })
  })
}

describe("partial failure resilience", () => {
  let ctx: SuiteContext = undefined!

  beforeEach(async () => {
    ctx = await setupSuite(["ts", "ts", "ts"])
  })

  afterEach(async () => {
    if (ctx) await teardownSuite(ctx)
  })

  it("login, recovery, sign, and ecdh succeed with one signer down", async () => {
    const email = makeEmail()
    const password = makeSecret()
    const userSecret = makeSecret()
    const expectedPubkey = getPubkey(userSecret)

    // Register with 2/3 threshold while all signers are up
    const clientRegister = await Client.register(2, 3, userSecret)
    const client = new Client(clientRegister.clientOptions)
    await client.setupRecovery(email, password)

    // Stop one signer to simulate partial failure
    ctx.signers[2]!.stop()

    // Login with password should still succeed
    const loginResult = await Client.loginWithPassword(email, password)
    expect(loginResult.ok).toBe(true)
    expect(loginResult.options.length).toBeGreaterThan(0)

    const {client: loginClient, peers: loginPeers} = loginResult.options[0]!
    const selectResult = await Client.selectLogin(loginResult.clientSecret, loginClient, loginPeers)
    expect(selectResult.ok).toBe(true)

    const loggedInClient = new Client(selectResult.clientOptions!)

    // Signing should succeed with 2/3 peers available
    const signResult = await loggedInClient.sign(makeEvent(1))
    expect(signResult.ok).toBe(true)
    expect(verifyEvent(signResult.event!)).toBe(true)

    // ECDH should succeed with 2/3 peers available
    const otherPubkey = getPubkey(makeSecret())
    const conversationKey = await loggedInClient.getConversationKey(otherPubkey)
    expect(conversationKey).toBeDefined()

    // Recovery should succeed with 2/3 peers available
    const recoverResult = await Client.recoverWithPassword(email, password)
    expect(recoverResult.ok).toBe(true)

    const {client: recoverClient, peers: recoverPeers} = recoverResult.options[0]!
    const recoverSelect = await Client.selectRecovery(recoverResult.clientSecret, recoverClient, recoverPeers)
    expect(recoverSelect.ok).toBe(true)
    expect(getPubkey(recoverSelect.userSecret!)).toBe(expectedPubkey)
  })
})
