import * as nt44 from "nostr-tools/nip44"
import {bytesToHex, hexToBytes} from "@noble/hashes/utils.js"
import {describe, it, expect, beforeEach, afterEach} from "vitest"
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
import {Client, hashEmail, hashPassword} from "@pomade/core"
import type {SignerKind} from "./harness.js"

const doLet = <T>(x: T, f: (x: T) => void) => f(x)

type SuiteSpec = {label: string; specs: SignerKind[]}

const suites: SuiteSpec[] = [
  {label: "8 typescript signers", specs: Array(8).fill("ts") as SignerKind[]},
  {label: "8 rust signers", specs: Array(8).fill("rust") as SignerKind[]},
  {label: "8 go signers", specs: Array(8).fill("go") as SignerKind[]},
  {label: "one of each", specs: ["ts", "rust", "go"]},
]

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

      it("successfully signs an event with 2/3 threshold", async () => {
        const clientRegister = await Client.register(2, 3, makeSecret())
        const client = new Client(clientRegister.clientOptions)
        const result = await client.sign(makeEvent(1))

        expect(result.ok).toBe(true)
        expect(verifyEvent(result.event!)).toBe(true)
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

    it("/sign", async () => {
      await expectMalformedAuthRejected("/sign", {})
      await expectSchemaRejected("/sign")

      const url = ctx.signers[0]!.url
      const body = {
        request: {
          content: null,
          hashes: [[makeSecret()]],
          members: [1],
          stamp: 1,
          type: "event",
          gid: makeSecret(),
          sid: makeSecret(),
        },
      }
      const auth = await makeSignedAuthHeader(makeSecret(), url, "/sign", body)
      const res = await postToSigner(url, "/sign", body, auth)

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
