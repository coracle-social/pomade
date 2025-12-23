import * as nt44 from "nostr-tools/nip44"
import {bytesToHex, hexToBytes, randomBytes} from "@noble/hashes/utils.js"
import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {sortBy, uniq} from "@welshman/lib"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {
  beforeHook,
  makeEmail,
  signerPubkeys,
  challengePayloads,
  afterHook,
  makeClientWithRecovery,
} from "./util"
import {Client, encodeChallenge} from "../src"

const doLet = <T>(x: T, f: <R>(x: T) => R) => f(x)

describe("protocol flows", () => {
  beforeEach(beforeHook)
  afterEach(afterHook)

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
      const sortFn = (c: any) => c.client + c.peer
      const expected = sortBy(
        sortFn,
        [c1, c2, c3].flatMap(c => c.peers.map(peer => ({client: c.pubkey, peer}))),
      )
      const actual = sortBy(
        sortFn,
        result.messages.flatMap(m =>
          m.payload.items.map(item => ({client: item.client, peer: m.event.pubkey})),
        ),
      )

      expect(actual.length).toBe(6)
      expect(actual).toStrictEqual(expected)
    })
  })

  describe("list and delete sessions", () => {
    it("successfully deletes current session", async () => {
      const secret = makeSecret()
      const client1Register = await Client.register(1, 2, secret)
      const client1 = new Client(client1Register.clientOptions)
      const client2Register = await Client.register(1, 2, secret)
      const client2 = new Client(client2Register.clientOptions)
      const client3Register = await Client.register(1, 2, secret)
      const client3 = new Client(client3Register.clientOptions)

      await client1.deleteSession(client1.pubkey, client1.peers)

      doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
      doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
      doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
    })

    it("successfully deletes other sessions", async () => {
      const secret = makeSecret()
      const client1Register = await Client.register(1, 2, secret)
      const client1 = new Client(client1Register.clientOptions)
      const client2Register = await Client.register(1, 2, secret)
      const client2 = new Client(client2Register.clientOptions)
      const client3Register = await Client.register(1, 2, secret)
      const client3 = new Client(client3Register.clientOptions)

      await client1.deleteSession(client2.pubkey, client2.peers)
      await client1.deleteSession(client3.pubkey, client3.peers)

      doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
      doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
      doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
    })
  })

  describe("signing", () => {
    it("successfully signs an event with 1/2 threshold", async () => {
      const clientRegister = await Client.register(1, 2, makeSecret())
      const client = new Client(clientRegister.clientOptions)
      const result = await client.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
    })

    it("successfully signs an event with 2/3 threshold", async () => {
      const clientRegister = await Client.register(2, 3, makeSecret())
      const client = new Client(clientRegister.clientOptions)
      const result = await client.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
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
      const res1 = await client.initializeRecoveryMethod(email, makeSecret())

      expect(res1.ok).toBe(true)

      const res2 = await client.initializeRecoveryMethod(email, makeSecret())

      expect(res2.ok).toBe(false)
    })

    it("rejects disabled recovery", async () => {
      const clientRegister = await Client.register(1, 2, makeSecret(), false)
      const client = new Client(clientRegister.clientOptions)
      const res = await client.initializeRecoveryMethod("test@example.com", makeSecret())

      expect(res.ok).toBe(false)
    })
  })

  describe("password-based login", () => {
    it("works", async () => {
      const email = makeEmail()
      const password = makeSecret()

      await makeClientWithRecovery(email, password)

      const res1 = await Client.loginWithPassword(email, password)
      const messages = res1.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

      expect(clients.length).toBe(1)
      expect(peers.length).toBe(3)

      const res2 = await Client.selectLogin(res1.clientSecret, clients[0], peers)

      expect(res2.ok).toBe(true)
      expect(res2.messages.every(m => m.payload.group)).toBe(true)
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
      const messages = res1.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)
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
      expect(challengePayloads.length).toBe(3)
      expect(challengePayloads[0].email).toBe(email)
      expect(challengePayloads[0].challenge.length).toBeGreaterThan(50)

      const challenges = challengePayloads.map(p => p.challenge)
      const res2 = await Client.loginWithChallenge(email, challenges)
      const messages = res2.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

      expect(clients.length).toBe(1)
      expect(peers.length).toBe(3)

      const res3 = await Client.selectLogin(res2.clientSecret, clients[0], peers)

      expect(res3.ok).toBe(true)
      expect(res3.messages.every(m => m.payload.group)).toBe(true)
    })

    it("rejects invalid challenge without revealing registration", async () => {
      const email = makeEmail()

      await makeClientWithRecovery(email)

      const res1 = await Client.requestChallenge(email)

      expect(res1.ok).toBe(true)

      const challenges = [encodeChallenge(signerPubkeys[0], bytesToHex(randomBytes(12)))]
      const res2 = await Client.loginWithChallenge(email, challenges)

      expect(res2.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      const email = makeEmail()

      await makeClientWithRecovery(email)

      const res1 = await Client.requestChallenge(email)

      expect(res1.ok).toBe(true)
      expect(challengePayloads.length).toBe(3)
      expect(challengePayloads[0].email).toBe(email)
      expect(challengePayloads[0].challenge.length).toBeGreaterThan(50)

      const challenges = challengePayloads.map(p => p.challenge)
      const res2 = await Client.loginWithChallenge(email, challenges)
      const messages = res2.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

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

      await makeClientWithRecovery(email, password)

      const res1 = await Client.recoverWithPassword(email, password)
      const messages = res1.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

      expect(clients.length).toBe(1)
      expect(peers.length).toBe(3)

      const res2 = await Client.selectRecovery(res1.clientSecret, clients[0], peers)

      expect(res2.ok).toBe(true)
      expect(res2.messages.every(m => m.payload.share && m.payload.group)).toBe(true)
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
      const messages = res1.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)
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
      expect(challengePayloads.length).toBe(3)
      expect(challengePayloads[0].email).toBe(email)
      expect(challengePayloads[0].challenge.length).toBeGreaterThan(50)

      const challenges = challengePayloads.map(p => p.challenge)
      const res2 = await Client.recoverWithChallenge(email, challenges)
      const messages = res2.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

      expect(clients.length).toBe(1)
      expect(peers.length).toBe(3)

      const res3 = await Client.selectRecovery(res2.clientSecret, clients[0], peers)

      expect(res3.ok).toBe(true)
      expect(res3.messages.every(m => m.payload.share && m.payload.group)).toBe(true)
    })

    it("rejects invalid challenge without revealing registration", async () => {
      const email = makeEmail()

      await makeClientWithRecovery(email)

      const res1 = await Client.requestChallenge(email)

      expect(res1.ok).toBe(true)

      const challenges = [encodeChallenge(signerPubkeys[0], bytesToHex(randomBytes(12)))]
      const res2 = await Client.loginWithChallenge(email, challenges)

      expect(res2.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      const email = makeEmail()

      await makeClientWithRecovery(email)

      const res1 = await Client.requestChallenge(email)

      expect(res1.ok).toBe(true)
      expect(challengePayloads.length).toBe(3)
      expect(challengePayloads[0].email).toBe(email)
      expect(challengePayloads[0].challenge.length).toBeGreaterThan(50)

      const challenges = challengePayloads.map(p => p.challenge)
      const res2 = await Client.recoverWithChallenge(email, challenges)
      const messages = res2.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

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
      const messages = res1.messages.filter(m => m.payload.ok)
      const clients = uniq(messages.flatMap(m => m.payload.items.map(it => it.client)))
      const peers = messages.map(m => m.event.pubkey)

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
      const messages1 = res1.messages.filter(m => m.payload.ok)
      const clients1 = uniq(messages1.flatMap(m => m.payload.items.map(it => it.client)))

      expect(clients1.length).toBe(2)

      const res2 = await Client.recoverWithPassword(email, password2)
      const messages2 = res2.messages.filter(m => m.payload.ok)
      const clients2 = uniq(messages2.flatMap(m => m.payload.items.map(it => it.client)))

      expect(clients2.length).toBe(1)

      await Client.requestChallenge(email)

      const challenges = challengePayloads.map(p => p.challenge)
      const res3 = await Client.loginWithChallenge(email, challenges)
      const messages3 = res3.messages.filter(m => m.payload.ok)
      const clients3 = uniq(messages3.flatMap(m => m.payload.items.map(it => it.client)))

      expect(clients3.length).toBe(3)
    }, 10_000)
  })
})
