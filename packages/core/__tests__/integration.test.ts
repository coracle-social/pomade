import * as nt44 from "nostr-tools/nip44"
import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {sleep, sortBy, hexToBytes, bytesToHex} from "@welshman/lib"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {beforeHook, afterHook, makeMailer, makeClientWithRecovery} from "./util"
import {buildChallenge, Client, context, generateOTP, RecoverPayload} from "../src"

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
        result
          .entries()
          .flatMap(([client, items]) => items.map(item => ({client, peer: item.peer}))),
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
    it("successfully sets user inbox multiple times", async () => {
      let payloads = []

      const mailer = makeMailer(makeSecret(), {
        sendValidation: payload => {
          payloads.push(payload)
        },
      })

      const clientRegister = await Client.register(1, 2, makeSecret())
      const client = new Client(clientRegister.clientOptions)

      await client.setRecoveryMethod("test@example.com", mailer.pubkey)
      await sleep(10)

      expect(payloads[0].inbox).toBe("test@example.com")
      expect(payloads[0].challenge.length).toBeGreaterThan(90)

      const confirmed1 = await client.finalizeRecoveryMethod(payloads[0].challenge)

      expect(confirmed1.ok).toBe(true)

      await client.setRecoveryMethod("test2@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed2 = await client.finalizeRecoveryMethod(payloads[1].challenge)

      expect(confirmed2.ok).toBe(true)
    })

    it("rejects inconsistent client", async () => {
      let challenge

      const mailer = makeMailer(makeSecret(), {
        sendValidation: payload => {
          challenge = payload.challenge
        },
      })

      const client1Register = await Client.register(1, 2, makeSecret())
      const client1 = new Client(client1Register.clientOptions)
      const client2Register = await Client.register(1, 2, makeSecret())
      const client2 = new Client(client2Register.clientOptions)

      await client1.setRecoveryMethod("test@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed = await client2.finalizeRecoveryMethod(challenge)

      await expect(confirmed.ok).toBe(false)
    })

    it("rejects invalid challenge", async () => {
      const mailer = makeMailer(makeSecret())
      const clientRegister = await Client.register(1, 2, makeSecret())
      const client = new Client(clientRegister.clientOptions)
      const challenge = buildChallenge(context.signerPubkeys.map(pk => [pk, generateOTP()]))

      await client.setRecoveryMethod("test@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed = await client.finalizeRecoveryMethod(challenge)

      await expect(confirmed.ok).toBe(false)
    })

    it("rejects disabled recovery", async () => {
      const mailer = makeMailer(makeSecret())
      const clientRegister = await Client.register(1, 2, makeSecret(), false)
      const client = new Client(clientRegister.clientOptions)
      const res = await client.setRecoveryMethod("test@example.com", mailer.pubkey)

      expect(res.ok).toBe(false)
    })
  })

  describe("recovery", () => {
    it("successfully allows recovery", async () => {
      let payload

      const client = await makeClientWithRecovery("test@example.com", {
        sendRecovery: payload_ => {
          payload = payload_
        },
      })

      const {clientSecret} = await Client.startRecovery("test@example.com")
      await sleep(10)

      expect(payload.inbox).toBe("test@example.com")
      expect(payload.challenge.length).toBeGreaterThan(90)

      const {ok, userSecret} = await Client.finalizeRecovery(clientSecret, payload.challenge)

      expect(ok).toBe(true)
      expect(getPubkey(userSecret)).toBe(client.group.group_pk.slice(2))
    })

    it("successfully allows login", async () => {
      let payload

      const client = await makeClientWithRecovery("test@example.com", {
        sendRecovery: payload_ => {
          payload = payload_
        },
      })

      const {clientSecret} = await Client.startLogin("test@example.com")
      await sleep(10)

      expect(payload.inbox).toBe("test@example.com")
      expect(payload.challenge.length).toBeGreaterThan(190)

      const {ok, clientOptions} = await Client.finalizeLogin(clientSecret, payload.challenge)

      expect(ok).toBe(true)
      expect(clientOptions.group.group_pk).toBe(client.group.group_pk)

      const client2 = await new Client(clientOptions)
      const result = await client2.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
    })

    it("prevents probing for session", async () => {
      const client = await makeClientWithRecovery("test@example.com")

      const res1 = await Client.startRecovery("test@example.com")

      expect(res1.ok).toBe(true)

      const res2 = await Client.startRecovery("test@example.com", client.pubkey)

      expect(res2.ok).toBe(true)
    })

    it("rejects invalid challenge", async () => {
      await makeClientWithRecovery("test@example.com")

      const {clientSecret} = await Client.startRecovery("test@example.com")
      await sleep(10)

      const challenge = buildChallenge(context.signerPubkeys.map(pk => [pk, generateOTP()]))

      const res = await Client.finalizeRecovery(clientSecret, challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      let challenge

      await makeClientWithRecovery("test@example.com", {
        sendRecovery: payload => {
          challenge = payload.challenge
        },
      })

      await Client.startRecovery("test@example.com")
      await sleep(10)

      const res = await Client.finalizeRecovery(makeSecret(), challenge)

      expect(res.ok).toBe(false)
    })

    it("handles multiple pubkeys associated with a single inbox", async () => {
      const payloads = []

      const provider = {
        sendRecovery: payload => {
          payloads.push(payload)
        },
      }

      await makeClientWithRecovery("test@example.com", provider)
      await makeClientWithRecovery("test@example.com", provider)

      const res1 = await Client.startRecovery("test@example.com")
      await sleep(10)

      expect(payloads.length).toBe(2)
      expect(res1.ok).toBe(true)

      const res2 = await Client.finalizeRecovery(res1.clientSecret, payloads[1].challenge)

      expect(res2.ok).toBe(true)
    })

    it("handles recovery across multiple mailers", async () => {
      const payloads: RecoverPayload[] = []
      const inbox = "complex@example.com"

      let challenge1
      let challenge2

      // Create two different mailers that will handle recovery and validation
      const mailer1 = makeMailer(makeSecret(), {
        sendRecovery: payload => {
          payloads.push(payload)
        },
        sendValidation: payload => {
          challenge1 = payload.challenge
        },
      })

      const mailer2 = makeMailer(makeSecret(), {
        sendRecovery: payload => {
          payloads.push(payload)
        },
        sendValidation: payload => {
          challenge2 = payload.challenge
        },
      })

      // Register first client with 1/2 threshold and mailer1
      const userSecret1 = makeSecret()
      const client1Register = await Client.register(1, 2, userSecret1)
      const client1 = new Client(client1Register.clientOptions)

      await client1.setRecoveryMethod(inbox, mailer1.pubkey)
      await sleep(10)
      await client1.finalizeRecoveryMethod(challenge1)

      // Register second client with 2/3 threshold and mailer2
      const userSecret2 = makeSecret()
      const client2Register = await Client.register(2, 3, userSecret2)
      const client2 = new Client(client2Register.clientOptions)

      await client2.setRecoveryMethod(inbox, mailer2.pubkey)
      await sleep(10)
      await client2.finalizeRecoveryMethod(challenge2)

      // Initiate recovery for the shared inbox - should trigger both mailers
      const res = await Client.startRecovery(inbox)
      await sleep(10)

      // Should have received challenges from both mailers
      expect(res.ok).toBe(true)
      expect(payloads.length).toBe(2)

      // Verify first payload is for client1 with correct threshold
      const payload1 = payloads.find(p => p.pubkey === client1.group.group_pk.slice(2))
      expect(payload1?.inbox).toBe(inbox)
      expect(payload1?.challenge.length).toBeGreaterThan(90)

      // Verify second payload is for client2 with correct threshold
      const payload2 = payloads.find(p => p.pubkey === client2.group.group_pk.slice(2))
      expect(payload2?.inbox).toBe(inbox)
      expect(payload2?.challenge.length).toBeGreaterThan(90)

      // Test recovery using first client's challenge
      const result1 = await Client.finalizeRecovery(res.clientSecret, payload1!.challenge)
      expect(result1.ok).toBe(true)
      expect(getPubkey(result1.userSecret)).toBe(client1.group.group_pk.slice(2))

      // Test recovery using second client's challenge with the same recovery secret
      // A single recovery request generates challenges for all clients with the inbox
      const result2 = await Client.finalizeRecovery(res.clientSecret, payload2!.challenge)
      expect(result2.ok).toBe(true)
      expect(getPubkey(result2.userSecret)).toBe(client2.group.group_pk.slice(2))
    })
  })
})
