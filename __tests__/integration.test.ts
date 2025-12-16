import * as nt44 from "nostr-tools/nip44"
import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {sleep, sortBy, hexToBytes, bytesToHex} from "@welshman/lib"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {beforeHook, afterHook, makeMailer, makeClientWithEmail} from "./util"
import {Client} from "../src/client"
import {generateOTP, buildChallenge, context} from "../src/lib"

const doLet = <T>(x: T, f: <R>(x: T) => R) => f(x)

describe("protocol flows", () => {
  beforeEach(beforeHook)
  afterEach(afterHook)

  describe("register", () => {
    it("successfully registers with multiple signers", async () => {
      const secret = makeSecret()
      const pubkey = getPubkey(secret)
      const client = await Client.register(1, 2, secret)

      expect(client.peers.length).toBe(2)
      expect(client.group.commits.length).toBe(2)
      expect(client.group.threshold).toBe(1)
      expect(client.group.group_pk.slice(2)).toBe(pubkey)
    })
  })

  describe("list sessions", () => {
    it("lists all sessions by pubkey", async () => {
      const secret = makeSecret()
      const c1 = await Client.register(1, 2, secret)
      const c2 = await Client.register(1, 2, secret)
      const c3 = await Client.register(1, 2, secret)

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

  describe("list sessions and logout", () => {
    it("successfully logouts current session", async () => {
      const secret = makeSecret()
      const client1 = await Client.register(1, 2, secret)
      const client2 = await Client.register(1, 2, secret)
      const client3 = await Client.register(1, 2, secret)

      await client1.logout(client1.pubkey, client1.peers)

      doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
      doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
      doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
    })

    it("successfully logouts other sessions", async () => {
      const secret = makeSecret()
      const client1 = await Client.register(1, 2, secret)
      const client2 = await Client.register(1, 2, secret)
      const client3 = await Client.register(1, 2, secret)

      await client1.logout(client2.pubkey, client2.peers)
      await client1.logout(client3.pubkey, client3.peers)

      doLet(await client1.sign(makeEvent(1)), res => expect(res.ok).toBe(true))
      doLet(await client2.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
      doLet(await client3.sign(makeEvent(1)), res => expect(res.ok).toBe(false))
    })
  })

  describe("signing", () => {
    it("successfully signs an event with 1/2 threshold", async () => {
      const client = await Client.register(1, 2, makeSecret())
      const result = await client.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
    })

    it("successfully signs an event with 2/3 threshold", async () => {
      const client = await Client.register(2, 3, makeSecret())
      const result = await client.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
    })
  })

  describe("ecdh", () => {
    it("successfully generates a conversation key", async () => {
      const clientSecret = makeSecret()
      const pubkey = getPubkey(makeSecret())
      const client = await Client.register(2, 3, clientSecret)
      const sharedSecret = await client.getConversationKey(pubkey)

      expect(sharedSecret).toBe(
        bytesToHex(nt44.v2.utils.getConversationKey(hexToBytes(clientSecret), pubkey)),
      )
    })
  })

  describe("set email", () => {
    it("successfully sets user email multiple times", async () => {
      let payloads = []

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: payload => {
          payloads.push(payload)
        },
      })

      const client = await Client.register(1, 2, makeSecret())

      await client.setEmailRequest("test@example.com", mailer.pubkey)
      await sleep(10)

      expect(payloads[0].email).toBe("test@example.com")
      expect(payloads[0].challenge.length).toBeGreaterThan(90)

      const confirmed1 = await client.setEmailFinalize("test@example.com", mailer.pubkey, payloads[0].challenge)

      expect(confirmed1.ok).toBe(true)

      await client.setEmailRequest("test2@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed2 = await client.setEmailFinalize(
        "test2@example.com",
        mailer.pubkey,
        payloads[1].challenge,
      )

      expect(confirmed2.ok).toBe(true)
    })

    it("rejects invalid email", async () => {
      let challenge

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: payload => {
          challenge = payload.challenge
        },
      })

      const client = await Client.register(1, 2, makeSecret())

      await client.setEmailRequest("test@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed = await client.setEmailFinalize("test2@example.com", mailer.pubkey, challenge)

      await expect(confirmed.ok).toBe(false)
    })

    it("rejects invalid challenge", async () => {
      let challenge

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: payload => {
          challenge = payload.challenge
        },
      })

      const client = await Client.register(1, 2, makeSecret())

      await client.setEmailRequest("test@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed = await client.setEmailFinalize("test2@example.com", mailer.pubkey, challenge)

      await expect(confirmed.ok).toBe(false)
    })
  })

  describe("recovery", () => {
    it("successfully allows recovery", async () => {
      let payload

      const client = await makeClientWithEmail("test@example.com", {
        sendRecoverEmail: payload_ => {
          payload = payload_
        },
      })

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      expect(payload.email).toBe("test@example.com")
      expect(payload.challenge.length).toBeGreaterThan(90)

      const res = await Client.recoverFinalize(secret, "test@example.com", payload.challenge)

      expect(res.ok).toBe(true)
      expect(getPubkey(res.secret)).toBe(client.group.group_pk.slice(2))
    })

    it("prevents probing for session", async () => {
      const client = await makeClientWithEmail("test@example.com")

      doLet(await Client.recoverRequest(makeSecret(), "test@example.com"), res =>
        expect(res.ok).toBe(true),
      )
      doLet(await Client.recoverRequest(makeSecret(), "test@example.com", client.pubkey), res =>
        expect(res.ok).toBe(true),
      )
    })

    it("rejects invalid email", async () => {
      let challenge

      await makeClientWithEmail("test@example.com", {
        sendRecoverEmail: payload => {
          challenge = payload.challenge
        },
      })

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      const res = await Client.recoverFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects invalid challenge", async () => {
      await makeClientWithEmail("test@example.com")

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      const challenge = buildChallenge(context.signerPubkeys.map(pk => [pk, generateOTP()]))

      const res = await Client.recoverFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      let challenge

      await makeClientWithEmail("test@example.com", {
        sendRecoverEmail: payload => {
          challenge = payload.challenge
        },
      })

      await Client.recoverRequest(makeSecret(), "test@example.com")
      await sleep(10)

      const res = await Client.recoverFinalize(makeSecret(), "test@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("handles multiple pubkeys associated with a single email", async () => {
      const payloads: RecoverEmailPayload[] = []

      const provider = {
        sendRecoverEmail: payload => {
          payloads.push(payload)
        },
      }

      await makeClientWithEmail("test@example.com", provider)
      await makeClientWithEmail("test@example.com", provider)

      const secret = makeSecret()
      const res1 = await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      expect(payloads.length).toBe(2)
      expect(res1.ok).toBe(true)

      const res2 = await Client.recoverFinalize(secret, "test@example.com", payloads[1].challenge)

      expect(res2.ok).toBe(true)
    })
  })
})
