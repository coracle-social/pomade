import * as nt44 from "nostr-tools/nip44"
import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {sleep, uniq, equals, hexToBytes, bytesToHex} from "@welshman/lib"
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

    it.skip("successfully unregisters with multiple signers", async () => {})
  })

  describe("signing", () => {
    it("successfully signs an event", async () => {
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
      let email, challenge

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: (_email, _challenge) => {
          email = _email
          challenge = _challenge
        },
      })

      const client = await Client.register(1, 2, makeSecret())

      await client.setEmailRequest("test@example.com", mailer.pubkey)
      await sleep(10)

      expect(email).toBe("test@example.com")
      expect(challenge.length).toBeGreaterThan(190)

      const confirmed1 = await client.setEmailFinalize("test@example.com", mailer.pubkey, challenge)

      expect(confirmed1.ok).toBe(true)

      await client.setEmailRequest("test2@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed2 = await client.setEmailFinalize("test2@example.com", mailer.pubkey, challenge)

      expect(confirmed2.ok).toBe(true)
    })

    it("rejects invalid email", async () => {
      let challenge

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: (_email, _challenge) => {
          challenge = _challenge
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
        sendValidationEmail: (_email, _challenge) => {
          challenge = _challenge
        },
      })

      const client = await Client.register(1, 2, makeSecret())

      await client.setEmailRequest("test@example.com", mailer.pubkey)
      await sleep(10)

      const confirmed = await client.setEmailFinalize("test2@example.com", mailer.pubkey, challenge)

      await expect(confirmed.ok).toBe(false)
    })
  })

  describe("login", () => {
    it("successfully allows user login", async () => {
      let email, challenge

      await makeClientWithEmail('test@example.com', {
        sendLoginEmail: (_email, _challenge) => {
          email = _email
          challenge = _challenge
        },
      })

      const secret = makeSecret()

      await Client.loginRequest(secret, "test@example.com")
      await sleep(10)

      expect(email).toBe("test@example.com")
      expect(challenge.length).toBeGreaterThan(190)

      const {ok, group, peers, messages} = await Client.loginFinalize(secret, "test@example.com", challenge)

      expect(ok).toBe(true)

      const client = new Client({secret, group, peers})
      const result = await client.sign(makeEvent(1))

      expect(result.ok).toBe(true)
      expect(verifyEvent(result.event)).toBe(true)
    })

    it("prevents probing for registrations", async () => {
      const client = await makeClientWithEmail('test@example.com')

      doLet(await Client.loginRequest(makeSecret(), "test@example.com"), res => expect(res.ok).toBe(true))
      doLet(await Client.loginRequest(makeSecret(), "test@example.com", client.rpc.pubkey), res => expect(res.ok).toBe(true))
    })

    it("rejects invalid email", async () => {
      let challenge

      await makeClientWithEmail('test@example.com', {
        sendLoginEmail: (_email, _challenge) => {
          challenge = _challenge
        },
      })

      const secret = makeSecret()

      await Client.loginRequest(secret, "test@example.com")
      await sleep(10)

      const res = await Client.loginFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects invalid challenge", async () => {
      await makeClientWithEmail('test@example.com')

      const secret = makeSecret()

      await Client.loginRequest(secret, "test@example.com")
      await sleep(10)

      const challenge = buildChallenge(context.signerPubkeys.map(pk => [pk, generateOTP()]))

      const res = await Client.loginFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      let challenge

      await makeClientWithEmail('test@example.com', {
        sendLoginEmail: (_email, _challenge) => {
          challenge = _challenge
        },
      })

      await Client.loginRequest(makeSecret(), "test@example.com")
      await sleep(10)

      const res = await Client.loginFinalize(makeSecret(), "test@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("handles pubkey selection", async () => {
      await makeClientWithEmail('test@example.com')
      await makeClientWithEmail('test@example.com')

      const res1 = await Client.loginRequest(makeSecret(), "test@example.com")

      expect(res1.ok).toBe(false)
      expect(res1.options.length).toBe(2)

      doLet(await Client.loginRequest(makeSecret(), "test@example.com", res1.options[1]), res => {
        expect(res.ok).toBe(true)
        expect(res.options.length).toBe(0)
      })
    })
  })

  describe("recovery", () => {
    it("successfully allows recovery", async () => {
      let email, challenge

      const client = await makeClientWithEmail('test@example.com', {
        sendRecoverEmail: (_email, _challenge) => {
          email = _email
          challenge = _challenge
        },
      })

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      expect(email).toBe("test@example.com")
      expect(challenge.length).toBeGreaterThan(190)

      const res = await Client.recoverFinalize(secret, "test@example.com", challenge)

      expect(res.ok).toBe(true)
      expect(getPubkey(res.secret)).toBe(client.group.group_pk.slice(2))
    })

    it("prevents probing for registrations", async () => {
      const client = await makeClientWithEmail('test@example.com')

      doLet(await Client.recoverRequest(makeSecret(), "test@example.com"), res => expect(res.ok).toBe(true))
      doLet(await Client.recoverRequest(makeSecret(), "test@example.com", client.rpc.pubkey), res => expect(res.ok).toBe(true))
    })

    it("rejects invalid email", async () => {
      let challenge

      await makeClientWithEmail('test@example.com', {
        sendRecoverEmail: (_email, _challenge) => {
          challenge = _challenge
        },
      })

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      const res = await Client.recoverFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects invalid challenge", async () => {
      await makeClientWithEmail('test@example.com')

      const secret = makeSecret()

      await Client.recoverRequest(secret, "test@example.com")
      await sleep(10)

      const challenge = buildChallenge(context.signerPubkeys.map(pk => [pk, generateOTP()]))

      const res = await Client.recoverFinalize(secret, "test2@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("rejects inconsistent client secret", async () => {
      let challenge

      await makeClientWithEmail('test@example.com', {
        sendRecoverEmail: (_email, _challenge) => {
          challenge = _challenge
        },
      })

      await Client.recoverRequest(makeSecret(), "test@example.com")
      await sleep(10)

      const res = await Client.recoverFinalize(makeSecret(), "test@example.com", challenge)

      expect(res.ok).toBe(false)
    })

    it("handles pubkey selection", async () => {
      await makeClientWithEmail('test@example.com')
      await makeClientWithEmail('test@example.com')

      const res1 = await Client.recoverRequest(makeSecret(), "test@example.com")

      expect(res1.ok).toBe(false)
      expect(res1.options.length).toBe(2)

      doLet(await Client.recoverRequest(makeSecret(), "test@example.com", res1.options[1]), res => {
        expect(res.ok).toBe(true)
        expect(res.options.length).toBe(0)
      })
    })
  })
})
