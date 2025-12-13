import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {sleep} from "@welshman/lib"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {LOCAL_RELAY_URL} from "@welshman/net"
import {Client} from "../src/client"
import {beforeHook, afterHook, clientSecret, makeMailer} from "./util"

describe("cryptography related methods", () => {
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
      const event = await client.sign(makeEvent(1))

      expect(verifyEvent(event)).toBe(true)
    })
  })

  describe("set email", () => {
    it("successfully sets user email multiple times", async () => {
      let email, otp

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: (_email, _otp) => {
          email = _email
          otp = _otp
        },
      })

      const client = await Client.register(1, 2, makeSecret())
      const confirmed1 = await client.setEmail("test@example.com", mailer.pubkey)

      await sleep(10)

      expect(confirmed1).toBe(false)
      expect(email).toBe("test@example.com")
      expect(otp.length).toBe(6)

      const confirmed2 = await client.setEmail("test@example.com", mailer.pubkey, otp)

      expect(confirmed2).toBe(true)

      const confirmed3 = await client.setEmail("test2@example.com", mailer.pubkey)

      await sleep(10)

      expect(confirmed3).toBe(false)

      const confirmed4 = await client.setEmail("test2@example.com", mailer.pubkey, otp)

      expect(confirmed4).toBe(true)
    })

    it("rejects invalid email", async () => {
      let otp

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: (_email, _otp) => {
          otp = _otp
        },
      })

      const client = await Client.register(1, 2, makeSecret())
      const confirmed1 = await client.setEmail("test@example.com", mailer.pubkey)

      await sleep(10)

      await expect(client.setEmail("test2@example.com", mailer.pubkey, otp)).rejects.toThrowError(
        /does not match/,
      )
    })

    it("rejects forged otp", async () => {
      let otp

      const mailer = makeMailer(makeSecret(), {
        sendValidationEmail: (_email, _otp) => {
          otp = _otp
        },
      })

      const client = await Client.register(1, 2, makeSecret())
      const confirmed1 = await client.setEmail("test@example.com", mailer.pubkey)

      await sleep(10)

      await expect(client.setEmail("test@example.com", mailer.pubkey, otp + '0')).rejects.toThrowError(
        /Invalid OTP/,
      )
    })
  })

  describe("login", () => {
    it.skip("successfully allows user login", async () => {})

    it.skip("rejects invalid email", async () => {})

    it.skip("rejects forged otp", async () => {})

    it.skip("handles pubkey selection", async () => {})
  })

  describe("recovery", () => {
    it.skip("successfully allows recovery", async () => {})

    it.skip("rejects invalid email", async () => {})

    it.skip("rejects forged otp", async () => {})

    it.skip("handles pubkey selection", async () => {})
  })
})
