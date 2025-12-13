import {describe, it, expect, beforeEach, afterEach} from "vitest"
import {makeSecret, verifyEvent, getPubkey, makeEvent} from "@welshman/util"
import {LOCAL_RELAY_URL} from "@welshman/net"
import {Client} from "../src/client"
import {beforeHook, afterHook, clientSecret} from "./util"

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
    it("successfully sets user email", async () => {})

    it.skip("successfully sets a different user email", async () => {})

    it.skip("rejects invalid email", async () => {})

    it.skip("rejects forged otp", async () => {})
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
