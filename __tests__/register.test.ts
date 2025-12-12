import {describe, it, expect, vi, beforeEach, afterEach} from "vitest"
import {makeSecret, getPubkey} from "@welshman/util"
import {LOCAL_RELAY_URL} from "@welshman/net"
import {defaultStorageFactory, context} from "../src/lib"
import {Client} from "../src/client"
import {Signer} from "../src/signer"
import {Mailer} from "../src/mailer"

describe("register", () => {
  it("happy path", async () => {
    context.indexerRelays = [LOCAL_RELAY_URL]

    const userSecret = makeSecret()
    const signer1Secret = makeSecret()
    const signer2Secret = makeSecret()

    const signer1 = new Signer({
      secret: signer1Secret,
      relays: [LOCAL_RELAY_URL],
      storage: defaultStorageFactory,
    })

    const signer2 = new Signer({
      secret: signer2Secret,
      relays: [LOCAL_RELAY_URL],
      storage: defaultStorageFactory,
    })

    context.signerPubkeys = [signer1.pubkey, signer2.pubkey]

    const client = await Client.register(1, 2, makeSecret())

    expect(client.group.startsWith('bfgroup')).toBe(true)
    expect(client.peers.length).toBe(2)
  })
})
