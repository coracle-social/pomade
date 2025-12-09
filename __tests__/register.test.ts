import {describe, it, expect, vi, beforeEach, afterEach} from "vitest"
import {makeSecret, getPubkey} from '@welshman/util'
import {LOCAL_RELAY_URL} from '@welshman/net'
import {defaultStorageFactory} from "../src/lib"
import {Client} from "../src/client"
import {Signer} from "../src/signer"
import {Mailer} from "../src/mailer"

describe("register", () => {
  it("happy path", async () => {
    const userSecret = makeSecret()
    const signerSecret = makeSecret()
    const mailerSecret = makeSecret()

    const mailer = new Mailer({
      secret: mailerSecret,
      inboxRelays: [LOCAL_RELAY_URL],
      outboxRelays: [LOCAL_RELAY_URL],
      indexerRelays: [LOCAL_RELAY_URL],
      storage: defaultStorageFactory,
    })

    await mailer.start()

    const signer = new Signer({
      secret: signerSecret,
      inboxRelays: [LOCAL_RELAY_URL],
      outboxRelays: [LOCAL_RELAY_URL],
      indexerRelays: [LOCAL_RELAY_URL],
      storage: defaultStorageFactory,
    })

    await signer.start()

    const client = new Client({
      inboxRelays: [LOCAL_RELAY_URL],
      outboxRelays: [LOCAL_RELAY_URL],
      indexerRelays: [LOCAL_RELAY_URL],
      signerPubkeys: [getPubkey(signerSecret)],
      storage: defaultStorageFactory,
    })

    const clientSigner = await client.register({
      total: 1,
      threshold: 1,
      userSecret,
      emailService: getPubkey(mailerSecret),
      userEmail: 'test@example.com',
    })
  })
})
