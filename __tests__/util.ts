import {range, sleep, noop} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {LOCAL_RELAY_URL} from "@welshman/net"
import {defaultStorageFactory, context} from "../src/lib"
import {Client} from "../src/client"
import {Signer} from "../src/signer"
import {Mailer} from "../src/mailer"

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.signerPubkeys = signerPubkeys
context.indexerRelays = [LOCAL_RELAY_URL]

let signers: Signer[]

export function makeSigner(secret: string) {
  return new Signer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: defaultStorageFactory,
  })
}

export function makeMailer(secret: string, provider: Partial<MailerProvider> = {}) {
  return new Mailer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: defaultStorageFactory,
    provider: {
      sendValidation: noop,
      sendRecover: noop,
      ...provider,
    },
  })
}

export function beforeHook() {
  signers = signerSecrets.map(makeSigner)
}

export function afterHook() {
  signers.forEach(signer => signer.stop())
}

export async function makeClientWithRecovery(inbox: string, provider: Partial<MailerProvider> = {}) {
  let challenge

  const mailer = makeMailer(makeSecret(), {
    ...provider,
    sendValidation: payload => {
      challenge = payload.challenge
    },
  })

  const client = await Client.register(2, 3, makeSecret())

  await client.setRecoveryMethodRequest(inbox, mailer.pubkey)
  await sleep(10)
  await client.setRecoveryMethodFinalize(challenge)

  return client
}
