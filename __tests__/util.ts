import {LOCAL_RELAY_URL} from "@welshman/net"
import {range, sleep, noop} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {inMemoryStorageFactory, context, Client, Signer, Mailer} from "../src"

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.signerPubkeys = signerPubkeys
context.indexerRelays = [LOCAL_RELAY_URL]

let signers: Signer[]

export function makeSigner(secret: string) {
  return new Signer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: inMemoryStorageFactory,
  })
}

export function makeMailer(secret: string, provider: Partial<MailerProvider> = {}) {
  return new Mailer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: inMemoryStorageFactory,
    provider: {
      sendValidation: noop,
      sendRecovery: noop,
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

export async function makeClientWithRecovery(
  inbox: string,
  provider: Partial<MailerProvider> = {},
) {
  let challenge

  const mailer = makeMailer(makeSecret(), {
    ...provider,
    sendValidation: payload => {
      challenge = payload.challenge
    },
  })

  const clientRegister = await Client.register(2, 3, makeSecret())
  const client = new Client(clientRegister.clientOptions)

  await client.setRecoveryMethod(inbox, mailer.pubkey)
  await sleep(10)
  await client.finalizeRecoveryMethod(challenge)

  return client
}
