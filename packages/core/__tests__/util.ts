import {LOCAL_RELAY_URL} from "@welshman/net"
import {range, sleep} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {inMemoryStorageFactory, context, Client, Signer} from "../src"

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.setSignerPubkeys(signerPubkeys)
context.setIndexerRelays([LOCAL_RELAY_URL])

type ChallengeSubscriber = (payload: ChallengePayload) => void

let signers: Signer[]
let challengeSubscribers: ChallengeSubscriber[] = []

export function onChallenge(cb: ChallengeSubscriber) {
  challengeSubscribers.push(cb)

  return () => {
    challengeSubscribers = without(cb, challengeSubscribers)
  }
}

export function makeSigner(secret: string) {
  return new Signer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: inMemoryStorageFactory,
    mailer: {
      sendChallenge: payload => {
        for (const cb of challengeSubscribers) {
          cb(payload)
        }
      },
    },
  })
}

export function beforeHook() {
  signers = signerSecrets.map(makeSigner)
}

export function afterHook() {
  signers.forEach(signer => signer.stop())
  challengeSubscribers = []
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
