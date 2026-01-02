import {LOCAL_RELAY_URL} from "@welshman/net"
import {range, randomId} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {inMemoryStorage, argonOptions, context, Client, Signer} from "../src"

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.setSignerPubkeys(signerPubkeys)
context.setIndexerRelays([LOCAL_RELAY_URL])

export let challengePayloads: ChallengePayload[] = []

export function makeSigner(secret: string) {
  return new Signer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: inMemoryStorage,
    hash: async (password: string) => password,
    compare: async (password: string, hash: string) => password === hash,
    sendChallenge: payload => {
      challengePayloads.push(payload)
    },
  })
}

let signers: Signer[]
let argonOptionsCopy = {...argonOptions}

export function beforeHook() {
  argonOptions.m = 1024
  signers = signerSecrets.map(makeSigner)
  challengePayloads.splice(0)
}

export function afterHook() {
  signers.forEach(signer => signer.stop())
  argonOptions.m = argonOptionsCopy.m
  challengePayloads.splice(0)
}

export async function makeClientWithRecovery(email: string, password = makeSecret()) {
  const clientRegister = await Client.register(2, 3, makeSecret())
  const client = new Client(clientRegister.clientOptions)

  await client.setupRecovery(email, password)

  return client
}

export function makeEmail() {
  return `test${randomId()}@example.com`
}
