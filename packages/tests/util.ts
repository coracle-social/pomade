import {range, randomId} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {Nip01Signer} from "@welshman/signer"
import {inMemoryStorage, argonOptions, context, Client, Signer, ChallengePayload, RPC} from "@pomade/core"

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.registerPow = 0

export let challengePayloads: ChallengePayload[] = []

let signers: Signer[]
let argonOptionsCopy = {...argonOptions}

export async function beforeHook() {
  argonOptions.m = 1024
  challengePayloads.splice(0)

  const signerUrls = signerSecrets.map((_, i) => `http://signer-${i}.test`)

  signers = signerSecrets.map(
    (secret, i) =>
      new Signer({
        url: signerUrls[i],
        signer: Nip01Signer.fromSecret(secret),
        storage: inMemoryStorage,
        sendChallenge: async payload => {
          challengePayloads.push(payload)
        },
      }),
  )

  const signerByUrl = new Map(signers.map((signer, i) => [signerUrls[i], signer]))

  RPC.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString())
    const signerUrl = `${url.protocol}//${url.host}`
    const signer = signerByUrl.get(signerUrl)

    if (!signer) {
      return new Response(JSON.stringify({ok: false, message: "Not found"}), {status: 404})
    }

    let body: Record<string, unknown> = {}
    if (init?.body) {
      try {
        body = JSON.parse(init.body.toString())
      } catch {
        return new Response(JSON.stringify({ok: false, message: "Invalid JSON"}), {status: 400})
      }
    }

    const authHeader = (init?.headers as Record<string, string>)?.["Authorization"] || ""
    const result = await signer.handle(url.pathname, authHeader, body)

    if (result === undefined) {
      return new Response(JSON.stringify({ok: false, message: "Not found"}), {status: 404})
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: {"Content-Type": "application/json"},
    })
  }

  context.setSignerUrls(signerUrls)
}

export async function afterHook() {
  signers.forEach(signer => signer.stop())
  RPC.fetch = globalThis.fetch.bind(globalThis)
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
