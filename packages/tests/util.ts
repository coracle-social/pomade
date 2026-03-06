import {randomId} from "@welshman/lib"
import {makeSecret} from "@welshman/util"
import {context, Client, RPC, type ChallengePayload} from "@pomade/core"
import {spawnSigners, type SignerKind, type SignerInstance} from "./harness.js"

type Json = Record<string, unknown>

export type SignerResponse = {
  ok: boolean
  message: string
  [key: string]: unknown
}

function decodeAuthHeader(header: string): Json {
  const encoded = header.slice(6)
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as Json
}

function encodeAuthHeader(event: Json): string {
  return `Nostr ${Buffer.from(JSON.stringify(event), "utf8").toString("base64")}`
}

export async function makeSignedAuthHeader(
  secret: string,
  signerUrl: string,
  path: string,
  body: unknown,
  pow?: number,
): Promise<string> {
  return RPC.fromSecret(secret).makeAuthHeader(`${signerUrl}${path}`, JSON.stringify(body), pow)
}

export function mutateAuthHeader(header: string, mutate: (event: Json) => Json): string {
  return encodeAuthHeader(mutate(decodeAuthHeader(header)))
}

export async function postToSigner(
  signerUrl: string,
  path: string,
  body: unknown,
  authHeader?: string,
): Promise<SignerResponse> {
  const response = await fetch(`${signerUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authHeader ? {Authorization: authHeader} : {}),
    },
    body: JSON.stringify(body),
  })

  return (await response.json()) as SignerResponse
}

export async function makeMalformedAuthHeaders(
  secret: string,
  signerUrl: string,
  path: string,
  body: unknown,
) {
  const valid = await makeSignedAuthHeader(secret, signerUrl, path, body)

  return {
    noPrefix: valid.slice(6),
    unsigned: mutateAuthHeader(valid, event => {
      delete event.sig
      return event
    }),
    forgedSignature: mutateAuthHeader(valid, event => ({
      ...event,
      sig: makeSecret() + makeSecret(),
    })),
    mismatchedPubkey: mutateAuthHeader(valid, event => ({
      ...event,
      pubkey: makeSecret(),
    })),
    wrongPath: mutateAuthHeader(valid, event => ({
      ...event,
      tags: Array.isArray(event.tags)
        ? event.tags.map(tag =>
            Array.isArray(tag) && tag[0] === "u" ? ["u", `${signerUrl}/malicious/path`] : tag,
          )
        : event.tags,
    })),
    wrongMethod: mutateAuthHeader(valid, event => ({
      ...event,
      tags: Array.isArray(event.tags)
        ? event.tags.map(tag => (Array.isArray(tag) && tag[0] === "method" ? ["method", "GET"] : tag))
        : event.tags,
    })),
    staleTimestamp: mutateAuthHeader(valid, event => ({
      ...event,
      created_at: 1,
    })),
    futureTimestamp: mutateAuthHeader(valid, event => ({
      ...event,
      created_at: 9999999999,
    })),
  }
}

export type SuiteContext = {
  signers: SignerInstance[]
  challengePayloads: ChallengePayload[]
}

export async function setupSuite(specs: SignerKind[]): Promise<SuiteContext> {
  context.debug = true
  context.registerPow = 0
  context.argonOptions = {...context.argonOptions, m: 1024}

  const challengePayloads: ChallengePayload[] = []
  const signers = await spawnSigners(specs, challengePayloads)

  context.setSignerUrls(signers.map(s => s.url))

  return {signers, challengePayloads}
}

export async function teardownSuite(ctx: SuiteContext) {
  ctx.signers.forEach(s => s.stop())
  ctx.challengePayloads.splice(0)
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
