import {randomId} from "@welshman/lib"
import {makeSecret} from "@welshman/util"
import {context, Client, type ChallengePayload} from "@pomade/core"
import {spawnSigners, type SignerKind, type SignerInstance} from "./harness.js"

export type SuiteContext = {
  signers: SignerInstance[]
  challengePayloads: ChallengePayload[]
}

export async function setupSuite(specs: SignerKind[]): Promise<SuiteContext> {
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
