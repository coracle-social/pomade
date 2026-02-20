import { range } from "@welshman/lib"
import { Nip01Signer } from "@welshman/signer"
import { getPubkey, makeSecret } from "@welshman/util"
import { inMemoryStorage, context, Signer, RPC } from "@pomade/core"

export const emails = []

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())

const signerUrls = signerSecrets.map((_, i) => `http://signer-${i}.local`)

context.debug = true
context.setSignerUrls(signerUrls)

let signerByUrl = new Map()

export function initializeSigners() {
  signerByUrl = new Map(
    signerSecrets.map((secret, i) => [
      signerUrls[i],
      new Signer({
        url: signerUrls[i],
        signer: Nip01Signer.fromSecret(secret),
        storage: inMemoryStorage,
        sendChallenge: payload => {
          emails.push({
            id: Date.now() + Math.random(),
            from: 'Pomade Recovery <noreply@pomade.example>',
            to: payload.email,
            subject: 'Your Pomade Recovery Code',
            date: new Date(),
            body: `Your recovery code is:\n\n${payload.otp}\n\nThis code will expire in 15 minutes.`,
            otp: payload.otp,
          })
        },
      }),
    ])
  )

  RPC.fetch = async (input, init) => {
    const url = new URL(input.toString())
    const signerUrl = `${url.protocol}//${url.host}`
    const signer = signerByUrl.get(signerUrl)

    if (!signer) {
      return new Response(JSON.stringify({ok: false, message: "Not found"}), {status: 404})
    }

    let body = {}
    if (init?.body) {
      try {
        body = JSON.parse(init.body.toString())
      } catch {
        return new Response(JSON.stringify({ok: false, message: "Invalid JSON"}), {status: 400})
      }
    }

    const authHeader = init?.headers?.["Authorization"] || ""
    const result = await signer.handle(url.pathname, authHeader, body)

    if (result === undefined) {
      return new Response(JSON.stringify({ok: false, message: "Not found"}), {status: 404})
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: {"Content-Type": "application/json"},
    })
  }
}

export function stopSigners() {
  for (const signer of signerByUrl.values()) signer.stop()
  signerByUrl.clear()
  RPC.fetch = globalThis.fetch.bind(globalThis)
}
