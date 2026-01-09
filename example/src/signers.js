import { LOCAL_RELAY_URL } from "@welshman/net"
import { range } from "@welshman/lib"
import { getPubkey, makeSecret } from "@welshman/util"
import { inMemoryStorage, context, Signer } from "@pomade/core"

export const emails = []

export const signerSecrets = Array.from(range(0, 8)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.setSignerPubkeys(signerPubkeys)
context.setIndexerRelays([LOCAL_RELAY_URL])

export function makeSigner(secret) {
  return new Signer({
    secret,
    relays: [LOCAL_RELAY_URL],
    storage: inMemoryStorage,
    hash: async (password) => password,
    compare: async (password, hash) => password === hash,
    sendChallenge: payload => {
      const email = {
        id: Date.now() + Math.random(),
        from: 'Pomade Recovery <noreply@pomade.example>',
        to: payload.email,
        subject: 'Your Pomade Recovery Code',
        date: new Date(),
        body: `Your recovery code is:\n\n${payload.challenge}\n\nThis code will expire in 10 minutes.`,
        challenge: payload.challenge,
        timestamp: Date.now()
      }
      emails.push(email)
    },
  })
}

export let signers = []

export function initializeSigners() {
  signers = signerSecrets.map(makeSigner)
}

export function stopSigners() {
  signers.forEach(signer => signer.stop())
  signers = []
}
