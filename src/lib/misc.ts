import * as nt44 from "nostr-tools/nip44"
import * as b58 from "base58-js"
import {cached, textDecoder, textEncoder, hexToBytes} from "@welshman/lib"
import type {EventTemplate} from "@welshman/util"
import {prep, sign, getPubkey} from "@welshman/util"

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}

export const nip44 = {
  getSharedSecret: cached({
    maxSize: 10000,
    getKey: ([secret, pubkey]) => `${secret}:${pubkey}`,
    getValue: ([secret, pubkey]: string[]) =>
      nt44.v2.utils.getConversationKey(hexToBytes(secret), pubkey),
  }),
  encrypt: (pubkey: string, secret: string, m: string) =>
    nt44.v2.encrypt(m, nip44.getSharedSecret(secret, pubkey)!),
  decrypt: (pubkey: string, secret: string, m: string) =>
    nt44.v2.decrypt(m, nip44.getSharedSecret(secret, pubkey)!),
}

export function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

export function buildChallenge(otpsByPeer: [string, string][]) {
  return b58.binary_to_base58(textEncoder.encode(new URLSearchParams(otpsByPeer).toString()))
}

export function parseChallenge(challenge: string): [string, string][] {
  return Array.from(new URLSearchParams(textDecoder.decode(b58.base58_to_binary(challenge))))
}
