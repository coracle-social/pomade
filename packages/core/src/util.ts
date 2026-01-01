import * as b58 from "base58-js"
import * as nt44 from "nostr-tools/nip44"
import {argon2id} from "hash-wasm"
import {bytesToHex} from "@noble/hashes/utils.js"
import {cached, uniq, textEncoder, hexToBytes} from "@welshman/lib"
import type {EventTemplate} from "@welshman/util"
import {
  prep,
  sign,
  getPubkey,
  RELAYS,
  getTagValues,
  normalizeRelayUrl,
  isRelayUrl,
} from "@welshman/util"
import {publish, request} from "@welshman/net"
import {ARGON_WORKER_CODE} from "./argon-worker-code.js"

// Signing and encryption

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

// Challenges

export function encodeChallenge(peer: string, otp: string) {
  const otpBytes = hexToBytes(otp)
  const peerBytes = hexToBytes(peer)

  const combined = new Uint8Array(peerBytes.length + otpBytes.length)

  combined.set(peerBytes, 0)
  combined.set(otpBytes, peerBytes.length)

  return b58.binary_to_base58(combined)
}

export function decodeChallenge(challenge: string) {
  const challengeBytes = b58.base58_to_binary(challenge)
  const peer = bytesToHex(challengeBytes.slice(0, 32))
  const otp = bytesToHex(challengeBytes.slice(32))

  return {peer, otp}
}

// Payload hashing

export const argonOptions = {t: 2, m: 32 * 1024, p: 1}

async function createArgonWorker() {
  const blob = new Blob([ARGON_WORKER_CODE], {type: "application/javascript"})
  const url = URL.createObjectURL(blob)
  const worker = new Worker(url, {type: "module"})

  URL.revokeObjectURL(url)

  return worker
}

export async function hashArgon(value: Uint8Array, salt: Uint8Array) {
  if (typeof Worker === "undefined") {
    return argon2id({
      password: value,
      salt: salt,
      parallelism: argonOptions.p,
      iterations: argonOptions.t,
      memorySize: argonOptions.m,
      hashLength: 32,
      outputType: "binary",
    })
  }

  const worker = await createArgonWorker()

  return new Promise<Uint8Array>((resolve, reject) => {
    worker.onmessage = (e: MessageEvent<Uint8Array>) => {
      resolve(e.data)
      worker.terminate()
    }

    worker.onerror = (e: ErrorEvent) => {
      reject(e.error || e)
      worker.terminate()
    }

    worker.postMessage({value, salt, options: argonOptions})
  })
}

export async function hashEmail(email: string, peer: string) {
  return bytesToHex(await hashArgon(textEncoder.encode(email), hexToBytes(peer)))
}

export async function hashPassword(email: string, password: string, peer: string) {
  return bytesToHex(await hashArgon(textEncoder.encode(email + password), hexToBytes(peer)))
}

// Context

export type Context = {
  debug: boolean
  signerPubkeys: string[]
  indexerRelays: string[]
  setSignerPubkeys: (pubkeys: string[]) => void
  setIndexerRelays: (relays: string[]) => void
}

export const context: Context = {
  debug: false,
  signerPubkeys: [],
  indexerRelays: [
    "wss://indexer.coracle.social/",
    "wss://relay.nostr.band/",
    "wss://purplepag.es/",
  ],
  setSignerPubkeys(pubkeys: string[]) {
    context.signerPubkeys = pubkeys

    // Prime our relay cache
    for (const pubkey of pubkeys) {
      fetchRelays(pubkey, AbortSignal.timeout(5000))
    }
  },
  setIndexerRelays(relays: string[]) {
    context.indexerRelays = relays.filter(isRelay).map(normalizeRelay)
  },
}

export function debug(...args: any) {
  if (context.debug) {
    console.log(...args)
  }
}

// Relays

export const LOCAL_RELAY_URL = "local://welshman.relay/"

export const isRelay = (url: string) => (url === LOCAL_RELAY_URL ? true : isRelayUrl(url))

export const normalizeRelay = (url: string) =>
  url === LOCAL_RELAY_URL ? url : normalizeRelayUrl(url)

export const relayCache = new Map<string, string[]>()

export const fetchRelays = async (pubkey: string, signal?: AbortSignal) => {
  let relays = relayCache.get(pubkey)

  if (!relays || relays?.length === 0) {
    const timeout = AbortSignal.timeout(5000)
    const [relayList] = await request({
      autoClose: true,
      relays: context.indexerRelays,
      filters: [{kinds: [RELAYS], authors: [pubkey]}],
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    })

    relays = getTagValues("r", relayList?.tags || [])
      .filter(isRelay)
      .map(normalizeRelay)

    relayCache.set(pubkey, relays)
  }

  return relays
}

export function publishRelays({
  secret,
  signal,
  relays,
}: {
  secret: string
  signal?: AbortSignal
  relays: string[]
}) {
  return publish({
    signal,
    relays: uniq([...relays, ...context.indexerRelays]),
    event: prepAndSign(secret, {
      kind: RELAYS,
      content: "",
      tags: relays.map(url => ["r", url]),
    }),
  })
}
