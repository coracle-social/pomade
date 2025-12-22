import * as nt44 from "nostr-tools/nip44"
import {argon2id} from "@noble/hashes/argon2.js"
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
import {publish, request, LOCAL_RELAY_URL} from "@welshman/net"

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

// Payload hashing

export async function hashArgon(text: string, peer: string) {
  return bytesToHex(argon2id(textEncoder.encode(text), hexToBytes(peer), {t: 3, m: 65536, p: 1}))
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
