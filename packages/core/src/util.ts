import * as nt44 from "nostr-tools/nip44"
import * as b58 from "base58-js"
import {cached, uniq, textDecoder, textEncoder, hexToBytes} from "@welshman/lib"
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

export const isRelay = (url: string) =>
  url === LOCAL_RELAY_URL ? true : isRelayUrl(url)

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

    relays = getTagValues("r", relayList?.tags || []).filter(isRelay).map(normalizeRelay)

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
