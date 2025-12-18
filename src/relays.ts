import {uniq} from "@welshman/lib"
import {publish, request} from "@welshman/net"
import {RELAYS, getTagValues} from "@welshman/util"
import {prepAndSign} from "./misc.js"
import {context} from "./context.js"

export function setSignerPubkeys(pubkeys: string[]) {
  context.signerPubkeys = pubkeys

  for (const pubkey of pubkeys) {
    fetchRelays(pubkey, AbortSignal.timeout(5000))
  }
}

export const relayCache = new Map<string, string[]>()

export const fetchRelays = async (pubkey: string, signal?: AbortSignal) => {
  let relays = relayCache.get(pubkey)

  if (!relays) {
    const timeout = AbortSignal.timeout(5000)
    const [relayList] = await request({
      autoClose: true,
      relays: context.indexerRelays,
      filters: [{kinds: [RELAYS], authors: [pubkey]}],
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    })

    relays = getTagValues("r", relayList?.tags || [])

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
