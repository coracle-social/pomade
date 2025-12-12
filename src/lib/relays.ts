import {uniq} from "@welshman/lib"
import {publish, request} from "@welshman/net"
import {RELAYS, getTagValues} from "@welshman/util"
import {prepAndSign} from "./misc.js"
import {context} from "./context.js"

export async function fetchRelays(pubkey: string, signal: AbortSignal) {
  const [relayList] = await request({
    autoClose: true,
    relays: context.indexerRelays,
    filters: [{kinds: [RELAYS], authors: [pubkey]}],
    signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
  })

  return getTagValues("r", relayList?.tags || [])
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
