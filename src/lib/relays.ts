import type {MaybeAsync, Maybe} from '@welshman/lib'
import {uniq, removeUndefined, maybe, always, spec, parseJson} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import type {EventTemplate, TrustedEvent, SignedEvent} from '@welshman/util'
import {prep, sign, getPubkey, RELAYS, getTagValues, getTagValue} from '@welshman/util'

export async function fetchRelays({
  pubkey,
  signal,
}: {
  pubkey: string
  signal?: AbortSignal
}) {
  const [relayList] = await request({
    signal,
    autoClose: true,
    relays: context.indexerRelays,
    filters: [{kinds: [RELAYS], authors: [pubkey]}],
  })

  return getTagValues("r", relayList?.tags || [])
}

export function publishRelays({
  secret,
  signal,
  inboxRelays,
  outboxRelays,
}: {
  secret: string
  signal?: AbortSignal
  inboxRelays: string[],
  outboxRelays: string[],
}) {
  return publish({
    signal,
    relays: uniq([...outboxRelays, ...context.indexerRelays]),
    event: prepAndSign(secret, {
      kind: RELAYS,
      content: "",
      tags: [
        ...outboxRelays.map(url => ["r", url, "write"]),
        ...inboxRelays.map(url => ["r", url, "read"]),
      ]
    })
  })
}
