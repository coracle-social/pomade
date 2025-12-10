import type {MaybeAsync} from '@welshman/lib'
import {uniq, maybe, always, spec} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import type {EventTemplate, TrustedEvent} from '@welshman/util'
import {prep, sign, getPubkey, RELAYS, getTagValues, getTagValue} from '@welshman/util'

export type IStorage<T> = {
  get(key: string): MaybeAsync<T>
  has(key: string): MaybeAsync<boolean>
  set(key: string, item: T): MaybeAsync<undefined>
  delete(key: string): MaybeAsync<undefined>
  entries(): MaybeAsync<Iterable<[string, T]>>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export const defaultStorageFactory = <T>(name: string) => new Map<string, T>()

export enum Kinds {
  Register = 28350,
  RegisterACK = 28351,
  ValidateEmail = 28352,
  ValidateEmailACK = 28353,
  Unregister = 28354,
  CommitRequest = 28360,
  Commit = 28362,
  CommitGroup = 28362,
  SignatureRequest = 28363,
  PartialSignature = 28364,
  RecoverShard = 28370,
  ReleaseShard = 28371,
  RequestOTP = 28372,
  SendOTP = 28373,
  OTPLogin = 28384,
}

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}

export async function rpcSend({
  authorSecret,
  indexerRelays,
  requestKind,
  recipientPubkey,
  requestContent,
  requestTags = [],
  signal,
}: {
  authorSecret: string,
  indexerRelays: string[]
  requestKind: number
  recipientPubkey: string
  requestContent: string[][]
  requestTags?: string[][]
  signal?: AbortSignal
}) {
  const timeout = AbortSignal.timeout(30_000)
  const relays = await fetchRelays({
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    pubkey: recipientPubkey,
    relays: indexerRelays,
  })

  const event = prepAndSign(authorSecret, {
    kind: requestKind,
    tags: [["p", recipientPubkey], ...requestTags],
    content: nip44.encrypt(recipientPubkey, authorSecret, JSON.stringify(requestContent)),
  })

  const results = await publish({signal, relays, event})

  if (!Object.values(results).some(spec({status: PublishStatus.Success}))) {
    throw new Error('Failed to publish event')
  }

  return event
}

export async function rpcReceive({
  indexerRelays,
  requestEvent,
  responseKind,
  acceptResponse = always(true),
}: {
  indexerRelays: string[]
  requestEvent: TrustedEvent,
  responseKind: number
  acceptResponse?: (response: TrustedEvent) => MaybeAsync<boolean | undefined>
}) {
  const controller = new AbortController()
  const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(30_000)])
  const pubkey = getTagValue("p", requestEvent.tags)

  if (!pubkey) throw new Error("No p tag found on rpc request event")

  const relays = await fetchRelays({signal, pubkey, relays: indexerRelays})

  let result = maybe<TrustedEvent>()

  await request({
    signal,
    relays,
    filters: [{
      authors: [pubkey],
      kinds: [responseKind],
      '#p': [requestEvent.pubkey],
      '#e': [requestEvent.id],
    }],
    onEvent: async (response: TrustedEvent) => {
      if (await acceptResponse(response)) {
        result = response
        controller.abort()
      }
    },
  })

  return result
}

export async function rpc({
  authorSecret,
  indexerRelays,
  requestKind,
  recipientPubkey,
  requestContent,
  requestTags = [],
  responseKind,
  acceptResponse = always(true),
}: {
  authorSecret: string,
  indexerRelays: string[]
  requestKind: number
  recipientPubkey: string
  requestContent: string[][]
  requestTags?: string[][]
  responseKind?: number
  acceptResponse?: (response: TrustedEvent) => MaybeAsync<boolean | undefined>
}) {
  const requestEvent = await rpcSend({
    authorSecret,
    indexerRelays,
    requestKind,
    recipientPubkey,
    requestContent,
    requestTags,
  })

  if (responseKind) {
    return rpcReceive({
      indexerRelays,
      requestEvent,
      responseKind,
      acceptResponse,
    })
  }
}

export async function fetchRelays({
  pubkey,
  relays,
  signal,
}: {
  pubkey: string
  relays: string[]
  signal?: AbortSignal
}) {
  const [relayList] = await request({
    signal,
    autoClose: true,
    relays: uniq(relays),
    filters: [{kinds: [RELAYS], authors: [pubkey]}],
  })

  return getTagValues("r", relayList?.tags || [])
}

export function publishRelays({
  secret,
  relays,
  signal,
  inboxRelays,
  outboxRelays,
}: {
  secret: string
  relays: string[]
  signal?: AbortSignal
  inboxRelays: string[],
  outboxRelays: string[],
}) {
  return publish({
    signal,
    relays: uniq(relays),
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
