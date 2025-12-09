import type {MaybeAsync} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import type {EventTemplate} from '@welshman/util'
import {prep, sign, getPubkey, RELAYS, getTagValues} from '@welshman/util'

export type IStorage<T> = {
  list(): MaybeAsync<Iterable<T>>
  get(key: string): MaybeAsync<T>
  set(key: string, item: T): MaybeAsync<undefined>
  del(key: string): MaybeAsync<undefined>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export enum Kinds {
  Register = 28350,
  RegisterACK = 28351,
  ValidateEmail = 28352,
  ValidateEmailACK = 28353,
  Unregister = 28354,
  CommitRequest = 28360,
  Commit = 28362,
  CommitGroup = 28362,
  PartialSignature = 28363,
  RecoverShard = 28370,
  ReleaseShard = 28371,
  RequestOTP = 28372,
  SendOTP = 28373,
  OTPLogin = 28384,
}

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}

export function makeRPCEvent({
  authorSecret,
  recipientPubkey,
  kind,
  content,
  tags = []
}: {
  authorSecret: string
  recipientPubkey: string
  kind: number
  content: string[][]
  tags?: string[][]
}) {
  return prepAndSign(authorSecret, {
    kind,
    tags: [["p", recipientPubkey], ...tags],
    content: nip44.encrypt(recipientPubkey, authorSecret, JSON.stringify(content)),
  })
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
  const filters = [{kinds: [RELAYS], authors: [pubkey]}]
  const [relayList] = await request({signal, relays, filters, autoClose: true})

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
    relays,
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
