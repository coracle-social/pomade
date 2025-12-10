import type {MaybeAsync} from '@welshman/lib'
import {uniq, maybe, always, spec, parseJson} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import type {EventTemplate, TrustedEvent} from '@welshman/util'
import {prep, sign, getPubkey, RELAYS, getTagValues, getTagValue} from '@welshman/util'
import {EventEmitter} from 'events'

// Storage

export type IStorage<T> = {
  get(key: string): MaybeAsync<T>
  has(key: string): MaybeAsync<boolean>
  set(key: string, item: T): MaybeAsync<undefined>
  delete(key: string): MaybeAsync<undefined>
  entries(): MaybeAsync<Iterable<[string, T]>>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export const defaultStorageFactory = <T>(name: string) => new Map<string, T>()

// Misc utils

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}

// RPC stuff

export enum RPCMethod {
  LoginConfirm = "login/confirm",
  LoginRequest = "login/request",
  LoginResult = "login/result",
  LoginSelect = "login/select",
  LoginShare = "login/share",
  RecoverRequest = "recover/request",
  RecoverSelect = "recover/select",
  RecoverShare = "recover/share",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
  UnregisterRequest = "unregister/request",
  ValidateRequest = "validate/request",
  ValidateResult = "validate/result",
}

export const RPCItem = {
  method: RPCMethod,
  event: TrustedEvent,
  tags: string[][],
  parent?: string,
}

export type RPCHandler = (item: RPCItem) => void

export type RPCMatcher = (item: RPCItem) => boolean

export type RPCOptions = {
  other: string
  secret: string
  indexerRelays: string[]
}

export class RPC {
  subscribers: Subscriber<RPCHandler>[] = []
  controller = maybe<AbortController>()
  relays: Promise<string[]>

  constructor(private options: RPCOptions) {
    this.relays = fetchRelays({
      pubkey: options.other,
      relays: options.indexerRelays,
    })

    this.start()
  }

  start() {
    const {signal} = this.controller
    const {other, secret, indexerRelays} = this.options

    if (this.controller) {
      throw new Error("RPC already started")
    }

    this.controller = new AbortController()

    request({
      signal,
      relays: await this.relays,
      filters: [{kinds: [28350], authors: [other]}],
      onEvent: (event: TrustedEvent) => {
        const content = await nip44.decrypt(event.pubkey, secret, event.content)
        const tags: string[][] = parseJson(content)

        if (!Array.isArray(tags)) return

        const method = getTagValue('method', tags)
        const parent = getTagValue("e", item.tags)

        for (const subscriber of this.subscribers) {
          subscriber({method, event, tags, parent})
        }
      },
    })

    try {
    } catch (e) {
      // Ignore decryption errors - event wasn't meant for us
    }
  }

  stop() {
    this.controller?.abort()
    this.controller = undefined
  }

  subscribe(handler: RPCHandler) {
    this.subscribers.push(handler)

    return () => subscribers.splice(subscribers.findIndex(s => s === handler), 1)
  }

  match(match: RPCMatcher, handler: ReceiverHandler) {
    return this.subscribe(item => {
      if (match(item)) {
        handler(event, tags)
      }
    })
  }

  once(match: RPCMatcher, handler: RPCHandler) {
    const unsubscribe = this.subscribe(item => {
      if (match(item)) {
        handler(item)
        unsubscribe()
      }
    })

    return unsubscribe
  }

  async send({tags, signal}: {tags: string[][], signal?: AbortSignal}) {
    const relays = await this.relays
    const {other, secret} = this.options
    const timeout = AbortSignal.timeout(30_000)
    const content = nip44.encrypt(other, secret, JSON.stringify(tags))
    const event = prepAndSign(secret, {kind: 28350, tags: [["p", other]], content})
    const results = await publish({signal, relays, event})

    if (!Object.values(results).some(spec({status: PublishStatus.Success}))) {
      throw new Error('Failed to publish event')
    }

    return event
  }
}

// Relays

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
