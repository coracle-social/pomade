import type {MaybeAsync, Maybe} from '@welshman/lib'
import {uniq, removeUndefined, maybe, always, spec, parseJson} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import type {EventTemplate, TrustedEvent, SignedEvent} from '@welshman/util'
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

export type RPCItem = {
  pubkey: string
  method: RPCMethod,
  event: TrustedEvent,
  tags: string[][],
  parent?: string,
}

export type RPCHandler = (item: RPCItem) => void

export type RPCMatcher = (item: RPCItem) => boolean

export type RPCOptions = {
  secret: string
  indexerRelays: string[]
}

export type RPCSendOptions = {
  pubkey: string
  method: RPCMethod,
  tags: string[][],
}

export type RPCStaticSendOptions = {
  secret: string
  indexerRelays: string[]
  pubkey: string
  method: RPCMethod,
  tags: string[][],
}

export type RPCStaticRequestOptions<T> = RPCStaticSendOptions & {
  handler: (item: RPCItem, done: (result: T) => void) => void
}

export class RPC {
  subscribers: RPCHandler[] = []

  constructor(private options: RPCOptions) {}

  static unwrap(secret: string, event: TrustedEvent): Maybe<RPCItem> {
    try {
      const {pubkey, content} = event
      const tags: string[][] = parseJson(nip44.decrypt(pubkey, secret, content))

      if (!Array.isArray(tags)) return

      const method = getTagValue('method', tags) as RPCMethod
      const parent = getTagValue("e", tags)

      if (method) {
        return {pubkey, method, event, tags, parent}
      }
    } catch (e) {
      // Pass
    }
  }

  static send<T>({
    secret,
    indexerRelays,
    pubkey,
    method,
    tags,
  }: RPCStaticSendOptions): Promise<SignedEvent> {
    const rpc = new RPC({secret, indexerRelays})
    const {event, pub} = rpc.send({pubkey, method, tags})

    return pub.then(() => event)
  }

  static request<T>({
    secret,
    indexerRelays,
    pubkey,
    method,
    tags,
    handler,
  }: RPCStaticRequestOptions<T>): Promise<T> {
    const rpc = new RPC({secret, indexerRelays})
    const close = rpc.open(pubkey)
    const {event, abort} = rpc.send({pubkey, method, tags})

    return new Promise<T>(resolve => {
      const unsubscribe = rpc.receive(item => {
        if (item.pubkey === pubkey && item.parent === event.id) {
          handler(item, (result: T) => {
            close()
            abort()
            unsubscribe()
            resolve(result)
          })
        }
      })
    })
  }

  open(pubkey: string) {
    const controller = new AbortController()

    fetchRelays({
      pubkey,
      signal: controller.signal,
      relays: this.options.indexerRelays,
    }).then(relays => {
      request({
        relays,
        signal: controller.signal,
        filters: [{kinds: [28350], authors: [pubkey]}],
        onEvent: async (event: TrustedEvent) => {
          const item = RPC.unwrap(this.options.secret, event)

          if (item) {
            for (const subscriber of this.subscribers) {
              subscriber(item)
            }
          }
        },
      })
    })

    return () => controller.abort()
  }

  receive(handler: RPCHandler) {
    this.subscribers.push(handler)

    return () => this.subscribers.splice(this.subscribers.findIndex(s => s === handler), 1)
  }

  send({pubkey, method, tags}: RPCSendOptions) {
    const {secret, indexerRelays} = this.options
    const controller = new AbortController()
    const timeout = AbortSignal.timeout(30_000)
    const signal = AbortSignal.any([controller.signal, timeout])
    const content = nip44.encrypt(pubkey, secret, JSON.stringify([["method", method], ...tags]))
    const event = prepAndSign(secret, {kind: 28350, tags: [["p", pubkey]], content})
    const relays = fetchRelays({pubkey, signal, relays: indexerRelays})
    const pub = relays.then(relays => publish({signal, relays, event}))
    const error = pub.then(r => !Object.values(r).some(spec({status: PublishStatus.Success})))

    return {
      pub,
      error,
      event,
      abort: () => controller.abort(),
    }
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
