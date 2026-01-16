import type {Maybe} from "@welshman/lib"
import {tryCatch, uniq, without, spec} from "@welshman/lib"
import {publish, request, PublishStatus} from "@welshman/net"
import type {TrustedEvent, StampedEvent, SignedEvent} from "@welshman/util"
import {prep, makePow} from "@welshman/util"
import {Nip01Signer} from "@welshman/signer"
import type {ISigner} from "@welshman/signer"
import {debug, fetchRelays, normalizeRelay} from "./util.js"
import {Message, parseMessage} from "./message.js"

export type WithEvent<T extends Message> = T & {event: TrustedEvent}

// Base RPC class

export function rpc(signer: ISigner) {
  return new RPC(signer)
}

export class RPC {
  static Kind = 28350

  relays: string[]
  subscribers: MessageHandler[] = []
  controller = new AbortController()
  channels = new Map<string, RPCChannel>()

  static fromSecret(secret: string, relays: string[] = []) {
    return new RPC(Nip01Signer.fromSecret(secret), relays)
  }

  constructor(
    public signer: ISigner,
    relays: string[] = [],
  ) {
    this.relays = relays.map(normalizeRelay)
    this.publishRelays()
    this.listenForEvents()
  }

  async publishRelays() {
    if (this.relays.length > 0) {
      debug("[rpc.publishRelays]", this.relays)

      const pubkey = await this.signer.getPubkey()
      const event = await this.signer.sign(
        prep(
          {
            kind: 10002,
            content: "",
            tags: this.relays.map(url => ["r", url]),
          },
          pubkey,
        ),
      )

      publish({
        event,
        relays: this.relays,
        signal: this.controller.signal,
      })
    }
  }

  async listenForEvents() {
    if (this.relays) {
      const pubkey = await this.signer.getPubkey()
      request({
        relays: this.relays,
        signal: this.controller.signal,
        filters: [{kinds: [RPC.Kind], "#p": [pubkey]}],
        onEvent: (event: TrustedEvent) => this.notify(event),
      })
    }
  }

  async read(event: TrustedEvent): Promise<Maybe<WithEvent<Message>>> {
    const decrypted = await this.decrypt(event.pubkey, event.content)
    const result = tryCatch(() => parseMessage(decrypted))

    if (result) {
      return {...result, event}
    }
  }

  async notify(event: TrustedEvent) {
    const message = await this.read(event)

    if (message) {
      for (const subscriber of this.subscribers) {
        subscriber(message)
      }
    }
  }

  subscribe(handler: MessageHandler) {
    if (this.controller.signal.aborted) {
      throw new Error("Attempted to subscribe to an rpc interface that has been closed")
    }

    this.subscribers.push(handler)

    return () =>
      this.subscribers.splice(
        this.subscribers.findIndex(s => s === handler),
        1,
      )
  }

  sign(event: StampedEvent): Promise<SignedEvent> {
    return this.signer.sign(event)
  }

  encrypt(peer: string, payload: string) {
    return this.signer.nip44.encrypt(peer, payload)
  }

  decrypt(peer: string, payload: string) {
    return this.signer.nip44.decrypt(peer, payload)
  }

  channel(peer: string, usePeerRelays = true) {
    let channel = this.channels.get(peer)

    if (!channel) {
      channel = new RPCChannel(this, peer, usePeerRelays)

      this.channels.set(peer, channel)
    }

    return channel
  }

  stop() {
    for (const channel of this.channels.values()) {
      channel.stop()
    }

    this.channels.clear()
    this.controller.abort()
    this.subscribers = []
  }
}

// RPC channel

export type MessageHandler = (message: WithEvent<Message>) => void

export type MessageHandlerWithCallback<T> = (
  message: WithEvent<Message>,
  resolve: (result?: T) => void,
) => void

export class RPCChannel {
  relays: Promise<string[]>
  controller = new AbortController()

  constructor(
    private rpc: RPC,
    readonly peer: string,
    readonly usePeerRelays = true,
  ) {
    const {signal} = this.controller

    this.relays = usePeerRelays ? fetchRelays(peer, signal) : Promise.resolve([])
    Promise.all([this.relays, this.rpc.signer.getPubkey()]).then(([relays, pubkey]) => {
      if (!signal.aborted) {
        const uniqueRelays = without(this.rpc.relays, relays)

        if (uniqueRelays.length > 0) {
          request({
            signal,
            relays: uniqueRelays,
            filters: [{kinds: [RPC.Kind], authors: [this.peer], "#p": [pubkey]}],
            onEvent: (event: TrustedEvent) => this.rpc.notify(event),
          })
        }
      }
    })
  }

  subscribe(handler: MessageHandler) {
    if (this.controller.signal.aborted) {
      throw new Error("Attempted to subscribe to a channel that has been closed")
    }

    return this.rpc.subscribe(message => {
      if (message.event.pubkey === this.peer) {
        handler(message)
      }
    })
  }

  receive<T>(handler: MessageHandlerWithCallback<T>) {
    return new Promise<Maybe<T>>((resolve, reject) => {
      const unsubscribe = this.subscribe(async message => {
        try {
          handler(message, done)
        } catch (e) {
          reject(e)
        }
      })

      const done = (result?: Maybe<T>) => {
        clearTimeout(timeout)
        resolve(result)
        unsubscribe()
      }

      const timeout = setTimeout(done, 30_000)
    })
  }

  async prep(message: Message, pow?: number): Promise<SignedEvent> {
    const pubkey = await this.rpc.signer.getPubkey()
    const template = {
      kind: RPC.Kind,
      tags: [["p", this.peer]],
      content: await this.encrypt(JSON.stringify(message)),
    }

    const prepped = prep(template, pubkey)

    if (pow) {
      return this.rpc.sign(await makePow(prepped, pow).result)
    }

    return this.rpc.sign(prepped)
  }

  encrypt(payload: string) {
    return this.rpc.encrypt(this.peer, payload)
  }

  decrypt(payload: string) {
    return this.rpc.decrypt(this.peer, payload)
  }

  send(message: Message, pow?: number) {
    const controller = new AbortController()
    const abort = () => controller.abort()
    const eventPromise = this.prep(message, pow)
    const relaysPromise = this.relays

    const res = Promise.all([eventPromise, relaysPromise]).then(([event, relays]) =>
      publish({
        event,
        relays: uniq([...relays, ...this.rpc.relays]),
        signal: AbortSignal.any([this.controller.signal, controller.signal]),
      }),
    )

    const ok = res.then(r => {
      return Object.values(r).some(spec({status: PublishStatus.Success}))
    })

    const receive = <T>(handler: MessageHandlerWithCallback<T>) =>
      eventPromise.then(event =>
        this.receive<T>((message, resolve) => {
          if ((message.payload as any).prev === event.id) {
            handler(message, resolve)
          }
        }),
      )

    return {abort, res, ok, receive}
  }

  stop() {
    this.controller.abort()
  }
}
