import type {Maybe} from "@welshman/lib"
import {tryCatch, uniq, without, spec} from "@welshman/lib"
import {publish, request, PublishStatus} from "@welshman/net"
import type {HashedEvent, TrustedEvent} from "@welshman/util"
import {prep, sign, getPubkey} from "@welshman/util"
import {nip44} from "./misc.js"
import {Message, parseMessage} from "./message.js"
import {fetchRelays, publishRelays} from "./relays.js"

export type WithEvent<T extends Message> = T & {event: TrustedEvent}

// Base RPC class

export function rpc(secret: string) {
  return new RPC(secret)
}

export class RPC {
  static Kind = 28350

  pubkey: string
  subscribers: MessageHandler[] = []
  controller = new AbortController()
  channels = new Map<string, RPCChannel>()

  constructor(
    private secret: string,
    readonly relays: string[] = [],
  ) {
    this.pubkey = getPubkey(secret)
    this.publishRelays()
    this.listenForEvents()
  }

  publishRelays() {
    if (this.relays) {
      publishRelays({
        secret: this.secret,
        relays: this.relays,
        signal: this.controller.signal,
      })
    }
  }

  listenForEvents() {
    if (this.relays) {
      request({
        relays: this.relays,
        signal: this.controller.signal,
        filters: [{kinds: [RPC.Kind], "#p": [this.pubkey]}],
        onEvent: (event: TrustedEvent) => this.notify(event),
      })
    }
  }

  read(event: TrustedEvent): Maybe<WithEvent<Message>> {
    const result = tryCatch(() => parseMessage(this.decrypt(event.pubkey, event.content)))

    if (result) {
      return {...result, event}
    }
  }

  notify(event: TrustedEvent) {
    const message = this.read(event)

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

  sign(event: HashedEvent) {
    return sign(event, this.secret)
  }

  encrypt(peer: string, payload: string) {
    return nip44.encrypt(peer, this.secret, payload)
  }

  decrypt(peer: string, payload: string) {
    return nip44.decrypt(peer, this.secret, payload)
  }

  channel(peer: string) {
    let channel = this.channels.get(peer)

    if (!channel) {
      channel = new RPCChannel(this, peer)

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
  ) {
    const {signal} = this.controller

    this.relays = fetchRelays(peer, signal)
    this.relays.then(relays => {
      if (!signal.aborted) {
        const uniqueRelays = without(this.rpc.relays, relays)

        if (uniqueRelays.length > 0) {
          request({
            signal,
            relays: uniqueRelays,
            filters: [{kinds: [RPC.Kind], authors: [this.peer], "#p": [this.rpc.pubkey]}],
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
        resolve(result)
        unsubscribe()
      }

      setTimeout(done, 30_000)
    })
  }

  prep(message: Message) {
    const template = {
      kind: RPC.Kind,
      tags: [["p", this.peer]],
      content: this.encrypt(JSON.stringify(message)),
    }

    return this.rpc.sign(prep(template, this.rpc.pubkey))
  }

  encrypt(payload: string) {
    return this.rpc.encrypt(this.peer, payload)
  }

  decrypt(payload: string) {
    return this.rpc.decrypt(this.peer, payload)
  }

  send(message: Message) {
    const controller = new AbortController()
    const abort = () => controller.abort()
    const event = this.prep(message)

    const res = this.relays.then(relays => {
      return publish({
        event,
        relays: uniq([...relays, ...this.rpc.relays]),
        signal: AbortSignal.any([this.controller.signal, controller.signal]),
      })
    })

    const ok = res.then(r => Object.values(r).some(spec({status: PublishStatus.Success})))

    return {abort, event, res, ok}
  }

  stop() {
    this.controller.abort()
  }
}
