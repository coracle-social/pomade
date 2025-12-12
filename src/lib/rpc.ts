import type {Maybe} from "@welshman/lib"
import {tryCatch, spec} from "@welshman/lib"
import {publish, request, PublishStatus} from "@welshman/net"
import type {HashedEvent, TrustedEvent, SignedEvent} from "@welshman/util"
import {prep, sign, getPubkey} from "@welshman/util"
import {nip44} from "./misc.js"
import {fetchRelays} from "./relays.js"
import {Message, parseMessage} from "./msg.js"

// Base RPC class

export function rpc(secret: string) {
  return new RPC(secret)
}

export class RPC {
  static Kind = 28350

  pubkey: string
  channels = new Map<string, RPCChannel>()

  constructor(private secret: string) {
    this.pubkey = getPubkey(secret)
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

  read(event: TrustedEvent): Maybe<Message> {
    return tryCatch(() => parseMessage(this.decrypt(event.pubkey, event.content)))
  }

  channel(peer: string) {
    let channel = this.channels.get(peer)

    if (!channel) {
      channel = new RPCChannel(this, peer)

      this.channels.set(peer, channel)
    }

    return channel
  }

  close() {
    for (const channel of this.channels.values()) {
      channel.close()
    }

    this.channels.clear()
  }
}

// RPC channel

export type MessageHandler = (message: Message, event: TrustedEvent) => void

export type MessageHandlerWithCallback<T> = (
  message: Message,
  event: TrustedEvent,
  resolve: (result?: T) => void,
) => void

export class RPCChannel {
  relays: Promise<string[]>
  subscribers: MessageHandler[] = []
  controller = new AbortController()

  constructor(
    private rpc: RPC,
    readonly peer: string,
  ) {
    this.relays = fetchRelays({pubkey: peer, signal: this.controller.signal})
    this.relays.then(relays => {
      request({
        relays,
        signal: this.controller.signal,
        filters: [{kinds: [RPC.Kind], authors: [peer], "#p": [rpc.pubkey]}],
        onEvent: (event: TrustedEvent) => {
          const message = rpc.read(event)

          if (message) {
            for (const subscriber of this.subscribers) {
              subscriber(message, event)
            }
          }
        },
      })
    })
  }

  close() {
    this.controller.abort()
    this.subscribers = []
  }

  subscribe(handler: MessageHandler) {
    if (this.controller.signal.aborted) {
      throw new Error("Attempted to subscribe to a channel that has been closed")
    }

    this.subscribers.push(handler)

    return () =>
      this.subscribers.splice(
        this.subscribers.findIndex(s => s === handler),
        1,
      )
  }

  receive<T>(handler: MessageHandlerWithCallback<T>) {
    return new Promise<Maybe<T>>(resolve => {
      const unsubscribe = this.subscribe((message, event) => {
        handler(message, event, done)
      })

      const done = () => {
        resolve(undefined)
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

  async publish(event: SignedEvent, callerSignal: AbortSignal) {
    const relays = await this.relays
    const signal = AbortSignal.any([
      callerSignal,
      this.controller.signal,
      AbortSignal.timeout(30_000),
    ])

    return publish({relays, event, signal})
  }

  send(message: Message) {
    const controller = new AbortController()
    const abort = () => this.controller.abort()
    const event = this.prep(message)
    const res = this.publish(event, controller.signal)
    const ok = res.then(r => Object.values(r).some(spec({status: PublishStatus.Success})))

    return {abort, event, res, ok}
  }
}
