import type {MaybeAsync, Maybe} from '@welshman/lib'
import {uniq, removeUndefined, call, maybe, always, spec, parseJson} from '@welshman/lib'
import {publish, request, PublishStatus} from '@welshman/net'
import type {EventTemplate, TrustedEvent, SignedEvent} from '@welshman/util'
import {prep, sign, getPubkey, RELAYS, getTagValues, getTagValue} from '@welshman/util'
import {Method, Message} from './msg.js'

export type IncomingMessage = Message & {
  method: Method,
  data: Record<string, string>,
  topic?: string,
  peer: string
  event: TrustedEvent,
}

// Base RPC class

export function rpc(secret: string) {
  return new RPC(secret)
}

export class RPC {
  pubkey: string
  channels = new Map<string, RPCChannel>()

  constructor(private secret: string) {
    this.pubkey = getPubkey(secret)
  }

  sign(event: HashedEvent) {
    return sign(this.secret, event)
  }

  encrypt(peer: string, payload: string) {
    return nip44.encrypt(peer, this.secret, payload)
  }

  decrypt(peer: string, payload: string) {
    return nip44.decrypt(peer, this.secret, payload)
  }

  read(event: TrustedEvent): Maybe<IncomingMessage> {
    try {
      const {pubkey: peer, content} = event
      const message = parseMessage(this.decrypt(peer, content))

      if (message) {
        return {...message, event, peer}
      }
    } catch (e) {
      // Pass
    }
  }

  channel(peer: string) {
    let channel = this.channels.get(peer)

    if (!channel) {
      const channel = new RPCChannel(this, peer)

      this.channels.set(peer, channel)
    }

    return channel
  }

  close() {
    for (const channel of this.channels) {
      channel.close()
    }

    this.channels.clear()
  }
}

// RPC channel

export type MessageHandler = (item: IncomingMessage) => void

export class RPCChannel {
  relays: Promise<string[]>
  subscribers: MessageHandler[] = []
  controller = new AbortController()

  constructor(private rpc, readonly peer) {
    this.relays = fetchRelays({pubkey: peer, signal: this.controller.signal})
    this.relays.then(relays => {
      request({
        relays,
        signal: this.controller.signal,
        filters: [{kinds: [28350], authors: [peer], '#p': [rpc.pubkey]}],
        onEvent: (event: TrustedEvent) => {
          const item = rpc.unwrap(event)

          if (item) {
            for (const subscriber of this.subscribers) {
              subscriber(item)
            }
          }
        },
      })
    })
  }

  close() {
    this.controller.abort()
    this.subscribers.forEach(call)
  }

  subscribe(handler: MessageHandler) {
    if (this.controller.signal.aborted) {
      throw new Error("Attempted to subscribe to a channel that has been closed")
    }

    this.subscribers.push(handler)

    return () => this.subscribers.splice(this.subscribers.findIndex(s => s === handler), 1)
  }

  receive(method: Method, topic?: string) {
    return new Promise(resolve => {
      this.subscribe(message => {
        if (message.method !== method) return
        if (topic && message.topic !== topic) return

        resolve(message)
      })
    })
  }

  prep(payload: Payload) {
    return this.rpc.sign(
      prep({
        kind: 28350,
        tags: [["p", this.peer]],
        content: this.encrypt(JSON.stringify(payload)),
      })
    )
  }

  encrypt(payload: string) {
    this.rpc.encrypt(this.peer, payload)
  }

  decrypt(payload: string) {
    this.rpc.decrypt(this.peer, payload)
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

  send<T>(method: Method, tags: string[][]): RPCSend {
    const controller = new AbortController()
    const abort = () => this.controller.abort()
    const event = this.prep({method, data, topic})
    const res = this.publish(event, controller.signal)
    const ok = res.then(r => Object.values(r).some(spec({status: PublishStatus.Success})))

    return {abort, event, res, ok}
  },
}
