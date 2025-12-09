import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {RELAYS, getPubkey} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, makeRPCEvent, prepAndSign} from '../lib/index.js'

export type MailerOptions = {
  secret: string
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
}

export class Mailer {
  private abortController = new AbortController()

  constructor(private options: MailerOptions) {}

  publishRelays() {
    return publish({
      signal: this.abortController.signal,
      relays: [...this.options.indexerRelays, ...this.options.outboxRelays],
      event: prepAndSign(this.options.secret, {
        kind: RELAYS,
        content: "",
        tags: [
          ...this.options.outboxRelays.map(url => ["r", url, "write"]),
          ...this.options.inboxRelays.map(url => ["r", url, "read"]),
        ]
      })
    })
  }

  listenForEvents() {
    return request({
      signal: this.abortController.signal,
      relays: this.options.inboxRelays,
      filters: [{
        kinds: [
          Kinds.ValidateEmail,
          Kinds.ReleaseShard,
          Kinds.SendOTP,
        ],
        '#p': [getPubkey(this.options.secret)],
      }],
      onEvent: (event: TrustedEvent) => {
        switch (event.kind) {
          case Kinds.ValidateEmail: return this.handleValidateEmail(event)
          case Kinds.ReleaseShard: return this.handleReleaseShard(event)
          case Kinds.SendOTP: return this.handleSendOTP(event)
        }
      },
    })
  }

  start() {
    this.publishRelays()
    this.listenForEvents()
  }

  stop() {
    this.abortController.abort()
  }

  async handleValidateEmail(event: TrustedEvent) {
  }

  async handleReleaseShard(event: TrustedEvent) {
  }

  async handleSendOTP(event: TrustedEvent) {
  }
}
