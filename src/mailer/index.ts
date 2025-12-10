import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {RELAYS, getPubkey} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, prepAndSign, publishRelays} from '../lib/index.js'
import type {IStorageFactory, IStorage} from '../lib/index.js'

export type MailerOptions = {
  secret: string
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
  storage: IStorageFactory
}

export class Mailer {
  private abortController = new AbortController()

  constructor(private options: MailerOptions) {}

  publishRelays() {
    return publishRelays({
      secret: this.options.secret,
      signal: this.abortController.signal,
      relays: [...this.options.indexerRelays, ...this.options.outboxRelays],
      outboxRelays: this.options.outboxRelays,
      inboxRelays: this.options.inboxRelays,
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

  async start() {
    await this.publishRelays()
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
