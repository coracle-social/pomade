import {int, now, groupBy, ago, MINUTE} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import {
  RPC,
  buildChallenge,
  isSetRecoveryMethodChallenge,
  isRecoverChallenge,
} from "../lib/index.js"
import type {
  IStorageFactory,
  IStorage,
  SetRecoveryMethodChallenge,
  RecoverChallenge,
  WithEvent,
} from "../lib/index.js"

// Mailer Provider

export type ValidationPayload = {
  inbox: string
  challenge: string
  callback_url?: string
}

export type RecoverPayload = {
  inbox: string
  pubkey: string
  challenge: string
  callback_url?: string
}

export type MailerProvider = {
  sendValidation: (payload: ValidationPayload) => Promise<void>
  sendRecover: (payload: RecoverPayload) => Promise<void>
}

// Mailer

export type ValidationItem = {
  otp: string
  peer: string
}

export type Validation = {
  sent_at?: number
  created_at: number
  items: ValidationItem[]
}

export type RecoverItem = {
  peer: string
  otp: string
  client: string
  threshold: number
}

export type Recover = {
  sent_at?: number
  created_at: number
  items: RecoverItem[]
}

export type MailerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
  provider: MailerProvider
}

export class Mailer {
  rpc: RPC
  pubkey: string
  validations: IStorage<Validation>
  recovers: IStorage<Recover>
  unsubscribe: () => void
  intervals: number[]

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.validations = options.storage("validations")
    this.recovers = options.storage("recovers")
    this.rpc = new RPC(options.secret, options.relays)
    this.unsubscribe = this.rpc.subscribe(message => {
      if (isSetRecoveryMethodChallenge(message)) this.handleSetRecoveryMethodChallenge(message)
      if (isRecoverChallenge(message)) this.handleRecoverChallenge(message)
    })

    // Periodically clean up data
    this.intervals = [
      setInterval(
        async () => {
          for (const [k, validation] of await this.validations.entries()) {
            if (validation.created_at < ago(15, MINUTE)) await this.validations.delete(k)
          }

          for (const [k, recover] of await this.recovers.entries()) {
            if (recover.created_at < ago(15, MINUTE)) await this.recovers.delete(k)
          }
        },
        int(5, MINUTE),
      ) as unknown as number,
    ]
  }

  stop() {
    this.unsubscribe()
    this.intervals.forEach(clearInterval)
  }

  async handleSetRecoveryMethodChallenge({payload, event}: WithEvent<SetRecoveryMethodChallenge>) {
    const {otp, client, inbox, pubkey, threshold, callback_url} = payload
    const key = `${client}:${pubkey}:${inbox}`

    await this.validations.tx(async () => {
      const validation = (await this.validations.get(key)) || {
        created_at: event.created_at,
        items: [],
      }

      if (validation.sent_at) {
        return
      }

      validation.items.push({otp, peer: event.pubkey})

      if (validation.items.length === threshold) {
        const challenge = buildChallenge(validation.items.map(o => [o.peer, o.otp]))

        await this.options.provider.sendValidation({inbox, challenge, callback_url})

        validation.sent_at = now()
      }

      await this.validations.set(key, validation)
    })
  }

  async handleRecoverChallenge({payload, event}: WithEvent<RecoverChallenge>) {
    const {inbox, pubkey, items, callback_url} = payload
    const key = `${pubkey}:${inbox}`

    await this.recovers.tx(async () => {
      const recover = (await this.recovers.get(key)) || {created_at: event.created_at, items: []}

      if (recover.sent_at) {
        return
      }

      for (const {otp, client, threshold} of items) {
        recover.items.push({otp, client, threshold, peer: event.pubkey})
      }

      for (const items of groupBy(o => o.client + o.threshold, recover.items).values()) {
        if (items.length === items[0].threshold) {
          const challenge = buildChallenge(items.map(o => [o.peer, o.otp]))

          await this.options.provider.sendRecover({inbox, pubkey, challenge, callback_url})

          recover.sent_at = now()

          continue
        }
      }

      await this.recovers.set(key, recover)
    })
  }
}
