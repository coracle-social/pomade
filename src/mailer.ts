import {int, now, sortBy, groupBy, ago, MINUTE} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import {IStorageFactory, IStorage} from "./storage"
import {buildChallenge} from "./misc"
import {WithEvent, RPC} from "./rpc"
import {
  isRecoveryChallenge,
  isRecoveryMethodChallenge,
  RecoveryChallenge,
  RecoveryMethodChallenge,
} from "./message"

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

// Storage types

export type MailerValidationItem = {
  otp: string
  peer: string
}

export type MailerValidation = {
  sent_at?: number
  created_at: number
  items: MailerValidationItem[]
}

export type MailerRecoverItem = {
  idx: number
  otp: string
  peer: string
  client: string
  threshold: number
}

export type MailerRecover = {
  sent_at?: number
  created_at: number
  items: MailerRecoverItem[]
}

// Mailer

export type MailerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
  provider: MailerProvider
}

export class Mailer {
  rpc: RPC
  pubkey: string
  validations: IStorage<MailerValidation>
  recovers: IStorage<MailerRecover>
  unsubscribe: () => void
  intervals: number[]

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.validations = options.storage("validations")
    this.recovers = options.storage("recovers")
    this.rpc = new RPC(options.secret, options.relays)
    this.unsubscribe = this.rpc.subscribe(message => {
      if (isRecoveryMethodChallenge(message)) this.handleRecoveryMethodChallenge(message)
      if (isRecoveryChallenge(message)) this.handleRecoveryChallenge(message)
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

  async handleRecoveryMethodChallenge({payload, event}: WithEvent<RecoveryMethodChallenge>) {
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
        const challenge = buildChallenge(validation.items.map(x => [x.peer, x.otp]))

        await this.options.provider.sendValidation({inbox, challenge, callback_url})

        validation.sent_at = now()
      }

      await this.validations.set(key, validation)
    })
  }

  async handleRecoveryChallenge({payload, event}: WithEvent<RecoveryChallenge>) {
    const {inbox, pubkey, items, callback_url} = payload
    const key = `${pubkey}:${inbox}`

    await this.recovers.tx(async () => {
      const recover = (await this.recovers.get(key)) || {created_at: event.created_at, items: []}

      if (recover.sent_at) {
        return
      }

      for (const {idx, otp, client, threshold} of items) {
        recover.items.push({idx, otp, client, threshold, peer: event.pubkey})
      }

      for (const items of groupBy(o => o.client + o.threshold, recover.items).values()) {
        if (items.length === items[0].threshold) {
          const challenge = buildChallenge(sortBy(x => x.idx, items).map(x => [x.peer, x.otp]))

          await this.options.provider.sendRecover({inbox, pubkey, challenge, callback_url})

          recover.sent_at = now()

          continue
        }
      }

      await this.recovers.set(key, recover)
    })
  }
}
