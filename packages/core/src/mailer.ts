import {int, now, ms, sortBy, groupBy, ago, MINUTE} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import {IStorageFactory, IStorage} from "./storage.js"
import {buildChallenge, debug} from "./util.js"
import {WithEvent, RPC} from "./rpc.js"
import {
  isRecoveryChallenge,
  isRecoveryMethodChallenge,
  RecoveryChallenge,
  RecoveryMethodChallenge,
} from "./message.js"

// Mailer Provider

export type ValidationPayload = {
  inbox: string
  challenge: string
  callback_url?: string
}

export type RecoveryPayload = {
  inbox: string
  pubkey: string
  challenge: string
  callback_url?: string
}

export type MailerProvider = {
  sendValidation: (payload: ValidationPayload) => Promise<void>
  sendRecovery: (payload: RecoveryPayload) => Promise<void>
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

export type MailerRecoveryItem = {
  idx: number
  otp: string
  peer: string
  client: string
  threshold: number
}

export type MailerRecovery = {
  sent_at?: number
  created_at: number
  items: MailerRecoveryItem[]
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
  recoveries: IStorage<MailerRecovery>
  intervals: number[]

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.validations = options.storage("validations")
    this.recoveries = options.storage("recoveries")
    this.rpc = new RPC(options.secret, options.relays)
    this.rpc.subscribe(message => {
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

          for (const [k, recovery] of await this.recoveries.entries()) {
            if (recovery.created_at < ago(15, MINUTE)) await this.recoveries.delete(k)
          }
        },
        ms(int(5, MINUTE)),
      ) as unknown as number,
    ]
  }

  stop() {
    this.rpc.stop()
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
        return debug("[mailer]: validation already sent", event.pubkey)
      }

      debug("[mailer]: validation item recieved", event.pubkey)

      validation.items.push({otp, peer: event.pubkey})

      if (validation.items.length === threshold) {
        const challenge = buildChallenge(validation.items.map(x => [x.peer, x.otp]))

        await this.options.provider.sendValidation({inbox, challenge, callback_url})

        validation.sent_at = now()

        debug("[mailer]: validation sent", event.pubkey)
      }

      await this.validations.set(key, validation)
    })
  }

  async handleRecoveryChallenge({payload, event}: WithEvent<RecoveryChallenge>) {
    const {inbox, pubkey, items, callback_url} = payload
    const key = `${pubkey}:${inbox}`

    await this.recoveries.tx(async () => {
      const recovery = (await this.recoveries.get(key)) || {created_at: event.created_at, items: []}

      if (recovery.sent_at) {
        return debug("[mailer]: recovery already sent", event.pubkey)
      }

      debug("[mailer]: recovery item received", event.pubkey)

      for (const {idx, otp, client, threshold} of items) {
        recovery.items.push({idx, otp, client, threshold, peer: event.pubkey})
      }

      for (const items of groupBy(o => o.client + o.threshold, recovery.items).values()) {
        if (items.length === items[0].threshold) {
          const challenge = buildChallenge(sortBy(x => x.idx, items).map(x => [x.peer, x.otp]))

          await this.options.provider.sendRecovery({inbox, pubkey, challenge, callback_url})

          recovery.sent_at = now()

          debug("[mailer]: recovery sent", event.pubkey)

          break
        }
      }

      await this.recoveries.set(key, recovery)
    })
  }
}
