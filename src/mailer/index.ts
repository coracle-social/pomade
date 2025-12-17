import {int, ago, MINUTE} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  buildChallenge,
  isSetRecoveryMethodChallenge,
  isRecoverChallenge,
  Method,
} from "../lib/index.js"
import type {
  IStorageFactory,
  IStorage,
  SetRecoveryMethodChallenge,
  RecoverChallenge,
  WithEvent,
} from "../lib/index.js"

export type Batch = {
  created_at: number
  peers: [string, string][]
}

const makeBatch = (event: TrustedEvent) => ({created_at: event.created_at, peers: []})

const getBatchKey = (pubkey: string, inbox: string, method: string) =>
  `${pubkey}:${inbox}:${method}`

export type ValidationPayload = {
  inbox: string,
  challenge: string,
  callback_url?: string
}

export type RecoverPayload = {
  inbox: string,
  pubkey: string,
  challenge: string,
  callback_url?: string
}

export type MailerProvider = {
  sendValidation: (payload: ValidationPayload) => Promise<void>
  sendRecover: (payload: RecoverPayload) => Promise<void>
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
  batches: IStorage<Batch>
  unsubscribe: () => void
  intervals: number[]

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.batches = options.storage("batches")
    this.rpc = new RPC(options.secret, options.relays)
    this.unsubscribe = this.rpc.subscribe(message => {
      if (isSetRecoveryMethodChallenge(message)) this.handleSetRecoveryMethodChallenge(message)
      if (isRecoverChallenge(message)) this.handleRecoverChallenge(message)
    })

    // Periodically clean up batches
    this.intervals = [
      setInterval(
        async () => {
          for (const [k, batch] of await this.batches.entries()) {
            if (batch.created_at < ago(15, MINUTE)) await this.batches.delete(k)
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

  async handleSetRecoveryMethodChallenge({method, payload, event}: WithEvent<SetRecoveryMethodChallenge>) {
    const {otp, inbox, pubkey, threshold, callback_url} = payload
    const key = getBatchKey(pubkey, inbox, method)

    await this.batches.tx(async () => {
      const batch = await this.batches.get(key) || makeBatch(event)

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === threshold) {
        const challenge = buildChallenge(batch.peers)

        await this.options.provider.sendValidation({inbox, challenge, callback_url})
        await this.batches.delete(key)
      } else {
        await this.batches.set(key, batch)
      }
    })
  }

  async handleRecoverChallenge({method, payload, event}: WithEvent<RecoverChallenge>) {
    const {otp, inbox, pubkey, threshold, callback_url} = payload
    const key = getBatchKey(pubkey, inbox, method)

    await this.batches.tx(async () => {
      const batch = await this.batches.get(key) || makeBatch(event)

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === threshold) {
        const challenge = buildChallenge(batch.peers)

        await this.options.provider.sendRecover({inbox, pubkey, challenge, callback_url})
      }

      await this.batches.set(key, batch)
    })
  }
}
