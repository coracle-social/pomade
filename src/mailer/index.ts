import {int, ago, MINUTE} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  buildChallenge,
  isSetEmailChallenge,
  isRecoverChallenge,
  Method,
} from "../lib/index.js"
import type {
  IStorageFactory,
  IStorage,
  SetEmailChallenge,
  RecoverChallenge,
  WithEvent,
} from "../lib/index.js"

export type Batch = {
  email: string
  threshold: number
  method: Method
  client: string
  event: TrustedEvent
  status: Status
  peers: [string, string][]
}

const getBatchKey = (email: string, client: string, method: Method) =>
  `${email}:${client}:${method}`

export type EmailProvider = {
  sendValidationEmail: (email: string, challenge: string, callbackUrl?: string) => Promise<void>
  sendRecoverEmail: (email: string, challenge: string, callbackUrl?: string) => Promise<void>
}

export type MailerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
  provider: EmailProvider
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
      if (isSetEmailChallenge(message)) this.handleSetEmailChallenge(message)
      if (isRecoverChallenge(message)) this.handleRecoverChallenge(message)
    })

    // Periodically clean up batches
    this.intervals = [
      setInterval(
        async () => {
          for (const [k, batch] of await this.batches.entries()) {
            if (batch.event.created_at < ago(15, MINUTE)) await this.batches.delete(k)
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

  async handleSetEmailChallenge({method, payload, event}: WithEvent<SetEmailChallenge>) {
    const {threshold, client, otp, email, callback_url} = payload
    const key = getBatchKey(email, client, method)

    await this.batches.tx(async () => {
      let batch = await this.batches.get(key)
      if (!batch) {
        batch = {email, threshold, client, method, event, status: Status.Pending, peers: []}
      }

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === batch.threshold) {
        await this.options.provider.sendValidationEmail(
          email,
          buildChallenge(batch.peers),
          callback_url,
        )
        await this.batches.delete(key)
      } else {
        await this.batches.set(key, batch)
      }
    })
  }

  async handleRecoverChallenge({method, payload, event}: WithEvent<RecoverChallenge>) {
    const {threshold, client, otp, email, callback_url} = payload
    const key = getBatchKey(email, client, method)

    await this.batches.tx(async () => {
      let batch = await this.batches.get(key)
      if (!batch) {
        batch = {email, threshold, client, method, event, status: Status.Pending, peers: []}
      }

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === batch.threshold) {
        const challenge = buildChallenge(batch.peers)

        await this.options.provider.sendRecoverEmail(email, challenge, callback_url)
        await this.batches.delete(key)
      } else {
        await this.batches.set(key, batch)
      }
    })
  }
}
