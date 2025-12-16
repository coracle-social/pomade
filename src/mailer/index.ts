import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import {
  RPC,
  Status,
  buildChallenge,
  isSetEmailChallenge,
  isLoginChallenge,
  isRecoverChallenge,
  Method,
} from "../lib/index.js"
import type {
  IStorageFactory,
  IStorage,
  SetEmailChallengeMessage,
  LoginChallengeMessage,
  RecoverChallengeMessage,
  WithEvent,
} from "../lib/index.js"

export type BatchState = {
  email: string
  total: number
  method: Method
  client: string
  peers: [string, string][]
  status: Status
}

const getBatchKey = (email: string, client: string, method: Method) =>
  `${email}:${client}:${method}`

export type EmailProvider = {
  sendValidationEmail: (email: string, challenge: string, callbackUrl?: string) => Promise<void>
  sendRecoverEmail: (email: string, challenge: string, callbackUrl?: string) => Promise<void>
  sendLoginEmail: (email: string, challenge: string, callbackUrl?: string) => Promise<void>
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
  batches: IStorage<BatchState>
  stop: () => void

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.batches = options.storage("batches")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe(message => {
      if (isSetEmailChallenge(message)) this.handleSetEmailChallenge(message)
      if (isLoginChallenge(message)) this.handleLoginChallenge(message)
      if (isRecoverChallenge(message)) this.handleRecoverChallenge(message)
    })
  }

  async handleSetEmailChallenge({method, payload, event}: WithEvent<SetEmailChallengeMessage>) {
    const {total, client, otp, email_ciphertext, callback_url} = payload
    const email = tryCatch(() => this.rpc.decrypt(client, email_ciphertext))

    if (!email) return

    const key = getBatchKey(email, client, method)

    await this.batches.tx(async () => {
      let batch = await this.batches.get(key)
      if (!batch) {
        batch = {email, total, client, method, status: Status.Pending, peers: []}
      }

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === batch.total) {
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

  async handleLoginChallenge({method, payload, event}: WithEvent<LoginChallengeMessage>) {
    const {total, client, otp, email_ciphertext, callback_url} = payload
    const email = tryCatch(() => this.rpc.decrypt(client, email_ciphertext))

    if (!email) return

    const key = getBatchKey(email, client, method)

    await this.batches.tx(async () => {
      let batch = await this.batches.get(key)
      if (!batch) {
        batch = {email, total, client, method, status: Status.Pending, peers: []}
      }

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === batch.total) {
        await this.options.provider.sendLoginEmail(email, buildChallenge(batch.peers), callback_url)
        await this.batches.delete(key)
      } else {
        await this.batches.set(key, batch)
      }
    })
  }

  async handleRecoverChallenge({method, payload, event}: WithEvent<RecoverChallengeMessage>) {
    const {total, client, otp, email_ciphertext, callback_url} = payload
    const email = tryCatch(() => this.rpc.decrypt(client, email_ciphertext))

    if (!email) return

    const key = getBatchKey(email, client, method)

    await this.batches.tx(async () => {
      let batch = await this.batches.get(key)
      if (!batch) {
        batch = {email, total, client, method, status: Status.Pending, peers: []}
      }

      batch.peers.push([event.pubkey, otp])

      if (batch.peers.length === batch.total) {
        await this.options.provider.sendRecoverEmail(
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
}
