import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {RPC, makeSetEmailConfirmed, Status, isSetEmailChallenge} from "../lib/index.js"
import type {IStorageFactory, IStorage, SetEmailChallenge} from "../lib/index.js"

export type ValidationState = {
  email: string
  index: number
  total: number
  client: string
  peers: [number, string][]
  status: Status
}

const getValidationKey = (email: string, client: string) => `${email}:${client}`

export type EmailProvider = {
  sendValidationEmail: (email: string, client: string) => Promise<void>
  sendRecoveryEmail: () => Promise<void>
  sendLoginEmail: () => Promise<void>
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
  validations: IStorage<ValidationState>
  stop: () => void

  constructor(private options: MailerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.validations = options.storage("validations")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe((message, event) => {
      if (isSetEmailChallenge(message)) this.handleSetEmailChallenge(message, event)
    })
  }

  async handleSetEmailChallenge(message: SetEmailChallenge, event: TrustedEvent) {
    const {index, total, client, otp, email_ciphertext} = message.payload
    const email = tryCatch(() => this.rpc.decrypt(client, email_ciphertext))

    if (!email) return cb(Status.Error, "Failed to decrypt email address")
    if (!email?.includes("@")) return cb(Status.Error, "Invalid email address provided")

    const key = getValidationKey(email, client)
    const validation = await this.validations.get(key) || {
      email,
      total,
      client,
      status: Status.Pending,
      peers: [],
    }

    validation.peers.push([index, otp])

    if (validation.peers.length === validation.total) {
      const combinedOTP = sortBy(first, validation.peers).map(last).join('')

      await this.validations.delete(key)
      await this.options.provider.sendValidationEmail(email, combinedOTP)
    } else {
      await this.validations.set(key, validation)
    }
  }
}
