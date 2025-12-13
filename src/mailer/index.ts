import {tryCatch, first, last, sortBy} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {RPC, Status, isSetEmailChallenge} from "../lib/index.js"
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
  sendValidationEmail: (email: string, otp: string) => Promise<void>
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

  async handleSetEmailChallenge({payload}: SetEmailChallenge, event: TrustedEvent) {
    const {index, total, client, otp, email_ciphertext} = payload
    const email = tryCatch(() => this.rpc.decrypt(client, email_ciphertext))

    if (!email?.includes("@")) return

    const key = getValidationKey(email, client)


    await this.validations.tx(async () => {
      let validation = await this.validations.get(key)
      if (!validation) {
        validation = {email, index, total, client, status: Status.Pending, peers: []}
      }

      validation.peers.push([index, otp])

      if (validation.peers.length === validation.total) {
        const combinedOTP = sortBy(first, validation.peers).map(last).join("")

        await this.options.provider.sendValidationEmail(email, combinedOTP)
        await this.validations.delete(key)
      } else {
        await this.validations.set(key, validation)
      }
    })
  }
}
