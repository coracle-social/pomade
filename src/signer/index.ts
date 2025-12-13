import {Lib, PackageEncoder} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  makeRegisterResult,
  makeSetEmailResult,
  makeSetEmailChallenge,
  isRegisterRequest,
  isSignRequest,
  isSetEmailRequest,
  makeSignResult,
  generateOTP,
} from "../lib/index.js"
import type {IStorageFactory, IStorage, RegisterRequest, SignRequest, SetEmailRequest} from "../lib/index.js"

export type SignerRegistration = {
  share: SharePackage
  group: GroupPackage
  event: TrustedEvent
  email_hash?: string
  email_ciphertext?: string
}

export type EmailChallenge = {
  otp: string
  attempts: number
  email_hash: string
  email_service: string
  email_ciphertext: string
}

export type SignerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
}

export class Signer {
  rpc: RPC
  pubkey: string
  registrations: IStorage<SignerRegistration>
  challenges: IStorage<EmailChallenge>
  stop: () => void

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.registrations = options.storage("registrations")
    this.challenges = options.storage("challenges")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe((message, event) => {
      if (isRegisterRequest(message)) this.handleRegisterRequest(message, event)
      if (isSetEmailRequest(message)) this.handleSetEmailRequest(message, event)
      if (isSignRequest(message)) this.handleSignRequest(message, event)
    })
  }

  async handleRegisterRequest({payload}: RegisterRequest, event: TrustedEvent) {
    const channel = this.rpc.channel(event.pubkey)
    const share = tryCatch(() => PackageEncoder.share.decode(payload.share))
    const group = tryCatch(() => PackageEncoder.group.decode(payload.group))
    const cb = (status: Status, message: string) =>
      channel.send(makeRegisterResult({status, message}))

    if (!share) return cb(Status.Error, `Failed to deserialize share package.`)
    if (!group) return cb(Status.Error, `Failed to deserialize group package.`)

    const isMember = Lib.is_group_member(group, share)

    if (!isMember) return cb(Status.Error, "Share does not belong to the provided group.")
    if (group.threshold <= 0) return cb(Status.Error, "Group threshold must be greater than zero.")
    if (group.threshold > group.commits.length) return cb(Status.Error, "Invalid group threshold.")

    const indices = new Set(group.commits.map(c => c.idx))
    const commit = group.commits.find(c => c.idx === share.idx)

    if (indices.size !== group.commits.length)
      return cb(Status.Error, "Group contains duplicate member indices.")
    if (!commit) return cb(Status.Error, "Share index not found in group commits.")
    if (await this.registrations.has(event.pubkey))
      return cb(Status.Error, "Client key has already been used.")

    await this.registrations.set(event.pubkey, {event, share, group})

    return cb(Status.Ok, "Your key has been registered")
  }

  async handleSetEmailRequest({payload}: SetEmailRequest, event: TrustedEvent) {
    const clientChannel = this.rpc.channel(event.pubkey)
    const registration = await this.registrations.get(event.pubkey)

    if (!registration) {
      return clientChannel.send(
        makeSetEmailResult({
          status: Status.Error,
          message: "No registration found for client",
        }),
      )
    }

    // Case 1: No OTP provided - initiate email verification
    if (!payload.otp) {
      const peers = registration.group.commits.length
      const otp = generateOTP(peers)
      const challenge: EmailChallenge = {
        otp,
        attempts: 0,
        email_hash: payload.email_hash,
        email_service: payload.email_service,
        email_ciphertext: payload.email_ciphertext,
      }

      await this.challenges.set(event.pubkey, challenge)

      this.rpc.channel(payload.email_service).send(
        makeSetEmailChallenge({
          otp,
          peers,
          client: event.pubkey,
          email_ciphertext: payload.email_ciphertext,
        }),
      )

      return clientChannel.send(
        makeSetEmailResult({
          status: Status.Pending,
          message: "Verification email sent. Please check your email for the OTP.",
        }),
      )
    }

    // Case 2: OTP provided - verify it
    const challenge = await this.challenges.get(event.pubkey)

    if (!challenge) {
      return clientChannel.send(
        makeSetEmailResult({
          status: Status.Error,
          message: "No email verification in progress",
        }),
      )
    }

    if (challenge.email_hash !== payload.email_hash) {
      return clientChannel.send(
        makeSetEmailResult({
          status: Status.Error,
          message: "Email address does not match verification request",
        }),
      )
    }

    if (challenge.otp !== payload.otp) {
      challenge.attempts += 1

      // Invalidate challenge after 2 failed attempts
      if (challenge.attempts >= 2) {
        await this.challenges.delete(event.pubkey)

        return clientChannel.send(
          makeSetEmailResult({
            status: Status.Error,
            message: "Too many invalid OTP attempts. Please request a new verification code.",
          }),
        )
      }

      // Save updated challenge with incremented attempts
      await this.challenges.set(event.pubkey, challenge)

      return clientChannel.send(
        makeSetEmailResult({
          status: Status.Error,
          message: `Invalid OTP. You have ${2 - challenge.attempts} attempt(s) remaining.`,
        }),
      )
    }

    // OTP is valid - associate email with registration
    registration.email_hash = payload.email_hash
    registration.email_ciphertext = payload.email_ciphertext
    await this.registrations.set(event.pubkey, registration)
    await this.challenges.delete(event.pubkey)

    return clientChannel.send(
      makeSetEmailResult({
        status: Status.Ok,
        message: "Email successfully verified and associated with your account",
      }),
    )
  }

  async handleSignRequest({payload}: SignRequest, event: TrustedEvent) {
    const channel = this.rpc.channel(event.pubkey)
    const registration = await this.registrations.get(event.pubkey)

    if (!registration) {
      return channel.send(
        makeSignResult({
          status: Status.Error,
          message: "No registration found for client",
        }),
      )
    }

    const ctx = Lib.get_session_ctx(registration.group, payload.session)
    const psig = Lib.create_psig_pkg(ctx, registration.share)
    channel.send(
      makeSignResult({
        psig,
        status: Status.Ok,
        message: "Successfully signed event",
      }),
    )
  }
}
