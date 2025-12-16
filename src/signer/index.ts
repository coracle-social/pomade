import {Lib, PackageEncoder} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {tryCatch} from "@welshman/lib"
import {getPubkey} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  makeRegisterResult,
  makeSetEmailRequestResult,
  makeSetEmailFinalizeResult,
  makeSetEmailChallenge,
  isRegisterRequest,
  isSignRequest,
  isEcdhRequest,
  isLoginRequest,
  isLoginFinalize,
  isSetEmailRequest,
  isSetEmailFinalize,
  makeSignResult,
  makeEcdhResult,
  makeLoginChallenge,
  makeLoginRequestResult,
  makeLoginFinalizeResult,
  generateOTP,
} from "../lib/index.js"
import type {
  IStorageFactory,
  IStorage,
  RegisterRequestMessage,
  SignRequestMessage,
  SetEmailRequestMessage,
  SetEmailFinalizeMessage,
  EcdhRequestMessage,
  LoginRequestMessage,
  LoginFinalizeMessage,
  WithEvent,
} from "../lib/index.js"

export type SignerRegistration = {
  client: string
  share: SharePackage
  group: GroupPackage
  event: TrustedEvent
  email_hash?: string
  email_service?: string
  email_ciphertext?: string
}

export type EmailChallenge = {
  otp: string
  email_hash: string
  email_service: string
  email_ciphertext: string
}

export type LoginRequest = {
  otp: string
  email_hash: string
  copy_from: string
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
  logins: IStorage<LoginRequest>
  stop: () => void

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.registrations = options.storage("registrations")
    this.challenges = options.storage("challenges")
    this.logins = options.storage("logins")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe(message => {
      if (isRegisterRequest(message)) this.handleRegisterRequest(message)
      if (isSetEmailRequest(message)) this.handleSetEmailRequestMessage(message)
      if (isSetEmailFinalize(message)) this.handleSetEmailFinalizeMessage(message)
      if (isLoginRequest(message)) this.handleLoginRequestMessage(message)
      if (isLoginFinalize(message)) this.handleLoginFinalizeMessage(message)
      if (isSignRequest(message)) this.handleSignRequestMessage(message)
      if (isEcdhRequest(message)) this.handleEcdhRequestMessage(message)
    })
  }

  async handleRegisterRequest({payload, event}: WithEvent<RegisterRequestMessage>) {
    const client = event.pubkey
    const {group, share} = payload
    const channel = this.rpc.channel(client)
    const cb = (status: Status, message: string) =>
      channel.send(makeRegisterResult({status, message, prev: event.id}))

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
    if (await this.registrations.has(client)) return cb(Status.Error, "Client key has already been used.")

    await this.registrations.set(client, {client, event, share, group})

    return cb(Status.Ok, "Your key has been registered")
  }

  async handleSetEmailRequestMessage({payload, event}: WithEvent<SetEmailRequestMessage>) {
    const client = event.pubkey
    const registration = await this.registrations.get(client)
    const {email_hash, email_service, email_ciphertext} = payload

    if (registration) {
      const otp = generateOTP()
      const total = registration.group.commits.length

      await this.challenges.set(client, {otp, email_hash, email_service, email_ciphertext})

      this.rpc.channel(email_service).send(
        makeSetEmailChallenge({otp, total, client, email_ciphertext}),
      )
    }

    // Always show success so attackers can't get information on who is registered
    this.rpc.channel(client).send(
      makeSetEmailRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleSetEmailFinalizeMessage({payload, event}: WithEvent<SetEmailFinalizeMessage>) {
    const client = event.pubkey
    const challenge = await this.challenges.get(client)
    const registration = await this.registrations.get(client)

    if (registration && challenge?.email_hash === payload.email_hash && challenge?.otp === payload.otp) {
      await this.registrations.set(client, {
        ...registration,
        email_hash: challenge.email_hash,
        email_service: challenge.email_service,
        email_ciphertext: challenge.email_ciphertext,
      })

      this.rpc.channel(client).send(
        makeSetEmailFinalizeResult({
          status: Status.Ok,
          message: "Email successfully verified and associated with your account",
          prev: event.id,
        }),
      )
    } else {
      this.rpc.channel(client).send(
        makeSetEmailFinalizeResult({
          status: Status.Error,
          message: `Failed to validate challenge. Please request a new one to try again.`,
          prev: event.id,
        }),
      )
    }
  }

  async handleLoginRequestMessage({payload, event}: WithEvent<LoginRequestMessage>) {
    const client = event.pubkey
    const {email_hash, pubkey} = payload
    const pubkeys = new Set<string>()
    const registrations: SignerRegistration[] = []
    for (const [_, reg] of await this.registrations.entries()) {
      if (reg.email_hash !== email_hash) continue
      if (pubkey && reg.group.group_pk !== pubkey) continue

      registrations.push(reg)
      pubkeys.add(reg.group.group_pk)
    }

    if (pubkeys.size > 1) {
      this.rpc.channel(client).send(
        makeLoginRequestResult({
          status: Status.Pending,
          message: "Multiple pubkeys are associated with this email. Please select one to continue.",
          prev: event.id,
        })
      )
    } else if (registrations.length > 0) {
      const otp = generateOTP()
      const [registration] = registrations
      const total = registration.group.commits.length

      await this.logins.set(client, {otp, email_hash, copy_from: registration.client})

      this.rpc.channel(registration.email_service!).send(
        makeLoginChallenge({
          otp,
          total,
          client: registration.client,
          email_ciphertext: registration.email_ciphertext!,
        }),
      )
    }

    // Always show success (if we can) so attackers can't get information on who is registered
    this.rpc.channel(client).send(
      makeLoginRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleLoginFinalizeMessage({payload, event}: WithEvent<LoginFinalizeMessage>) {
    const client = event.pubkey
    const login = await this.logins.get(client)
    const registration = login ? await this.registrations.get(login.copy_from) : undefined

    if (registration && login?.email_hash === payload.email_hash && login?.otp === payload.otp) {
      await this.registrations.set(client, {...registration, event})

      this.rpc.channel(client).send(
        makeLoginFinalizeResult({
          status: Status.Ok,
          message: "Email successfully verified and associated with your account",
          group: registration.group,
          prev: event.id,
        }),
      )
    } else {
      this.rpc.channel(client).send(
        makeLoginFinalizeResult({
          status: Status.Error,
          message: `Failed to validate challenge. Please request a new one to try again.`,
          prev: event.id,
        }),
      )
    }
  }

  async handleSignRequestMessage({payload, event}: WithEvent<SignRequestMessage>) {
    const channel = this.rpc.channel(event.pubkey)
    const registration = await this.registrations.get(event.pubkey)

    if (!registration) {
      return channel.send(
        makeSignResult({
          status: Status.Error,
          message: "No registration found for client",
          prev: event.id,
        }),
      )
    }

    const {session} = payload
    const ctx = Lib.get_session_ctx(registration.group, session)
    const partialSignature = Lib.create_psig_pkg(ctx, registration.share)

    channel.send(
      makeSignResult({
        result: partialSignature,
        status: Status.Ok,
        message: "Successfully signed event",
        prev: event.id,
      }),
    )
  }

  async handleEcdhRequestMessage({payload, event}: WithEvent<EcdhRequestMessage>) {
    const channel = this.rpc.channel(event.pubkey)
    const registration = await this.registrations.get(event.pubkey)

    if (!registration) {
      return channel.send(
        makeSignResult({
          status: Status.Error,
          message: "No registration found for client",
          prev: event.id,
        }),
      )
    }

    const {members, ecdh_pk} = payload
    const ecdhPackage = Lib.create_ecdh_pkg(members, ecdh_pk, registration.share)

    channel.send(
      makeEcdhResult({
        result: ecdhPackage,
        status: Status.Ok,
        message: "Successfully signed event",
        prev: event.id,
      }),
    )
  }
}
