import {Lib} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {now, ago, MINUTE} from "@welshman/lib"
import {getPubkey, verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  makeClientListResult,
  makeRegisterResult,
  makeSetEmailRequestResult,
  makeSetEmailFinalizeResult,
  makeSetEmailChallenge,
  isClientListRequest,
  isRegisterRequest,
  isSignRequest,
  isEcdhRequest,
  isLoginRequest,
  isLoginFinalize,
  isRecoverRequest,
  isRecoverFinalize,
  isSetEmailRequest,
  isSetEmailFinalize,
  isUnregisterRequest,
  makeSignResult,
  makeEcdhResult,
  makeLoginChallenge,
  makeLoginRequestResult,
  makeLoginFinalizeResult,
  makeRecoverChallenge,
  makeRecoverRequestResult,
  makeRecoverFinalizeResult,
  makeUnregisterResult,
  generateOTP,
  Method,
} from "../lib/index.js"
import type {
  ClientListRequest,
  IStorageFactory,
  IStorage,
  ClientListResult,
  RegisterRequest,
  SignRequest,
  SetEmailRequest,
  SetEmailFinalize,
  EcdhRequest,
  LoginRequest,
  LoginFinalize,
  RecoverRequest,
  RecoverFinalize,
  UnregisterRequest,
  WithEvent,
} from "../lib/index.js"

export type SignerRegistration = {
  client: string
  share: SharePackage
  group: GroupPackage
  event: TrustedEvent
  last_activity: number
  email?: string
  email_service?: string
}

export type EmailChallenge = {
  otp: string
  email: string
  email_service: string
}

export type Login = {
  otp: string
  email: string
  copy_from: string
}

export type Recover = {
  otp: string
  email: string
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
  logins: IStorage<Login>
  recovers: IStorage<Recover>
  stop: () => void

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.registrations = options.storage("registrations")
    this.challenges = options.storage("challenges")
    this.logins = options.storage("logins")
    this.recovers = options.storage("recovers")
    this.rpc = new RPC(options.secret, options.relays)
    this.stop = this.rpc.subscribe(message => {
      if (isRegisterRequest(message)) this.handleRegisterRequest(message)
      if (isSetEmailRequest(message)) this.handleSetEmailRequest(message)
      if (isSetEmailFinalize(message)) this.handleSetEmailFinalize(message)
      if (isLoginRequest(message)) this.handleLoginRequest(message)
      if (isLoginFinalize(message)) this.handleLoginFinalize(message)
      if (isRecoverRequest(message)) this.handleRecoverRequest(message)
      if (isRecoverFinalize(message)) this.handleRecoverFinalize(message)
      if (isSignRequest(message)) this.handleSignRequest(message)
      if (isEcdhRequest(message)) this.handleEcdhRequest(message)
      if (isClientListRequest(message)) this.handleClientListRequest(message)
      if (isUnregisterRequest(message)) this.handleUnregisterRequest(message)
    })
  }

  async handleRegisterRequest({payload, event}: WithEvent<RegisterRequest>) {
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
    if (await this.registrations.has(client)) return cb(Status.Error, "Client is already registered.")

    await this.registrations.set(client, {client, event, share, group, last_activity: now()})

    return cb(Status.Ok, "Your key has been registered")
  }

  async handleSetEmailRequest({payload, event}: WithEvent<SetEmailRequest>) {
    const client = event.pubkey
    const registration = await this.registrations.get(client)
    const {email, email_service} = payload

    if (!registration) {
      return this.rpc.channel(client).send(
        makeSetEmailRequestResult({
          status: Status.Error,
          message: "No registration found for client.",
          prev: event.id,
        }),
      )
    }

    // email has to be bound at (or shorly after) registration, otherwise an attacker with access
    // to any session could escalate permissions by recovering the secret key to their own email
    if (registration.event.created_at < ago(5, MINUTE)) {
      return this.rpc.channel(client).send(
        makeSetEmailRequestResult({
          status: Status.Error,
          message: "Email must be set within 5 minutes of registration.",
          prev: event.id,
        }),
      )
    }

    const otp = generateOTP()
    const total = registration.group.commits.length

    await this.challenges.set(client, {otp, email, email_service})

    this.rpc.channel(email_service).send(makeSetEmailChallenge({otp, total, email, client}))

    this.rpc.channel(client).send(
      makeSetEmailRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleSetEmailFinalize({payload, event}: WithEvent<SetEmailFinalize>) {
    const client = event.pubkey
    const challenge = await this.challenges.get(client)
    const registration = await this.registrations.get(client)

    if (registration && challenge?.otp === payload.otp && challenge?.email === payload.email) {
      await this.registrations.set(client, {
        ...registration,
        email: challenge.email,
        email_service: challenge.email_service,
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

  async handleLoginRequest({payload, event}: WithEvent<LoginRequest>) {
    const client = event.pubkey
    const {email, pubkey} = payload
    const pubkeys = new Set<string>()
    const registrations: SignerRegistration[] = []
    for (const [_, reg] of await this.registrations.entries()) {
      if (reg.email !== email) continue
      if (pubkey && reg.group.group_pk !== pubkey) continue

      registrations.push(reg)
      pubkeys.add(reg.group.group_pk.slice(2))
    }

    if (pubkeys.size > 1) {
      this.rpc.channel(client).send(
        makeLoginRequestResult({
          status: Status.Pending,
          message:
            "Multiple pubkeys are associated with this email. Please select one to continue.",
          options: Array.from(pubkeys),
          prev: event.id,
        }),
      )
    } else if (registrations.length > 0) {
      const otp = generateOTP()
      const [registration] = registrations
      const total = registration.group.commits.length

      await this.logins.set(client, {otp, email, copy_from: registration.client})

      this.rpc
        .channel(registration.email_service!)
        .send(makeLoginChallenge({otp, total, client, email: registration.email!}))
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

  async handleLoginFinalize({payload, event}: WithEvent<LoginFinalize>) {
    const client = event.pubkey
    const login = await this.logins.get(client)
    const registration = login ? await this.registrations.get(login.copy_from) : undefined

    if (registration && login?.email === payload.email && login?.otp === payload.otp) {
      await this.registrations.set(client, {...registration, event, last_activity: now()})

      this.rpc.channel(client).send(
        makeLoginFinalizeResult({
          status: Status.Ok,
          message: "Login successfully completed.",
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

  async handleRecoverRequest({payload, event}: WithEvent<RecoverRequest>) {
    const client = event.pubkey
    const {email, pubkey} = payload
    const pubkeys = new Set<string>()
    const registrations: SignerRegistration[] = []
    for (const [_, reg] of await this.registrations.entries()) {
      if (reg.email !== email) continue
      if (pubkey && reg.group.group_pk !== pubkey) continue

      registrations.push(reg)
      pubkeys.add(reg.group.group_pk.slice(2))
    }

    if (pubkeys.size > 1) {
      this.rpc.channel(client).send(
        makeRecoverRequestResult({
          status: Status.Pending,
          message:
            "Multiple pubkeys are associated with this email. Please select one to continue.",
          options: Array.from(pubkeys),
          prev: event.id,
        }),
      )
    } else if (registrations.length > 0) {
      const otp = generateOTP()
      const [registration] = registrations
      const total = registration.group.commits.length

      await this.recovers.set(client, {otp, email, copy_from: registration.client})

      this.rpc
        .channel(registration.email_service!)
        .send(makeRecoverChallenge({otp, total, client, email: registration.email!}))
    }

    // Always show success (if we can) so attackers can't get information on who is registered
    this.rpc.channel(client).send(
      makeRecoverRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleRecoverFinalize({payload, event}: WithEvent<RecoverFinalize>) {
    const client = event.pubkey
    const recover = await this.recovers.get(client)
    const registration = recover ? await this.registrations.get(recover.copy_from) : undefined

    if (registration && recover?.otp === payload.otp && recover?.email === payload.email) {
      await this.registrations.set(client, {...registration, event, last_activity: now()})

      this.rpc.channel(client).send(
        makeRecoverFinalizeResult({
          status: Status.Ok,
          message: "Recovery successfully completed.",
          group: registration.group,
          share: registration.share,
          prev: event.id,
        }),
      )
    } else {
      this.rpc.channel(client).send(
        makeRecoverFinalizeResult({
          status: Status.Error,
          message: `Failed to validate challenge. Please request a new one to try again.`,
          prev: event.id,
        }),
      )
    }
  }

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
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

  async handleEcdhRequest({payload, event}: WithEvent<EcdhRequest>) {
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

  async handleClientListRequest({payload, event}: WithEvent<ClientListRequest>) {
    const channel = this.rpc.channel(event.pubkey)
    if (
      !verifyEvent(payload.auth) ||
      payload.auth.kind !== HTTP_AUTH ||
      getTagValue("u", payload.auth.tags) !== this.pubkey ||
      getTagValue("method", payload.auth.tags) !== Method.ClientListRequest
    ) {
      return channel.send(
        makeClientListResult({
          clients: [],
          status: Status.Error,
          message: "Failed to validate authentication.",
          prev: event.id,
        }),
      )
    }

    const clients: ClientListResult["payload"]["clients"] = []
    for (const [_, reg] of await this.registrations.entries()) {
      if (reg.group.group_pk.slice(2) === payload.auth.pubkey) {
        clients.push({
          email: reg.email,
          client: reg.client,
          created_at: reg.event.created_at,
          last_activity: reg.last_activity,
        })
      }
    }

    channel.send(
      makeClientListResult({
        clients,
        status: Status.Ok,
        message: "Successfully retrieved client list.",
        prev: event.id,
      }),
    )
  }

  async handleUnregisterRequest({payload, event}: WithEvent<UnregisterRequest>) {
    const channel = this.rpc.channel(event.pubkey)

    if (
      !verifyEvent(payload.auth) ||
      payload.auth.kind !== HTTP_AUTH ||
      getTagValue("u", payload.auth.tags) !== this.pubkey ||
      getTagValue("method", payload.auth.tags) !== Method.UnregisterRequest
    ) {
      return channel.send(
        makeUnregisterResult({
          status: Status.Error,
          message: "Failed to unregister selected client.",
          prev: event.id,
        }),
      )
    }

    const registration = await this.registrations.get(payload.client)

    if (registration?.group.group_pk.slice(2) === payload.auth.pubkey) {
      await this.registrations.delete(payload.client)

      channel.send(
        makeUnregisterResult({
          status: Status.Ok,
          message: "Successfully unregister selected client.",
          prev: event.id,
        }),
      )
    } else {
      return channel.send(
        makeUnregisterResult({
          status: Status.Error,
          message: "Failed to unregister selected client.",
          prev: event.id,
        }),
      )
    }
  }
}
