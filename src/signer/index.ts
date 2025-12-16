import {Lib} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {now, groupBy, first, sortBy, textEncoder, map, sha256, spec, call, int, ago, MINUTE, YEAR} from "@welshman/lib"
import {getPubkey, verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent, SignedEvent} from "@welshman/util"
import {
  RPC,
  Status,
  makeSessionListResult,
  makeRegisterResult,
  makeSetEmailRequestResult,
  makeSetEmailFinalizeResult,
  makeSetEmailChallenge,
  isSessionListRequest,
  isRegisterRequest,
  isSignRequest,
  isEcdhRequest,
  isRecoverRequest,
  isRecoverFinalize,
  isSetEmailRequest,
  isSetEmailFinalize,
  isLogoutRequest,
  makeSignResult,
  makeEcdhResult,
  makeRecoverChallenge,
  makeRecoverRequestResult,
  makeRecoverFinalizeResult,
  makeLogoutResult,
  generateOTP,
  Method,
} from "../lib/index.js"
import type {
  SessionListRequest,
  IStorageFactory,
  IStorage,
  SessionListResult,
  RegisterRequest,
  SignRequest,
  SetEmailRequest,
  SetEmailFinalize,
  EcdhRequest,
  RecoverRequest,
  RecoverFinalize,
  LogoutRequest,
  WithEvent,
} from "../lib/index.js"

export type Session = {
  client: string
  share: SharePackage
  group: GroupPackage
  event: TrustedEvent
  last_activity: number
  email?: string
  email_service?: string
}

export type Validation = {
  otp: string
  email: string
  email_service: string
  event: TrustedEvent
}

export type RecoverItem = {
  otp: string
  client: string
}

export type Recover = {
  email: string
  event: TrustedEvent
  items: RecoverItem[]
}

export type SignerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
}

export class Signer {
  rpc: RPC
  pubkey: string
  sessions: IStorage<Session>
  validations: IStorage<Validation>
  recovers: IStorage<Recover>
  unsubscribe: () => void
  intervals: number[]

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.sessions = options.storage("sessions")
    this.validations = options.storage("validations")
    this.recovers = options.storage("recovers")
    this.rpc = new RPC(options.secret, options.relays)
    this.unsubscribe = this.rpc.subscribe(message => {
      if (isRegisterRequest(message)) this.handleRegisterRequest(message)
      if (isSetEmailRequest(message)) this.handleSetEmailRequest(message)
      if (isSetEmailFinalize(message)) this.handleSetEmailFinalize(message)
      if (isRecoverRequest(message)) this.handleRecoverRequest(message)
      if (isRecoverFinalize(message)) this.handleRecoverFinalize(message)
      if (isSignRequest(message)) this.handleSignRequest(message)
      if (isEcdhRequest(message)) this.handleEcdhRequest(message)
      if (isSessionListRequest(message)) this.handleSessionListRequest(message)
      if (isLogoutRequest(message)) this.handleLogoutRequest(message)
    })

    // Periodically clean up recover requests
    this.intervals = [
      setInterval(
        async () => {
          for (const [k, recover] of await this.recovers.entries()) {
            if (recover.event.created_at < ago(15, MINUTE)) await this.recovers.delete(k)
          }
        },
        int(5, MINUTE),
      ) as unknown as number,
    ]

    // Immediately clean up old sessions/validations
    call(async () => {
      for (const [k, session] of await this.sessions.entries()) {
        if (session.last_activity < ago(YEAR)) await this.sessions.delete(k)
      }

      for (const [k, validation] of await this.validations.entries()) {
        if (validation.event.created_at < ago(YEAR)) await this.validations.delete(k)
      }
    })
  }

  stop() {
    this.unsubscribe()
    this.intervals.forEach(clearInterval)
  }

  _isAuthValid(auth: SignedEvent, method: Method) {
    return (
      verifyEvent(auth) &&
      auth.kind === HTTP_AUTH &&
      auth.created_at > ago(15) &&
      auth.created_at < now() + 5 &&
      getTagValue("u", auth.tags) === this.pubkey &&
      getTagValue("method", auth.tags) === method
    )
  }

  async handleRegisterRequest({payload, event}: WithEvent<RegisterRequest>) {
    const client = event.pubkey
    const {group, share} = payload
    const cb = (status: Status, message: string) =>
      this.rpc.channel(client).send(makeRegisterResult({status, message, prev: event.id}))

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
    if (await this.sessions.has(client)) return cb(Status.Error, "Client is already registered.")

    await this.sessions.set(client, {client, event, share, group, last_activity: now()})

    return cb(Status.Ok, "Your key has been registered")
  }

  async handleSetEmailRequest({payload, event}: WithEvent<SetEmailRequest>) {
    const client = event.pubkey
    const session = await this.sessions.get(client)
    const {email, email_service, callback_url} = payload

    if (!session) {
      return this.rpc.channel(client).send(
        makeSetEmailRequestResult({
          status: Status.Error,
          message: "No session found for client.",
          prev: event.id,
        }),
      )
    }

    // email has to be bound at (or shorly after) session, otherwise an attacker with access
    // to any session could escalate permissions by recovering the secret key to their own email
    if (session.event.created_at < ago(5, MINUTE)) {
      return this.rpc.channel(client).send(
        makeSetEmailRequestResult({
          status: Status.Error,
          message: "Email must be set within 5 minutes of session.",
          prev: event.id,
        }),
      )
    }

    const otp = generateOTP()
    const pubkey = session.group.group_pk.slice(2)
    const threshold = session.group.commits.length

    await this.validations.set(client, {otp, email, email_service, event})

    this.rpc.channel(email_service)
      .send(makeSetEmailChallenge({otp, email, pubkey, threshold, callback_url}))

    this.rpc.channel(client).send(
      makeSetEmailRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleSetEmailFinalize({payload, event}: WithEvent<SetEmailFinalize>) {
    return this.sessions.tx(async sessions => {
      const client = event.pubkey
      const session = await sessions.get(client)
      const challenge = await this.validations.get(client)

      if (session && challenge?.otp === payload.otp && challenge?.email === payload.email) {
        await sessions.set(client, {
          ...session,
          last_activity: now(),
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
    })
  }

  async handleRecoverRequest({payload, event}: WithEvent<RecoverRequest>) {
    const {email, pubkey, callback_url} = payload

    // Pick the most recently active session to log into for each associated pubkey
    const sessionsByPubkey = groupBy(
      s => s.group.group_pk.slice(2),
      map(s => s[1], await this.sessions.entries())
        .filter(s => s.email == email && (!pubkey || s.group.group_pk.slice(2) === pubkey))
    )

    const items: RecoverItem[] = []
    for (const [pubkey, sessions] of sessionsByPubkey) {
      const otp = generateOTP()
      const session = first(sortBy(s => -s.last_activity, sessions))!
      const threshold = session.group.threshold

      items.push({client: session.client, otp})

      this.rpc
        .channel(session.email_service!)
        .send(makeRecoverChallenge({otp, email, pubkey, threshold, callback_url}))
    }

    await this.recovers.set(event.pubkey, {email, event, items})

    // Always show success so attackers can't get information on who is registered
    this.rpc.channel(event.pubkey).send(
      makeRecoverRequestResult({
        status: Status.Ok,
        message: "Verification email sent. Please check your email to continue.",
        prev: event.id,
      }),
    )
  }

  async handleRecoverFinalize({payload, event}: WithEvent<RecoverFinalize>) {
    return this.sessions.tx(async sessions => {
      const recover = await this.recovers.get(event.pubkey)

      for (const item of recover?.items || []) {
        if (item.otp !== payload.otp) continue

        const session = await sessions.get(item.client)

        if (session?.email !== payload.email) continue

        return this.rpc.channel(event.pubkey).send(
          makeRecoverFinalizeResult({
            status: Status.Ok,
            message: "Recovery successfully completed.",
            group: session.group,
            share: session.share,
            prev: event.id,
          }),
        )
      }

      this.rpc.channel(event.pubkey).send(
        makeRecoverFinalizeResult({
          status: Status.Error,
          message: `Failed to validate your request. Please try again.`,
          prev: event.id,
        }),
      )
    })
  }

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
    return this.sessions.tx(async sessions => {
      const session = await sessions.get(event.pubkey)

      if (!session) {
        return this.rpc.channel(event.pubkey).send(
          makeSignResult({
            status: Status.Error,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      const ctx = Lib.get_session_ctx(session.group, payload.session)
      const partialSignature = Lib.create_psig_pkg(ctx, session.share)

      await sessions.set(event.pubkey, {...session, last_activity: now()})

      this.rpc.channel(event.pubkey).send(
        makeSignResult({
          result: partialSignature,
          status: Status.Ok,
          message: "Successfully signed event",
          prev: event.id,
        }),
      )
    })
  }

  async handleEcdhRequest({payload, event}: WithEvent<EcdhRequest>) {
    return this.sessions.tx(async sessions => {
      const session = await sessions.get(event.pubkey)

      if (!session) {
        return this.rpc.channel(event.pubkey).send(
          makeSignResult({
            status: Status.Error,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      const {members, ecdh_pk} = payload
      const ecdhPackage = Lib.create_ecdh_pkg(members, ecdh_pk, session.share)

      await sessions.set(event.pubkey, {...session, last_activity: now()})

      this.rpc.channel(event.pubkey).send(
        makeEcdhResult({
          result: ecdhPackage,
          status: Status.Ok,
          message: "Successfully signed event",
          prev: event.id,
        }),
      )
    })
  }

  async handleSessionListRequest({payload, event}: WithEvent<SessionListRequest>) {
    if (!this._isAuthValid(payload.auth, Method.SessionListRequest)) {
      return this.rpc.channel(event.pubkey).send(
        makeSessionListResult({
          sessions: [],
          status: Status.Error,
          message: "Failed to validate authentication.",
          prev: event.id,
        }),
      )
    }

    const sessions: SessionListResult["payload"]["sessions"] = []
    for (const [_, session] of await this.sessions.entries()) {
      if (session.group.group_pk.slice(2) === payload.auth.pubkey) {
        sessions.push({
          email: session.email,
          client: session.client,
          created_at: session.event.created_at,
          last_activity: session.last_activity,
        })
      }
    }

    this.rpc.channel(event.pubkey).send(
      makeSessionListResult({
        sessions,
        status: Status.Ok,
        message: "Successfully retrieved client list.",
        prev: event.id,
      }),
    )
  }

  async handleLogoutRequest({payload, event}: WithEvent<LogoutRequest>) {
    if (!this._isAuthValid(payload.auth, Method.LogoutRequest)) {
      return this.rpc.channel(event.pubkey).send(
        makeLogoutResult({
          status: Status.Error,
          message: "Failed to logout selected client.",
          prev: event.id,
        }),
      )
    }

    return this.sessions.tx(async sessions => {
      const session = await sessions.get(payload.client)

      if (session?.group.group_pk.slice(2) === payload.auth.pubkey) {
        await sessions.delete(payload.client)

        this.rpc.channel(event.pubkey).send(
          makeLogoutResult({
            status: Status.Ok,
            message: "Successfully logout selected client.",
            prev: event.id,
          }),
        )
      } else {
        return this.rpc.channel(event.pubkey).send(
          makeLogoutResult({
            status: Status.Error,
            message: "Failed to logout selected client.",
            prev: event.id,
          }),
        )
      }
    })
  }
}
