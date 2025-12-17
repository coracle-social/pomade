import {Lib} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {now, groupBy, map, call, int, ago, MINUTE, YEAR} from "@welshman/lib"
import {getPubkey, verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent, SignedEvent} from "@welshman/util"
import {
  RPC,
  makeSessionListResult,
  makeRegisterResult,
  makeRecoveryMethodSetResult,
  makeRecoveryMethodFinalizeResult,
  makeRecoveryMethodChallenge,
  isSessionList,
  isRegisterRequest,
  isSignRequest,
  isEcdhRequest,
  isRecoveryStart,
  isRecoveryFinalize,
  isRecoveryMethodSet,
  isRecoveryMethodFinalize,
  isSessionDelete,
  makeSignResult,
  makeEcdhResult,
  makeRecoveryChallenge,
  makeRecoveryStartResult,
  makeRecoveryFinalizeResult,
  makeSessionDeleteResult,
  generateOTP,
  Method,
} from "../lib/index.js"
import type {
  SessionList,
  IStorageFactory,
  IStorage,
  SessionListResult,
  RecoveryChallenge,
  RegisterRequest,
  SignRequest,
  RecoveryMethodSet,
  RecoveryMethodFinalize,
  EcdhRequest,
  RecoveryStart,
  RecoveryFinalize,
  SessionDelete,
  WithEvent,
} from "../lib/index.js"

export type Session = {
  client: string
  share: SharePackage
  group: GroupPackage
  recovery: boolean
  event: TrustedEvent
  last_activity: number
  inbox?: string
  mailer?: string
}

export type Validation = {
  otp: string
  inbox: string
  mailer: string
  event: TrustedEvent
}

export type RecoverOption = {
  otp: string
  client: string
  threshold: number
}

export type Recover = {
  inbox: string
  event: TrustedEvent
  items: RecoverOption[]
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
      if (isRecoveryMethodSet(message)) this.handleRecoveryMethodSet(message)
      if (isRecoveryMethodFinalize(message)) this.handleRecoveryMethodFinalize(message)
      if (isRecoveryStart(message)) this.handleRecoveryStart(message)
      if (isRecoveryFinalize(message)) this.handleRecoveryFinalize(message)
      if (isSignRequest(message)) this.handleSignRequest(message)
      if (isEcdhRequest(message)) this.handleEcdhRequest(message)
      if (isSessionList(message)) this.handleSessionList(message)
      if (isSessionDelete(message)) this.handleSessionDelete(message)
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
    const {group, share, recovery} = payload
    const cb = (ok: boolean, message: string) =>
      this.rpc.channel(client).send(makeRegisterResult({ok, message, prev: event.id}))

    if (!share) return cb(false, `Failed to deserialize share package.`)
    if (!group) return cb(false, `Failed to deserialize group package.`)

    const isMember = Lib.is_group_member(group, share)

    if (!isMember) return cb(false, "Share does not belong to the provided group.")
    if (group.threshold <= 0) return cb(false, "Group threshold must be greater than zero.")
    if (group.threshold > group.commits.length) return cb(false, "Invalid group threshold.")

    const indices = new Set(group.commits.map(c => c.idx))
    const commit = group.commits.find(c => c.idx === share.idx)

    if (indices.size !== group.commits.length)
      return cb(false, "Group contains duplicate member indices.")
    if (!commit) return cb(false, "Share index not found in group commits.")
    if (await this.sessions.has(client)) return cb(false, "Client is already registered.")

    await this.sessions.set(client, {client, event, share, group, recovery, last_activity: now()})

    return cb(true, "Your key has been registered")
  }

  async handleRecoveryMethodSet({payload, event}: WithEvent<RecoveryMethodSet>) {
    const client = event.pubkey
    const session = await this.sessions.get(client)
    const {inbox, mailer, callback_url} = payload

    if (!session) {
      return this.rpc.channel(client).send(
        makeRecoveryMethodSetResult({
          ok: false,
          message: "No session found for client.",
          prev: event.id,
        }),
      )
    }

    if (!session.recovery) {
      return this.rpc.channel(client).send(
        makeRecoveryMethodSetResult({
          ok: false,
          message: "Recovery is disabled on this session.",
          prev: event.id,
        }),
      )
    }

    // recovery method has to be bound at (or shorly after) session, otherwise an attacker with access
    // to any session could escalate permissions by setting up their own recovery method
    if (session.event.created_at < ago(5, MINUTE)) {
      return this.rpc.channel(client).send(
        makeRecoveryMethodSetResult({
          ok: false,
          message: "Recovery method must be set within 5 minutes of session.",
          prev: event.id,
        }),
      )
    }

    const otp = generateOTP()
    const pubkey = session.group.group_pk.slice(2)
    const threshold = session.group.commits.length

    await this.validations.set(client, {otp, inbox, mailer, event})

    this.rpc
      .channel(mailer)
      .send(makeRecoveryMethodChallenge({otp, client, inbox, pubkey, threshold, callback_url}))

    this.rpc.channel(client).send(
      makeRecoveryMethodSetResult({
        ok: true,
        message: "Verification sent. Please check your recovery method to continue.",
        prev: event.id,
      }),
    )
  }

  async handleRecoveryMethodFinalize({payload, event}: WithEvent<RecoveryMethodFinalize>) {
    return this.sessions.tx(async sessions => {
      const session = await sessions.get(event.pubkey)
      const challenge = await this.validations.get(event.pubkey)

      if (session && challenge?.otp === payload.otp) {
        await sessions.set(event.pubkey, {
          ...session,
          last_activity: now(),
          inbox: challenge.inbox,
          mailer: challenge.mailer,
        })

        this.rpc.channel(event.pubkey).send(
          makeRecoveryMethodFinalizeResult({
            ok: true,
            message: "Recovery method successfully verified and associated with your account",
            prev: event.id,
          }),
        )
      } else {
        this.rpc.channel(event.pubkey).send(
          makeRecoveryMethodFinalizeResult({
            ok: false,
            message: `Failed to validate challenge. Please request a new one to try again.`,
            prev: event.id,
          }),
        )
      }

      await this.validations.delete(event.pubkey)
    })
  }

  async handleRecoveryStart({payload, event}: WithEvent<RecoveryStart>) {
    const {inbox, pubkey, callback_url} = payload

    const sessions = map(s => s[1], await this.sessions.entries()).filter(
      s => s.mailer && s.inbox == inbox && (!pubkey || s.group.group_pk.slice(2) === pubkey),
    )

    const sessionsByPubkey = groupBy(s => s.group.group_pk.slice(2), sessions)

    const allItems: RecoveryChallenge["payload"]["items"] = []
    for (const [pubkey, pubkeySessions] of sessionsByPubkey) {
      const sessionsByMailer = groupBy(s => s.mailer, pubkeySessions)

      for (const [mailer, mailerSessions] of sessionsByMailer) {
        const items = mailerSessions.map(s => ({
          otp: generateOTP(),
          threshold: s.group.threshold,
          client: s.client,
        }))

        allItems.push(...items)

        this.rpc.channel(mailer!).send(makeRecoveryChallenge({inbox, pubkey, items, callback_url}))
      }
    }

    await this.recovers.set(event.pubkey, {inbox, event, items: allItems})

    // Always show success so attackers can't get information on who is registered
    this.rpc.channel(event.pubkey).send(
      makeRecoveryStartResult({
        ok: true,
        message: "Verification sent. Please check your inbox to continue.",
        prev: event.id,
      }),
    )
  }

  async handleRecoveryFinalize({payload, event}: WithEvent<RecoveryFinalize>) {
    return this.sessions.tx(async sessions => {
      const recover = await this.recovers.get(event.pubkey)

      for (const item of recover?.items || []) {
        if (item.otp !== payload.otp) continue

        const session = await sessions.get(item.client)

        if (session) {
          return this.rpc.channel(event.pubkey).send(
            makeRecoveryFinalizeResult({
              ok: true,
              message: "Recovery successfully completed.",
              group: session.group,
              share: session.share,
              prev: event.id,
            }),
          )
        }
      }

      this.rpc.channel(event.pubkey).send(
        makeRecoveryFinalizeResult({
          ok: false,
          message: `Failed to validate your request. Please try again.`,
          prev: event.id,
        }),
      )

      await this.recovers.delete(event.pubkey)
    })
  }

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
    return this.sessions.tx(async sessions => {
      const session = await sessions.get(event.pubkey)

      if (!session) {
        return this.rpc.channel(event.pubkey).send(
          makeSignResult({
            ok: false,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      const ctx = Lib.get_session_ctx(session.group, payload.request)
      const partialSignature = Lib.create_psig_pkg(ctx, session.share)

      await sessions.set(event.pubkey, {...session, last_activity: now()})

      this.rpc.channel(event.pubkey).send(
        makeSignResult({
          result: partialSignature,
          ok: true,
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
            ok: false,
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
          ok: true,
          message: "Successfully signed event",
          prev: event.id,
        }),
      )
    })
  }

  async handleSessionList({payload, event}: WithEvent<SessionList>) {
    if (!this._isAuthValid(payload.auth, Method.SessionList)) {
      return this.rpc.channel(event.pubkey).send(
        makeSessionListResult({
          sessions: [],
          ok: false,
          message: "Failed to validate authentication.",
          prev: event.id,
        }),
      )
    }

    const sessions: SessionListResult["payload"]["sessions"] = []
    for (const [_, session] of await this.sessions.entries()) {
      if (session.group.group_pk.slice(2) === payload.auth.pubkey) {
        sessions.push({
          inbox: session.inbox,
          client: session.client,
          created_at: session.event.created_at,
          last_activity: session.last_activity,
        })
      }
    }

    this.rpc.channel(event.pubkey).send(
      makeSessionListResult({
        sessions,
        ok: true,
        message: "Successfully retrieved client list.",
        prev: event.id,
      }),
    )
  }

  async handleSessionDelete({payload, event}: WithEvent<SessionDelete>) {
    if (!this._isAuthValid(payload.auth, Method.SessionDelete)) {
      return this.rpc.channel(event.pubkey).send(
        makeSessionDeleteResult({
          ok: false,
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
          makeSessionDeleteResult({
            ok: true,
            message: "Successfully logout selected client.",
            prev: event.id,
          }),
        )
      } else {
        return this.rpc.channel(event.pubkey).send(
          makeSessionDeleteResult({
            ok: false,
            message: "Failed to logout selected client.",
            prev: event.id,
          }),
        )
      }
    })
  }
}
