import * as z from "zod"
import {Lib} from "@frostr/bifrost"
import {randomBytes} from "@noble/hashes/utils.js"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {
  now,
  filter,
  remove,
  removeUndefined,
  append,
  ms,
  uniq,
  between,
  call,
  int,
  ago,
  MINUTE,
  YEAR,
} from "@welshman/lib"
import {verifyEvent, getTagValue, getPow, HTTP_AUTH} from "@welshman/util"
import type {SignedEvent} from "@welshman/util"
import type {ISigner} from "@welshman/signer"
import {SessionItem, Auth, isPasswordAuth, isOTPAuth, Schema} from "./schema.js"
import {IStorage, ICollection} from "./storage.js"
import {hashEmail, debug, context} from "./util.js"
import {
  RegisterRequest,
  RegisterResponse,
  RecoverySetupRequest,
  RecoverySetupResponse,
  ChallengeRequest,
  ChallengeResponse,
  LoginStartRequest,
  LoginStartResponse,
  LoginSelectRequest,
  LoginSelectResponse,
  RecoveryStartRequest,
  RecoveryStartResponse,
  RecoverySelectRequest,
  RecoverySelectResponse,
  SessionListResponse,
  SessionDeleteRequest,
  SessionDeleteResponse,
  SignRequest,
  SignResponse,
  EcdhRequest,
  EcdhResponse,
} from "./message.js"
import {
  RateLimitBucket,
  RateLimitConfig,
  isRateLimited,
  recordAttempt,
  getRateLimitResetTime,
  cleanupRateLimits,
} from "./ratelimit.js"

const CLIENT_RATE_LIMITS: RateLimitConfig = {
  maxAttempts: 100,
  windowSeconds: int(1, MINUTE),
}

const EMAIL_RATE_LIMITS: RateLimitConfig = {
  maxAttempts: 5,
  windowSeconds: int(2, MINUTE),
}

type Handler<T, R> = (pubkey: SignedEvent, data: T) => Promise<R>

function randomInt(min: number, max: number): number {
  const bytes = randomBytes(4)
  const value = new DataView(bytes.buffer).getUint32(0)
  return min + (value % (max - min))
}

function makeSessionItem(session: SignerSession): SessionItem {
  return {
    pubkey: session.group.group_pk.slice(2),
    client: session.client,
    created_at: session.created_at,
    last_activity: session.last_activity,
    threshold: session.group.threshold,
    total: session.group.commits.length,
    idx: session.share.idx,
    email: session.email,
  }
}

export type SignerSession = {
  client: string
  share: SharePackage
  group: GroupPackage
  recovery: boolean
  created_at: number
  last_activity: number
  email?: string
  email_hash?: string
  password_hash?: string
}

export type SignerSessionIndex = {
  clients: string[]
}

export type SignerRecoverOption = {
  otp: string
  client: string
  threshold: number
}

export type SignerRecovery = {
  created_at: number
  clients: string[]
}

export type SignerLogin = {
  created_at: number
  clients: string[]
}

export type SignerChallenge = {
  created_at: number
  otp: string
}

export type ChallengePayload = {
  email: string
  otp: string
}

export type SignerOptions = {
  url: string
  signer: ISigner
  storage: IStorage
  sendChallenge: (payload: ChallengePayload) => Promise<void>
}

export class Signer {
  intervals: number[]
  logins: ICollection<SignerLogin>
  sessions: ICollection<SignerSession>
  recoveries: ICollection<SignerRecovery>
  challenges: ICollection<SignerChallenge>
  sessionsByEmailHash: ICollection<SignerSessionIndex>
  rateLimitByEmailHash: ICollection<RateLimitBucket>
  rateLimitByClient: ICollection<RateLimitBucket>

  constructor(private options: SignerOptions) {
    this.logins = options.storage.collection("logins")
    this.sessions = options.storage.collection("sessions")
    this.recoveries = options.storage.collection("recoveries")
    this.challenges = options.storage.collection("challenges")
    this.sessionsByEmailHash = options.storage.collection("sessionsByEmailHash")
    this.rateLimitByEmailHash = options.storage.collection("rateLimitByEmailHash")
    this.rateLimitByClient = options.storage.collection("rateLimitByClient")

    this.intervals = [
      setInterval(
        async () => {
          debug("[signer]: cleaning up logins, recoveries, and rate limits")

          for (const [client, recovery] of await this.recoveries.entries()) {
            if (recovery.created_at < ago(15, MINUTE)) await this.recoveries.delete(client)
          }

          for (const [client, login] of await this.logins.entries()) {
            if (login.created_at < ago(15, MINUTE)) await this.logins.delete(client)
          }

          for (const [client, challenge] of await this.challenges.entries()) {
            if (challenge.created_at < ago(15, MINUTE)) await this.challenges.delete(client)
          }

          await cleanupRateLimits(this.rateLimitByEmailHash, EMAIL_RATE_LIMITS.windowSeconds)

          await cleanupRateLimits(this.rateLimitByClient, CLIENT_RATE_LIMITS.windowSeconds)
        },
        ms(int(5, MINUTE)),
      ) as unknown as number,
    ]

    // Immediately clean up old sessions
    call(async () => {
      for (const [client, session] of await this.sessions.entries()) {
        if (session.last_activity < ago(YEAR)) await this.sessions.delete(client)
      }
    })
  }

  stop() {
    this.intervals.forEach(clearInterval)
  }

  // Internal utils

  _parseAuth(header?: string, path = "") {
    if (header?.startsWith("Nostr ")) {
      let auth: SignedEvent
      try {
        auth = JSON.parse(atob(header.slice(6)))
      } catch {
        return
      }

      if (
        verifyEvent(auth) &&
        auth.kind === HTTP_AUTH &&
        auth.created_at >= ago(15) &&
        auth.created_at <= now() + 5 &&
        getTagValue("u", auth.tags) === `${this.options.url}${path}` &&
        getTagValue("method", auth.tags) === "POST"
      ) {
        return auth
      }
    }
  }

  async _checkAndRecordRateLimit(client: string): Promise<boolean> {
    const bucket = await this.rateLimitByClient.get(client)

    if (isRateLimited(bucket, CLIENT_RATE_LIMITS)) {
      const resetTime = getRateLimitResetTime(bucket, CLIENT_RATE_LIMITS)
      debug(
        `[signer]: rate limit exceeded for client ${client.slice(0, 8)}, reset in ${resetTime}s`,
      )
      return false
    }

    const updatedBucket = recordAttempt(bucket, CLIENT_RATE_LIMITS)
    await this.rateLimitByClient.set(client, updatedBucket)
    return true
  }

  async _getAuthenticatedSessions(auth: Auth): Promise<SignerSession[]> {
    const bucket = await this.rateLimitByEmailHash.get(auth.email_hash)

    if (isRateLimited(bucket, EMAIL_RATE_LIMITS)) {
      const resetTime = getRateLimitResetTime(bucket, EMAIL_RATE_LIMITS)
      debug(
        `[signer]: rate limit exceeded for email_hash ${auth.email_hash.slice(0, 8)}, reset in ${resetTime}s`,
      )
      return []
    }

    const index = await this.sessionsByEmailHash.get(auth.email_hash)
    let sessions: SignerSession[] = []

    if (index) {
      if (isPasswordAuth(auth)) {
        sessions = filter(
          session => session?.password_hash === auth.password_hash,
          await Promise.all(index.clients.map(client => this.sessions.get(client))),
        ) as SignerSession[]
      }

      if (isOTPAuth(auth)) {
        const challenge = await this.challenges.get(auth.email_hash)

        if (challenge) {
          await this.challenges.delete(auth.email_hash)

          if (auth.otp === challenge.otp) {
            sessions = removeUndefined(
              await Promise.all(index.clients.map(client => this.sessions.get(client))),
            )
          }
        }
      }
    }

    if (sessions.length === 0) {
      await this.rateLimitByEmailHash.set(auth.email_hash, recordAttempt(bucket, EMAIL_RATE_LIMITS))
    }

    return sessions
  }

  async _checkKeyReuse(client: string): Promise<boolean> {
    if (await this.sessions.get(client)) {
      debug(`[client ${client.slice(0, 8)}]: session key re-used`)
      return true
    }

    if (await this.recoveries.get(client)) {
      debug(`[client ${client.slice(0, 8)}]: recovery key re-used`)
      return true
    }

    if (await this.logins.get(client)) {
      debug(`[client ${client.slice(0, 8)}]: login key re-used`)
      return true
    }

    return false
  }

  async _addSession(client: string, session: SignerSession) {
    await this.sessions.set(client, session)

    if (session.email_hash) {
      let index = await this.sessionsByEmailHash.get(session.email_hash)

      if (!index) {
        index = {clients: []}
      }

      await this.sessionsByEmailHash.set(session.email_hash, {
        clients: append(client, index.clients),
      })
    }
  }

  async _deleteSession(client: string) {
    const session = await this.sessions.get(client)

    if (session) {
      if (session.email_hash) {
        const index = await this.sessionsByEmailHash.get(session.email_hash)

        if (index) {
          const clients = remove(client, index.clients)

          if (clients.length === 0) {
            await this.sessionsByEmailHash.delete(session.email_hash)
          } else {
            await this.sessionsByEmailHash.set(session.email_hash, {clients})
          }
        }
      }

      await this.sessions.delete(client)
    }
  }

  // Handlers

  async _handleRegister(auth: SignedEvent, data: RegisterRequest): Promise<RegisterResponse> {
    return this.options.storage.tx(async () => {
      const {pubkey: client} = auth
      const {group, share, recovery} = data

      if (await this._checkKeyReuse(client)) {
        return {ok: false, message: "Do not re-use session keys."}
      }

      if (getPow(auth) < context.registerPow) {
        debug(`[client ${client.slice(0, 8)}]: insufficient proof of work`)
        return {ok: false, message: "Registration requires 20 bits of proof of work (NIP-13)."}
      }

      if (!between([0, group.commits.length], group.threshold)) {
        debug(`[client ${client.slice(0, 8)}]: invalid group threshold`)
        return {ok: false, message: "Invalid group threshold."}
      }

      if (!Lib.is_group_member(group, share)) {
        debug(`[client ${client.slice(0, 8)}]: share does not belong to the provided group`)
        return {ok: false, message: "Share does not belong to the provided group."}
      }

      if (uniq(group.commits.map(c => c.idx)).length !== group.commits.length) {
        debug(`[client ${client.slice(0, 8)}]: group contains duplicate member indices`)
        return {ok: false, message: "Group contains duplicate member indices."}
      }

      if (!group.commits.find(c => c.idx === share.idx)) {
        debug(`[client ${client.slice(0, 8)}]: share index not found in group commits`)
        return {ok: false, message: "Share index not found in group commits."}
      }

      if (await this.sessions.get(client)) {
        debug(`[client ${client.slice(0, 8)}]: client is already registered`)
        return {ok: false, message: "Client is already registered."}
      }

      await this._addSession(client, {
        client,
        share,
        group,
        recovery,
        created_at: now(),
        last_activity: now(),
      })

      debug(`[client ${client.slice(0, 8)}]: registered`)

      return {ok: true, message: "Your key has been registered"}
    })
  }

  async _handleRecoverySetup({pubkey: client}: SignedEvent, data: RecoverySetupRequest): Promise<RecoverySetupResponse> {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(client)

      if (!session) {
        debug(`[client ${client.slice(0, 8)}]: no session found for recovery setup`)
        return {ok: false, message: "No session found."}
      }

      if (!session.recovery) {
        debug(`[client ${client.slice(0, 8)}]: recovery is disabled for session`)
        return {ok: false, message: "Recovery is disabled on this session."}
      }

      if (session.created_at < ago(15, MINUTE)) {
        debug(`[client ${client.slice(0, 8)}]: recovery method set too late`)
        return {ok: false, message: "Recovery method must be set within 15 minutes of session."}
      }

      if (session.email) {
        debug(`[client ${client.slice(0, 8)}]: recovery is already set`)
        return {ok: false, message: "Recovery has already been initialized."}
      }

      if (!data.password_hash.match(/^[a-f0-9]{64}$/)) {
        debug(`[client ${client.slice(0, 8)}]: invalid password_hash provided on setup`)
        return {
          ok: false,
          message:
            "Recovery method password hash must be an argon2id hash of user email and password.",
        }
      }

      const {email, password_hash} = data
      const signerUrl = new URL(this.options.url).origin
      const email_hash = await hashEmail(email, signerUrl)

      await this._addSession(client, {
        ...session,
        last_activity: now(),
        email,
        email_hash,
        password_hash,
      })

      debug(`[client ${client.slice(0, 8)}]: recovery method initialized`)

      return {ok: true, message: "Recovery method successfully initialized."}
    })
  }

  async _handleChallenge(_auth: SignedEvent, data: ChallengeRequest): Promise<ChallengeResponse> {
    const bucket = await this.rateLimitByEmailHash.get(data.email_hash)

    if (isRateLimited(bucket, EMAIL_RATE_LIMITS)) {
      return {ok: true, message: "Please check your email inbox for a one-time password."}
    }

    const index = await this.sessionsByEmailHash.get(data.email_hash)

    if (index && index.clients.length > 0) {
      const session = await this.sessions.get(index.clients[0])

      if (session?.email) {
        await this.rateLimitByEmailHash.set(
          data.email_hash,
          recordAttempt(bucket, EMAIL_RATE_LIMITS),
        )

        const otp = data.prefix + randomInt(100000, 1000000).toString()

        await this.challenges.set(data.email_hash, {otp, created_at: now()})

        this.options.sendChallenge({email: session.email, otp})

        debug(`[challenge]: sent for ${data.email_hash}`)
      }
    } else {
      debug(`[challenge]: no session found for ${data.email_hash}`)
    }

    return {ok: true, message: "Please check your email inbox for a one-time password."}
  }

  async _handleRecoveryStart({pubkey: client}: SignedEvent, data: RecoveryStartRequest): Promise<RecoveryStartResponse> {
    return this.options.storage.tx(async () => {
      if (await this._checkKeyReuse(client)) {
        return {ok: false, message: "Do not re-use session keys."}
      }

      const sessions = await this._getAuthenticatedSessions(data.auth)

      if (sessions.length === 0) {
        debug(`[client ${client.slice(0, 8)}]: no sessions found for recovery`)
        return {ok: false, message: "No sessions found."}
      }

      debug(`[client ${client.slice(0, 8)}]: sending recovery options`)

      const clients = sessions.map(s => s.client)
      const items = sessions.map(makeSessionItem)

      await this.recoveries.set(client, {created_at: now(), clients})

      return {ok: true, message: "Successfully retrieved recovery options.", items}
    })
  }

  async _handleRecoverySelect({pubkey: client}: SignedEvent, data: RecoverySelectRequest): Promise<RecoverySelectResponse> {
    const recovery = await this.recoveries.get(client)

    if (!recovery) {
      debug(`[client ${client.slice(0, 8)}]: no active recovery found`)
      return {ok: false, message: "No active recovery found."}
    }

    await this.recoveries.delete(client)

    if (!recovery.clients.includes(data.client)) {
      debug(`[client ${client.slice(0, 8)}]: invalid session selected for recovery`)
      return {ok: false, message: "Invalid session selected for recovery."}
    }

    const session = await this.sessions.get(data.client)

    if (!session) {
      debug(`[client ${client.slice(0, 8)}]: recovery session not found`)
      return {ok: false, message: "Recovery session not found."}
    }

    debug(`[client ${client.slice(0, 8)}]: recovery successfully completed`)

    return {
      ok: true,
      message: "Recovery successfully completed.",
      group: session.group,
      share: session.share,
    }
  }

  async _handleLoginStart({pubkey: client}: SignedEvent, data: LoginStartRequest): Promise<LoginStartResponse> {
    return this.options.storage.tx(async () => {
      if (await this._checkKeyReuse(client)) {
        return {ok: false, message: "Do not re-use session keys."}
      }

      const sessions = await this._getAuthenticatedSessions(data.auth)

      if (sessions.length === 0) {
        debug(`[client ${client.slice(0, 8)}]: no sessions found for login`)
        return {ok: false, message: "No sessions found."}
      }

      debug(`[client ${client.slice(0, 8)}]: sending login options`)

      const clients = sessions.map(s => s.client)
      const items = sessions.map(makeSessionItem)

      await this.logins.set(client, {created_at: now(), clients})

      return {ok: true, message: "Successfully retrieved login options.", items}
    })
  }

  async _handleLoginSelect({pubkey: client}: SignedEvent, data: LoginSelectRequest): Promise<LoginSelectResponse> {
    const login = await this.logins.get(client)

    if (!login) {
      debug(`[client ${client.slice(0, 8)}]: no active login found`)
      return {ok: false, message: "No active login found."}
    }

    await this.logins.delete(client)

    if (!login.clients.includes(data.client)) {
      debug(`[client ${client.slice(0, 8)}]: invalid session selected for login`)
      return {ok: false, message: "Invalid session selected for login."}
    }

    const session = await this.sessions.get(data.client)

    if (!session) {
      debug(`[client ${client.slice(0, 8)}]: login session not found`)
      return {ok: false, message: "Login session not found."}
    }

    await this._addSession(client, {
      recovery: true,
      client,
      share: session.share,
      group: session.group,
      email: session.email,
      email_hash: session.email_hash,
      password_hash: session.password_hash,
      created_at: now(),
      last_activity: now(),
    })

    debug(`[client ${client.slice(0, 8)}]: login successfully completed`)

    return {ok: true, message: "Login successfully completed.", group: session.group}
  }

  async _handleSign({pubkey: client}: SignedEvent, data: SignRequest): Promise<SignResponse> {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(client)

      if (!session) {
        debug(`[client ${client.slice(0, 8)}]: signing failed - no session found`)
        return {ok: false, message: "No session found for client"}
      }

      const allowed = await this._checkAndRecordRateLimit(client)
      if (!allowed) {
        return {ok: false, message: "Rate limit exceeded. Please try again later."}
      }

      try {
        const ctx = Lib.get_session_ctx(session.group, data.request)
        const partialSignature = Lib.create_psig_pkg(ctx, session.share)

        await this.sessions.set(client, {...session, last_activity: now()})

        debug(`[client ${client.slice(0, 8)}]: signing complete`)

        return {result: partialSignature, ok: true, message: "Successfully signed event"}
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        debug(`[client ${client.slice(0, 8)}]: signing failed - ${msg}`)
        return {ok: false, message: "Failed to sign event"}
      }
    })
  }

  async _handleEcdh({pubkey: client}: SignedEvent, {members, ecdh_pk}: EcdhRequest): Promise<EcdhResponse> {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(client)

      if (!session) {
        debug(`[client ${client.slice(0, 8)}]: ecdh failed - no session found`)
        return {ok: false, message: "No session found for client"}
      }

      const allowed = await this._checkAndRecordRateLimit(client)
      if (!allowed) {
        return {ok: false, message: "Rate limit exceeded. Please try again later."}
      }

      try {
        const ecdhPackage = Lib.create_ecdh_pkg(members, ecdh_pk, session.share)

        await this.sessions.set(client, {...session, last_activity: now()})

        debug(`[client ${client.slice(0, 8)}]: ecdh complete`)

        return {result: ecdhPackage, ok: true, message: "Successfully derived shared secret"}
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        debug(`[client ${client.slice(0, 8)}]: ecdh failed - ${msg}`)
        return {ok: false, message: "Key derivation failed"}
      }
    })
  }

  async _handleSessionList({pubkey}: SignedEvent, _data: Record<string, never>): Promise<SessionListResponse> {
    const items: SessionListResponse["items"] = []
    for (const [_, session] of await this.sessions.entries()) {
      if (session.group.group_pk.slice(2) === pubkey) {
        items.push(makeSessionItem(session))
      }
    }

    debug(`[session/list]: successfully retrieved ${items.length} sessions`)

    return {items, ok: true, message: "Successfully retrieved session list."}
  }

  async _handleSessionDelete({pubkey}: SignedEvent, data: SessionDeleteRequest): Promise<SessionDeleteResponse> {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(data.client)

      if (session?.group.group_pk.slice(2) === pubkey) {
        await this._deleteSession(data.client)

        debug(`[session/delete]: deleted session ${data.client.slice(0, 8)}`)

        return {ok: true, message: "Successfully deleted selected session."}
      } else {
        debug(`[session/delete]: failed to delete session ${data.client.slice(0, 8)}`)
        return {ok: false, message: "Failed to logout selected client."}
      }
    })
  }

  // Routing handlers

  async _handle<T>(
    auth: SignedEvent,
    body: Record<string, unknown>,
    schema: z.ZodType<T>,
    handler: Handler<T, unknown>,
  ) {
    const result = schema.safeParse(body)

    if (!result.success) {
      debug(`[route]: failed to validate request body: ${result.error.message}`)
      return {ok: false, message: "Failed to validate request data."}
    }

    return handler(auth, result.data)
  }

  async handle(path: string, authHeader: string, body: Record<string, unknown>) {
    const auth = this._parseAuth(authHeader, path)

    if (!auth) {
      debug(`[path]: failed to validate authentication`)

      return {ok: false, message: "Failed to validate authentication."}
    }

    switch (path) {
      case "/challenge":
        return this._handle(auth, body, Schema.challengeRequest, this._handleChallenge.bind(this))
      case "/ecdh":
        return this._handle(auth, body, Schema.ecdhRequest, this._handleEcdh.bind(this))
      case "/login/select":
        return this._handle(auth, body, Schema.loginSelectRequest, this._handleLoginSelect.bind(this))
      case "/login/start":
        return this._handle(auth, body, Schema.loginStartRequest, this._handleLoginStart.bind(this))
      case "/recovery/select":
        return this._handle(auth, body, Schema.recoverySelectRequest, this._handleRecoverySelect.bind(this))
      case "/recovery/setup":
        return this._handle(auth, body, Schema.recoverySetupRequest, this._handleRecoverySetup.bind(this))
      case "/recovery/start":
        return this._handle(auth, body, Schema.recoveryStartRequest, this._handleRecoveryStart.bind(this))
      case "/register":
        return this._handle(auth, body, Schema.registerRequest, this._handleRegister.bind(this))
      case "/session/delete":
        return this._handle(auth, body, Schema.sessionDeleteRequest, this._handleSessionDelete.bind(this))
      case "/session/list":
        return this._handle(auth, body, Schema.sessionListRequest, this._handleSessionList.bind(this))
      case "/sign":
        return this._handle(auth, body, Schema.signRequest, this._handleSign.bind(this))
      default:
        return {ok: false, message: "Not found"}
    }
  }
}
