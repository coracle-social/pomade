import {Lib} from "@frostr/bifrost"
import {randomBytes, bytesToHex} from "@noble/hashes/utils.js"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {
  not,
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
  HOUR,
  YEAR,
} from "@welshman/lib"
import {verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent, SignedEvent} from "@welshman/util"
import type {ISigner} from "@welshman/signer"
import {Method, SessionItem, Auth, isPasswordAuth, isOTPAuth} from "./schema.js"
import {RPC, WithEvent} from "./rpc.js"
import {IStorage, ICollection} from "./storage.js"
import {hashEmail, encodeChallenge, debug} from "./util.js"
import {
  ChallengeRequest,
  EcdhRequest,
  isChallengeRequest,
  isEcdhRequest,
  isLoginSelect,
  isLoginStart,
  isRecoverySetup,
  isRecoverySelect,
  isRecoveryStart,
  isRegisterRequest,
  isSessionDelete,
  isSessionList,
  isSignRequest,
  LoginSelect,
  LoginStart,
  makeEcdhResult,
  makeLoginOptions,
  makeLoginResult,
  makeRecoverySetupResult,
  makeRecoveryOptions,
  makeRecoveryResult,
  makeRegisterResult,
  makeSessionDeleteResult,
  makeSessionListResult,
  makeSignResult,
  RecoverySetup,
  RecoverySelect,
  RecoveryStart,
  RegisterRequest,
  SessionDelete,
  SessionList,
  SessionListResult,
  SignRequest,
} from "./message.js"
import {
  RateLimitBucket,
  RateLimitConfig,
  isRateLimited,
  recordAttempt,
  getRateLimitResetTime,
  cleanupRateLimits,
} from "./ratelimit.js"

// Rate limiting for client requests (sign + ecdh combined)
const CLIENT_REQUEST_RATE_LIMIT: RateLimitConfig = {
  maxAttempts: 100,
  windowSeconds: int(1, MINUTE),
}

// Utils

function makeSessionItem(session: SignerSession): SessionItem {
  return {
    pubkey: session.group.group_pk.slice(2),
    client: session.client,
    created_at: session.event.created_at,
    last_activity: session.last_activity,
    threshold: session.group.threshold,
    total: session.group.commits.length,
    idx: session.share.idx,
    email: session.email,
  }
}

// Storage types

export type SignerSession = {
  client: string
  share: SharePackage
  group: GroupPackage
  recovery: boolean
  event: TrustedEvent
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
  event: TrustedEvent
  clients: string[]
}

export type SignerLogin = {
  event: TrustedEvent
  clients: string[]
}

export type SignerChallenge = {
  event: TrustedEvent
  otp: string
}

// Signer

export type ChallengePayload = {
  email: string
  challenge: string
}

export type SignerRateLimitConfig = {
  auth: RateLimitConfig
  challenge: RateLimitConfig
}

export type SignerOptions = {
  signer: ISigner
  relays: string[]
  storage: IStorage
  sendChallenge: (payload: ChallengePayload) => Promise<void>
  rateLimits?: SignerRateLimitConfig
}

export class Signer {
  rpc: RPC
  intervals: number[]
  logins: ICollection<SignerLogin>
  sessions: ICollection<SignerSession>
  recoveries: ICollection<SignerRecovery>
  challenges: ICollection<SignerChallenge>
  sessionsByEmailHash: ICollection<SignerSessionIndex>
  rateLimitByEmailHash: ICollection<RateLimitBucket>
  rateLimitByChallengeHash: ICollection<RateLimitBucket>
  rateLimitByClient: ICollection<RateLimitBucket>
  rateLimitConfig: SignerRateLimitConfig

  constructor(private options: SignerOptions) {
    this.logins = options.storage.collection("logins")
    this.sessions = options.storage.collection("sessions")
    this.recoveries = options.storage.collection("recoveries")
    this.challenges = options.storage.collection("challenges")
    this.sessionsByEmailHash = options.storage.collection("sessionsByEmailHash")
    this.rateLimitByEmailHash = options.storage.collection("rateLimitByEmailHash")
    this.rateLimitByChallengeHash = options.storage.collection("rateLimitByChallengeHash")
    this.rateLimitByClient = options.storage.collection("rateLimitByClient")

    // Default rate limits (conservative but reasonable)
    this.rateLimitConfig = {
      // 5 auth attempts per email_hash per 5 minutes
      auth: {maxAttempts: 5, windowSeconds: int(5, MINUTE)},
      // 3 challenge requests per email_hash per 5 minutes
      challenge: {maxAttempts: 3, windowSeconds: int(5, MINUTE)},
      ...options.rateLimits,
    }

    this.rpc = new RPC(options.signer, options.relays)
    this.rpc.subscribe(message => {
      // Ignore events with weird timestamps
      if (!between([now() - int(1, HOUR), now() + int(1, HOUR)], message.event.created_at)) {
        return debug("[signer]: ignoring event", message.event.id)
      }

      if (isRegisterRequest(message)) this.handleRegisterRequest(message)
      if (isRecoverySetup(message)) this.handleRecoverySetup(message)
      if (isChallengeRequest(message)) this.handleChallengeRequest(message)
      if (isRecoveryStart(message)) this.handleRecoveryStart(message)
      if (isRecoverySelect(message)) this.handleRecoverySelect(message)
      if (isLoginStart(message)) this.handleLoginStart(message)
      if (isLoginSelect(message)) this.handleLoginSelect(message)
      if (isSignRequest(message)) this.handleSignRequest(message)
      if (isEcdhRequest(message)) this.handleEcdhRequest(message)
      if (isSessionList(message)) this.handleSessionList(message)
      if (isSessionDelete(message)) this.handleSessionDelete(message)
    })

    // Periodically clean up recovery requests and rate limits
    this.intervals = [
      setInterval(
        async () => {
          debug("[signer]: cleaning up logins, recoveries, and rate limits")

          for (const [client, recovery] of await this.recoveries.entries()) {
            if (recovery.event.created_at < ago(15, MINUTE)) await this.recoveries.delete(client)
          }

          for (const [client, login] of await this.logins.entries()) {
            if (login.event.created_at < ago(15, MINUTE)) await this.logins.delete(client)
          }

          for (const [client, challenge] of await this.challenges.entries()) {
            if (challenge.event.created_at < ago(15, MINUTE)) await this.challenges.delete(client)
          }

          // Clean up rate limit buckets
          await cleanupRateLimits(
            this.rateLimitByEmailHash,
            this.rateLimitConfig.auth.windowSeconds,
          )
          await cleanupRateLimits(
            this.rateLimitByChallengeHash,
            this.rateLimitConfig.challenge.windowSeconds,
          )
          await cleanupRateLimits(this.rateLimitByClient, CLIENT_REQUEST_RATE_LIMIT.windowSeconds)
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
    this.rpc.stop()
    this.intervals.forEach(clearInterval)
  }

  // Internal utils

  async _checkAndRecordRateLimit(client: string): Promise<boolean> {
    const bucket = await this.rateLimitByClient.get(client)

    if (isRateLimited(bucket, CLIENT_REQUEST_RATE_LIMIT)) {
      const resetTime = getRateLimitResetTime(bucket, CLIENT_REQUEST_RATE_LIMIT)
      debug(
        `[signer]: rate limit exceeded for client ${client.slice(0, 8)}, reset in ${resetTime}s`,
      )
      return false
    }

    // Record the attempt
    const updatedBucket = recordAttempt(bucket, CLIENT_REQUEST_RATE_LIMIT)
    await this.rateLimitByClient.set(client, updatedBucket)
    return true
  }

  async _getAuthenticatedSessions(auth: Auth): Promise<SignerSession[]> {
    // Check rate limit for auth attempts
    const bucket = await this.rateLimitByEmailHash.get(auth.email_hash)

    if (isRateLimited(bucket, this.rateLimitConfig.auth)) {
      const resetTime = getRateLimitResetTime(bucket, this.rateLimitConfig.auth)
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

    // Record failed authentication attempt for rate limiting
    if (sessions.length === 0) {
      const updatedBucket = recordAttempt(bucket, this.rateLimitConfig.auth)
      await this.rateLimitByEmailHash.set(auth.email_hash, updatedBucket)
    }

    return sessions
  }

  async _isNip98AuthValid(auth: SignedEvent, method: Method) {
    const pubkey = await this.options.signer.getPubkey()

    return (
      verifyEvent(auth) &&
      auth.kind === HTTP_AUTH &&
      auth.created_at > ago(15) &&
      auth.created_at < now() + 5 &&
      getTagValue("u", auth.tags) === pubkey &&
      getTagValue("method", auth.tags) === method
    )
  }

  async _checkKeyReuse(event: TrustedEvent) {
    if (await this.sessions.get(event.pubkey)) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: session key re-used`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use session keys.",
          prev: event.id,
        }),
      )
    }

    if (await this.recoveries.get(event.pubkey)) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: recovery key re-used`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use recovery keys.",
          prev: event.id,
        }),
      )
    }

    if (await this.logins.get(event.pubkey)) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: login key re-used`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use login keys.",
          prev: event.id,
        }),
      )
    }
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

  // Registration

  async handleRegisterRequest({payload, event}: WithEvent<RegisterRequest>) {
    return this.options.storage.tx(async () => {
      const {group, share, recovery} = payload
      const cb = (ok: boolean, message: string) =>
        this.rpc
          .channel(event.pubkey, false)
          .send(makeRegisterResult({ok, message, prev: event.id}))

      if (await this._checkKeyReuse(event)) return

      if (!between([0, group.commits.length], group.threshold)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: invalid group threshold`)
        return cb(false, "Invalid group threshold.")
      }

      if (!Lib.is_group_member(group, share)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: share does not belong to the provided group`)
        return cb(false, "Share does not belong to the provided group.")
      }

      if (uniq(group.commits.map(c => c.idx)).length !== group.commits.length) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: group contains duplicate member indices`)
        return cb(false, "Group contains duplicate member indices.")
      }

      if (!group.commits.find(c => c.idx === share.idx)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: share index not found in group commits`)
        return cb(false, "Share index not found in group commits.")
      }

      if (await this.sessions.get(event.pubkey)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: client is already registered`)
        return cb(false, "Client is already registered.")
      }

      await this._addSession(event.pubkey, {
        client: event.pubkey,
        event,
        share,
        group,
        recovery,
        last_activity: now(),
      })

      debug(`[client ${event.pubkey.slice(0, 8)}]: registered`)

      return cb(true, "Your key has been registered")
    })
  }

  // Recovery setup

  async handleRecoverySetup({payload, event}: WithEvent<RecoverySetup>) {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: no session found for recovery setup`)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "No session found.",
            prev: event.id,
          }),
        )
      }

      if (!session.recovery) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: recovery is disabled for session`)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "Recovery is disabled on this session.",
            prev: event.id,
          }),
        )
      }

      // recovery method has to be bound at (or shorly after) session, otherwise an attacker with access
      // to any session could escalate permissions by setting up their own recovery method
      if (session.event.created_at < ago(15, MINUTE)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: recovery method set too late`)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "Recovery method must be set within 5 minutes of session.",
            prev: event.id,
          }),
        )
      }

      if (session.email) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: recovery is already set`)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "Recovery has already been initialized.",
            prev: event.id,
          }),
        )
      }

      if (!payload.password_hash.match(/^[a-f0-9]{64}$/)) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: invalid password_hash provided on setup`)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message:
              "Recovery method password hash must be an argon2id hash of user email and password.",
            prev: event.id,
          }),
        )
      }

      const {email, password_hash} = payload
      const pubkey = await this.options.signer.getPubkey()
      const email_hash = await hashEmail(email, pubkey)

      await this._addSession(event.pubkey, {
        ...session,
        last_activity: now(),
        email,
        email_hash,
        password_hash,
      })

      debug(`[client ${event.pubkey.slice(0, 8)}]: recovery method initialized`)

      this.rpc.channel(event.pubkey, false).send(
        makeRecoverySetupResult({
          ok: true,
          message: "Recovery method successfully initialized.",
          prev: event.id,
        }),
      )
    })
  }

  async handleChallengeRequest({payload, event}: WithEvent<ChallengeRequest>) {
    // Check rate limit for challenge requests per email_hash
    const bucket = await this.rateLimitByChallengeHash.get(payload.email_hash)

    if (isRateLimited(bucket, this.rateLimitConfig.challenge)) {
      const resetTime = getRateLimitResetTime(bucket, this.rateLimitConfig.challenge)
      debug(
        `[signer]: challenge rate limit exceeded for email_hash ${payload.email_hash.slice(0, 8)}, reset in ${resetTime}s`,
      )
      return
    }

    const index = await this.sessionsByEmailHash.get(payload.email_hash)

    if (index && index.clients.length > 0) {
      const session = await this.sessions.get(index.clients[0])

      if (session?.email) {
        // Record challenge request for rate limiting
        const updatedBucket = recordAttempt(bucket, this.rateLimitConfig.challenge)
        await this.rateLimitByChallengeHash.set(payload.email_hash, updatedBucket)

        const otp = bytesToHex(randomBytes(8))
        const pubkey = await this.options.signer.getPubkey()
        const challenge = encodeChallenge(pubkey, otp)

        await this.challenges.set(payload.email_hash, {otp, event})

        this.options.sendChallenge({email: session.email, challenge})

        debug(`[client ${event.pubkey.slice(0, 8)}]: challenge sent for ${payload.email_hash}`)
      }
    } else {
      debug(`[client ${event.pubkey.slice(0, 8)}]: no session found for ${payload.email_hash}`)
    }
  }

  // Recovery

  async handleRecoveryStart({payload, event}: WithEvent<RecoveryStart>) {
    if (await this._checkKeyReuse(event)) return

    const sessions = await this._getAuthenticatedSessions(payload.auth)

    if (sessions.length === 0) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: no sessions found for recovery`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "No sessions found.",
          prev: event.id,
        }),
      )
    }

    debug(`[client ${event.pubkey.slice(0, 8)}]: sending recovery options`)

    const clients = sessions.map(s => s.client)
    const items = sessions.map(makeSessionItem)

    await this.recoveries.set(event.pubkey, {event, clients})

    this.rpc.channel(event.pubkey, false).send(
      makeRecoveryOptions({
        items,
        ok: true,
        message: "Successfully retrieved recovery options.",
        prev: event.id,
      }),
    )
  }

  async handleRecoverySelect({payload, event}: WithEvent<RecoverySelect>) {
    const recovery = await this.recoveries.get(event.pubkey)

    if (!recovery) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: no active recovery found`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryResult({
          ok: false,
          message: `No active recovery found.`,
          prev: event.id,
        }),
      )
    }

    // Cleanup right away
    await this.recoveries.delete(event.pubkey)

    if (!recovery.clients.includes(payload.client)) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: invalid session selected for recovery`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryResult({
          ok: false,
          message: `Invalid session selected for recovery.`,
          prev: event.id,
        }),
      )
    }

    const session = await this.sessions.get(payload.client)

    if (!session) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: recovery session not found`)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryResult({
          ok: false,
          message: `Recovery session not found.`,
          prev: event.id,
        }),
      )
    }

    this.rpc.channel(event.pubkey, false).send(
      makeRecoveryResult({
        ok: true,
        message: "Recovery successfully completed.",
        group: session.group,
        share: session.share,
        prev: event.id,
      }),
    )

    debug(`[client ${event.pubkey.slice(0, 8)}]: recovery successfully completed`)
  }

  // Login

  async handleLoginStart({payload, event}: WithEvent<LoginStart>) {
    if (await this._checkKeyReuse(event)) return

    const sessions = await this._getAuthenticatedSessions(payload.auth)

    if (sessions.length === 0) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: no sessions found for login`)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginOptions({
          ok: false,
          message: "No sessions found.",
          prev: event.id,
        }),
      )
    }

    debug(`[client ${event.pubkey.slice(0, 8)}]: sending login options`)

    const clients = sessions.map(s => s.client)
    const items = sessions.map(makeSessionItem)

    await this.logins.set(event.pubkey, {event, clients})

    this.rpc.channel(event.pubkey, false).send(
      makeLoginOptions({
        items,
        ok: true,
        message: "Successfully retrieved login options.",
        prev: event.id,
      }),
    )
  }

  async handleLoginSelect({payload, event}: WithEvent<LoginSelect>) {
    const login = await this.logins.get(event.pubkey)

    if (!login) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: no active login found`)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginResult({
          ok: false,
          message: `No active login found.`,
          prev: event.id,
        }),
      )
    }

    // Cleanup right away
    await this.logins.delete(event.pubkey)

    if (!login.clients.includes(payload.client)) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: invalid session selected for login`)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginResult({
          ok: false,
          message: `Invalid session selected for login.`,
          prev: event.id,
        }),
      )
    }

    const session = await this.sessions.get(payload.client)

    if (!session) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: login session not found`)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginResult({
          ok: false,
          message: `Login session not found.`,
          prev: event.id,
        }),
      )
    }

    await this._addSession(event.pubkey, {
      event,
      recovery: true,
      client: event.pubkey,
      share: session.share,
      group: session.group,
      email: session.email,
      email_hash: session.email_hash,
      password_hash: session.password_hash,
      last_activity: now(),
    })

    this.rpc.channel(event.pubkey, false).send(
      makeLoginResult({
        ok: true,
        message: "Login successfully completed.",
        group: session.group,
        prev: event.id,
      }),
    )

    debug(`[client ${event.pubkey.slice(0, 8)}]: login successfully completed`)
  }

  // Signing

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: signing failed - no session found`)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      // Check rate limit
      const allowed = await this._checkAndRecordRateLimit(event.pubkey)
      if (!allowed) {
        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "Rate limit exceeded. Please try again later.",
            prev: event.id,
          }),
        )
      }

      try {
        const ctx = Lib.get_session_ctx(session.group, payload.request)
        const partialSignature = Lib.create_psig_pkg(ctx, session.share)

        await this.sessions.set(event.pubkey, {...session, last_activity: now()})

        debug(`[client ${event.pubkey.slice(0, 8)}]: signing complete`)

        this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            result: partialSignature,
            ok: true,
            message: "Successfully signed event",
            prev: event.id,
          }),
        )
      } catch (e: any) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: signing failed - ${e.message || e}`)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "Failed to sign event",
            prev: event.id,
          }),
        )
      }
    })
  }

  // Key exchange

  async handleEcdhRequest({payload, event}: WithEvent<EcdhRequest>) {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: ecdh failed - no session found`)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      // Check rate limit
      const allowed = await this._checkAndRecordRateLimit(event.pubkey)
      if (!allowed) {
        return this.rpc.channel(event.pubkey, false).send(
          makeEcdhResult({
            ok: false,
            message: "Rate limit exceeded. Please try again later.",
            prev: event.id,
          }),
        )
      }

      const {members, ecdh_pk} = payload

      try {
        const ecdhPackage = Lib.create_ecdh_pkg(members, ecdh_pk, session.share)

        await this.sessions.set(event.pubkey, {...session, last_activity: now()})

        debug(`[client ${event.pubkey.slice(0, 8)}]: ecdh complete`)

        this.rpc.channel(event.pubkey, false).send(
          makeEcdhResult({
            result: ecdhPackage,
            ok: true,
            message: "Successfully signed event",
            prev: event.id,
          }),
        )
      } catch (e: any) {
        debug(`[client ${event.pubkey.slice(0, 8)}]: ecdh failed - ${e.message || e}`)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "Key derivation failed",
            prev: event.id,
          }),
        )
      }
    })
  }

  // Session management

  async handleSessionList({payload, event}: WithEvent<SessionList>) {
    if (not(await this._isNip98AuthValid(payload.auth, Method.SessionList))) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: invalid auth event for session list`)

      return this.rpc.channel(event.pubkey, false).send(
        makeSessionListResult({
          items: [],
          ok: false,
          message: "Failed to validate authentication.",
          prev: event.id,
        }),
      )
    }

    const items: SessionListResult["payload"]["items"] = []
    for (const [_, session] of await this.sessions.entries()) {
      if (session.group.group_pk.slice(2) === payload.auth.pubkey) {
        items.push(makeSessionItem(session))
      }
    }

    debug(`[client ${event.pubkey.slice(0, 8)}]: successfully retrieved session list`)

    this.rpc.channel(event.pubkey, false).send(
      makeSessionListResult({
        items,
        ok: true,
        message: "Successfully retrieved session list.",
        prev: event.id,
      }),
    )
  }

  async handleSessionDelete({payload, event}: WithEvent<SessionDelete>) {
    if (not(await this._isNip98AuthValid(payload.auth, Method.SessionDelete))) {
      debug(`[client ${event.pubkey.slice(0, 8)}]: invalid auth event for session deletion`)

      return this.rpc.channel(event.pubkey, false).send(
        makeSessionDeleteResult({
          ok: false,
          message: "Failed to delete selected session.",
          prev: event.id,
        }),
      )
    }

    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(payload.client)

      if (session?.group.group_pk.slice(2) === payload.auth.pubkey) {
        await this._deleteSession(payload.client)

        debug(`[client ${event.pubkey.slice(0, 8)}]: deleted session`, payload.client)

        this.rpc.channel(event.pubkey, false).send(
          makeSessionDeleteResult({
            ok: true,
            message: "Successfully deleted selected session.",
            prev: event.id,
          }),
        )
      } else {
        debug(`[client ${event.pubkey.slice(0, 8)}]: failed to delete session`, payload.client)

        return this.rpc.channel(event.pubkey, false).send(
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
