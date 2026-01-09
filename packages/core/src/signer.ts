import {Lib} from "@frostr/bifrost"
import {randomBytes, bytesToHex} from "@noble/hashes/utils.js"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {
  now,
  filter,
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
import {getPubkey, verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent, SignedEvent} from "@welshman/util"
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

export type SignerOptions = {
  secret: string
  relays: string[]
  storage: IStorage
  sendChallenge: (payload: ChallengePayload) => Promise<void>
}

export class Signer {
  rpc: RPC
  pubkey: string
  intervals: number[]
  logins: ICollection<SignerLogin>
  sessions: ICollection<SignerSession>
  recoveries: ICollection<SignerRecovery>
  challenges: ICollection<SignerChallenge>
  sessionsByEmailHash: ICollection<SignerSessionIndex>

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.logins = options.storage.collection("logins")
    this.sessions = options.storage.collection("sessions")
    this.recoveries = options.storage.collection("recoveries")
    this.challenges = options.storage.collection("challenges")
    this.sessionsByEmailHash = options.storage.collection("sessionsByEmailHash")
    this.rpc = new RPC(options.secret, options.relays)
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

    // Periodically clean up recovery requests
    this.intervals = [
      setInterval(
        async () => {
          debug("[signer]: cleaning up logins and recoveries")

          for (const [client, recovery] of await this.recoveries.entries()) {
            if (recovery.event.created_at < ago(15, MINUTE)) await this.recoveries.delete(client)
          }

          for (const [client, login] of await this.logins.entries()) {
            if (login.event.created_at < ago(15, MINUTE)) await this.logins.delete(client)
          }

          for (const [client, challenge] of await this.challenges.entries()) {
            if (challenge.event.created_at < ago(15, MINUTE)) await this.challenges.delete(client)
          }
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

  async _getAuthenticatedSessions(auth: Auth): Promise<SignerSession[]> {
    const index = await this.sessionsByEmailHash.get(auth.email_hash)

    if (index) {
      if (isPasswordAuth(auth)) {
        return filter(
          session => session?.password_hash === auth.password_hash,
          await Promise.all(index.clients.map(client => this.sessions.get(client))),
        ) as SignerSession[]
      }

      if (isOTPAuth(auth)) {
        const challenge = await this.challenges.get(auth.email_hash)

        if (challenge) {
          await this.challenges.delete(auth.email_hash)

          if (auth.otp === challenge.otp) {
            return removeUndefined(
              await Promise.all(index.clients.map(client => this.sessions.get(client))),
            )
          }
        }
      }
    }

    return []
  }

  _isNip98AuthValid(auth: SignedEvent, method: Method) {
    return (
      verifyEvent(auth) &&
      auth.kind === HTTP_AUTH &&
      auth.created_at > ago(15) &&
      auth.created_at < now() + 5 &&
      getTagValue("u", auth.tags) === this.pubkey &&
      getTagValue("method", auth.tags) === method
    )
  }

  async _checkKeyReuse(event: TrustedEvent) {
    if (await this.sessions.get(event.pubkey)) {
      debug("[signer]: session key re-used", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use session keys.",
          prev: event.id,
        }),
      )
    }

    if (await this.recoveries.get(event.pubkey)) {
      debug("[signer]: recovery key re-used", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use recovery keys.",
          prev: event.id,
        }),
      )
    }

    if (await this.logins.get(event.pubkey)) {
      debug("[signer]: login key re-used", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "Do not re-use login keys.",
          prev: event.id,
        }),
      )
    }
  }

  // Registration

  async handleRegisterRequest({payload, event}: WithEvent<RegisterRequest>) {
    debug("[signer]: attempting to register session", event.pubkey)

    return this.options.storage.tx(async () => {
      const {group, share, recovery} = payload
      const cb = (ok: boolean, message: string) =>
        this.rpc
          .channel(event.pubkey, false)
          .send(makeRegisterResult({ok, message, prev: event.id}))

      if (await this._checkKeyReuse(event)) return

      if (!between([0, group.commits.length], group.threshold)) {
        debug("[signer]: invalid group threshold", event.pubkey)
        return cb(false, "Invalid group threshold.")
      }

      if (!Lib.is_group_member(group, share)) {
        debug("[signer]: share does not belong to the provided group", event.pubkey)
        return cb(false, "Share does not belong to the provided group.")
      }

      if (uniq(group.commits.map(c => c.idx)).length !== group.commits.length) {
        debug("[signer]: group contains duplicate member indices", event.pubkey)
        return cb(false, "Group contains duplicate member indices.")
      }

      if (!group.commits.find(c => c.idx === share.idx)) {
        debug("[signer]: share index not found in group commits", event.pubkey)
        return cb(false, "Share index not found in group commits.")
      }

      if (await this.sessions.get(event.pubkey)) {
        debug("[signer]: client is already registered", event.pubkey)
        return cb(false, "Client is already registered.")
      }

      await this.sessions.set(event.pubkey, {
        client: event.pubkey,
        event,
        share,
        group,
        recovery,
        last_activity: now(),
      })

      debug("[signer]: registered", event.pubkey)

      return cb(true, "Your key has been registered")
    })
  }

  // Recovery setup

  async handleRecoverySetup({payload, event}: WithEvent<RecoverySetup>) {
    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug("[signer]: no session found for recovery setup", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "No session found.",
            prev: event.id,
          }),
        )
      }

      if (!session.recovery) {
        debug("[signer]: recovery is disabled for session", event.pubkey)

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
        debug("[signer]: recovery method set too late", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "Recovery method must be set within 5 minutes of session.",
            prev: event.id,
          }),
        )
      }

      if (session.email) {
        debug("[signer]: recovery is already set", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
          makeRecoverySetupResult({
            ok: false,
            message: "Recovery has already been initialized.",
            prev: event.id,
          }),
        )
      }

      if (!payload.password_hash.match(/^[a-f0-9]{64}$/)) {
        debug("[signer]: invalid password_hash provided on setup", event.pubkey)

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
      const email_hash = await hashEmail(email, this.pubkey)
      const index = (await this.sessionsByEmailHash.get(email_hash)) || {clients: []}

      await this.sessions.set(event.pubkey, {
        ...session,
        last_activity: now(),
        email,
        email_hash,
        password_hash,
      })
      await this.sessionsByEmailHash.set(email_hash, {clients: append(event.pubkey, index.clients)})

      debug("[signer]: recovery method initialized", event.pubkey)

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
    const index = await this.sessionsByEmailHash.get(payload.email_hash)

    if (index && index.clients.length > 0) {
      const session = await this.sessions.get(index.clients[0])

      if (session?.email) {
        const otp = bytesToHex(randomBytes(12))
        const challenge = encodeChallenge(this.pubkey, otp)

        await this.challenges.set(payload.email_hash, {otp, event})

        this.options.sendChallenge({email: session.email, challenge})
      }
    }
  }

  // Recovery

  async handleRecoveryStart({payload, event}: WithEvent<RecoveryStart>) {
    if (await this._checkKeyReuse(event)) return

    const sessions = await this._getAuthenticatedSessions(payload.auth)

    if (sessions.length === 0) {
      debug("[signer]: no sessions found for recovery", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryOptions({
          ok: false,
          message: "No sessions found.",
          prev: event.id,
        }),
      )
    }

    debug("[signer]: sending recovery options", event.pubkey)

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
      debug("[signer]: no active recovery found", event.pubkey)

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
      debug("[signer]: invalid session selected for recovery", event.pubkey)

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
      debug("[signer]: recovery session not found", event.pubkey)

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

    debug("[signer]: recovery successfully completed", event.pubkey)
  }

  // Login

  async handleLoginStart({payload, event}: WithEvent<LoginStart>) {
    if (await this._checkKeyReuse(event)) return

    const sessions = await this._getAuthenticatedSessions(payload.auth)

    if (sessions.length === 0) {
      debug("[signer]: no sessions found for login", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginOptions({
          ok: false,
          message: "No sessions found.",
          prev: event.id,
        }),
      )
    }

    debug("[signer]: sending login options", event.pubkey)

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
      debug("[signer]: no active login found", event.pubkey)

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
      debug("[signer]: invalid session selected for login", event.pubkey)

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
      debug("[signer]: login session not found", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeLoginResult({
          ok: false,
          message: `Login session not found.`,
          prev: event.id,
        }),
      )
    }

    await this.sessions.set(event.pubkey, {
      event,
      recovery: true,
      client: event.pubkey,
      share: session.share,
      group: session.group,
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

    debug("[signer]: login successfully completed", event.pubkey)
  }

  // Signing

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
    debug("[signer]: attempting signing flow", event.pubkey)

    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug("[signer]: signing failed - no session found", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      try {
        const ctx = Lib.get_session_ctx(session.group, payload.request)
        const partialSignature = Lib.create_psig_pkg(ctx, session.share)

        await this.sessions.set(event.pubkey, {...session, last_activity: now()})

        debug("[signer]: signing complete", event.pubkey)

        this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            result: partialSignature,
            ok: true,
            message: "Successfully signed event",
            prev: event.id,
          }),
        )
      } catch (e: any) {
        debug(`[signer]: signing failed - ${e.message || e}`, event.pubkey)

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
    debug("[signer]: attempting ecdh flow", event.pubkey)

    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(event.pubkey)

      if (!session) {
        debug("[signer]: ecdh failed - no session found", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
          makeSignResult({
            ok: false,
            message: "No session found for client",
            prev: event.id,
          }),
        )
      }

      const {members, ecdh_pk} = payload

      try {
        const ecdhPackage = Lib.create_ecdh_pkg(members, ecdh_pk, session.share)

        await this.sessions.set(event.pubkey, {...session, last_activity: now()})

        debug("[signer]: ecdh complete", event.pubkey)

        this.rpc.channel(event.pubkey, false).send(
          makeEcdhResult({
            result: ecdhPackage,
            ok: true,
            message: "Successfully signed event",
            prev: event.id,
          }),
        )
      } catch (e: any) {
        debug("[signer]: ecdh failed - ${e.message || e}", event.pubkey)

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
    if (!this._isNip98AuthValid(payload.auth, Method.SessionList)) {
      debug("[signer]: invalid auth event for session list", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeSessionListResult({
          items: [],
          ok: false,
          message: "Failed to validate authentication.",
          prev: event.id,
        }),
      )
    }

    debug("[signer]: attempting to retrieve session list", event.pubkey)

    const items: SessionListResult["payload"]["items"] = []
    for (const [_, session] of await this.sessions.entries()) {
      if (session.group.group_pk.slice(2) === payload.auth.pubkey) {
        items.push(makeSessionItem(session))
      }
    }

    debug("[signer]: successfully retrieved session list", event.pubkey)

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
    if (!this._isNip98AuthValid(payload.auth, Method.SessionDelete)) {
      debug("[signer]: invalid auth event for session deletion", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeSessionDeleteResult({
          ok: false,
          message: "Failed to delete selected session.",
          prev: event.id,
        }),
      )
    }

    debug("[signer]: attempting to delete session", event.pubkey)

    return this.options.storage.tx(async () => {
      const session = await this.sessions.get(payload.client)

      if (session?.group.group_pk.slice(2) === payload.auth.pubkey) {
        await this.sessions.delete(payload.client)

        debug("[signer]: deleted session", event.pubkey)

        this.rpc.channel(event.pubkey, false).send(
          makeSessionDeleteResult({
            ok: true,
            message: "Successfully deleted selected session.",
            prev: event.id,
          }),
        )
      } else {
        debug("[signer]: failed to delete session", event.pubkey)

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
