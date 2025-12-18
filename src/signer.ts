import {Lib} from "@frostr/bifrost"
import type {GroupPackage, SharePackage} from "@frostr/bifrost"
import {
  now,
  ms,
  spec,
  uniq,
  between,
  groupBy,
  map,
  call,
  int,
  ago,
  MINUTE,
  YEAR,
} from "@welshman/lib"
import {getPubkey, verifyEvent, getTagValue, HTTP_AUTH} from "@welshman/util"
import type {TrustedEvent, SignedEvent} from "@welshman/util"
import {IStorageFactory, IStorage} from "./storage.js"
import {RecoveryType, Method} from "./schema.js"
import {RPC, WithEvent} from "./rpc.js"
import {generateOTP} from "./misc.js"
import {debug} from "./context.js"
import {
  EcdhRequest,
  isEcdhRequest,
  isRecoveryFinalize,
  isRecoveryMethodFinalize,
  isRecoveryMethodSet,
  isRecoveryStart,
  isRegisterRequest,
  isSessionDelete,
  isSessionList,
  isSignRequest,
  makeEcdhResult,
  makeRecoveryChallenge,
  makeRecoveryFinalizeResult,
  makeRecoveryMethodChallenge,
  makeRecoveryMethodFinalizeResult,
  makeRecoveryMethodSetResult,
  makeRecoveryStartResult,
  makeRegisterResult,
  makeSessionDeleteResult,
  makeSessionListResult,
  makeSignResult,
  RecoveryChallenge,
  RecoveryFinalize,
  RecoveryMethodFinalize,
  RecoveryMethodSet,
  RecoveryStart,
  RegisterRequest,
  SessionDelete,
  SessionList,
  SessionListResult,
  SignRequest,
} from "./message.js"

// Storage types

export type SignerSession = {
  client: string
  share: SharePackage
  group: GroupPackage
  recovery: boolean
  event: TrustedEvent
  created_at: number
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

export type SignerRecoverOption = {
  otp: string
  client: string
  threshold: number
}

export type SignerRecovery = {
  type: RecoveryType
  inbox: string
  event: TrustedEvent
  items: SignerRecoverOption[]
}

// Signer

export type SignerOptions = {
  secret: string
  relays: string[]
  storage: IStorageFactory
}

export class Signer {
  rpc: RPC
  pubkey: string
  sessions: IStorage<SignerSession>
  recoveries: IStorage<SignerRecovery>
  validations: IStorage<Validation>
  intervals: number[]

  constructor(private options: SignerOptions) {
    this.pubkey = getPubkey(options.secret)
    this.sessions = options.storage("sessions")
    this.recoveries = options.storage("recoveries")
    this.validations = options.storage("validations")
    this.rpc = new RPC(options.secret, options.relays)
    this.rpc.subscribe(message => {
      // Ignore events with weird timestamps
      if (!between([now() - 60, now() + 60], message.event.created_at)) {
        return debug("[signer.constructor]: ignoring event", message.event.id)
      }

      debug("[signer.constructor]: received message", message.event.id)

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

    // Periodically clean up recovery requests
    this.intervals = [
      setInterval(
        async () => {
          debug("[signer.constructor]: cleaning up recoveries")

          for (const [k, recovery] of await this.recoveries.entries()) {
            if (recovery.event.created_at < ago(15, MINUTE)) await this.recoveries.delete(k)
          }
        },
        ms(int(5, MINUTE)),
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
    this.rpc.stop()
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
    return this.sessions.tx(async sessions => {
      const client = event.pubkey
      const {group, share, recovery} = payload
      const cb = (ok: boolean, message: string) =>
        this.rpc.channel(client, false).send(makeRegisterResult({ok, message, prev: event.id}))

      if (!between([0, group.commits.length], group.threshold)) {
        debug("[signer.handleRegisterRequest]: invalid group threshold")
        return cb(false, "Invalid group threshold.")
      }

      if (!Lib.is_group_member(group, share)) {
        debug("[signer.handleRegisterRequest]: share does not belong to the provided group")
        return cb(false, "Share does not belong to the provided group.")
      }

      if (uniq(group.commits.map(c => c.idx)).length !== group.commits.length) {
        debug("[signer.handleRegisterRequest]: group contains duplicate member indices")
        return cb(false, "Group contains duplicate member indices.")
      }

      if (!group.commits.find(c => c.idx === share.idx)) {
        debug("[signer.handleRegisterRequest]: share index not found in group commits")
        return cb(false, "Share index not found in group commits.")
      }

      if (await sessions.has(client)) {
        debug("[signer.handleRegisterRequest]: client is already registered")
        return cb(false, "Client is already registered.")
      }

      await sessions.set(client, {
        client,
        event,
        share,
        group,
        recovery,
        created_at: now(),
        last_activity: now(),
      })

      debug("[signer.handleRegisterRequest]: registered", client)

      return cb(true, "Your key has been registered")
    })
  }

  async handleRecoveryMethodSet({payload, event}: WithEvent<RecoveryMethodSet>) {
    const session = await this.sessions.get(event.pubkey)
    const {inbox, mailer, callback_url} = payload

    if (!session) {
      debug("[signer.handleRecoveryMethodSet]: no session found", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryMethodSetResult({
          ok: false,
          message: "No session found.",
          prev: event.id,
        }),
      )
    }

    if (!session.recovery) {
      debug("[signer.handleRecoveryMethodSet]: recovery is disabled for", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
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
      debug("[signer.handleRecoveryMethodSet]: recovery method set too late", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryMethodSetResult({
          ok: false,
          message: "Recovery method must be set within 5 minutes of session.",
          prev: event.id,
        }),
      )
    }

    const otp = generateOTP()
    const client = event.pubkey
    const pubkey = session.group.group_pk.slice(2)
    const threshold = session.group.commits.length

    await this.validations.set(event.pubkey, {otp, inbox, mailer, event})

    this.rpc
      .channel(mailer)
      .send(makeRecoveryMethodChallenge({otp, client, inbox, pubkey, threshold, callback_url}))

    debug("[signer.handleRecoveryMethodSet]: recovery method set", client, inbox)

    this.rpc.channel(client, false).send(
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
      const validation = await this.validations.get(event.pubkey)

      if (session && validation?.otp === payload.otp) {
        await sessions.set(event.pubkey, {
          ...session,
          last_activity: now(),
          inbox: validation.inbox,
          mailer: validation.mailer,
        })

        debug(
          "[signer.handleRecoveryMethodFinalize]: recovery method finalized successfully",
          event.pubkey,
        )

        this.rpc.channel(event.pubkey, false).send(
          makeRecoveryMethodFinalizeResult({
            ok: true,
            message: "Recovery method successfully verified and associated with your account",
            prev: event.id,
          }),
        )
      } else {
        debug("[signer.handleRecoveryMethodFinalize]: recovery method not finalized", event.pubkey)

        this.rpc.channel(event.pubkey, false).send(
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
    const {type, inbox, pubkey, callback_url} = payload

    const allSessions = map(s => s[1], await this.sessions.entries())

    if (allSessions.some(spec({client: event.pubkey}))) {
      debug("[signer.handleRecoveryStart]: recovery key re-used", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeRecoveryFinalizeResult({
          ok: false,
          message: "Do not re-use a session key as a recovery key.",
          prev: event.id,
        }),
      )
    }

    const sessionsByPubkey = groupBy(
      s => s.group.group_pk.slice(2),
      allSessions.filter(s => {
        // Skip sessions that have no recovery method
        if (!s.mailer) return false

        // Skip sessions with a different recovery method
        if (s.inbox !== inbox) return false

        // If they provided a pubkey, only recover that one
        if (pubkey && s.group.group_pk.slice(2) !== pubkey) return true

        return true
      }),
    )

    const allItems: RecoveryChallenge["payload"]["items"] = []
    for (const [pubkey, pubkeySessions] of sessionsByPubkey) {
      const sessionsByMailer = groupBy(s => s.mailer, pubkeySessions)

      for (const [mailer, mailerSessions] of sessionsByMailer) {
        const items = mailerSessions.map(({group, share, client}) => {
          // If we're logging in we need all signers to participate
          const threshold = type === RecoveryType.Login ? group.commits.length : group.threshold
          const otp = generateOTP()
          const idx = share.idx

          return {idx, otp, threshold, client}
        })

        allItems.push(...items)

        this.rpc.channel(mailer!).send(makeRecoveryChallenge({inbox, pubkey, items, callback_url}))
      }
    }

    await this.recoveries.set(event.pubkey, {type, inbox, event, items: allItems})

    debug("[signer.handleRecoveryStart]: recovery started", event.pubkey)

    // Always show success so attackers can't get information on who is registered
    this.rpc.channel(event.pubkey, false).send(
      makeRecoveryStartResult({
        ok: true,
        message: "Verification sent. Please check your inbox to continue.",
        prev: event.id,
      }),
    )
  }

  async handleRecoveryFinalize({payload, event}: WithEvent<RecoveryFinalize>) {
    return this.sessions.tx(async sessions => {
      const recovery = await this.recoveries.get(event.pubkey)

      if (recovery) {
        for (const item of recovery.items) {
          if (item.otp !== payload.otp) continue

          const session = await sessions.get(item.client)

          if (session) {
            if (recovery.type === RecoveryType.Login) {
              await sessions.set(event.pubkey, {
                ...session,
                client: event.pubkey,
                created_at: event.created_at,
                last_activity: now(),
              })

              debug("[signer.handleRecoveryFinalize]: login succeeded", event.pubkey)

              return this.rpc.channel(event.pubkey, false).send(
                makeRecoveryFinalizeResult({
                  ok: true,
                  message: "Login successfully completed.",
                  group: session.group,
                  prev: event.id,
                }),
              )
            }

            if (recovery.type === RecoveryType.Recovery) {
              debug("[signer.handleRecoveryFinalize]: recovery succeeded", event.pubkey)

              return this.rpc.channel(event.pubkey, false).send(
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
        }
      }

      debug("[signer.handleRecoveryFinalize]: recovery failed", event.pubkey)

      this.rpc.channel(event.pubkey, false).send(
        makeRecoveryFinalizeResult({
          ok: false,
          message: `Failed to validate your request. Please try again.`,
          prev: event.id,
        }),
      )

      await this.recoveries.delete(event.pubkey)
    })
  }

  async handleSignRequest({payload, event}: WithEvent<SignRequest>) {
    return this.sessions.tx(async sessions => {
      const session = await sessions.get(event.pubkey)

      if (!session) {
        debug("[signer.handleSignRequest]: signing failed", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
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

      debug("[signer.handleSignRequest]: signing complete", event.pubkey)

      this.rpc.channel(event.pubkey, false).send(
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
        debug("[signer.handleEcdhRequest]: ecdh failed", event.pubkey)

        return this.rpc.channel(event.pubkey, false).send(
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

      debug("[signer.handleEcdhRequest]: ecdh complete", event.pubkey)

      this.rpc.channel(event.pubkey, false).send(
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
      debug("[signer.handleSessionList]: invalid auth event", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
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

    debug("[signer.handleSessionList]: successfully retrieved session list", event.pubkey)

    this.rpc.channel(event.pubkey, false).send(
      makeSessionListResult({
        sessions,
        ok: true,
        message: "Successfully retrieved session list.",
        prev: event.id,
      }),
    )
  }

  async handleSessionDelete({payload, event}: WithEvent<SessionDelete>) {
    if (!this._isAuthValid(payload.auth, Method.SessionDelete)) {
      debug("[signer.handleSessionDelete]: invalid auth event", event.pubkey)

      return this.rpc.channel(event.pubkey, false).send(
        makeSessionDeleteResult({
          ok: false,
          message: "Failed to delete selected session.",
          prev: event.id,
        }),
      )
    }

    return this.sessions.tx(async sessions => {
      const session = await sessions.get(payload.client)

      if (session?.group.group_pk.slice(2) === payload.auth.pubkey) {
        await sessions.delete(payload.client)

        debug("[signer.handleSessionDelete]: deleted session", event.pubkey)

        this.rpc.channel(event.pubkey, false).send(
          makeSessionDeleteResult({
            ok: true,
            message: "Successfully deleted selected session.",
            prev: event.id,
          }),
        )
      } else {
        debug("[signer.handleSessionDelete]: failed to delete session", event.pubkey)

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
