import * as z from "zod"

export enum Method {
  ChallengeRequest = "challenge/request",
  EcdhRequest = "ecdh/request",
  EcdhResult = "ecdh/result",
  LoginStart = "login/start",
  LoginOptions = "login/options",
  LoginSelect = "login/select",
  LoginResult = "login/result",
  RecoveryStart = "recovery/start",
  RecoveryOptions = "recovery/options",
  RecoverySelect = "recovery/select",
  RecoveryResult = "recovery/result",
  RecoverySetup = "recovery/setup",
  RecoverySetupResult = "recovery/setup/result",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SessionDelete = "session/delete",
  SessionDeleteResult = "session/delete/result",
  SessionList = "session/list",
  SessionListResult = "session/list/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
}

// Security limits to prevent DoS attacks via unbounded payloads
const MAX_HASHES_PER_REQUEST = 10 // Maximum number of hashes in a single signature request
const MAX_HASH_VECTORS = 10 // Maximum number of hash vectors per request
const MAX_MEMBERS = 5 // Maximum number of members in a signing group
const MAX_COMMITS = 5 // Maximum number of commits in a group

const hex = z
  .string()
  .regex(/^[0-9a-fA-F]*$/)
  .refine(e => e.length % 2 === 0)
const hex32 = hex.refine(e => e.length === 64)
const hex33 = hex.refine(e => e.length === 66)

const commit = z.object({
  idx: z.number(),
  pubkey: hex33,
  hidden_pn: hex33,
  binder_pn: hex33,
})

const group = z.object({
  commits: z.array(commit).max(MAX_COMMITS),
  group_pk: hex33,
  threshold: z.number(),
})

const share = z.object({
  idx: z.number(),
  binder_sn: hex32,
  hidden_sn: hex32,
  seckey: hex32,
})

const psig_entry = z.tuple([hex32, hex32])
// Use tuple with rest to maintain type compatibility while enforcing max length
const sighash_vec = z
  .tuple([hex32])
  .rest(hex32)
  .refine(arr => arr.length <= MAX_HASHES_PER_REQUEST, {
    message: `Maximum ${MAX_HASHES_PER_REQUEST} hashes allowed per request`,
  })

const event = z.object({
  sig: hex,
  id: hex32,
  pubkey: hex32,
  kind: z.int().nonnegative(),
  tags: z.string().array().array(),
  content: z.string(),
  created_at: z.int().positive(),
})

const sessionItem = z.object({
  pubkey: hex32,
  client: hex32,
  created_at: z.int().positive(),
  last_activity: z.int().positive(),
  threshold: z.int().positive(),
  total: z.number(),
  idx: z.number(),
  email: z.string().email().optional(),
})

const passwordAuth = z.object({
  email_hash: z.string(),
  password_hash: z.string(),
})

const otpAuth = z.object({
  email_hash: z.string(),
  otp: z.string(),
})

const auth = z.union([passwordAuth, otpAuth])

export type SessionItem = z.infer<typeof sessionItem>
export type PasswordAuth = z.infer<typeof passwordAuth>
export type OTPAuth = z.infer<typeof otpAuth>
export type Auth = z.infer<typeof auth>

export const isPasswordAuth = (auth: Auth): auth is PasswordAuth =>
  Boolean((auth as any).password_hash)

export const isOTPAuth = (auth: Auth): auth is OTPAuth => Boolean((auth as any).otp)

export const Schema = {
  ecdhRequest: z.object({
    idx: z.number(),
    members: z.number().array().max(MAX_MEMBERS),
    ecdh_pk: hex32,
  }),
  ecdhResult: z.object({
    result: z.optional(
      z.object({
        idx: z.number(),
        keyshare: hex,
        members: z.number().array().max(MAX_MEMBERS),
        ecdh_pk: hex,
      }),
    ),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  challengeRequest: z.object({
    prefix: z.string().regex(/^\d{2}$/),
    email_hash: z.string(),
  }),
  loginStart: z.object({
    auth,
  }),
  loginOptions: z.object({
    items: z.array(sessionItem).optional(),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  loginSelect: z.object({
    client: hex32,
  }),
  loginResult: z.object({
    group: group.optional(),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoveryStart: z.object({
    auth,
  }),
  recoveryOptions: z.object({
    items: z.array(sessionItem).optional(),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoverySelect: z.object({
    client: hex32,
  }),
  recoveryResult: z.object({
    share: share.optional(),
    group: group.optional(),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoverySetup: z.object({
    email: z.string().email(),
    password_hash: z.string(),
  }),
  recoverySetupResult: z.object({
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  registerRequest: z.object({
    share: share,
    group: group,
    recovery: z.boolean(),
  }),
  registerResult: z.object({
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  sessionDelete: z.object({
    client: hex32,
    auth: event,
  }),
  sessionDeleteResult: z.object({
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  sessionList: z.object({
    auth: event,
  }),
  sessionListResult: z.object({
    items: z.array(sessionItem),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  signRequest: z.object({
    request: z.object({
      content: z.string().nullable(),
      hashes: sighash_vec.array().max(MAX_HASH_VECTORS),
      members: z.number().array().max(MAX_MEMBERS),
      stamp: z.number(),
      type: z.string(),
      gid: hex32,
      sid: hex32,
    }),
  }),
  signResult: z.object({
    result: z.optional(
      z.object({
        idx: z.number(),
        psigs: psig_entry.array(),
        pubkey: hex33,
        sid: hex32,
      }),
    ),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
}
