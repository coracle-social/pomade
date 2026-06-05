import * as z from "zod"

// Security limits to prevent DoS attacks via unbounded payloads
const MAX_HASHES_PER_REQUEST = 10 // Maximum number of hashes in a single signature request
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

const publicNonceItem = z.object({
  idx: z.number(),
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

const sessionItem = z.object({
  pubkey: hex32,
  client: hex32,
  created_at: z.int().positive(),
  deactivated_at: z.int().optional(),
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
  Boolean((auth as unknown as PasswordAuth).password_hash)

export const isOTPAuth = (auth: Auth): auth is OTPAuth => Boolean((auth as unknown as OTPAuth).otp)

export const Schema = {
  registerRequest: z.object({
    share: share,
    group: group,
    recovery: z.boolean(),
  }),
  registerResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
  }),
  signCommitRequest: z.object({
    members: z.number().array().max(MAX_MEMBERS),
  }),
  signCommitResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    result: z
      .object({
        commit_id: hex32,
        idx: z.number(),
        pubkey: hex33,
        hidden_pn: hex33,
        binder_pn: hex33,
      })
      .optional(),
  }),
  signCompleteRequest: z.object({
    commit_id: hex32,
    request: z.object({
      content: z.string().nullable(),
      hash: sighash_vec,
      members: z.number().array().max(MAX_MEMBERS),
      stamp: z.number(),
      type: z.string(),
      gid: hex32,
      sid: hex32,
    }),
    pnonces: publicNonceItem.array().max(MAX_MEMBERS),
  }),
  signCompleteResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    result: z
      .object({
        idx: z.number(),
        psig: psig_entry,
        pubkey: hex33,
        sid: hex32,
      })
      .optional(),
  }),
  ecdhRequest: z.object({
    idx: z.number(),
    members: z.number().array().max(MAX_MEMBERS),
    ecdh_pk: hex32,
  }),
  ecdhResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    result: z
      .object({
        idx: z.number(),
        keyshare: hex,
        members: z.number().array().max(MAX_MEMBERS),
        ecdh_pk: hex,
      })
      .optional(),
  }),
  recoverySetupRequest: z.object({
    email: z.string().email(),
    password_hash: z.string(),
  }),
  recoverySetupResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
  }),
  challengeRequest: z.object({
    prefix: z.string().regex(/^\d{2}$/),
    email_hash: z.string(),
  }),
  challengeResponse: z.object({
    ok: z.literal(true),
    message: z.string(),
  }),
  loginStartRequest: z.object({
    auth,
  }),
  loginStartResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    items: z.array(sessionItem).optional(),
  }),
  loginSelectRequest: z.object({
    client: hex32,
  }),
  loginSelectResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    group: group.optional(),
  }),
  recoveryStartRequest: z.object({
    auth,
  }),
  recoveryStartResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    items: z.array(sessionItem).optional(),
  }),
  recoverySelectRequest: z.object({
    client: hex32,
  }),
  recoverySelectResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    share: share.optional(),
    group: group.optional(),
  }),
  sessionListRequest: z.object({}),
  sessionListResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
    items: z.array(sessionItem).optional(),
  }),
  sessionDeactivateRequest: z.object({
    client: hex32,
  }),
  sessionDeactivateResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
  }),
  sessionDeleteRequest: z.object({
    client: hex32,
  }),
  sessionDeleteResponse: z.object({
    ok: z.boolean(),
    message: z.string(),
  }),
}
