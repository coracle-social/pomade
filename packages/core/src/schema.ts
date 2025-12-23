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
  commits: z.array(commit),
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
const sighash_vec = z.tuple([hex32]).rest(hex32)

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
  email: z.string().optional(),
})

const authPayload = z.union([
  z.string(),
  z.object({
    email: z.string(),
    otp: z.string(),
  }),
])

export type SessionItem = z.infer<typeof sessionItem>
export type AuthPayload = z.infer<typeof authPayload>

export const Schema = {
  ecdhRequest: z.object({
    idx: z.number(),
    members: z.number().array(),
    ecdh_pk: hex32,
  }),
  ecdhResult: z.object({
    result: z.optional(
      z.object({
        idx: z.number(),
        keyshare: hex,
        members: z.number().array(),
        ecdh_pk: hex,
      }),
    ),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  challengeRequest: z.object({
    email_hash: z.string(),
  }),
  loginStart: z.object({
    auth: authPayload,
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
    auth: authPayload,
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
    email: z.string(),
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
      hashes: sighash_vec.array(),
      members: z.number().array(),
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
