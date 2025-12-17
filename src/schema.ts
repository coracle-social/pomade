import * as z from "zod"

export enum Method {
  EcdhRequest = "ecdh/request",
  EcdhResult = "ecdh/result",
  RecoveryChallenge = "recovery/challenge",
  RecoveryFinalize = "recovery/finalize",
  RecoveryFinalizeResult = "recovery/finalize/result",
  RecoveryMethodChallenge = "recoveryMethod/challenge",
  RecoveryMethodFinalize = "recoveryMethod/finalize",
  RecoveryMethodFinalizeResult = "recoveryMethod/finalize/result",
  RecoveryMethodSet = "recoveryMethod/set",
  RecoveryMethodSetResult = "recoveryMethod/set/result",
  RecoveryStart = "recovery/start",
  RecoveryStartResult = "recovery/start/result",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SessionDelete = "session/delete",
  SessionDeleteResult = "session/delete/result",
  SessionList = "session/list",
  SessionListResult = "session/list/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
}

export enum RecoveryType {
  Login = "login",
  Recovery = "recovery",
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
  client: hex32,
  inbox: z.string().optional(),
  created_at: z.int().positive(),
  last_activity: z.int().positive(),
})

export const Schema = {
  sessionItem,
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
  recoveryChallenge: z.object({
    inbox: z.string(),
    pubkey: hex32,
    items: z.array(
      z.object({
        idx: z.number(),
        otp: z.string(),
        client: hex32,
        threshold: z.int().positive(),
      }),
    ),
    callback_url: z.string().optional(),
  }),
  recoveryFinalize: z.object({
    otp: z.string(),
  }),
  recoveryFinalizeResult: z.object({
    group: group.optional(),
    share: share.optional(),
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoveryMethodChallenge: z.object({
    otp: z.string(),
    client: hex32,
    inbox: z.string(),
    pubkey: hex32,
    threshold: z.number(),
    callback_url: z.string().optional(),
  }),
  recoveryMethodFinalize: z.object({
    otp: z.string(),
  }),
  recoveryMethodFinalizeResult: z.object({
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoveryMethodSet: z.object({
    mailer: hex32,
    inbox: z.string(),
    callback_url: z.string().optional(),
  }),
  recoveryMethodSetResult: z.object({
    ok: z.boolean(),
    message: z.string(),
    prev: hex32,
  }),
  recoveryStart: z.object({
    type: z.enum(Object.values(RecoveryType)),
    inbox: z.string(),
    pubkey: hex32.optional(),
    callback_url: z.string().optional(),
  }),
  recoveryStartResult: z.object({
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
    sessions: z.array(sessionItem),
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
