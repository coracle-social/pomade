import * as z from "zod"

export enum Method {
  SessionListRequest = "session/list/request",
  SessionListResult = "session/list/result",
  EcdhRequest = "ecdh/request",
  EcdhResult = "ecdh/result",
  RecoverRequest = "recover/request",
  RecoverRequestResult = "recover/request/result",
  RecoverChallenge = "recover/challenge",
  RecoverFinalize = "recover/finalize",
  RecoverFinalizeResult = "recover/finalize/result",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SetEmailRequest = "setEmail/request",
  SetEmailRequestResult = "setEmail/request/result",
  SetEmailChallenge = "setEmail/challenge",
  SetEmailFinalize = "setEmail/finalize",
  SetEmailFinalizeResult = "setEmail/finalize/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
  LogoutRequest = "logout/request",
  LogoutResult = "logout/result",
}

export enum Status {
  Ok = "ok",
  Error = "error",
  Pending = "pending",
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

const ecdh = z.object({
  idx: z.number(),
  keyshare: hex,
  members: z.number().array(),
  ecdh_pk: hex,
})

const psig_entry = z.tuple([hex32, hex32])
const sighash_vec = z.tuple([hex32]).rest(hex32)

const template = z.object({
  content: z.string().nullable(),
  hashes: sighash_vec.array(),
  members: z.number().array(),
  stamp: z.number(),
  type: z.string(),
})

const session = template.extend({
  gid: hex32,
  sid: hex32,
})

const psig = z.object({
  idx: z.number(),
  psigs: psig_entry.array(),
  pubkey: hex33,
  sid: hex32,
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
  client: hex32,
  email: z.string().optional(),
  created_at: z.int().positive(),
  last_activity: z.int().positive(),
})

export const Schema = {
  sessionItem,
  sessionListRequest: z.object({
    auth: event,
  }),
  sessionListResult: z.object({
    sessions: z.array(sessionItem),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  ecdhRequest: z.object({
    idx: z.number(),
    members: z.number().array(),
    ecdh_pk: hex32,
  }),
  ecdhResult: z.object({
    result: ecdh.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  recoverRequest: z.object({
    email: z.string(),
    callback_url: z.string().optional(),
    pubkey: hex32.optional(),
  }),
  recoverRequestResult: z.object({
    options: hex32.array().optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  recoverChallenge: z.object({
    otp: z.string(),
    email: z.string(),
    client: hex32,
    threshold: z.number(),
    callback_url: z.string().optional(),
  }),
  recoverFinalize: z.object({
    email: z.string(),
    otp: z.string(),
  }),
  recoverFinalizeResult: z.object({
    group: group.optional(),
    share: share.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  registerRequest: z.object({
    threshold: z.int().positive(),
    share: share,
    group: group,
  }),
  registerResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  setEmailRequest: z.object({
    email: z.string(),
    email_service: hex32,
    callback_url: z.string().optional(),
    pubkey: hex32.optional(),
  }),
  setEmailRequestResult: z.object({
    options: hex32.array().optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  setEmailChallenge: z.object({
    otp: z.string(),
    threshold: z.number(),
    email: z.string(),
    client: hex32,
    callback_url: z.string().optional(),
  }),
  setEmailFinalize: z.object({
    email: z.string(),
    otp: z.string(),
  }),
  setEmailFinalizeResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  signRequest: z.object({
    session: session,
  }),
  signResult: z.object({
    result: psig.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  logoutRequest: z.object({
    client: hex32,
    auth: event,
  }),
  logoutResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
}
