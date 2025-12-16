import * as z from "zod"

export enum Method {
  ClientListRequest = "client/list/request",
  ClientListResult = "client/list/result",
  EcdhRequest = "ecdh/request",
  EcdhResult = "ecdh/result",
  LoginRequest = "login/request",
  LoginRequestResult = "login/request/result",
  LoginChallenge = "login/challenge",
  LoginFinalize = "login/finalize",
  LoginFinalizeResult = "login/finalize/result",
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
  UnregisterRequest = "unregister/request",
  UnregisterResult = "unregister/result",
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

export const Schema = {
  clientListRequest: z.object({
    auth: event,
  }),
  clientListResult: z.object({
    clients: z.array(
      z.object({
        client: hex32,
        email_hash: z.string().optional(),
      }),
    ),
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
  loginRequest: z.object({
    email_hash: z.string(),
    callback_url: z.string().optional(),
    pubkey: hex32.optional(),
  }),
  loginRequestResult: z.object({
    options: hex32.array().optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  loginChallenge: z.object({
    otp: z.string(),
    total: z.number(),
    client: hex32,
    email_ciphertext: z.string(),
    callback_url: z.string().optional(),
  }),
  loginFinalize: z.object({
    email_hash: z.string(),
    otp: z.string(),
  }),
  loginFinalizeResult: z.object({
    group: group.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
  recoverRequest: z.object({
    email_hash: z.string(),
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
    total: z.number(),
    client: hex32,
    email_ciphertext: z.string(),
    callback_url: z.string().optional(),
  }),
  recoverFinalize: z.object({
    email_hash: z.string(),
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
    email_hash: z.string(),
    email_service: z.string().length(64),
    email_ciphertext: z.string(),
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
    total: z.number(),
    client: hex32,
    email_ciphertext: z.string(),
    callback_url: z.string().optional(),
  }),
  setEmailFinalize: z.object({
    email_hash: z.string(),
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
  unregisterRequest: z.object({
    client: hex32,
    auth: event,
  }),
  unregisterResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: hex32,
  }),
}
