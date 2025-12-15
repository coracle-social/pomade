import * as z from "zod"
import {Schema as Bifrost} from "@frostr/bifrost"

export enum Method {
  EcdhRequest = "ecdh/request",
  EcdhResult = "ecdh/result",
  LoginRequest = "login/request",
  LoginRequestResult = "login/request/result",
  LoginRequestSelect = "login/request/select",
  LoginChallenge = "login/challenge",
  LoginFinalize = "login/finalize",
  LoginFinalizeResult = "login/finalize/result",
  RecoverRequest = "recover/request",
  RecoverRequestResult = "recover/request/result",
  RecoverRequestSelect = "recover/request/select",
  RecoverChallenge = "recover/challenge",
  RecoverFinalize = "recover/finalize",
  RecoverFinalizeResult = "recover/finalize/result",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SetEmailRequest = "setEmail/request",
  SetEmailRequestResult = "setEmail/request/result",
  SetEmailRequestSelect = "setEmail/request/select",
  SetEmailChallenge = "setEmail/challenge",
  SetEmailFinalize = "setEmail/finalize",
  SetEmailFinalizeResult = "setEmail/finalize/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
  UnregisterRequest = "unregister/request",
  UnregisterResult = "unregister/result",
}

export enum RevokeScope {
  All = "all",
  Others = "others",
  Current = "current",
}

export enum Status {
  Ok = "ok",
  Error = "error",
  Pending = "pending",
}

export const Schema = {
  ecdhRequest: z.object({
    idx: z.number(),
    members: z.number().array(),
    ecdh_pk: Bifrost.base.hex32,
  }),
  ecdhResult: z.object({
    result: Bifrost.pkg.ecdh.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  loginRequest: z.object({
    email_hash: z.string(),
  }),
  loginRequestResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  loginRequestSelect: z.object({
    options: z.string().array(),
    prev: Bifrost.base.hex32,
  }),
  loginChallenge: z.object({
    otp: z.string(),
    index: z.number(),
    total: z.number(),
    client: z.string(),
    email_ciphertext: z.string(),
  }),
  loginFinalize: z.object({
    email_hash: z.string(),
    otp: z.string(),
  }),
  loginResult: z.object({
    group: z.string().optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  recoverRequest: z.object({
    email_hash: z.string(),
  }),
  recoverRequestResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  recoverRequestSelect: z.object({
    options: z.string().array(),
    prev: Bifrost.base.hex32,
  }),
  recoverChallenge: z.object({
    otp: z.string(),
    index: z.number(),
    total: z.number(),
    client: z.string(),
    email_ciphertext: z.string(),
  }),
  recoverFinalize: z.object({
    email_hash: z.string(),
    otp: z.string(),
  }),
  recoverResult: z.object({
    group: z.string().optional(),
    share: z.string().optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  registerRequest: z.object({
    threshold: z.int().positive(),
    share: z.string(),
    group: z.string(),
  }),
  registerResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  setEmailRequest: z.object({
    email_hash: z.string(),
    email_service: z.string().length(64),
    email_ciphertext: z.string(),
  }),
  setEmailRequestResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  setEmailRequestSelect: z.object({
    options: z.string().array(),
    prev: Bifrost.base.hex32,
  }),
  setEmailChallenge: z.object({
    otp: z.string(),
    index: z.number(),
    total: z.number(),
    client: z.string(),
    email_ciphertext: z.string(),
  }),
  setEmailFinalize: z.object({
    email_hash: z.string(),
    otp: z.string(),
  }),
  setEmailResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  signRequest: z.object({
    session: Bifrost.sign.session,
  }),
  signResult: z.object({
    result: Bifrost.sign.psig_pkg.optional(),
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
  unregisterRequest: z.object({
    revoke: z.enum(Object.values(RevokeScope)),
  }),
  unregisterResult: z.object({
    status: z.enum(Object.values(Status)),
    message: z.string(),
    prev: Bifrost.base.hex32,
  }),
}
