import * as z from "zod"
import {parseJson, switcher} from "@welshman/lib"
import type {Maybe} from "@welshman/lib"
import {Schema} from "@frostr/bifrost"

export enum Method {
  LoginChallenge = "login/challenge",
  LoginRequest = "login/request",
  LoginResult = "login/result",
  LoginSelect = "login/select",
  RecoverChallenge = "recover/challenge",
  RecoverRequest = "recover/request",
  RecoverResult = "recover/result",
  RecoverSelect = "recover/select",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SetEmailRequest = "setEmail/request",
  SetEmailResult = "setEmail/result",
  SetEmailChallenge = "setEmail/challenge",
  SignRequest = "sign/request",
  SignResult = "sign/result",
  UnregisterRequest = "unregister/request",
  ValidateRequest = "validate/request",
  ValidateResult = "validate/result",

  // EcdhRequest
  // EcdhResult
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

// Payload schemas

export const LoginRequestPayload = z.object({
  email_hash: z.string(),
  otp: z.optional(z.string()),
})

export const LoginResultPayload = z.object({
  group: z.string().optional(),
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const LoginSelectPayload = z.object({
  pubkey: z.array(z.string()),
})

export const LoginChallengePayload = z.object({
  peers: z.number(),
  client: z.string(),
  otp_ciphertext: z.string(),
  email_ciphertext: z.string(),
})

export const RecoverRequestPayload = z.object({
  email_hash: z.string(),
  otp: z.optional(z.string()),
})

export const RecoverResultPayload = z.object({
  group: z.string().optional(),
  share: z.string().optional(),
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const RecoverSelectPayload = z.object({
  pubkey: z.array(z.string()),
})

export const RecoverChallengePayload = z.object({
  peers: z.number(),
  client: z.string(),
  otp_ciphertext: z.string(),
  email_ciphertext: z.string(),
})

export const RegisterRequestPayload = z.object({
  threshold: z.int().positive(),
  share: z.string(),
  group: z.string(),
})

export const RegisterResultPayload = z.object({
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const SetEmailRequestPayload = z.object({
  email_hash: z.string(),
  email_service: z.string().length(64),
  email_ciphertext: z.string(),
  otp: z.string().optional(),
})

export const SetEmailResultPayload = z.object({
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const SetEmailChallengePayload = z.object({
  peers: z.number(),
  client: z.string(),
  otp_ciphertext: z.string(),
  email_ciphertext: z.string(),
})

export const SignRequestPayload = z.object({
  session: Schema.sign.session,
  event: z.object({
    id: z.string(),
    kind: z.number(),
    pubkey: z.string(),
    content: z.string(),
    created_at: z.int(),
    tags: z.array(z.array(z.string())),
  }),
})

export const SignResultPayload = z.object({
  psig: Schema.sign.psig_pkg.optional(),
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const UnregisterRequestPayload = z.object({
  revoke: z.enum(Object.values(RevokeScope)),
})

export const ValidateRequestPayload = z.object({
  client: z.string(),
  email_ciphertext: z.string(),
})

export const ValidateResultPayload = z.object({
  client: z.string(),
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

// Message schemas

export const LoginRequestSchema = z.object({
  method: z.literal(Method.LoginRequest),
  payload: LoginRequestPayload,
})

export const LoginResultSchema = z.object({
  method: z.literal(Method.LoginResult),
  payload: LoginResultPayload,
})

export const LoginSelectSchema = z.object({
  method: z.literal(Method.LoginSelect),
  payload: LoginSelectPayload,
})

export const LoginChallengeSchema = z.object({
  method: z.literal(Method.LoginChallenge),
  payload: LoginChallengePayload,
})

export const RecoverRequestSchema = z.object({
  method: z.literal(Method.RecoverRequest),
  payload: RecoverRequestPayload,
})

export const RecoverResultSchema = z.object({
  method: z.literal(Method.RecoverResult),
  payload: RecoverResultPayload,
})

export const RecoverSelectSchema = z.object({
  method: z.literal(Method.RecoverSelect),
  payload: RecoverSelectPayload,
})

export const RecoverChallengeSchema = z.object({
  method: z.literal(Method.RecoverChallenge),
  payload: RecoverChallengePayload,
})

export const RegisterRequestSchema = z.object({
  method: z.literal(Method.RegisterRequest),
  payload: RegisterRequestPayload,
})

export const RegisterResultSchema = z.object({
  method: z.literal(Method.RegisterResult),
  payload: RegisterResultPayload,
})

export const SetEmailRequestSchema = z.object({
  method: z.literal(Method.SetEmailRequest),
  payload: SetEmailRequestPayload,
})

export const SetEmailResultSchema = z.object({
  method: z.literal(Method.SetEmailResult),
  payload: SetEmailResultPayload,
})

export const SetEmailChallengeSchema = z.object({
  method: z.literal(Method.SetEmailChallenge),
  payload: SetEmailChallengePayload,
})

export const SignRequestSchema = z.object({
  method: z.literal(Method.SignRequest),
  payload: SignRequestPayload,
})

export const SignResultSchema = z.object({
  method: z.literal(Method.SignResult),
  payload: SignResultPayload,
})

export const UnregisterRequestSchema = z.object({
  method: z.literal(Method.UnregisterRequest),
  payload: UnregisterRequestPayload,
})

export const ValidateRequestSchema = z.object({
  method: z.literal(Method.ValidateRequest),
  payload: ValidateRequestPayload,
})

export const ValidateResultSchema = z.object({
  method: z.literal(Method.ValidateResult),
  payload: ValidateResultPayload,
})

export function getMessageSchema(method: Method) {
  return switcher(method, {
    [Method.LoginRequest]: LoginRequestSchema,
    [Method.LoginResult]: LoginResultSchema,
    [Method.LoginSelect]: LoginSelectSchema,
    [Method.LoginChallenge]: LoginChallengeSchema,
    [Method.RecoverRequest]: RecoverRequestSchema,
    [Method.RecoverResult]: RecoverResultSchema,
    [Method.RecoverSelect]: RecoverSelectSchema,
    [Method.RecoverChallenge]: RecoverChallengeSchema,
    [Method.RegisterRequest]: RegisterRequestSchema,
    [Method.RegisterResult]: RegisterResultSchema,
    [Method.SetEmailRequest]: SetEmailRequestSchema,
    [Method.SetEmailResult]: SetEmailResultSchema,
    [Method.SetEmailChallenge]: SetEmailChallengeSchema,
    [Method.SignRequest]: SignRequestSchema,
    [Method.SignResult]: SignResultSchema,
    [Method.UnregisterRequest]: UnregisterRequestSchema,
    [Method.ValidateRequest]: ValidateRequestSchema,
    [Method.ValidateResult]: ValidateResultSchema,
  })
}

// Types

export type LoginRequest = z.infer<typeof LoginRequestSchema>
export type LoginResult = z.infer<typeof LoginResultSchema>
export type LoginSelect = z.infer<typeof LoginSelectSchema>
export type LoginChallenge = z.infer<typeof LoginChallengeSchema>
export type RecoverRequest = z.infer<typeof RecoverRequestSchema>
export type RecoverResult = z.infer<typeof RecoverResultSchema>
export type RecoverSelect = z.infer<typeof RecoverSelectSchema>
export type RecoverChallenge = z.infer<typeof RecoverChallengeSchema>
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>
export type RegisterResult = z.infer<typeof RegisterResultSchema>
export type SetEmailRequest = z.infer<typeof SetEmailRequestSchema>
export type SetEmailResult = z.infer<typeof SetEmailResultSchema>
export type SetEmailChallenge = z.infer<typeof SetEmailChallengeSchema>
export type SignRequest = z.infer<typeof SignRequestSchema>
export type SignResult = z.infer<typeof SignResultSchema>
export type UnregisterRequest = z.infer<typeof UnregisterRequestSchema>
export type ValidateRequest = z.infer<typeof ValidateRequestSchema>
export type ValidateResult = z.infer<typeof ValidateResultSchema>

export type Message =
  | LoginRequest
  | LoginResult
  | LoginSelect
  | LoginChallenge
  | RecoverRequest
  | RecoverResult
  | RecoverSelect
  | RecoverChallenge
  | RegisterRequest
  | RegisterResult
  | SetEmailRequest
  | SetEmailResult
  | SetEmailChallenge
  | SignRequest
  | SignResult
  | UnregisterRequest
  | ValidateRequest
  | ValidateResult

// Construction

export function makeMessage(method: Method, payload: Record<string, unknown>): Message {
  const schema = getMessageSchema(method)

  if (!schema) {
    throw new Error(`Invalid method: ${method}`)
  }

  return schema.parse({method, payload})
}

export const makeLoginRequest = (payload: z.infer<typeof LoginRequestPayload>) =>
  makeMessage(Method.LoginRequest, payload) as LoginRequest

export const makeLoginResult = (payload: z.infer<typeof LoginResultPayload>) =>
  makeMessage(Method.LoginResult, payload) as LoginResult

export const makeLoginSelect = (payload: z.infer<typeof LoginSelectPayload>) =>
  makeMessage(Method.LoginSelect, payload) as LoginSelect

export const makeLoginChallenge = (payload: z.infer<typeof LoginChallengePayload>) =>
  makeMessage(Method.LoginChallenge, payload) as LoginChallenge

export const makeRecoverRequest = (payload: z.infer<typeof RecoverRequestPayload>) =>
  makeMessage(Method.RecoverRequest, payload) as RecoverRequest

export const makeRecoverResult = (payload: z.infer<typeof RecoverResultPayload>) =>
  makeMessage(Method.RecoverResult, payload) as RecoverResult

export const makeRecoverSelect = (payload: z.infer<typeof RecoverSelectPayload>) =>
  makeMessage(Method.RecoverSelect, payload) as RecoverSelect

export const makeRecoverChallenge = (payload: z.infer<typeof RecoverChallengePayload>) =>
  makeMessage(Method.RecoverChallenge, payload) as RecoverChallenge

export const makeRegisterRequest = (payload: z.infer<typeof RegisterRequestPayload>) =>
  makeMessage(Method.RegisterRequest, payload) as RegisterRequest

export const makeRegisterResult = (payload: z.infer<typeof RegisterResultPayload>) =>
  makeMessage(Method.RegisterResult, payload) as RegisterResult

export const makeSetEmailRequest = (payload: z.infer<typeof SetEmailRequestPayload>) =>
  makeMessage(Method.SetEmailRequest, payload) as SetEmailRequest

export const makeSetEmailResult = (payload: z.infer<typeof SetEmailResultPayload>) =>
  makeMessage(Method.SetEmailResult, payload) as SetEmailResult

export const makeSetEmailChallenge = (payload: z.infer<typeof SetEmailChallengePayload>) =>
  makeMessage(Method.SetEmailChallenge, payload) as SetEmailChallenge

export const makeSignRequest = (payload: z.infer<typeof SignRequestPayload>) =>
  makeMessage(Method.SignRequest, payload) as SignRequest

export const makeSignResult = (payload: z.infer<typeof SignResultPayload>) =>
  makeMessage(Method.SignResult, payload) as SignResult

export const makeUnregisterRequest = (payload: z.infer<typeof UnregisterRequestPayload>) =>
  makeMessage(Method.UnregisterRequest, payload) as UnregisterRequest

export const makeValidateRequest = (payload: z.infer<typeof ValidateRequestPayload>) =>
  makeMessage(Method.ValidateRequest, payload) as ValidateRequest

export const makeValidateResult = (payload: z.infer<typeof ValidateResultPayload>) =>
  makeMessage(Method.ValidateResult, payload) as ValidateResult

// Parse

export function parseMessage(s: string): Maybe<Message> {
  const message = parseJson(s)
  const result = getMessageSchema(message?.method)?.safeParse(message)

  if (result?.success) {
    return result.data
  }
}

// Type guards

export const isLoginRequest = (m: Message): m is LoginRequest => m.method === Method.LoginRequest
export const isLoginResult = (m: Message): m is LoginResult => m.method === Method.LoginResult
export const isLoginSelect = (m: Message): m is LoginSelect => m.method === Method.LoginSelect
export const isLoginChallenge = (m: Message): m is LoginChallenge =>
  m.method === Method.LoginChallenge
export const isRecoverRequest = (m: Message): m is RecoverRequest =>
  m.method === Method.RecoverRequest
export const isRecoverResult = (m: Message): m is RecoverResult => m.method === Method.RecoverResult
export const isRecoverSelect = (m: Message): m is RecoverSelect => m.method === Method.RecoverSelect
export const isRecoverChallenge = (m: Message): m is RecoverChallenge =>
  m.method === Method.RecoverChallenge
export const isRegisterRequest = (m: Message): m is RegisterRequest =>
  m.method === Method.RegisterRequest
export const isRegisterResult = (m: Message): m is RegisterResult =>
  m.method === Method.RegisterResult
export const isSetEmailRequest = (m: Message): m is SetEmailRequest =>
  m.method === Method.SetEmailRequest
export const isSetEmailResult = (m: Message): m is SetEmailResult =>
  m.method === Method.SetEmailResult
export const isSetEmailChallenge = (m: Message): m is SetEmailChallenge =>
  m.method === Method.SetEmailChallenge
export const isSignRequest = (m: Message): m is SignRequest => m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResult => m.method === Method.SignResult
export const isUnregisterRequest = (m: Message): m is UnregisterRequest =>
  m.method === Method.UnregisterRequest
export const isValidateRequest = (m: Message): m is ValidateRequest =>
  m.method === Method.ValidateRequest
export const isValidateResult = (m: Message): m is ValidateResult =>
  m.method === Method.ValidateResult
