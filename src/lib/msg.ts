import * as z from 'zod'
import {parseJson, switcher} from '@welshman/lib'
import type {Maybe} from '@welshman/lib'

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

  // ConversationKeyRequest
  // ConversationKeyResult
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
  batch: z.string(),
  peers: z.number(),
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
  batch: z.string(),
  peers: z.number(),
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
  otp: z.optional(z.string()),
})

export const SetEmailResultPayload = z.object({
  status: z.enum(Object.values(Status)),
  message: z.string(),
})

export const SetEmailChallengePayload = z.object({
  batch: z.string(),
  peers: z.number(),
  otp_ciphertext: z.string(),
  email_ciphertext: z.string(),
})

export const SignRequestPayload = z.object({
  pkg: z.object({
  }),
  event: z.object({
    id: z.string(),
    pubkey: z.string(),
    content: z.string(),
    created_at: z.int(),
    tags: z.array(z.array(z.string())),
  }),
})

export const SignResultPayload = z.object({
  psig: z.object({
  }),
})

export const UnregisterRequestPayload = z.object({
  revoke: z.enum(Object.values(RevokeScope)),
})

export const ValidateRequestPayload = z.object({
  batch: z.string(),
  email_ciphertext: z.string(),
})

export const ValidateResultPayload = z.object({
  batch: z.string(),
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
  payload: SetEmailRequestPayload
})

export const SetEmailResultPSchema = z.object({
  method: z.literal(Method.SetEmailResultP),
  payload: SetEmailResultPPayload
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

export type LoginRequestMessage = z.infer<typeof LoginRequestSchema>
export type LoginResultMessage = z.infer<typeof LoginResultSchema>
export type LoginSelectMessage = z.infer<typeof LoginSelectSchema>
export type LoginChallengeMessage = z.infer<typeof LoginChallengeSchema>
export type RecoverRequestMessage = z.infer<typeof RecoverRequestSchema>
export type RecoverResultMessage = z.infer<typeof RecoverResultSchema>
export type RecoverSelectMessage = z.infer<typeof RecoverSelectSchema>
export type RecoverChallengeMessage = z.infer<typeof RecoverChallengeSchema>
export type RegisterRequestMessage = z.infer<typeof RegisterRequestSchema>
export type RegisterResultMessage = z.infer<typeof RegisterResultSchema>
export type SetEmailRequestMessage = z.infer<typeof SetEmailRequestSchema>
export type SetEmailResultMessage = z.infer<typeof SetEmailResultSchema>
export type SetEmailChallengeMessage = z.infer<typeof SetEmailChallengeSchema>
export type SignRequestMessage = z.infer<typeof SignRequestSchema>
export type SignResultMessage = z.infer<typeof SignResultSchema>
export type UnregisterRequestMessage = z.infer<typeof UnregisterRequestSchema>
export type ValidateRequestMessage = z.infer<typeof ValidateRequestSchema>
export type ValidateResultMessage = z.infer<typeof ValidateResultSchema>

export type Message =
  | LoginRequestMessage
  | LoginResultMessage
  | LoginSelectMessage
  | LoginChallengeMessage
  | RecoverRequestMessage
  | RecoverResultMessage
  | RecoverSelectMessage
  | RecoverChallengeMessage
  | RegisterRequestMessage
  | RegisterResultMessage
  | SetEmailRequestMessage
  | SetEmailResultMessage
  | SetEmailChallengeMessage
  | SignRequestMessage
  | SignResultMessage
  | UnregisterRequestMessage
  | ValidateRequestMessage
  | ValidateResultMessage

// Construction

export function makeMessage(method: Method.LoginRequest, payload: LoginRequestPayload): LoginRequestMessage
export function makeMessage(method: Method.LoginResult, payload: LoginResultPayload): LoginResultMessage
export function makeMessage(method: Method.LoginSelect, payload: LoginSelectPayload): LoginSelectMessage
export function makeMessage(method: Method.LoginChallenge, payload: LoginChallengePayload): LoginChallengeMessage
export function makeMessage(method: Method.RecoverRequest, payload: RecoverRequestPayload): RecoverRequestMessage
export function makeMessage(method: Method.RecoverResult, payload: RecoverResultPayload): RecoverResultMessage
export function makeMessage(method: Method.RecoverSelect, payload: RecoverSelectPayload): RecoverSelectMessage
export function makeMessage(method: Method.RecoverChallenge, payload: RecoverChallengePayload): RecoverChallengeMessage
export function makeMessage(method: Method.RegisterRequest, payload: RegisterRequestPayload): RegisterRequestMessage
export function makeMessage(method: Method.RegisterResult, payload: RegisterResultPayload): RegisterResultMessage
export function makeMessage(method: Method.SetEmailRequestMessage, payload: SetEmailRequestPayload): SetEmailRequestMessage
export function makeMessage(method: Method.SetEmailResultMessage, payload: SetEmailResultPayload): SetEmailResultMessage
export function makeMessage(method: Method.SetEmailChallengeMessage, payload: SetEmailChallengePayload): SetEmailChallengeMessage
export function makeMessage(method: Method.SignRequest, payload: SignRequestPayload): SignRequestMessage
export function makeMessage(method: Method.SignResult, payload: SignResultPayload): SignResultMessage
export function makeMessage(method: Method.UnregisterRequest, payload: UnregisterRequestPayload): UnregisterRequestMessage
export function makeMessage(method: Method.ValidateRequest, payload: ValidateRequestPayload): ValidateRequestMessage
export function makeMessage(method: Method.ValidateResult, payload: ValidateResultPayload): ValidateResultMessage
export function makeMessage(method: Method, payload: Record<string, unknown>): Maybe<Message> {
  const schema = getMessageSchema(method)

  if (schema) {
    const result = schema.parse({method, payload})

    if (result.success) {
      return result.data
    }
  }
}

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
export const isLoginChallenge = (m: Message): m is LoginChallenge => m.method === Method.LoginChallenge
export const isRecoverRequest = (m: Message): m is RecoverRequest => m.method === Method.RecoverRequest
export const isRecoverResult = (m: Message): m is RecoverResult => m.method === Method.RecoverResult
export const isRecoverSelect = (m: Message): m is RecoverSelect => m.method === Method.RecoverSelect
export const isRecoverChallenge = (m: Message): m is RecoverChallenge => m.method === Method.RecoverChallenge
export const isRegisterRequest = (m: Message): m is RegisterRequest => m.method === Method.RegisterRequest
export const isRegisterResult = (m: Message): m is RegisterResult => m.method === Method.RegisterResult
export const isSetEmailRequest, (m: Message): m is SetEmailRequest => m.method === Method.SetEmailRequest
export const isSetEmailResult, (m: Message): m is SetEmailResult => m.method === Method.SetEmailResult
export const isSetEmailChallenge, (m: Message): m is SetEmailChallenge => m.method === Method.SetEmailChallenge
export const isSignRequest = (m: Message): m is SignRequest => m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResult => m.method === Method.SignResult
export const isUnregisterRequest = (m: Message): m is UnregisterRequest => m.method === Method.UnregisterRequest
export const isValidateRequest = (m: Message): m is ValidateRequest => m.method === Method.ValidateRequest
export const isValidateResult = (m: Message): m is ValidateResult => m.method === Method.ValidateResult
