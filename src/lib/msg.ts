import * as z from 'zod'
import {parseJson, switcher} from '@welshman/lib'
import type {Maybe} from '@welshman/lib'

export enum Method {
  LoginConfirm = "login/confirm",
  LoginRequest = "login/request",
  LoginResult = "login/result",
  LoginSelect = "login/select",
  LoginShare = "login/share",
  RecoverRequest = "recover/request",
  RecoverSelect = "recover/select",
  RecoverShare = "recover/share",
  RegisterRequest = "register/request",
  RegisterResult = "register/result",
  SignRequest = "sign/request",
  SignResult = "sign/result",
  UnregisterRequest = "unregister/request",
  ValidateRequest = "validate/request",
  ValidateResult = "validate/result",
}

// Schemas

export const LoginConfirmPayload = z.object({
})

export const LoginRequestPayload = z.object({
})

export const LoginResultPayload = z.object({
})

export const LoginSelectPayload = z.object({
})

export const LoginSharePayload = z.object({
})

export const RecoverRequestPayload = z.object({
})

export const RecoverSelectPayload = z.object({
})

export const RecoverSharePayload = z.object({
})

export const RegisterRequestPayload = z.object({
  threshold: z.int().positive(),
  share: z.string(),
  group: z.string(),
  email_hash: z.string(),
  email_service: z.string().length(64),
  email_ciphertext: z.string(),
}),


export const RegisterResultPayload = z.object({
})

export const SignRequestPayload = z.object({
})

export const SignResultPayload = z.object({
})

export const UnregisterRequestPayload = z.object({
})

export const ValidateRequestPayload = z.object({
})

export const ValidateResultPayload = z.object({
})

export const LoginConfirmSchema = z.object({
  method: z.literal(Method.LoginConfirm),
  payload: LoginConfirmPayload,
})

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

export const LoginShareSchema = z.object({
  method: z.literal(Method.LoginShare),
  payload: LoginSharePayload,
})

export const RecoverRequestSchema = z.object({
  method: z.literal(Method.RecoverRequest),
  payload: RecoverRequestPayload,
})

export const RecoverSelectSchema = z.object({
  method: z.literal(Method.RecoverSelect),
  payload: RecoverSelectPayload,
})

export const RecoverShareSchema = z.object({
  method: z.literal(Method.RecoverShare),
  payload: RecoverSharePayload,
})

export const RegisterRequestSchema = z.object({
  method: z.literal(Method.RegisterRequest),
  payload: RegisterRequestPayload,
})

export const RegisterResultSchema = z.object({
  method: z.literal(Method.RegisterResult),
  payload: RegisterResultPayload,
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
    [Method.LoginConfirm]: LoginConfirmSchema,
    [Method.LoginRequest]: LoginRequestSchema,
    [Method.LoginResult]: LoginResultSchema,
    [Method.LoginSelect]: LoginSelectSchema,
    [Method.LoginShare]: LoginShareSchema,
    [Method.RecoverRequest]: RecoverRequestSchema,
    [Method.RecoverSelect]: RecoverSelectSchema,
    [Method.RecoverShare]: RecoverShareSchema,
    [Method.RegisterRequest]: RegisterRequestSchema,
    [Method.RegisterResult]: RegisterResultSchema,
    [Method.SignRequest]: SignRequestSchema,
    [Method.SignResult]: SignResultSchema,
    [Method.UnregisterRequest]: UnregisterRequestSchema,
    [Method.ValidateRequest]: ValidateRequestSchema,
    [Method.ValidateResult]: ValidateResultSchema,
  })
}

// Types

export type LoginConfirmMessage = z.infer<typeof LoginConfirmSchema>
export type LoginRequestMessage = z.infer<typeof LoginRequestSchema>
export type LoginResultMessage = z.infer<typeof LoginResultSchema>
export type LoginSelectMessage = z.infer<typeof LoginSelectSchema>
export type LoginShareMessage = z.infer<typeof LoginShareSchema>
export type RecoverRequestMessage = z.infer<typeof RecoverRequestSchema>
export type RecoverSelectMessage = z.infer<typeof RecoverSelectSchema>
export type RecoverShareMessage = z.infer<typeof RecoverShareSchema>
export type RegisterRequestMessage = z.infer<typeof RegisterRequestSchema>
export type RegisterResultMessage = z.infer<typeof RegisterResultSchema>
export type SignRequestMessage = z.infer<typeof SignRequestSchema>
export type SignResultMessage = z.infer<typeof SignResultSchema>
export type UnregisterRequestMessage = z.infer<typeof UnregisterRequestSchema>
export type ValidateRequestMessage = z.infer<typeof ValidateRequestSchema>
export type ValidateResultMessage = z.infer<typeof ValidateResultSchema>

export type Message =
  | LoginConfirmMessage
  | LoginRequestMessage
  | LoginResultMessage
  | LoginSelectMessage
  | LoginShareMessage
  | RecoverRequestMessage
  | RecoverSelectMessage
  | RecoverShareMessage
  | RegisterRequestMessage
  | RegisterResultMessage
  | SignRequestMessage
  | SignResultMessage
  | UnregisterRequestMessage
  | ValidateRequestMessage
  | ValidateResultMessage

// Construction

export function makeMessage(method: Method.LoginConfirm, payload: LoginConfirmPayload): LoginConfirmMessage
export function makeLoginConfirm(method: Method.LoginConfirm, payload: LoginConfirmPayload): LoginConfirmMessage
export function makeLoginRequest(method: Method.LoginRequest, payload: LoginRequestPayload): LoginRequestMessage
export function makeLoginResult(method: Method.LoginResult, payload: LoginResultPayload): LoginResultMessage
export function makeLoginSelect(method: Method.LoginSelect, payload: LoginSelectPayload): LoginSelectMessage
export function makeLoginShare(method: Method.LoginShare, payload: LoginSharePayload): LoginShareMessage
export function makeRecoverRequest(method: Method.RecoverRequest, payload: RecoverRequestPayload): RecoverRequestMessage
export function makeRecoverSelect(method: Method.RecoverSelect, payload: RecoverSelectPayload): RecoverSelectMessage
export function makeRecoverShare(method: Method.RecoverShare, payload: RecoverSharePayload): RecoverShareMessage
export function makeRegisterRequest(method: Method.RegisterRequest, payload: RegisterRequestPayload): RegisterRequestMessage
export function makeRegisterResult(method: Method.RegisterResult, payload: RegisterResultPayload): RegisterResultMessage
export function makeSignRequest(method: Method.SignRequest, payload: SignRequestPayload): SignRequestMessage
export function makeSignResult(method: Method.SignResult, payload: SignResultPayload): SignResultMessage
export function makeUnregisterRequest(method: Method.UnregisterRequest, payload: UnregisterRequestPayload): UnregisterRequestMessage
export function makeValidateRequest(method: Method.ValidateRequest, payload: ValidateRequestPayload): ValidateRequestMessage
export function makeValidateResult(method: Method.ValidateResult, payload: ValidateResultPayload): ValidateResultMessage
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
