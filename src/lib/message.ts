import * as z from "zod"
import {parseJson, switcher} from "@welshman/lib"
import type {Maybe} from "@welshman/lib"
import {Schema, Method} from "./schema"

// Message types

type DefineMessage<M, P> = {method: M; payload: z.infer<P>}

export type SessionListRequest = DefineMessage<
  Method.SessionListRequest,
  typeof Schema.sessionListRequest
>
export type SessionListResult = DefineMessage<
  Method.SessionListResult,
  typeof Schema.sessionListResult
>
export type EcdhRequest = DefineMessage<Method.EcdhRequest, typeof Schema.ecdhRequest>
export type EcdhResult = DefineMessage<Method.EcdhResult, typeof Schema.ecdhResult>
export type LoginRequest = DefineMessage<Method.LoginRequest, typeof Schema.loginRequest>
export type LoginRequestResult = DefineMessage<
  Method.LoginRequestResult,
  typeof Schema.loginRequestResult
>
export type LoginChallenge = DefineMessage<Method.LoginChallenge, typeof Schema.loginChallenge>
export type LoginFinalize = DefineMessage<Method.LoginFinalize, typeof Schema.loginFinalize>
export type LoginFinalizeResult = DefineMessage<
  Method.LoginFinalizeResult,
  typeof Schema.loginFinalizeResult
>
export type RecoverRequest = DefineMessage<Method.RecoverRequest, typeof Schema.recoverRequest>
export type RecoverRequestResult = DefineMessage<
  Method.RecoverRequestResult,
  typeof Schema.recoverRequestResult
>
export type RecoverChallenge = DefineMessage<
  Method.RecoverChallenge,
  typeof Schema.recoverChallenge
>
export type RecoverFinalize = DefineMessage<Method.RecoverFinalize, typeof Schema.recoverFinalize>
export type RecoverFinalizeResult = DefineMessage<
  Method.RecoverFinalizeResult,
  typeof Schema.recoverFinalizeResult
>
export type RegisterRequest = DefineMessage<Method.RegisterRequest, typeof Schema.registerRequest>
export type RegisterResult = DefineMessage<Method.RegisterResult, typeof Schema.registerResult>
export type SetEmailRequest = DefineMessage<Method.SetEmailRequest, typeof Schema.setEmailRequest>
export type SetEmailRequestResult = DefineMessage<
  Method.SetEmailRequestResult,
  typeof Schema.setEmailRequestResult
>
export type SetEmailChallenge = DefineMessage<
  Method.SetEmailChallenge,
  typeof Schema.setEmailChallenge
>
export type SetEmailFinalize = DefineMessage<
  Method.SetEmailFinalize,
  typeof Schema.setEmailFinalize
>
export type SetEmailFinalizeResult = DefineMessage<
  Method.SetEmailFinalizeResult,
  typeof Schema.setEmailFinalizeResult
>
export type SignRequest = DefineMessage<Method.SignRequest, typeof Schema.signRequest>
export type SignResult = DefineMessage<Method.SignResult, typeof Schema.signResult>
export type UnregisterRequest = DefineMessage<
  Method.UnregisterRequest,
  typeof Schema.unregisterRequest
>
export type UnregisterResult = DefineMessage<
  Method.UnregisterResult,
  typeof Schema.unregisterResult
>

export type Message =
  | SessionListRequest
  | SessionListResult
  | EcdhRequest
  | EcdhResult
  | LoginRequest
  | LoginRequestResult
  | LoginChallenge
  | LoginFinalize
  | LoginFinalizeResult
  | RecoverRequest
  | RecoverRequestResult
  | RecoverChallenge
  | RecoverFinalize
  | RecoverFinalizeResult
  | RegisterRequest
  | RegisterResult
  | SetEmailRequest
  | SetEmailRequestResult
  | SetEmailChallenge
  | SetEmailFinalize
  | SetEmailFinalizeResult
  | SignRequest
  | SignResult
  | UnregisterRequest
  | UnregisterResult

// Construction

export function makeSessionListRequest(payload: SessionListRequest["payload"]): SessionListRequest {
  return {method: Method.SessionListRequest, payload: Schema.sessionListRequest.parse(payload)}
}

export function makeSessionListResult(payload: SessionListResult["payload"]): SessionListResult {
  return {method: Method.SessionListResult, payload: Schema.sessionListResult.parse(payload)}
}

export function makeEcdhRequest(payload: EcdhRequest["payload"]): EcdhRequest {
  return {method: Method.EcdhRequest, payload: Schema.ecdhRequest.parse(payload)}
}

export function makeEcdhResult(payload: EcdhResult["payload"]): EcdhResult {
  return {method: Method.EcdhResult, payload: Schema.ecdhResult.parse(payload)}
}

export function makeLoginRequest(payload: LoginRequest["payload"]): LoginRequest {
  return {method: Method.LoginRequest, payload: Schema.loginRequest.parse(payload)}
}

export function makeLoginRequestResult(payload: LoginRequestResult["payload"]): LoginRequestResult {
  return {method: Method.LoginRequestResult, payload: Schema.loginRequestResult.parse(payload)}
}

export function makeLoginChallenge(payload: LoginChallenge["payload"]): LoginChallenge {
  return {method: Method.LoginChallenge, payload: Schema.loginChallenge.parse(payload)}
}

export function makeLoginFinalize(payload: LoginFinalize["payload"]): LoginFinalize {
  return {method: Method.LoginFinalize, payload: Schema.loginFinalize.parse(payload)}
}

export function makeLoginFinalizeResult(
  payload: LoginFinalizeResult["payload"],
): LoginFinalizeResult {
  return {method: Method.LoginFinalizeResult, payload: Schema.loginFinalizeResult.parse(payload)}
}

export function makeRecoverRequest(payload: RecoverRequest["payload"]): RecoverRequest {
  return {method: Method.RecoverRequest, payload: Schema.recoverRequest.parse(payload)}
}

export function makeRecoverRequestResult(
  payload: RecoverRequestResult["payload"],
): RecoverRequestResult {
  return {method: Method.RecoverRequestResult, payload: Schema.recoverRequestResult.parse(payload)}
}

export function makeRecoverChallenge(payload: RecoverChallenge["payload"]): RecoverChallenge {
  return {method: Method.RecoverChallenge, payload: Schema.recoverChallenge.parse(payload)}
}

export function makeRecoverFinalize(payload: RecoverFinalize["payload"]): RecoverFinalize {
  return {method: Method.RecoverFinalize, payload: Schema.recoverFinalize.parse(payload)}
}

export function makeRecoverFinalizeResult(
  payload: RecoverFinalizeResult["payload"],
): RecoverFinalizeResult {
  return {
    method: Method.RecoverFinalizeResult,
    payload: Schema.recoverFinalizeResult.parse(payload),
  }
}

export function makeRegisterRequest(payload: RegisterRequest["payload"]): RegisterRequest {
  return {method: Method.RegisterRequest, payload: Schema.registerRequest.parse(payload)}
}

export function makeRegisterResult(payload: RegisterResult["payload"]): RegisterResult {
  return {method: Method.RegisterResult, payload: Schema.registerResult.parse(payload)}
}

export function makeSetEmailRequest(payload: SetEmailRequest["payload"]): SetEmailRequest {
  return {method: Method.SetEmailRequest, payload: Schema.setEmailRequest.parse(payload)}
}

export function makeSetEmailRequestResult(
  payload: SetEmailRequestResult["payload"],
): SetEmailRequestResult {
  return {
    method: Method.SetEmailRequestResult,
    payload: Schema.setEmailRequestResult.parse(payload),
  }
}

export function makeSetEmailChallenge(payload: SetEmailChallenge["payload"]): SetEmailChallenge {
  return {method: Method.SetEmailChallenge, payload: Schema.setEmailChallenge.parse(payload)}
}

export function makeSetEmailFinalize(payload: SetEmailFinalize["payload"]): SetEmailFinalize {
  return {method: Method.SetEmailFinalize, payload: Schema.setEmailFinalize.parse(payload)}
}

export function makeSetEmailFinalizeResult(
  payload: SetEmailFinalizeResult["payload"],
): SetEmailFinalizeResult {
  return {
    method: Method.SetEmailFinalizeResult,
    payload: Schema.setEmailFinalizeResult.parse(payload),
  }
}

export function makeSignRequest(payload: SignRequest["payload"]): SignRequest {
  return {method: Method.SignRequest, payload: Schema.signRequest.parse(payload)}
}

export function makeSignResult(payload: SignResult["payload"]): SignResult {
  return {method: Method.SignResult, payload: Schema.signResult.parse(payload)}
}

export function makeUnregisterRequest(payload: UnregisterRequest["payload"]): UnregisterRequest {
  return {method: Method.UnregisterRequest, payload: Schema.unregisterRequest.parse(payload)}
}

export function makeUnregisterResult(payload: UnregisterResult["payload"]): UnregisterResult {
  return {method: Method.UnregisterResult, payload: Schema.unregisterResult.parse(payload)}
}

// Parsing

export function getMessageSchema(method: Method) {
  return switcher(method, {
    [Method.SessionListRequest]: Schema.sessionListRequest,
    [Method.SessionListResult]: Schema.sessionListResult,
    [Method.EcdhRequest]: Schema.ecdhRequest,
    [Method.EcdhResult]: Schema.ecdhResult,
    [Method.LoginRequest]: Schema.loginRequest,
    [Method.LoginRequestResult]: Schema.loginRequestResult,
    [Method.LoginChallenge]: Schema.loginChallenge,
    [Method.LoginFinalize]: Schema.loginFinalize,
    [Method.LoginFinalizeResult]: Schema.loginFinalizeResult,
    [Method.RecoverRequest]: Schema.recoverRequest,
    [Method.RecoverRequestResult]: Schema.recoverRequestResult,
    [Method.RecoverChallenge]: Schema.recoverChallenge,
    [Method.RecoverFinalize]: Schema.recoverFinalize,
    [Method.RecoverFinalizeResult]: Schema.recoverFinalizeResult,
    [Method.RegisterRequest]: Schema.registerRequest,
    [Method.RegisterResult]: Schema.registerResult,
    [Method.SetEmailRequest]: Schema.setEmailRequest,
    [Method.SetEmailRequestResult]: Schema.setEmailRequestResult,
    [Method.SetEmailChallenge]: Schema.setEmailChallenge,
    [Method.SetEmailFinalize]: Schema.setEmailFinalize,
    [Method.SetEmailFinalizeResult]: Schema.setEmailFinalizeResult,
    [Method.SignRequest]: Schema.signRequest,
    [Method.SignResult]: Schema.signResult,
    [Method.UnregisterRequest]: Schema.unregisterRequest,
    [Method.UnregisterResult]: Schema.unregisterResult,
  })
}

export function parseMessage(s: string): Maybe<Message> {
  const message = parseJson(s)
  const result = getMessageSchema(message?.method)?.safeParse(message.payload)

  if (result?.success) {
    return {method: message.method, payload: result.data} as Message
  }
}

// Type guards

export const isSessionListRequest = (m: Message): m is SessionListRequest =>
  m.method === Method.SessionListRequest
export const isSessionListResult = (m: Message): m is SessionListResult =>
  m.method === Method.SessionListResult
export const isEcdhRequest = (m: Message): m is EcdhRequest => m.method === Method.EcdhRequest
export const isEcdhResult = (m: Message): m is EcdhResult => m.method === Method.EcdhResult
export const isLoginRequest = (m: Message): m is LoginRequest => m.method === Method.LoginRequest
export const isLoginRequestResult = (m: Message): m is LoginRequestResult =>
  m.method === Method.LoginRequestResult
export const isLoginChallenge = (m: Message): m is LoginChallenge =>
  m.method === Method.LoginChallenge
export const isLoginFinalize = (m: Message): m is LoginFinalize => m.method === Method.LoginFinalize
export const isLoginFinalizeResult = (m: Message): m is LoginFinalizeResult =>
  m.method === Method.LoginFinalizeResult
export const isRecoverRequest = (m: Message): m is RecoverRequest =>
  m.method === Method.RecoverRequest
export const isRecoverRequestResult = (m: Message): m is RecoverRequestResult =>
  m.method === Method.RecoverRequestResult
export const isRecoverChallenge = (m: Message): m is RecoverChallenge =>
  m.method === Method.RecoverChallenge
export const isRecoverFinalize = (m: Message): m is RecoverFinalize =>
  m.method === Method.RecoverFinalize
export const isRecoverFinalizeResult = (m: Message): m is RecoverFinalizeResult =>
  m.method === Method.RecoverFinalizeResult
export const isRegisterRequest = (m: Message): m is RegisterRequest =>
  m.method === Method.RegisterRequest
export const isRegisterResult = (m: Message): m is RegisterResult =>
  m.method === Method.RegisterResult
export const isSetEmailRequest = (m: Message): m is SetEmailRequest =>
  m.method === Method.SetEmailRequest
export const isSetEmailRequestResult = (m: Message): m is SetEmailRequestResult =>
  m.method === Method.SetEmailRequestResult
export const isSetEmailChallenge = (m: Message): m is SetEmailChallenge =>
  m.method === Method.SetEmailChallenge
export const isSetEmailFinalize = (m: Message): m is SetEmailFinalize =>
  m.method === Method.SetEmailFinalize
export const isSetEmailFinalizeResult = (m: Message): m is SetEmailFinalizeResult =>
  m.method === Method.SetEmailFinalizeResult
export const isSignRequest = (m: Message): m is SignRequest => m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResult => m.method === Method.SignResult
export const isUnregisterRequest = (m: Message): m is UnregisterRequest =>
  m.method === Method.UnregisterRequest
export const isUnregisterResult = (m: Message): m is UnregisterResult =>
  m.method === Method.UnregisterResult
