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
export type SetRecoveryMethodRequest = DefineMessage<
  Method.SetRecoveryMethodRequest,
  typeof Schema.setRecoveryMethodRequest
>
export type SetRecoveryMethodRequestResult = DefineMessage<
  Method.SetRecoveryMethodRequestResult,
  typeof Schema.setRecoveryMethodRequestResult
>
export type SetRecoveryMethodChallenge = DefineMessage<
  Method.SetRecoveryMethodChallenge,
  typeof Schema.setRecoveryMethodChallenge
>
export type SetRecoveryMethodFinalize = DefineMessage<
  Method.SetRecoveryMethodFinalize,
  typeof Schema.setRecoveryMethodFinalize
>
export type SetRecoveryMethodFinalizeResult = DefineMessage<
  Method.SetRecoveryMethodFinalizeResult,
  typeof Schema.setRecoveryMethodFinalizeResult
>
export type SignRequest = DefineMessage<Method.SignRequest, typeof Schema.signRequest>
export type SignResult = DefineMessage<Method.SignResult, typeof Schema.signResult>
export type LogoutRequest = DefineMessage<Method.LogoutRequest, typeof Schema.logoutRequest>
export type LogoutResult = DefineMessage<Method.LogoutResult, typeof Schema.logoutResult>

export type Message =
  | SessionListRequest
  | SessionListResult
  | EcdhRequest
  | EcdhResult
  | RecoverRequest
  | RecoverRequestResult
  | RecoverChallenge
  | RecoverFinalize
  | RecoverFinalizeResult
  | RegisterRequest
  | RegisterResult
  | SetRecoveryMethodRequest
  | SetRecoveryMethodRequestResult
  | SetRecoveryMethodChallenge
  | SetRecoveryMethodFinalize
  | SetRecoveryMethodFinalizeResult
  | SignRequest
  | SignResult
  | LogoutRequest
  | LogoutResult

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

export function makeSetRecoveryMethodRequest(
  payload: SetRecoveryMethodRequest["payload"],
): SetRecoveryMethodRequest {
  return {
    method: Method.SetRecoveryMethodRequest,
    payload: Schema.setRecoveryMethodRequest.parse(payload),
  }
}

export function makeSetRecoveryMethodRequestResult(
  payload: SetRecoveryMethodRequestResult["payload"],
): SetRecoveryMethodRequestResult {
  return {
    method: Method.SetRecoveryMethodRequestResult,
    payload: Schema.setRecoveryMethodRequestResult.parse(payload),
  }
}

export function makeSetRecoveryMethodChallenge(
  payload: SetRecoveryMethodChallenge["payload"],
): SetRecoveryMethodChallenge {
  return {
    method: Method.SetRecoveryMethodChallenge,
    payload: Schema.setRecoveryMethodChallenge.parse(payload),
  }
}

export function makeSetRecoveryMethodFinalize(
  payload: SetRecoveryMethodFinalize["payload"],
): SetRecoveryMethodFinalize {
  return {
    method: Method.SetRecoveryMethodFinalize,
    payload: Schema.setRecoveryMethodFinalize.parse(payload),
  }
}

export function makeSetRecoveryMethodFinalizeResult(
  payload: SetRecoveryMethodFinalizeResult["payload"],
): SetRecoveryMethodFinalizeResult {
  return {
    method: Method.SetRecoveryMethodFinalizeResult,
    payload: Schema.setRecoveryMethodFinalizeResult.parse(payload),
  }
}

export function makeSignRequest(payload: SignRequest["payload"]): SignRequest {
  return {method: Method.SignRequest, payload: Schema.signRequest.parse(payload)}
}

export function makeSignResult(payload: SignResult["payload"]): SignResult {
  return {method: Method.SignResult, payload: Schema.signResult.parse(payload)}
}

export function makeLogoutRequest(payload: LogoutRequest["payload"]): LogoutRequest {
  return {method: Method.LogoutRequest, payload: Schema.logoutRequest.parse(payload)}
}

export function makeLogoutResult(payload: LogoutResult["payload"]): LogoutResult {
  return {method: Method.LogoutResult, payload: Schema.logoutResult.parse(payload)}
}

// Parsing

export function getMessageSchema(method: Method) {
  return switcher(method, {
    [Method.SessionListRequest]: Schema.sessionListRequest,
    [Method.SessionListResult]: Schema.sessionListResult,
    [Method.EcdhRequest]: Schema.ecdhRequest,
    [Method.EcdhResult]: Schema.ecdhResult,
    [Method.RecoverRequest]: Schema.recoverRequest,
    [Method.RecoverRequestResult]: Schema.recoverRequestResult,
    [Method.RecoverChallenge]: Schema.recoverChallenge,
    [Method.RecoverFinalize]: Schema.recoverFinalize,
    [Method.RecoverFinalizeResult]: Schema.recoverFinalizeResult,
    [Method.RegisterRequest]: Schema.registerRequest,
    [Method.RegisterResult]: Schema.registerResult,
    [Method.SetRecoveryMethodRequest]: Schema.setRecoveryMethodRequest,
    [Method.SetRecoveryMethodRequestResult]: Schema.setRecoveryMethodRequestResult,
    [Method.SetRecoveryMethodChallenge]: Schema.setRecoveryMethodChallenge,
    [Method.SetRecoveryMethodFinalize]: Schema.setRecoveryMethodFinalize,
    [Method.SetRecoveryMethodFinalizeResult]: Schema.setRecoveryMethodFinalizeResult,
    [Method.SignRequest]: Schema.signRequest,
    [Method.SignResult]: Schema.signResult,
    [Method.LogoutRequest]: Schema.logoutRequest,
    [Method.LogoutResult]: Schema.logoutResult,
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
export const isSetRecoveryMethodRequest = (m: Message): m is SetRecoveryMethodRequest =>
  m.method === Method.SetRecoveryMethodRequest
export const isSetRecoveryMethodRequestResult = (m: Message): m is SetRecoveryMethodRequestResult =>
  m.method === Method.SetRecoveryMethodRequestResult
export const isSetRecoveryMethodChallenge = (m: Message): m is SetRecoveryMethodChallenge =>
  m.method === Method.SetRecoveryMethodChallenge
export const isSetRecoveryMethodFinalize = (m: Message): m is SetRecoveryMethodFinalize =>
  m.method === Method.SetRecoveryMethodFinalize
export const isSetRecoveryMethodFinalizeResult = (
  m: Message,
): m is SetRecoveryMethodFinalizeResult => m.method === Method.SetRecoveryMethodFinalizeResult
export const isSignRequest = (m: Message): m is SignRequest => m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResult => m.method === Method.SignResult
export const isLogoutRequest = (m: Message): m is LogoutRequest => m.method === Method.LogoutRequest
export const isLogoutResult = (m: Message): m is LogoutResult => m.method === Method.LogoutResult
