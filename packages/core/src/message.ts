import * as z from "zod"
import {parseJson, switcher} from "@welshman/lib"
import type {Maybe} from "@welshman/lib"
import {Schema, Method} from "./schema.js"

// Message types

type DefineMessage<M, P> = {method: M; payload: z.infer<P>}

export type ChallengeRequest = DefineMessage<
  Method.ChallengeRequest,
  typeof Schema.challengeRequest
>
export type EcdhRequest = DefineMessage<Method.EcdhRequest, typeof Schema.ecdhRequest>
export type EcdhResult = DefineMessage<Method.EcdhResult, typeof Schema.ecdhResult>
export type LoginStart = DefineMessage<Method.LoginStart, typeof Schema.loginStart>
export type LoginOptions = DefineMessage<Method.LoginOptions, typeof Schema.loginOptions>
export type LoginSelect = DefineMessage<Method.LoginSelect, typeof Schema.loginSelect>
export type LoginResult = DefineMessage<Method.LoginResult, typeof Schema.loginResult>
export type RecoveryStart = DefineMessage<Method.RecoveryStart, typeof Schema.recoveryStart>
export type RecoveryOptions = DefineMessage<Method.RecoveryOptions, typeof Schema.recoveryOptions>
export type RecoverySelect = DefineMessage<Method.RecoverySelect, typeof Schema.recoverySelect>
export type RecoveryResult = DefineMessage<Method.RecoveryResult, typeof Schema.recoveryResult>
export type RecoveryMethodInit = DefineMessage<
  Method.RecoveryMethodInit,
  typeof Schema.initRecoveryMethod
>
export type RecoveryMethodInitResult = DefineMessage<
  Method.RecoveryMethodInitResult,
  typeof Schema.initRecoveryMethodResult
>
export type RegisterRequest = DefineMessage<Method.RegisterRequest, typeof Schema.registerRequest>
export type RegisterResult = DefineMessage<Method.RegisterResult, typeof Schema.registerResult>
export type SessionDelete = DefineMessage<Method.SessionDelete, typeof Schema.sessionDelete>
export type SessionDeleteResult = DefineMessage<
  Method.SessionDeleteResult,
  typeof Schema.sessionDeleteResult
>
export type SessionList = DefineMessage<Method.SessionList, typeof Schema.sessionList>
export type SessionListResult = DefineMessage<
  Method.SessionListResult,
  typeof Schema.sessionListResult
>
export type SignRequest = DefineMessage<Method.SignRequest, typeof Schema.signRequest>
export type SignResult = DefineMessage<Method.SignResult, typeof Schema.signResult>

export type Message =
  | ChallengeRequest
  | EcdhRequest
  | EcdhResult
  | LoginStart
  | LoginOptions
  | LoginSelect
  | LoginResult
  | RecoveryStart
  | RecoveryOptions
  | RecoverySelect
  | RecoveryResult
  | RecoveryMethodInit
  | RecoveryMethodInitResult
  | RegisterRequest
  | RegisterResult
  | SessionDelete
  | SessionDeleteResult
  | SessionList
  | SessionListResult
  | SignRequest
  | SignResult

// Construction

export function makeChallengeRequest(payload: ChallengeRequest["payload"]): ChallengeRequest {
  return {method: Method.ChallengeRequest, payload: Schema.challengeRequest.parse(payload)}
}

export function makeEcdhRequest(payload: EcdhRequest["payload"]): EcdhRequest {
  return {method: Method.EcdhRequest, payload: Schema.ecdhRequest.parse(payload)}
}

export function makeEcdhResult(payload: EcdhResult["payload"]): EcdhResult {
  return {method: Method.EcdhResult, payload: Schema.ecdhResult.parse(payload)}
}

export function makeLoginStart(payload: LoginStart["payload"]): LoginStart {
  return {method: Method.LoginStart, payload: Schema.loginStart.parse(payload)}
}

export function makeLoginOptions(payload: LoginOptions["payload"]): LoginOptions {
  return {method: Method.LoginOptions, payload: Schema.loginOptions.parse(payload)}
}

export function makeLoginSelect(payload: LoginSelect["payload"]): LoginSelect {
  return {method: Method.LoginSelect, payload: Schema.loginSelect.parse(payload)}
}

export function makeLoginResult(payload: LoginResult["payload"]): LoginResult {
  return {method: Method.LoginResult, payload: Schema.loginResult.parse(payload)}
}

export function makeRecoveryStart(payload: RecoveryStart["payload"]): RecoveryStart {
  return {method: Method.RecoveryStart, payload: Schema.recoveryStart.parse(payload)}
}

export function makeRecoveryOptions(payload: RecoveryOptions["payload"]): RecoveryOptions {
  return {method: Method.RecoveryOptions, payload: Schema.recoveryOptions.parse(payload)}
}

export function makeRecoverySelect(payload: RecoverySelect["payload"]): RecoverySelect {
  return {method: Method.RecoverySelect, payload: Schema.recoverySelect.parse(payload)}
}

export function makeRecoveryResult(payload: RecoveryResult["payload"]): RecoveryResult {
  return {method: Method.RecoveryResult, payload: Schema.recoveryResult.parse(payload)}
}

export function makeRecoveryMethodInit(payload: RecoveryMethodInit["payload"]): RecoveryMethodInit {
  return {
    method: Method.RecoveryMethodInit,
    payload: Schema.initRecoveryMethod.parse(payload),
  }
}

export function makeRecoveryMethodInitResult(
  payload: RecoveryMethodInitResult["payload"],
): RecoveryMethodInitResult {
  return {
    method: Method.RecoveryMethodInitResult,
    payload: Schema.initRecoveryMethodResult.parse(payload),
  }
}

export function makeRegisterRequest(payload: RegisterRequest["payload"]): RegisterRequest {
  return {method: Method.RegisterRequest, payload: Schema.registerRequest.parse(payload)}
}

export function makeRegisterResult(payload: RegisterResult["payload"]): RegisterResult {
  return {method: Method.RegisterResult, payload: Schema.registerResult.parse(payload)}
}

export function makeSessionDelete(payload: SessionDelete["payload"]): SessionDelete {
  return {method: Method.SessionDelete, payload: Schema.sessionDelete.parse(payload)}
}

export function makeSessionDeleteResult(
  payload: SessionDeleteResult["payload"],
): SessionDeleteResult {
  return {method: Method.SessionDeleteResult, payload: Schema.sessionDeleteResult.parse(payload)}
}

export function makeSessionList(payload: SessionList["payload"]): SessionList {
  return {method: Method.SessionList, payload: Schema.sessionList.parse(payload)}
}

export function makeSessionListResult(payload: SessionListResult["payload"]): SessionListResult {
  return {method: Method.SessionListResult, payload: Schema.sessionListResult.parse(payload)}
}

export function makeSignRequest(payload: SignRequest["payload"]): SignRequest {
  return {method: Method.SignRequest, payload: Schema.signRequest.parse(payload)}
}

export function makeSignResult(payload: SignResult["payload"]): SignResult {
  return {method: Method.SignResult, payload: Schema.signResult.parse(payload)}
}

// Parsing

export function getMessageSchema(method: Method) {
  return switcher(method, {
    [Method.ChallengeRequest]: Schema.challengeRequest,
    [Method.EcdhRequest]: Schema.ecdhRequest,
    [Method.EcdhResult]: Schema.ecdhResult,
    [Method.LoginStart]: Schema.loginStart,
    [Method.LoginOptions]: Schema.loginOptions,
    [Method.LoginSelect]: Schema.loginSelect,
    [Method.LoginResult]: Schema.loginResult,
    [Method.RecoveryStart]: Schema.recoveryStart,
    [Method.RecoveryOptions]: Schema.recoveryOptions,
    [Method.RecoverySelect]: Schema.recoverySelect,
    [Method.RecoveryResult]: Schema.recoveryResult,
    [Method.RecoveryMethodInit]: Schema.initRecoveryMethod,
    [Method.RecoveryMethodInitResult]: Schema.initRecoveryMethodResult,
    [Method.RegisterRequest]: Schema.registerRequest,
    [Method.RegisterResult]: Schema.registerResult,
    [Method.SessionDelete]: Schema.sessionDelete,
    [Method.SessionDeleteResult]: Schema.sessionDeleteResult,
    [Method.SessionList]: Schema.sessionList,
    [Method.SessionListResult]: Schema.sessionListResult,
    [Method.SignRequest]: Schema.signRequest,
    [Method.SignResult]: Schema.signResult,
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

export const isChallengeRequest = (m: Message): m is ChallengeRequest =>
  m.method === Method.ChallengeRequest
export const isEcdhRequest = (m: Message): m is EcdhRequest => m.method === Method.EcdhRequest
export const isEcdhResult = (m: Message): m is EcdhResult => m.method === Method.EcdhResult
export const isLoginStart = (m: Message): m is LoginStart => m.method === Method.LoginStart
export const isLoginOptions = (m: Message): m is LoginOptions => m.method === Method.LoginOptions
export const isLoginSelect = (m: Message): m is LoginSelect => m.method === Method.LoginSelect
export const isLoginResult = (m: Message): m is LoginResult => m.method === Method.LoginResult
export const isRecoveryStart = (m: Message): m is RecoveryStart => m.method === Method.RecoveryStart
export const isRecoveryOptions = (m: Message): m is RecoveryOptions =>
  m.method === Method.RecoveryOptions
export const isRecoverySelect = (m: Message): m is RecoverySelect =>
  m.method === Method.RecoverySelect
export const isRecoveryResult = (m: Message): m is RecoveryResult =>
  m.method === Method.RecoveryResult
export const isRecoveryMethodInit = (m: Message): m is RecoveryMethodInit =>
  m.method === Method.RecoveryMethodInit
export const isRecoveryMethodInitResult = (m: Message): m is RecoveryMethodInitResult =>
  m.method === Method.RecoveryMethodInitResult
export const isRegisterRequest = (m: Message): m is RegisterRequest =>
  m.method === Method.RegisterRequest
export const isRegisterResult = (m: Message): m is RegisterResult =>
  m.method === Method.RegisterResult
export const isSessionDelete = (m: Message): m is SessionDelete => m.method === Method.SessionDelete
export const isSessionDeleteResult = (m: Message): m is SessionDeleteResult =>
  m.method === Method.SessionDeleteResult
export const isSessionList = (m: Message): m is SessionList => m.method === Method.SessionList
export const isSessionListResult = (m: Message): m is SessionListResult =>
  m.method === Method.SessionListResult
export const isSignRequest = (m: Message): m is SignRequest => m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResult => m.method === Method.SignResult
