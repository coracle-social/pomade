import * as z from "zod"
import {parseJson, switcher} from "@welshman/lib"
import type {Maybe} from "@welshman/lib"
import {Schema, Method} from "./schema.js"

// Message types

type DefineMessage<M, P> = {method: M; payload: z.infer<P>}

export type EcdhRequest = DefineMessage<Method.EcdhRequest, typeof Schema.ecdhRequest>
export type EcdhResult = DefineMessage<Method.EcdhResult, typeof Schema.ecdhResult>
export type RecoveryChallenge = DefineMessage<
  Method.RecoveryChallenge,
  typeof Schema.recoveryChallenge
>
export type RecoveryFinalize = DefineMessage<
  Method.RecoveryFinalize,
  typeof Schema.recoveryFinalize
>
export type RecoveryFinalizeResult = DefineMessage<
  Method.RecoveryFinalizeResult,
  typeof Schema.recoveryFinalizeResult
>
export type RecoveryMethodChallenge = DefineMessage<
  Method.RecoveryMethodChallenge,
  typeof Schema.recoveryMethodChallenge
>
export type RecoveryMethodFinalize = DefineMessage<
  Method.RecoveryMethodFinalize,
  typeof Schema.finalizeRecoveryMethod
>
export type RecoveryMethodFinalizeResult = DefineMessage<
  Method.RecoveryMethodFinalizeResult,
  typeof Schema.finalizeRecoveryMethodResult
>
export type RecoveryMethodSet = DefineMessage<
  Method.RecoveryMethodSet,
  typeof Schema.setRecoveryMethod
>
export type RecoveryMethodSetResult = DefineMessage<
  Method.RecoveryMethodSetResult,
  typeof Schema.setRecoveryMethodResult
>
export type RecoveryStart = DefineMessage<Method.RecoveryStart, typeof Schema.recoveryStart>
export type RecoveryStartResult = DefineMessage<
  Method.RecoveryStartResult,
  typeof Schema.recoveryStartResult
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
  | EcdhRequest
  | EcdhResult
  | RecoveryChallenge
  | RecoveryFinalize
  | RecoveryFinalizeResult
  | RecoveryMethodChallenge
  | RecoveryMethodFinalize
  | RecoveryMethodFinalizeResult
  | RecoveryMethodSet
  | RecoveryMethodSetResult
  | RecoveryStart
  | RecoveryStartResult
  | RegisterRequest
  | RegisterResult
  | SessionDelete
  | SessionDeleteResult
  | SessionList
  | SessionListResult
  | SignRequest
  | SignResult

// Construction

export function makeEcdhRequest(payload: EcdhRequest["payload"]): EcdhRequest {
  return {method: Method.EcdhRequest, payload: Schema.ecdhRequest.parse(payload)}
}

export function makeEcdhResult(payload: EcdhResult["payload"]): EcdhResult {
  return {method: Method.EcdhResult, payload: Schema.ecdhResult.parse(payload)}
}

export function makeRecoveryChallenge(payload: RecoveryChallenge["payload"]): RecoveryChallenge {
  return {method: Method.RecoveryChallenge, payload: Schema.recoveryChallenge.parse(payload)}
}

export function makeRecoveryFinalize(payload: RecoveryFinalize["payload"]): RecoveryFinalize {
  return {method: Method.RecoveryFinalize, payload: Schema.recoveryFinalize.parse(payload)}
}

export function makeRecoveryFinalizeResult(
  payload: RecoveryFinalizeResult["payload"],
): RecoveryFinalizeResult {
  return {
    method: Method.RecoveryFinalizeResult,
    payload: Schema.recoveryFinalizeResult.parse(payload),
  }
}

export function makeRecoveryMethodChallenge(
  payload: RecoveryMethodChallenge["payload"],
): RecoveryMethodChallenge {
  return {
    method: Method.RecoveryMethodChallenge,
    payload: Schema.recoveryMethodChallenge.parse(payload),
  }
}

export function makeRecoveryMethodFinalize(
  payload: RecoveryMethodFinalize["payload"],
): RecoveryMethodFinalize {
  return {
    method: Method.RecoveryMethodFinalize,
    payload: Schema.finalizeRecoveryMethod.parse(payload),
  }
}

export function makeRecoveryMethodFinalizeResult(
  payload: RecoveryMethodFinalizeResult["payload"],
): RecoveryMethodFinalizeResult {
  return {
    method: Method.RecoveryMethodFinalizeResult,
    payload: Schema.finalizeRecoveryMethodResult.parse(payload),
  }
}

export function makeRecoveryMethodSet(payload: RecoveryMethodSet["payload"]): RecoveryMethodSet {
  return {
    method: Method.RecoveryMethodSet,
    payload: Schema.setRecoveryMethod.parse(payload),
  }
}

export function makeRecoveryMethodSetResult(
  payload: RecoveryMethodSetResult["payload"],
): RecoveryMethodSetResult {
  return {
    method: Method.RecoveryMethodSetResult,
    payload: Schema.setRecoveryMethodResult.parse(payload),
  }
}

export function makeRecoveryStart(payload: RecoveryStart["payload"]): RecoveryStart {
  return {method: Method.RecoveryStart, payload: Schema.recoveryStart.parse(payload)}
}

export function makeRecoveryStartResult(
  payload: RecoveryStartResult["payload"],
): RecoveryStartResult {
  return {method: Method.RecoveryStartResult, payload: Schema.recoveryStartResult.parse(payload)}
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
    [Method.EcdhRequest]: Schema.ecdhRequest,
    [Method.EcdhResult]: Schema.ecdhResult,
    [Method.RecoveryChallenge]: Schema.recoveryChallenge,
    [Method.RecoveryFinalize]: Schema.recoveryFinalize,
    [Method.RecoveryFinalizeResult]: Schema.recoveryFinalizeResult,
    [Method.RecoveryMethodChallenge]: Schema.recoveryMethodChallenge,
    [Method.RecoveryMethodFinalize]: Schema.finalizeRecoveryMethod,
    [Method.RecoveryMethodFinalizeResult]: Schema.finalizeRecoveryMethodResult,
    [Method.RecoveryMethodSet]: Schema.setRecoveryMethod,
    [Method.RecoveryMethodSetResult]: Schema.setRecoveryMethodResult,
    [Method.RecoveryStart]: Schema.recoveryStart,
    [Method.RecoveryStartResult]: Schema.recoveryStartResult,
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

export const isEcdhRequest = (m: Message): m is EcdhRequest => m.method === Method.EcdhRequest
export const isEcdhResult = (m: Message): m is EcdhResult => m.method === Method.EcdhResult
export const isRecoveryChallenge = (m: Message): m is RecoveryChallenge =>
  m.method === Method.RecoveryChallenge
export const isRecoveryFinalize = (m: Message): m is RecoveryFinalize =>
  m.method === Method.RecoveryFinalize
export const isRecoveryFinalizeResult = (m: Message): m is RecoveryFinalizeResult =>
  m.method === Method.RecoveryFinalizeResult
export const isRecoveryMethodChallenge = (m: Message): m is RecoveryMethodChallenge =>
  m.method === Method.RecoveryMethodChallenge
export const isRecoveryMethodFinalize = (m: Message): m is RecoveryMethodFinalize =>
  m.method === Method.RecoveryMethodFinalize
export const isRecoveryMethodFinalizeResult = (m: Message): m is RecoveryMethodFinalizeResult =>
  m.method === Method.RecoveryMethodFinalizeResult
export const isRecoveryMethodSet = (m: Message): m is RecoveryMethodSet =>
  m.method === Method.RecoveryMethodSet
export const isRecoveryMethodSetResult = (m: Message): m is RecoveryMethodSetResult =>
  m.method === Method.RecoveryMethodSetResult
export const isRecoveryStart = (m: Message): m is RecoveryStart => m.method === Method.RecoveryStart
export const isRecoveryStartResult = (m: Message): m is RecoveryStartResult =>
  m.method === Method.RecoveryStartResult
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
