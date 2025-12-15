import * as z from "zod"
import {parseJson, switcher} from "@welshman/lib"
import type {Maybe} from "@welshman/lib"
import {Schema, Method} from "./schema"

// Message types

type DefineMessage<M, P> = {method: M; payload: z.infer<P>}

export type EcdhRequestMessage = DefineMessage<Method.EcdhRequest, typeof Schema.ecdhRequest>
export type EcdhResultMessage = DefineMessage<Method.EcdhResult, typeof Schema.ecdhResult>
export type LoginRequestMessage = DefineMessage<Method.LoginRequest, typeof Schema.loginRequest>
export type LoginRequestResultMessage = DefineMessage<
  Method.LoginRequestResult,
  typeof Schema.loginRequestResult
>
export type LoginRequestSelectMessage = DefineMessage<
  Method.LoginRequestSelect,
  typeof Schema.loginRequestSelect
>
export type LoginChallengeMessage = DefineMessage<
  Method.LoginChallenge,
  typeof Schema.loginChallenge
>
export type LoginFinalizeMessage = DefineMessage<Method.LoginFinalize, typeof Schema.loginFinalize>
export type LoginFinalizeResultMessage = DefineMessage<
  Method.LoginFinalizeResult,
  typeof Schema.loginResult
>
export type RecoverRequestMessage = DefineMessage<
  Method.RecoverRequest,
  typeof Schema.recoverRequest
>
export type RecoverRequestResultMessage = DefineMessage<
  Method.RecoverRequestResult,
  typeof Schema.recoverRequestResult
>
export type RecoverRequestSelectMessage = DefineMessage<
  Method.RecoverRequestSelect,
  typeof Schema.recoverRequestSelect
>
export type RecoverChallengeMessage = DefineMessage<
  Method.RecoverChallenge,
  typeof Schema.recoverChallenge
>
export type RecoverFinalizeMessage = DefineMessage<
  Method.RecoverFinalize,
  typeof Schema.recoverFinalize
>
export type RecoverFinalizeResultMessage = DefineMessage<
  Method.RecoverFinalizeResult,
  typeof Schema.recoverResult
>
export type RegisterRequestMessage = DefineMessage<
  Method.RegisterRequest,
  typeof Schema.registerRequest
>
export type RegisterResultMessage = DefineMessage<
  Method.RegisterResult,
  typeof Schema.registerResult
>
export type SetEmailRequestMessage = DefineMessage<
  Method.SetEmailRequest,
  typeof Schema.setEmailRequest
>
export type SetEmailRequestResultMessage = DefineMessage<
  Method.SetEmailRequestResult,
  typeof Schema.setEmailRequestResult
>
export type SetEmailRequestSelectMessage = DefineMessage<
  Method.SetEmailRequestSelect,
  typeof Schema.setEmailRequestSelect
>
export type SetEmailChallengeMessage = DefineMessage<
  Method.SetEmailChallenge,
  typeof Schema.setEmailChallenge
>
export type SetEmailFinalizeMessage = DefineMessage<
  Method.SetEmailFinalize,
  typeof Schema.setEmailFinalize
>
export type SetEmailFinalizeResultMessage = DefineMessage<
  Method.SetEmailFinalizeResult,
  typeof Schema.setEmailResult
>
export type SignRequestMessage = DefineMessage<Method.SignRequest, typeof Schema.signRequest>
export type SignResultMessage = DefineMessage<Method.SignResult, typeof Schema.signResult>
export type UnregisterRequestMessage = DefineMessage<
  Method.UnregisterRequest,
  typeof Schema.unregisterRequest
>
export type UnregisterResultMessage = DefineMessage<
  Method.UnregisterResult,
  typeof Schema.unregisterResult
>

export type Message =
  | EcdhRequestMessage
  | EcdhResultMessage
  | LoginRequestMessage
  | LoginRequestResultMessage
  | LoginRequestSelectMessage
  | LoginChallengeMessage
  | LoginFinalizeMessage
  | LoginFinalizeResultMessage
  | RecoverRequestMessage
  | RecoverRequestResultMessage
  | RecoverRequestSelectMessage
  | RecoverChallengeMessage
  | RecoverFinalizeMessage
  | RecoverFinalizeResultMessage
  | RegisterRequestMessage
  | RegisterResultMessage
  | SetEmailRequestMessage
  | SetEmailRequestResultMessage
  | SetEmailRequestSelectMessage
  | SetEmailChallengeMessage
  | SetEmailFinalizeMessage
  | SetEmailFinalizeResultMessage
  | SignRequestMessage
  | SignResultMessage
  | UnregisterRequestMessage
  | UnregisterResultMessage

// Construction

export function makeEcdhRequest(payload: EcdhRequestMessage["payload"]): EcdhRequestMessage {
  return {method: Method.EcdhRequest, payload: Schema.ecdhRequest.parse(payload)}
}

export function makeEcdhResult(payload: EcdhResultMessage["payload"]): EcdhResultMessage {
  return {method: Method.EcdhResult, payload: Schema.ecdhResult.parse(payload)}
}

export function makeLoginRequest(payload: LoginRequestMessage["payload"]): LoginRequestMessage {
  return {method: Method.LoginRequest, payload: Schema.loginRequest.parse(payload)}
}

export function makeLoginRequestResult(
  payload: LoginRequestResultMessage["payload"],
): LoginRequestResultMessage {
  return {method: Method.LoginRequestResult, payload: Schema.loginRequestResult.parse(payload)}
}

export function makeLoginRequestSelect(
  payload: LoginRequestSelectMessage["payload"],
): LoginRequestSelectMessage {
  return {method: Method.LoginRequestSelect, payload: Schema.loginRequestSelect.parse(payload)}
}

export function makeLoginChallenge(
  payload: LoginChallengeMessage["payload"],
): LoginChallengeMessage {
  return {method: Method.LoginChallenge, payload: Schema.loginChallenge.parse(payload)}
}

export function makeLoginFinalize(payload: LoginFinalizeMessage["payload"]): LoginFinalizeMessage {
  return {method: Method.LoginFinalize, payload: Schema.loginFinalize.parse(payload)}
}

export function makeLoginFinalizeResult(
  payload: LoginFinalizeResultMessage["payload"],
): LoginFinalizeResultMessage {
  return {method: Method.LoginFinalizeResult, payload: Schema.loginResult.parse(payload)}
}

export function makeRecoverRequest(
  payload: RecoverRequestMessage["payload"],
): RecoverRequestMessage {
  return {method: Method.RecoverRequest, payload: Schema.recoverRequest.parse(payload)}
}

export function makeRecoverRequestResult(
  payload: RecoverRequestResultMessage["payload"],
): RecoverRequestResultMessage {
  return {method: Method.RecoverRequestResult, payload: Schema.recoverRequestResult.parse(payload)}
}

export function makeRecoverRequestSelect(
  payload: RecoverRequestSelectMessage["payload"],
): RecoverRequestSelectMessage {
  return {method: Method.RecoverRequestSelect, payload: Schema.recoverRequestSelect.parse(payload)}
}

export function makeRecoverChallenge(
  payload: RecoverChallengeMessage["payload"],
): RecoverChallengeMessage {
  return {method: Method.RecoverChallenge, payload: Schema.recoverChallenge.parse(payload)}
}

export function makeRecoverFinalize(
  payload: RecoverFinalizeMessage["payload"],
): RecoverFinalizeMessage {
  return {method: Method.RecoverFinalize, payload: Schema.recoverFinalize.parse(payload)}
}

export function makeRecoverFinalizeResult(
  payload: RecoverFinalizeResultMessage["payload"],
): RecoverFinalizeResultMessage {
  return {method: Method.RecoverFinalizeResult, payload: Schema.recoverResult.parse(payload)}
}

export function makeRegisterRequest(
  payload: RegisterRequestMessage["payload"],
): RegisterRequestMessage {
  return {method: Method.RegisterRequest, payload: Schema.registerRequest.parse(payload)}
}

export function makeRegisterResult(
  payload: RegisterResultMessage["payload"],
): RegisterResultMessage {
  return {method: Method.RegisterResult, payload: Schema.registerResult.parse(payload)}
}

export function makeSetEmailRequest(
  payload: SetEmailRequestMessage["payload"],
): SetEmailRequestMessage {
  return {method: Method.SetEmailRequest, payload: Schema.setEmailRequest.parse(payload)}
}

export function makeSetEmailRequestResult(
  payload: SetEmailRequestResultMessage["payload"],
): SetEmailRequestResultMessage {
  return {
    method: Method.SetEmailRequestResult,
    payload: Schema.setEmailRequestResult.parse(payload),
  }
}

export function makeSetEmailRequestSelect(
  payload: SetEmailRequestSelectMessage["payload"],
): SetEmailRequestSelectMessage {
  return {
    method: Method.SetEmailRequestSelect,
    payload: Schema.setEmailRequestSelect.parse(payload),
  }
}

export function makeSetEmailChallenge(
  payload: SetEmailChallengeMessage["payload"],
): SetEmailChallengeMessage {
  return {method: Method.SetEmailChallenge, payload: Schema.setEmailChallenge.parse(payload)}
}

export function makeSetEmailFinalize(
  payload: SetEmailFinalizeMessage["payload"],
): SetEmailFinalizeMessage {
  return {method: Method.SetEmailFinalize, payload: Schema.setEmailFinalize.parse(payload)}
}

export function makeSetEmailFinalizeResult(
  payload: SetEmailFinalizeResultMessage["payload"],
): SetEmailFinalizeResultMessage {
  return {method: Method.SetEmailFinalizeResult, payload: Schema.setEmailResult.parse(payload)}
}

export function makeSignRequest(payload: SignRequestMessage["payload"]): SignRequestMessage {
  return {method: Method.SignRequest, payload: Schema.signRequest.parse(payload)}
}

export function makeSignResult(payload: SignResultMessage["payload"]): SignResultMessage {
  return {method: Method.SignResult, payload: Schema.signResult.parse(payload)}
}

export function makeUnregisterRequest(
  payload: UnregisterRequestMessage["payload"],
): UnregisterRequestMessage {
  return {method: Method.UnregisterRequest, payload: Schema.unregisterRequest.parse(payload)}
}

export function makeUnregisterResult(
  payload: UnregisterResultMessage["payload"],
): UnregisterResultMessage {
  return {method: Method.UnregisterResult, payload: Schema.unregisterResult.parse(payload)}
}

// Parsing

export function getMessageSchema(method: Method) {
  return switcher(method, {
    [Method.EcdhRequest]: Schema.ecdhRequest,
    [Method.EcdhResult]: Schema.ecdhResult,
    [Method.LoginRequest]: Schema.loginRequest,
    [Method.LoginRequestResult]: Schema.loginRequestResult,
    [Method.LoginRequestSelect]: Schema.loginRequestSelect,
    [Method.LoginChallenge]: Schema.loginChallenge,
    [Method.LoginFinalize]: Schema.loginFinalize,
    [Method.LoginFinalizeResult]: Schema.loginResult,
    [Method.RecoverRequest]: Schema.recoverRequest,
    [Method.RecoverRequestResult]: Schema.recoverRequestResult,
    [Method.RecoverRequestSelect]: Schema.recoverRequestSelect,
    [Method.RecoverChallenge]: Schema.recoverChallenge,
    [Method.RecoverFinalize]: Schema.recoverFinalize,
    [Method.RecoverFinalizeResult]: Schema.recoverResult,
    [Method.RegisterRequest]: Schema.registerRequest,
    [Method.RegisterResult]: Schema.registerResult,
    [Method.SetEmailRequest]: Schema.setEmailRequest,
    [Method.SetEmailRequestResult]: Schema.setEmailRequestResult,
    [Method.SetEmailRequestSelect]: Schema.setEmailRequestSelect,
    [Method.SetEmailChallenge]: Schema.setEmailChallenge,
    [Method.SetEmailFinalize]: Schema.setEmailFinalize,
    [Method.SetEmailFinalizeResult]: Schema.setEmailResult,
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
    return {method: message.method, payload: result.data}
  }
}

// Type guards

export const isEcdhRequest = (m: Message): m is EcdhRequestMessage =>
  m.method === Method.EcdhRequest
export const isEcdhResult = (m: Message): m is EcdhResultMessage => m.method === Method.EcdhResult
export const isLoginRequest = (m: Message): m is LoginRequestMessage =>
  m.method === Method.LoginRequest
export const isLoginRequestResult = (m: Message): m is LoginRequestResultMessage =>
  m.method === Method.LoginRequestResult
export const isLoginRequestSelect = (m: Message): m is LoginRequestSelectMessage =>
  m.method === Method.LoginRequestSelect
export const isLoginChallenge = (m: Message): m is LoginChallengeMessage =>
  m.method === Method.LoginChallenge
export const isLoginFinalize = (m: Message): m is LoginFinalizeMessage =>
  m.method === Method.LoginFinalize
export const isLoginFinalizeResult = (m: Message): m is LoginFinalizeResultMessage =>
  m.method === Method.LoginFinalizeResult
export const isRecoverRequest = (m: Message): m is RecoverRequestMessage =>
  m.method === Method.RecoverRequest
export const isRecoverRequestResult = (m: Message): m is RecoverRequestResultMessage =>
  m.method === Method.RecoverRequestResult
export const isRecoverRequestSelect = (m: Message): m is RecoverRequestSelectMessage =>
  m.method === Method.RecoverRequestSelect
export const isRecoverChallenge = (m: Message): m is RecoverChallengeMessage =>
  m.method === Method.RecoverChallenge
export const isRecoverFinalize = (m: Message): m is RecoverFinalizeMessage =>
  m.method === Method.RecoverFinalize
export const isRecoverFinalizeResult = (m: Message): m is RecoverFinalizeResultMessage =>
  m.method === Method.RecoverFinalizeResult
export const isRegisterRequest = (m: Message): m is RegisterRequestMessage =>
  m.method === Method.RegisterRequest
export const isRegisterResult = (m: Message): m is RegisterResultMessage =>
  m.method === Method.RegisterResult
export const isSetEmailRequest = (m: Message): m is SetEmailRequestMessage =>
  m.method === Method.SetEmailRequest
export const isSetEmailRequestResult = (m: Message): m is SetEmailRequestResultMessage =>
  m.method === Method.SetEmailRequestResult
export const isSetEmailRequestSelect = (m: Message): m is SetEmailRequestSelectMessage =>
  m.method === Method.SetEmailRequestSelect
export const isSetEmailChallenge = (m: Message): m is SetEmailChallengeMessage =>
  m.method === Method.SetEmailChallenge
export const isSetEmailFinalize = (m: Message): m is SetEmailFinalizeMessage =>
  m.method === Method.SetEmailFinalize
export const isSetEmailFinalizeResult = (m: Message): m is SetEmailFinalizeResultMessage =>
  m.method === Method.SetEmailFinalizeResult
export const isSignRequest = (m: Message): m is SignRequestMessage =>
  m.method === Method.SignRequest
export const isSignResult = (m: Message): m is SignResultMessage => m.method === Method.SignResult
export const isUnregisterRequest = (m: Message): m is UnregisterRequestMessage =>
  m.method === Method.UnregisterRequest
export const isUnregisterResult = (m: Message): m is UnregisterResultMessage =>
  m.method === Method.UnregisterResult
