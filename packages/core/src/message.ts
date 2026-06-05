import * as z from "zod"
import {Schema} from "./schema.js"

export type Message<T> = {
  url: string
  res?: T
}

export type RegisterRequest = z.infer<typeof Schema.registerRequest>
export type RegisterResponse = z.infer<typeof Schema.registerResponse>

export type SignRequest = z.infer<typeof Schema.signRequest>
export type SignResponse = z.infer<typeof Schema.signResponse>

export type SignCommitRequest = z.infer<typeof Schema.signCommitRequest>
export type SignCommitResponse = z.infer<typeof Schema.signCommitResponse>

export type SignCompleteRequest = z.infer<typeof Schema.signCompleteRequest>
export type SignCompleteResponse = z.infer<typeof Schema.signCompleteResponse>

export type SignCompleteRequestInner = SignCompleteRequest["request"]
export type SignCompleteResult = NonNullable<SignCompleteResponse["result"]>

export type EcdhRequest = z.infer<typeof Schema.ecdhRequest>
export type EcdhResponse = z.infer<typeof Schema.ecdhResponse>

export type RecoverySetupRequest = z.infer<typeof Schema.recoverySetupRequest>
export type RecoverySetupResponse = z.infer<typeof Schema.recoverySetupResponse>

export type ChallengeRequest = z.infer<typeof Schema.challengeRequest>
export type ChallengeResponse = z.infer<typeof Schema.challengeResponse>

export type LoginStartRequest = z.infer<typeof Schema.loginStartRequest>
export type LoginStartResponse = z.infer<typeof Schema.loginStartResponse>

export type LoginSelectRequest = z.infer<typeof Schema.loginSelectRequest>
export type LoginSelectResponse = z.infer<typeof Schema.loginSelectResponse>

export type RecoveryStartRequest = z.infer<typeof Schema.recoveryStartRequest>
export type RecoveryStartResponse = z.infer<typeof Schema.recoveryStartResponse>

export type RecoverySelectRequest = z.infer<typeof Schema.recoverySelectRequest>
export type RecoverySelectResponse = z.infer<typeof Schema.recoverySelectResponse>

export type SessionListRequest = z.infer<typeof Schema.sessionListRequest>
export type SessionListResponse = z.infer<typeof Schema.sessionListResponse>

export type SessionDeactivateRequest = z.infer<typeof Schema.sessionDeactivateRequest>
export type SessionDeactivateResponse = z.infer<typeof Schema.sessionDeactivateResponse>

export type SessionDeleteRequest = z.infer<typeof Schema.sessionDeleteRequest>
export type SessionDeleteResponse = z.infer<typeof Schema.sessionDeleteResponse>
