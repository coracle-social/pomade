import type {MaybeAsync} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import type {EventTemplate} from '@welshman/util'
import {prep, sign, getPubkey} from '@welshman/util'

export type IStorage<T> = {
  list(): MaybeAsync<Iterable<T>>
  get(key: string): MaybeAsync<T>
  set(key: string, item: T): MaybeAsync<undefined>
  del(key: string): MaybeAsync<undefined>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export enum Kinds {
  Register = 28350,
  RegisterACK = 28351,
  ValidateEmail = 28352,
  ValidateEmailACK = 28353,
  Unregister = 28354,
  CommitRequest = 28360,
  Commit = 28362,
  CommitGroup = 28362,
  PartialSignature = 28363,
  RecoverShard = 28370,
  ReleaseShard = 28371,
  RequestOTP = 28372,
  SendOTP = 28373,
  OTPLogin = 28384,
}

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}

export function makeRPCEvent({
  authorSecret,
  recipientPubkey,
  kind,
  content,
  tags = []
}: {
  authorSecret: string
  recipientPubkey: string
  kind: number
  content: string[][]
  tags?: string[][]
}) {
  return prepAndSign(authorSecret, {
    kind,
    tags: [["p", recipientPubkey], ...tags],
    content: nip44.encrypt(recipientPubkey, authorSecret, JSON.stringify(content)),
  })
}
