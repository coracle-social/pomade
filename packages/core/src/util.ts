import {argon2id} from "hash-wasm"
import {bytesToHex} from "@noble/hashes/utils.js"
import {cached, once, textEncoder} from "@welshman/lib"
import * as nt44 from "nostr-tools/nip44"
import {hexToBytes} from "@welshman/lib"

// Signing and encryption

export const nip44 = {
  getSharedSecret: cached({
    maxSize: 10000,
    getKey: ([secret, pubkey]) => `${secret}:${pubkey}`,
    getValue: ([secret, pubkey]: string[]) =>
      nt44.v2.utils.getConversationKey(hexToBytes(secret), pubkey),
  }),
  encrypt: (pubkey: string, secret: string, m: string) =>
    nt44.v2.encrypt(m, nip44.getSharedSecret(secret, pubkey)!),
  decrypt: (pubkey: string, secret: string, m: string) =>
    nt44.v2.decrypt(m, nip44.getSharedSecret(secret, pubkey)!),
}

// Payload hashing

export const argonOptions = {t: 3, m: 64 * 1024, p: 2}

export type ArgonImpl = (
  value: Uint8Array,
  salt: Uint8Array,
  options: {t: number; m: number; p: number},
) => Promise<Uint8Array>

const warnArgonImpl = once(() => {
  // @ts-ignore
  if (typeof window !== "undefined") {
    console.warn(
      "Default argon implementation can lead to UI jank. Call `context.setArgonWorker(import('@pomade/core/argon-worker.js?worker'))` to improve performance.",
    )
  }
})

const defaultArgonImpl: ArgonImpl = async (value, salt, options) => {
  warnArgonImpl()

  return argon2id({
    password: value,
    salt: salt,
    parallelism: options.p,
    iterations: options.t,
    memorySize: options.m,
    hashLength: 32,
    outputType: "binary",
  })
}

const emailHashCache = new Map<string, string>()

export async function hashEmail(email: string, signerUrl: string) {
  const key = email + signerUrl
  let hash = emailHashCache.get(key)
  if (!hash) {
    hash = bytesToHex(
      await context.argonImpl(
        textEncoder.encode(email),
        textEncoder.encode(signerUrl),
        argonOptions,
      ),
    )
    emailHashCache.set(key, hash)
  }

  return hash!
}

export async function hashPassword(email: string, password: string, signerUrl: string) {
  // Concatenate email and password before hashing to prevent cross-account correlation
  const input = textEncoder.encode(email + password)
  return bytesToHex(await context.argonImpl(input, textEncoder.encode(signerUrl), argonOptions))
}

// Context

export type Context = {
  debug: boolean
  registerPow: number
  signerUrls: string[]
  argonImpl: ArgonImpl
  setSignerUrls: (urls: string[]) => void
  setArgonWorker: (workerModuleOrPromise: any) => void
}

export const context: Context = {
  debug: false,
  registerPow: 20,
  signerUrls: [],
  argonImpl: defaultArgonImpl,
  setSignerUrls(urls: string[]) {
    context.signerUrls = urls
  },
  setArgonWorker(workerModuleOrPromise: any) {
    context.argonImpl = async (value, salt, options) => {
      const workerModule = await Promise.resolve(workerModuleOrPromise)
      const WorkerClass = workerModule.default || workerModule
      const worker = new WorkerClass()

      return new Promise<Uint8Array>((resolve, reject) => {
        worker.onmessage = (e: {data: Uint8Array}) => {
          resolve(e.data)
          worker.terminate()
        }

        worker.onerror = (e: any) => {
          reject(e.error || e)
          worker.terminate()
        }

        worker.postMessage({value, salt, options})
      })
    }
  },
}

export function debug(...args: any) {
  if (context.debug) {
    console.log(...args)
  }
}
