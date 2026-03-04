import {prep, makePow, makeHttpAuth, makeHttpAuthHeader} from "@welshman/util"
import {Nip01Signer} from "@welshman/signer"
import type {ISigner} from "@welshman/signer"
import type {Message} from "./message.js"
import {debug} from "./util.js"

export type PreppedRequest = {
  signerUrl: string
  requestUrl?: string
  options?: {
    method: "POST"
    body: string
    headers: {
      "Content-Type": string
      Authorization: string
    }
  }
}

export class RPC {
  static fetch = globalThis.fetch.bind(globalThis)

  constructor(public signer: ISigner) {}

  static fromSecret(secret: string) {
    return new RPC(Nip01Signer.fromSecret(secret))
  }

  async makeAuthHeader(url: string, body: string, pow?: number) {
    const template = await makeHttpAuth(url, "POST", body)
    const prepped = prep(template, await this.signer.getPubkey())

    const signed = pow
      ? await this.signer.sign(await makePow(prepped, pow).result)
      : await this.signer.sign(prepped)

    return makeHttpAuthHeader(signed)
  }

  async prep(
    signerUrl: string,
    path: string,
    body: unknown,
    pow?: number,
  ): Promise<PreppedRequest> {
    const requestUrl = `${signerUrl}${path}`
    const requestBody = JSON.stringify(body)

    try {
      const authHeader = await this.makeAuthHeader(requestUrl, requestBody, pow)

      return {
        signerUrl,
        requestUrl,
        options: {
          method: "POST",
          body: requestBody,
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeader,
          },
        },
      }
    } catch (e: any) {
      debug(`RPC ${requestUrl} failed to prepare: ${e.message}`)
      return {signerUrl}
    }
  }

  async send<T>({signerUrl, requestUrl, options}: PreppedRequest): Promise<Message<T>> {
    if (!options || !requestUrl) {
      return {url: signerUrl}
    }

    try {
      const response = await RPC.fetch(requestUrl, options)

      if (!response.ok) {
        debug(`RPC ${requestUrl} HTTP ${response.status}`)
        return {url: signerUrl}
      }

      return {url: signerUrl, res: (await response.json()) as T}
    } catch (e) {
      debug(`RPC ${requestUrl} threw:`, e)
      return {url: signerUrl}
    }
  }

  async post<T>(signerUrl: string, path: string, body: unknown, pow?: number): Promise<Message<T>> {
    return this.send<T>(await this.prep(signerUrl, path, body, pow))
  }
}
