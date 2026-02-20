import {prep, makePow, makeHttpAuth, makeHttpAuthHeader} from "@welshman/util"
import {Nip01Signer} from "@welshman/signer"
import type {ISigner} from "@welshman/signer"
import type {Message} from "./message.js"

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

  async post<T>(signerUrl: string, path: string, body: unknown, pow?: number): Promise<Message<T>> {
    const requestUrl = `${signerUrl}${path}`
    const bodyStr = JSON.stringify(body)
    try {
      const authHeader = await this.makeAuthHeader(requestUrl, bodyStr, pow)

      const response = await RPC.fetch(requestUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
        body: bodyStr,
      })

      if (!response.ok) {
        return {url: signerUrl}
      }

      return {url: signerUrl, res: (await response.json()) as T}
    } catch {
      return {url: signerUrl}
    }
  }
}
