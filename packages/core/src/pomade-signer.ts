import * as nt44 from "nostr-tools/nip44"
import type {Client} from "./client.js"
import type {StampedEvent, SignedEvent} from "@welshman/util"
import {thrower, hexToBytes} from "@welshman/lib"
import type {ISigner, SignOptions} from "@welshman/signer"

export class PomadeSigner implements ISigner {
  #pubkey: string
  #sharedSecretCache = new Map<string, Uint8Array<ArrayBuffer>>()

  constructor(readonly client: Client) {
    this.#pubkey = client.userPubkey
  }

  private getSharedSecret = async (pubkey: string) => {
    let sharedSecret = this.#sharedSecretCache.get(pubkey)

    if (!sharedSecret) {
      const hexSharedSecret = await this.client.getConversationKey(pubkey)

      if (hexSharedSecret) {
        sharedSecret = hexToBytes(hexSharedSecret)
        this.#sharedSecretCache.set(pubkey, sharedSecret)
      }
    }

    return sharedSecret
  }

  getPubkey = async () => this.#pubkey

  sign = async (event: StampedEvent, options: SignOptions = {}): Promise<SignedEvent> => {
    const result = await this.client.sign(event)

    if (!result.event) {
      throw new Error(result.messages[0]?.payload.message || "Failed to sign event")
    }

    return result.event as SignedEvent
  }

  nip04 = {
    encrypt: thrower("PomadeSigner does not support nip04"),
    decrypt: thrower("PomadeSigner does not support nip04"),
  }

  nip44 = {
    encrypt: async (pubkey: string, message: string) => {
      const sharedSecret = await this.getSharedSecret(pubkey)

      if (!sharedSecret) {
        throw new Error("Failed to get shared secret")
      }

      return nt44.v2.encrypt(message, sharedSecret)
    },
    decrypt: async (pubkey: string, message: string) => {
      const sharedSecret = await this.getSharedSecret(pubkey)

      if (!sharedSecret) {
        throw new Error("Failed to get shared secret")
      }

      return nt44.v2.decrypt(message, sharedSecret)
    },
  }

  async cleanup() {
    this.client.rpc.stop()
  }
}
