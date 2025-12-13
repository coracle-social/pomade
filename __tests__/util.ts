import {range} from "@welshman/lib"
import {getPubkey, makeSecret} from "@welshman/util"
import {LOCAL_RELAY_URL} from "@welshman/net"
import {defaultStorageFactory, context} from "../src/lib"
import {Signer} from "../src/signer"

export const signerSecrets = Array.from(range(0, 3)).map(() => makeSecret())
export const signerPubkeys = signerSecrets.map(secret => getPubkey(secret))

context.signerPubkeys = signerPubkeys
context.indexerRelays = [LOCAL_RELAY_URL]

let signers: Signer[]

export function beforeHook() {
  signers = signerSecrets.map(
    secret =>
      new Signer({
        secret,
        relays: [LOCAL_RELAY_URL],
        storage: defaultStorageFactory,
      }),
  )
}

export function afterHook() {
  signers.forEach(signer => signer.stop())
}
