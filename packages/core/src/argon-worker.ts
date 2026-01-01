import {expose} from "threads/worker"
import {argon2id} from "@noble/hashes/argon2.js"

expose({
  argon2id: (v: Uint8Array, s: Uint8Array, o: any) => argon2id(v, s, o),
})
