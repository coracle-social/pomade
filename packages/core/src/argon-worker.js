import {argon2id} from "@noble/hashes/argon2.js"

self.onmessage = async function (ev) {
  const {value, salt, options} = ev.data

  postMessage(await argon2id(value, salt, options))
}
