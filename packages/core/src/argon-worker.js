import {argon2id} from "hash-wasm"

self.onmessage = async function (ev) {
  const {value, salt, options} = ev.data

  const result = await argon2id({
    password: value,
    salt: salt,
    parallelism: options.p,
    iterations: options.t,
    memorySize: options.m,
    hashLength: 32,
    outputType: "binary",
  })

  postMessage(result)
}
