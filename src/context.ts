export type Context = {
  debug: boolean
  signerPubkeys: string[]
  indexerRelays: string[]
}

export const context: Context = {
  debug: false,
  signerPubkeys: [],
  indexerRelays: [
    "wss://indexer.coracle.social/",
    "wss://relay.nostr.band/",
    "wss://purplepag.es/",
  ],
}

export function debug(...args: any) {
  if (context.debug) {
    console.log(...args)
  }
}
