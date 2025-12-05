export type Commit = {
}

export type Shard = {
}

export type CreateShardsResult = {
  pubkey: Uint8Array
  commits: Commit[]
  shards: Shard[]
}

export const createShards = (secret: Uint8Array, total: number, threshold: number): CreateShardsResult => {
}
