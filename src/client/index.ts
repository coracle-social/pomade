import {sha256, textEncoder} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request} from '@welshman/net'
import {makeSecret, getPubkey} from '@welshman/util'
import {Kinds, makeRPCEvent} from '../lib/index.js'

export type CreateClientOptions = {
  inboxRelays: string[]
}

export type ClientOptions = CreateClientOptions & {
  secret: string
}

export class Client {
  constructor(private options: ClientOptions) {}

  static create(options: CreateClientOptions) {
    return new Client({...options, secret: makeSecret()})
  }

  async register({
    threshold,
    userSecret,
    signerPubkeys,
    recoveryService,
    recoveryEmail,
  }: {
    threshold: number
    userSecret: string
    signerPubkeys: string[]
    recoveryService: string
    recoveryEmail: string
  }) {
    const userPubkey = getPubkey(userSecret)
    const recoveryEmailHash = await sha256(textEncoder.encode(recoveryEmail))
    const recoveryEmailCiphertext = await nip44.encrypt(recoveryService, this.options.secret, recoveryEmail)

    // todo: implement logic for sending shards and handling errors.
    //
    // here is a stubbed out register event:
    // const event = makeRPCEvent({
    //   authorSecret: this.secret,
    //   recipientPubkey: signerPubkey,
    //   kind: Kinds.Register,
    //   content: [
    //     ["shard", "<hex encoded secret key shard>"],
    //     ["pubkey", userPubkey],
    //     ["signers_count", signerPubkeys.length],
    //     ["signers_threshold", threshold],
    //     ["recovery_service", recoveryService],
    //     ["recovery_email_hash", recoveryEmailHash],
    //     ["recovery_email_ciphertext", recoveryEmailCiphertext],
    //     ["recovery_email_collision", "reject"],
    //   ],
    // })
    //
    // Here is code from a different implementation that uses a coordinator. Do not use the coordinator, but do use similar logic:
    // const [m, n] = options.policy

    // if (options.signerPubkeys.length < n) {
    //   throw new Error("Not enough signers to create all shards")
    // }

    // const deal = trustedKeyDeal(BigInt("0x" + options.secret), m, n)

    // // Add the VSS commits to each shard
    // // for (const shard of deal.shards) {
    // //   shard.pubShard.vssCommit = deal.commits
    // // }

    // // Use the pubkey and adjusted secret from the deal (BIP-340 adjusted if needed)
    // const signer = Nip01Signer.fromSecret(options.secret)
    // const ourPubkey = await signer.getPubkey()
    // const ackRelays = await options.getPubkeyRelays(ourPubkey, RelayMode.Read)
    // const remainingSignerPubkeys = shuffle(uniq(options.signerPubkeys))
    // const errorsBySignerPubkey = new Map<string, string>()
    // const shardsBySignerPubkey = new Map<string, KeyShard>()

    // if (ackRelays.length === 0) {
    //   throw new Error("No read relays returned for user pubkey")
    // }

    // nip46Log(`generated promenade shards for user ${ourPubkey}`, deal)

    // await Promise.all(
    //   deal.shards.map(async (shard, i) => {
    //     while (remainingSignerPubkeys.length > 0) {
    //       const signerPubkey = remainingSignerPubkeys.shift()!

    //       nip46Log(`generating proof of work for shard ${i}`)

    //       const shardTemplate = makeEvent(PROMENADE_SHARD_SHARE, {
    //         content: await signer.nip44.encrypt(signerPubkey, hexShard(shard)),
    //         tags: [
    //           ["p", signerPubkey],
    //           ["coordinator", options.coordinatorUrl],
    //           ...ackRelays.map(url => ["reply", url]),
    //         ],
    //       })

    //       const shardTemplateWithWork = await tryCatch(() =>
    //         options.generatePow(prep(shardTemplate, ourPubkey), 20),
    //       )

    //       if (!shardTemplateWithWork) {
    //         errorsBySignerPubkey.set(signerPubkey, "Failed to generate work")
    //         continue
    //       }

    //       const shardEvent = await signer.sign(shardTemplateWithWork)
    //       const shardRelays = await options.getPubkeyRelays(signerPubkey, RelayMode.Read)
    //       const publishResults = await publish({relays: shardRelays, event: shardEvent})

    //       nip46Log(`published shard ${i} to signer ${signerPubkey}`, shardRelays, publishResults)

    //       if (!Object.values(publishResults).some(spec({status: PublishStatus.Success}))) {
    //         errorsBySignerPubkey.set(signerPubkey, "Failed to publish shard")
    //         continue
    //       }

    //       const controller = new AbortController()
    //       const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(30_000)])

    //       await request({
    //         signal,
    //         relays: ackRelays,
    //         filters: [
    //           {
    //             kinds: [PROMENADE_SHARD_ACK],
    //             authors: [signerPubkey],
    //             "#p": [ourPubkey],
    //             "#e": [shardEvent.id],
    //           },
    //         ],
    //         onEvent: (event: TrustedEvent, url: string) => {
    //           nip46Log(`received ack for shard ${i} from signer ${signerPubkey} on ${url}`)
    //           shardsBySignerPubkey.set(signerPubkey, shard)
    //           options.onProgress?.(shardsBySignerPubkey.size / inc(n))
    //           controller.abort()
    //         },
    //       })

    //       if (shardsBySignerPubkey.has(signerPubkey)) {
    //         break
    //       } else {
    //         errorsBySignerPubkey.set(signerPubkey, "Failed to receive shard ACK")
    //         nip46Log(`failed to receive ack for shard ${i} from signer ${signerPubkey}`)
    //       }
    //     }
    //   }),
    // )

    // if (shardsBySignerPubkey.size < deal.shards.length) {
    //   throw new PromenadeShardError("Failed to publish all shards", errorsBySignerPubkey)
    // }

    // const connectSecret = randomId()
    // const signerSecret = makeSecret()
    // const signerPubkey = getPubkey(signerSecret)
    // const tags = [
    //   ["h", signerPubkey],
    //   ["threshold", String(m)],
    //   ["handlersecret", signerSecret],
    //   ["profile", "MAIN", connectSecret, ""],
    // ]

    // for (const [pubkey, shard] of shardsBySignerPubkey) {
    //   tags.push(["p", pubkey, hexPubShard(shard.pubShard)])
    // }

    // nip46Log(`registering coordinator account`, tags)

    // const relays = [options.coordinatorUrl]
    // const event = await signer.sign(makeEvent(PROMENADE_REGISTER_ACCOUNT, {tags}))
    // const accountResults = await publish({relays, event})

    // if (!Object.values(accountResults).some(spec({status: PublishStatus.Success}))) {
    //   throw new Error("Failed to publish accounts to coordinator")
    // }

    // nip46Log(`successfully created promenade broker`)

    // const clientSecret = makeSecret()

    // return new Nip46Broker({
    //   relays,
    //   clientSecret,
    //   signerPubkey,
    //   connectSecret,
    // })
  }
}
