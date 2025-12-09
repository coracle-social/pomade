import {sha256, parseJson, spec, textEncoder} from '@welshman/lib'
import {nip44} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import {makeSecret, getPubkey, getTagValue} from '@welshman/util'
import type {TrustedEvent} from '@welshman/util'
import {Kinds, makeRPCEvent, fetchRelays} from '../lib/index.js'
import {trustedKeyDeal, hexShard} from '../lib/frost.js'
import type {KeyShard} from '../lib/frost.js'

export type CreateClientOptions = {
  inboxRelays: string[]
  outboxRelays: string[]
  indexerRelays: string[]
  signerPubkeys: string[]
}

export type ClientOptions = CreateClientOptions & {
  secret: string
}

export class Client {
  constructor(private options: ClientOptions) {
    if (options.inboxRelays.length === 0) {
      throw new Error('No inbox relays configured for client')
    }
  }

  static create(options: CreateClientOptions) {
    return new Client({...options, secret: makeSecret()})
  }

  async register({
    threshold,
    maxSigners,
    userSecret,
    emailService,
    userEmail,
    emailCollisionPolicy = 'reject',
  }: {
    threshold: number
    maxSigners: number
    userSecret: string
    emailService: string
    userEmail: string
    emailCollisionPolicy?: 'reject' | 'replace'
  }) {
    if (maxSigners < threshold) {
      throw new Error('Not enough signers to meet threshold')
    }

    if (threshold <= 0) {
      throw new Error('Threshold must be greater than 0')
    }

    const deal = trustedKeyDeal(BigInt('0x' + userSecret), threshold, maxSigners)
    const userPubkey = getPubkey(userSecret)
    const userEmailHash = await sha256(textEncoder.encode(userEmail))
    const userEmailCiphertext = await nip44.encrypt(emailService, this.options.secret, userEmail)
    const remainingSignerPubkeys = Array.from(this.options.signerPubkeys)
    const shardsBySignerPubkey = new Map<string, KeyShard>()
    const errorsBySignerPubkey = new Map<string, string>()

    await Promise.all(
      deal.shards.map(async (shard, i) => {
        while (remainingSignerPubkeys.length > 0) {
          const signerPubkey = remainingSignerPubkeys.shift()!
          const signerRelays = await fetchRelays({pubkey: signerPubkey, relays: this.options.indexerRelays})

          const registerEvent = makeRPCEvent({
            authorSecret: this.options.secret,
            recipientPubkey: signerPubkey,
            kind: Kinds.Register,
            content: [
              ['shard', hexShard(shard)],
              ['pubkey', userPubkey],
              ['signers_count', String(maxSigners)],
              ['signers_threshold', String(threshold)],
              ['email_service', emailService],
              ['email_hash', userEmailHash],
              ['email_ciphertext', userEmailCiphertext],
              ['email_collision_policy', emailCollisionPolicy],
            ],
          })

          const publishResults = await publish({relays: signerRelays, event: registerEvent})

          // Check if at least one relay accepted the event
          if (!Object.values(publishResults).some(spec({status: PublishStatus.Success}))) {
            errorsBySignerPubkey.set(signerPubkey, 'Failed to publish registration event')
            return
          }

          // Wait for acknowledgment from the signer
          const controller = new AbortController()
          const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(30_000)])


          let ackReceived = false

          await request({
            signal,
            relays: this.options.inboxRelays,
            filters: [
              {
                kinds: [Kinds.RegisterACK],
                authors: [signerPubkey],
                '#p': [getPubkey(this.options.secret)],
                '#e': [registerEvent.id],
              },
            ],
            onEvent: async (event: TrustedEvent) => {
              const tags: string[][] = parseJson(await nip44.decrypt(signerPubkey, this.options.secret, event.content))
              const message = getTagValue('message', tags)
              const status = getTagValue('status', tags)

              if (status === 'ok') {
                shardsBySignerPubkey.set(signerPubkey, shard)
                ackReceived = true
                controller.abort()
              }

              if (status === 'error') {
                errorsBySignerPubkey.set(signerPubkey, message || "Unknown error")
                controller.abort()
              }
            },
          })

          if (!ackReceived) {
            errorsBySignerPubkey.set(signerPubkey, 'Failed to receive acknowledgment')
          }
        }
      }),
    )

    // Check if we have enough successful registrations
    if (shardsBySignerPubkey.size < deal.shards.length) {
      const errors = Array.from(errorsBySignerPubkey.entries())
        .map(([pubkey, error]) => `${pubkey}: ${error}`)
        .join('\n')

      throw new Error(`Failed to register all shards:\n${errors}`)
    }

    return {
      userPubkey,
      shardsBySignerPubkey,
    }
  }
}
