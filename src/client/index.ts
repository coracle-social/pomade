import {sha256, sample, call, thrower, parseJson, spec, textEncoder} from '@welshman/lib'
import {nip44, signWithOptions} from '@welshman/signer'
import type {ISigner, SignOptions} from '@welshman/signer'
import {publish, request, PublishStatus} from '@welshman/net'
import {prep, makeSecret, getPubkey, getTagValue} from '@welshman/util'
import type {TrustedEvent, SignedEvent, EventTemplate, StampedEvent} from '@welshman/util'
import {Schema, Lib, PackageEncoder} from '@frostr/bifrost'
import type {GroupPackage} from '@frostr/bifrost'

import {Kinds, rpc} from '../lib/index.js'
import type {IStorageFactory, IStorage} from '../lib/index.js'

export type ClientOptions = {
  indexerRelays: string[]
  signerPubkeys: string[]
  storage: IStorageFactory
}

export class Client {
  constructor(readonly options: ClientOptions) {}

  async register({
    total,
    threshold,
    userSecret,
    emailService,
    userEmail,
  }: {
    total: number
    threshold: number
    userSecret: string
    emailService: string
    userEmail: string
  }) {
    const {indexerRelays, signerPubkeys} = this.options

    if (signerPubkeys.length < total) {
      throw new Error('Not enough signers to meet threshold')
    }

    if (threshold <= 0) {
      throw new Error('Threshold must be greater than 0')
    }

    const clientSecret = makeSecret()
    const {group, shares} = Lib.generate_dealer_pkg(threshold, total, [userSecret])
    const hexGroup = Buffer.from(PackageEncoder.group.encode(group)).toString('hex')
    const userPubkey = getPubkey(userSecret)
    const userEmailHash = await sha256(textEncoder.encode(userEmail))
    const userEmailCiphertext = await nip44.encrypt(emailService, clientSecret, userEmail)
    const remainingSignerPubkeys = Array.from(signerPubkeys)
    const errorsBySignerPubkey = new Map<string, string>()
    const signerPubkeysByIndex = new Map<number, string>()

    await Promise.all(
      shares.map(async (share, i) => {
        const hexShare = Buffer.from(PackageEncoder.share.encode(share)).toString('hex')

        while (remainingSignerPubkeys.length > 0) {
          const signerPubkey = remainingSignerPubkeys.shift()!

          let ackReceived = false

          try {
            await rpc({
              indexerRelays,
              responseKind: Kinds.RegisterACK,
              authorSecret: clientSecret,
              recipientPubkey: signerPubkey,
              requestKind: Kinds.Register,
              requestContent: [
                ['shard', hexShare],
                ['group', hexGroup],
                ['threshold', String(threshold)],
                ['email_service', emailService],
                ['email_hash', userEmailHash],
                ['email_ciphertext', userEmailCiphertext],
              ],
              acceptResponse: async (event: TrustedEvent) => {
                const tags: string[][] = parseJson(await nip44.decrypt(signerPubkey, clientSecret, event.content))
                const message = getTagValue('message', tags)
                const status = getTagValue('status', tags)

                if (status === 'ok') {
                  signerPubkeysByIndex.set(i, signerPubkey)
                  ackReceived = true

                  return true
                }

                if (status === 'error') {
                  errorsBySignerPubkey.set(signerPubkey, message || "Unknown error")

                  return true
                }
              },
            })
          } catch (e) {
            errorsBySignerPubkey.set(signerPubkey, 'Failed to publish registration event')
          }

          if (!ackReceived && !errorsBySignerPubkey.has(signerPubkey)) {
            errorsBySignerPubkey.set(signerPubkey, 'Failed to receive acknowledgment')
          }
        }
      }),
    )

    // Check if we have enough successful registrations
    if (signerPubkeysByIndex.size < total) {
      const errors = Array.from(errorsBySignerPubkey.entries())
        .map(([pubkey, error]) => `${pubkey}: ${error}`)
        .join('\n')

      throw new Error(`Failed to register all shards:\n${errors}`)
    }

    return new Signer(this, {group, clientSecret, signerPubkeysByIndex})
  }

  async unregister(revoke: "current" | "others" | "all") {
  }

  async startRecovery(email: string) {
  }

  async completeRecovery(payload: string) {
  }

  async startLogin(email: string) {
  }

  async completeLogin(email: string, payload: string) {
  }
}

export type SignerOptions = {
  group: GroupPackage,
  clientSecret: string,
  signerPubkeysByIndex: Map<number, string>,
}

export class Signer implements ISigner {
  constructor(private client: Client, private state: SignerOptions) {}

  getPubkey = async () => this.state.group.group_pk

  sign = (event: StampedEvent, options: SignOptions = {}) => {
    const {indexerRelays} = this.client.options
    const {group, clientSecret, signerPubkeysByIndex} = this.state
    const controller = new AbortController()
    const hashedEvent = prep(event, group.group_pk)
    const members = sample(group.threshold, group.commits).map(c => c.idx)
    const template = Lib.create_session_template(members, hashedEvent.id)

    if (!template) {
      throw new Error("Failed to build signing template")
    }

    const pkg = Lib.create_session_pkg(group, template)
    const promise = Promise.all(
      members.map(async idx => {
        const signerPubkey = signerPubkeysByIndex.get(idx)!

        const response = await rpc({
          indexerRelays,
          requestKind: Kinds.SignatureRequest,
          responseKind: Kinds.PartialSignature,
          recipientPubkey: signerPubkey,
          authorSecret: clientSecret,
          requestContent: [
            ['package', JSON.stringify(pkg)],
            ['event', JSON.stringify(event)],
          ],
        })

        const psigJson = getTagValue('psig', response?.tags || [])

        return Schema.sign.psig_pkg.parse(parseJson(psigJson))
      })
    ).then(partialSignatures => {
      const ctx = Lib.get_session_ctx(group, pkg)
      const signatureEntries = Lib.combine_signature_pkgs(ctx, partialSignatures)
      const signature = signatureEntries[0]?.[2]

      if (!signature) {
        throw new Error('Failed to combine signatures')
      }

      return {...hashedEvent, sig: signature} as SignedEvent
    })

    options.signal?.addEventListener("abort", () => {
      controller.abort()
    })

    return signWithOptions(promise, options)
  }

  nip04 = {
    encrypt: thrower("Multisig signers do not support encryption."),
    decrypt: thrower("Multisig signers do not support encryption."),
  }

  nip44 = {
    encrypt: thrower("Multisig signers do not support encryption."),
    decrypt: thrower("Multisig signers do not support encryption."),
  }
}
