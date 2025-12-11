import type {EventTemplate} from '@welshman/util'
import {prep, sign, getPubkey} from '@welshman/util'

export function prepAndSign(secret: string, event: EventTemplate) {
  return sign(prep(event, getPubkey(secret)), secret)
}
