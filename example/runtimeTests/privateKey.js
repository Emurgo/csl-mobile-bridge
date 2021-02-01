// @flow

import {Bip32PrivateKey} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * PrivateKey
 */

const test: () => void = async () => {
  // start from Bip32PrivateKey
  const bip32PrvKeyHex =
    '20afd5ff1f7f551c481b7e3f3541f7c63f5f6bcb293af92565af3deea0bcd648' +
    '1a6e7b8acbe38f3906c63ccbe8b2d9b876572651ac5d2afc0aca284d9412bb1b' +
    '4839bf02e1d990056d0f06af22ce4bcca52ac00f1074324aab96bbaaaccf290d'
  const _bip32PrivateKey = await Bip32PrivateKey.from_bytes(
    Buffer.from(bip32PrvKeyHex, 'hex'),
  )
  // get PrivateKey from Bip32PrivateKey
  const privateKey = await _bip32PrivateKey.to_raw_key()
  assert(
    (await (await privateKey.to_public()).as_bytes()).length === 32,
    'PrivateKey::to_public()',
  )
}

export default test
