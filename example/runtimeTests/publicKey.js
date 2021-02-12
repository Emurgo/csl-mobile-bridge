// @flow

import {PublicKey} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * PublicKey
 */

const test: () => void = async () => {
  const pkeyBech32 =
    'ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2'
  const publicKey = await PublicKey.from_bech32(pkeyBech32)
  assert(
    (await publicKey.to_bech32()) === pkeyBech32,
    'PublicKey.to_bech32() should match original input value',
  )
  assert(
    (await publicKey.as_bytes()).length === 32,
    'PublicKey.as_bytes() should be 32 bytes length',
  )
  assert((await (await publicKey.hash()).to_bytes()).length, 'PublicKey.hash()')
}

export default test
