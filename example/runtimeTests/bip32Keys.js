// @flow

import {
  Bip32PrivateKey,
  Bip32PublicKey,
} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

const test: () => void = async () => {
  /**
   * Bip32PrivateKey
   */
  const bip32PrivKeyBytes =
    '2001e30383cdb706f494829906e1d5090fcd67db66eba8c573a9e6f036161c59' +
    '5cbcccbf3b32e9b94e9cf1dfd29270af1f242f7d0bf1344c9b8034567ac2a7e1' +
    '15582aa9bf54e792ef62aba8ba3014c6a86c186140ad317fbfbba00929ec458b'
  const bip32PrivateKey = await Bip32PrivateKey.from_bytes(
    Buffer.from(bip32PrivKeyBytes, 'hex'),
  )
  assert(
    Buffer.from(await bip32PrivateKey.as_bytes()).toString('hex') ===
      bip32PrivKeyBytes,
    'bip32PrivateKey.as_bytes() should match original input value',
  )

  /**
   * Bip32PublicKey
   */
  const bip32PubKeyBytes =
    '64593d25cfbb70ddff435e75194cc4854e5d0f67a26e4493c5c00e0a989bd144' +
    '4839bf02e1d990056d0f06af22ce4bcca52ac00f1074324aab96bbaaaccf290d'
  const bip32PublicKey = await Bip32PublicKey.from_bytes(
    Buffer.from(bip32PubKeyBytes, 'hex'),
  )
  assert(
    Buffer.from(await bip32PublicKey.as_bytes()).toString('hex') ===
      bip32PubKeyBytes,
    'bip32PublicKey.as_bytes() should match original input value',
  )
}

export default test
