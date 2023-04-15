// @flow
/* eslint-disable max-len */

import {
  Vkeywitness,
  Vkeywitnesses,
  PublicKey,
  Vkey,
  Ed25519Signature,
} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

/**
 * <Name>
 */

const test: () => void = async () => {
  const pkeyBech32 =
    'ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2'
  const publicKey = await PublicKey.from_bech32(pkeyBech32)
  const vkey = await Vkey.new(publicKey)

  const signatureHex =
    '00b36cebd884e6661f27d8888d7e1baa5de6ced4eb66dd14b4103abb755c83f0196d5cbd7851ec1b60e94f6a8e4b9ef2deab3f680af7319e4fc86aba1c412f02'
  const ed25519Signature = await Ed25519Signature.from_bytes(
    Buffer.from(signatureHex, 'hex'),
  )

  // ------------------------------------------------
  // ------------------ Vkeywitness -----------------
  const _vkeywitness = await Vkeywitness.new(vkey, ed25519Signature)
  assert(_vkeywitness instanceof Vkeywitness, 'Vkeywitness::new()')
  const _vkeywitnessToBytes = await _vkeywitness.to_bytes()
  const _vkeywitnessFromBytes = await Vkeywitness.from_bytes(
    _vkeywitnessToBytes,
  )
  const _vkeywitnessFromBytesToBytes = await _vkeywitnessFromBytes.to_bytes()
  assert(
    Buffer.from(_vkeywitnessToBytes).toString('hex') ===
      Buffer.from(_vkeywitnessFromBytesToBytes).toString('hex'),
    'Vkeywitness from_bytes/to_bytes',
  )

  // ------------------------------------------------
  // ---------------- Vkeywitnesses -----------------
  const vkeyWits = await Vkeywitnesses.new()
  assert((await vkeyWits.len()) === 0, 'Vkeywitnesses.len() should return 0')
}

export default test
