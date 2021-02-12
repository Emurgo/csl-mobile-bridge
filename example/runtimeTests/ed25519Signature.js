// @flow
/* eslint-disable  max-len */

import {Ed25519Signature} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * Ed25519Signature
 */

const test: () => void = async () => {
  const signatureHex =
    '00b36cebd884e6661f27d8888d7e1baa5de6ced4eb66dd14b4103abb755c83f0196d5cbd7851ec1b60e94f6a8e4b9ef2deab3f680af7319e4fc86aba1c412f02'
  const ed25519Signature = await Ed25519Signature.from_bytes(
    Buffer.from(signatureHex, 'hex'),
  )
  const ed25519SignatureToBytes = await ed25519Signature.to_bytes()
  assert(
    Buffer.from(ed25519SignatureToBytes).toString('hex') === signatureHex,
    'Ed25519Signature from_bytes/to_bytes',
  )
}

export default test
