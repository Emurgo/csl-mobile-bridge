// @flow

import {
  TransactionInput,
  TransactionHash,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * TransactionInput
 */

const test: () => void = async () => {
  const hash32Hex =
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  const hash32Bytes = Buffer.from(hash32Hex, 'hex')
  const txHash = await TransactionHash.from_bytes(hash32Bytes)
  const txHashToBytes = await txHash.to_bytes()

  const txInput = await TransactionInput.new(txHash, 0)
  assert((await txInput.index()) === 0, 'TransactionInput:: index should match')
  // prettier-ignore
  assert(
    Buffer.from(
      (await (await txInput.transaction_id()).to_bytes()),
    ).toString('hex') === Buffer.from(txHashToBytes).toString('hex'),
    'TransactionInput:: transaction id should match',
  )
}

export default test
