// @flow

import {
  MetadataList,
  TransactionMetadatum,
} from '@emurgo/react-native-haskell-shelley'

import {testVector, assert} from '../util'

/**
 * Tests for TransactionMetadata and related structs
 */

const test: () => void = async () => {
  const metadatumPtr = await TransactionMetadatum.from_bytes(
    Buffer.from('01', 'hex'),
  )

  const metadatumPtrToBytes = await metadatumPtr.to_bytes()
  assert(
    Buffer.from(metadatumPtrToBytes).toString('hex') === '01',
    'TransactionMetadatum.to_bytes should match original input address',
  )

  await testVector(MetadataList, TransactionMetadatum, metadatumPtr)
}

export default test
