// @flow

import {
  AssetName,
  AssetNames,
  PolicyID,
  PolicyIDs,
} from '@emurgo/react-native-haskell-shelley'

import {assert, testHashToFromBytes, testVector} from '../util'

/**
 * Tests for:
 *   - AssetName
 *   - AssetNames
 */

const test: () => void = async () => {
  /**
   * AssetName
   */
  const nameHex = 'ab3d1f'
  const assetName = await AssetName.new(Buffer.from(nameHex, 'hex'))
  assert(
    assetName instanceof AssetName,
    'AssetName.new should return instance of AssetName',
  )
  const assetNameToBytes = Buffer.from(
    await assetName.to_bytes(),
    'hex',
  ).toString('hex')
  // TODO: fix
  // assert(
  //   assetNameToBytes === nameHex,
  //   'AssetName.to_bytes() should match original input value. ' +
  //     `Received: ${assetNameToBytes}, expected: ${nameHex}`,
  // )

  /**
   * AssetNames
   */
  await testVector(AssetNames, AssetName, assetName)

  /**
   * PolicyID
   */
  const policyIDHex = '3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  await testHashToFromBytes(PolicyID, policyIDHex)

  /**
   * PolicyIDs
   */
  const policyID = await PolicyID.from_bytes(Buffer.from(policyIDHex, 'hex'))
  await testVector(PolicyIDs, PolicyID, policyID)
}

export default test
