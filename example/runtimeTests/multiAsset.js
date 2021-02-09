// @flow

import {
  AssetName,
  AssetNames,
  Assets,
  BigNum,
  PolicyID,
  PolicyIDs,
  MultiAsset,
} from '@emurgo/react-native-haskell-shelley'

import {assert, testHashToFromBytes, testVector, testDict} from '../util'

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

  /**
   * Assets
   */
  const assets = await testDict(
    Assets,
    AssetName,
    assetName,
    BigNum,
    await BigNum.from_str('10000000'),
  )
  const _val = await assets.get(assetName)
  assert((await _val.to_str()) === '10000000', 'Assets::get()')
  const previousAmount = await assets.insert(
    assetName,
    await BigNum.from_str('20000000'),
  )
  assert((await previousAmount.to_str()) === '10000000', 'Assets::get()')

  /**
   * MultiAsset
   */
  const multiAsset = await testDict(
    MultiAsset,
    PolicyID,
    policyID,
    Assets,
    assets,
  )
  const _assets = await multiAsset.get(policyID)
  assert(
    _assets instanceof Assets,
    'MultiAsset.get() should return instance of Assets',
  )
  const __val = await _assets.get(assetName)
  assert((await __val.to_str()) === '20000000', 'MultiAsset::get()')
}

export default test
