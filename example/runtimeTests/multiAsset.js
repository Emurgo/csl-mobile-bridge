// @flow

import {
  AssetName,
  AssetNames,
  Assets,
  BigNum,
  ScriptHash,
  ScriptHashes,
  MultiAsset,
  Value,
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
  const assetNameFromRust = Buffer.from(await assetName.name(), 'hex').toString(
    'hex',
  )

  assert(
    assetNameFromRust === nameHex,
    'AssetName.name() should match original input value. ' +
      `Received: ${assetNameFromRust}, expected: ${nameHex}`,
  )

  /**
   * AssetNames
   */
  await testVector(AssetNames, AssetName, assetName)

  /**
   * PolicyID
   */
  const policyIDHex = '3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  await testHashToFromBytes(ScriptHash, policyIDHex)

  /**
   * PolicyIDs
   */
  const policyID = await ScriptHash.from_bytes(Buffer.from(policyIDHex, 'hex'))
  await testVector(ScriptHashes, ScriptHash, policyID)

  /**
   * Assets
   */
  const assets = await testDict(
    Assets,
    AssetName,
    assetName,
    BigNum,
    await BigNum.from_str('100'),
  )
  const _val = await assets.get(assetName)
  assert((await _val.to_str()) === '100', 'Assets::get()')
  const previousAmount = await assets.insert(
    assetName,
    await BigNum.from_str('200'),
  )
  assert((await previousAmount.to_str()) === '100', 'Assets::get()')

  /**
   * MultiAsset
   */
  const multiAsset = await testDict(
    MultiAsset,
    ScriptHash,
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
  assert((await __val.to_str()) === '200', 'MultiAsset::get()')

  const otherMa = await MultiAsset.new()
  const otherAssets = await Assets.new()
  await otherAssets.insert(assetName, await BigNum.from_str('200'))
  await otherMa.insert(policyID, otherAssets)

  const subResult = await multiAsset.sub(otherMa)
  const subResultAssets = await subResult.get(policyID)
  assert(subResultAssets == null, 'MultiAsset::sub()')

  /**
   * Value
   */
  const value = await Value.new(await BigNum.from_str('200'))
  // prettier-ignore
  assert((await (await value.coin()).to_str()) === '200', 'Value::coin()')
  const otherValue = await Value.new(await BigNum.from_str('100'))
  assert((await value.compare(otherValue)) === 1, 'Value::compare()')
  assert((await otherValue.compare(value)) === -1, 'Value::compare()')
  await value.set_multiasset(multiAsset)
  // since otherValue does not contain multiasset, all the corresponding
  // asset values are assumed to be 0. so value > otherValue
  assert((await value.compare(otherValue)) === 1, 'Value::compare()')

  const otherValueAssets = await Assets.new()
  await otherValueAssets.insert(
    await AssetName.new(Buffer.from('0ada', 'hex')),
    await BigNum.from_str('40000000'),
  )
  const otherValueMultiAsset = await MultiAsset.new()
  const otherPolicyID = await ScriptHash.from_bytes(
    Buffer.from(
      '4aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf',
      'hex',
    ),
  )
  // await otherValueMultiAsset.insert(policyID, assets) // same asset that value has
  await otherValueMultiAsset.insert(otherPolicyID, otherValueAssets)
  await otherValue.set_multiasset(otherValueMultiAsset)
  assert((await value.compare(otherValue)) == null, 'Value::compare()')
}

export default test
