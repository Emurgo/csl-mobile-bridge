// @flow

import {AssetName, AssetNames} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * Tests for:
 *   - AssetName
 */

const test: () => void = async () => {
  const nameHex = 'ab3d1f'
  const assetName = await AssetName.new(Buffer.from(nameHex, 'hex'))
  assert(
    assetName instanceof AssetName,
    'AssetName.new should return instance of AssetName',
  )
  const toBytes = Buffer.from(await assetName.to_bytes(), 'hex').toString('hex')
  assert(
    Buffer.from(await assetName.to_bytes(), 'hex').toString('hex') === nameHex,
    'AssetName.to_bytes() should match original input value. ' +
      `Received: ${toBytes}, expected: ${nameHex}`,
  )

  /**
   * AssetNames
   */
  const assetNames = await AssetNames.new()
  assert((await assetNames.len()) === 0, 'AssetNames.len() should return 0')
  await assetNames.add(assetName)
  assert((await assetNames.len()) === 1, 'AssetNames.len() should return 1')
  assert((await assetNames.get(0)) instanceof AssetName, 'AssetNames::get()')
}

export default test
