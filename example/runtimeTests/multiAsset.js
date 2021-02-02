// @flow

import {AssetName} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * Tests for:
 *   - AssetName
 */

const test: () => void = async () => {
  const name = Buffer.from('ab3d1f', 'hex')
  const assetName = await AssetName.new(name)
  assert(
    assetName instanceof AssetName,
    'AssetName.new should return instance of AssetName',
  )
}

export default test
