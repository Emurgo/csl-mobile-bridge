// @flow
/* eslint-disable  max-len */

import {Address} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

/**
 * <Name>
 */

const test: () => void = async () => {
  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
  const address = await Address.from_bytes(baseAddrBytes)
  const addrPtrToBytes = await address.to_bytes()
  assert(
    Buffer.from(addrPtrToBytes).toString('hex') === baseAddrHex,
    'Address.to_bytes should match original input address',
  )
  let addrFromBech32 = await Address.from_bech32(
    'addr1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8sxy9w7g',
  )
  assert(
    (await addrFromBech32.to_bech32('foobar')) ===
      'foobar1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8s92n4tm',
    'Address.to_bech32 with prefix',
  )
  assert(
    (await addrFromBech32.to_bech32()) ===
      'stake1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8squng76',
    'Address.to_bech32 with default prefix',
  )
  addrFromBech32 = await Address.from_bech32(
    'addr1qyfh4879pratq227f5z6qr48mvwa3acwvtyvgq5553jk8g7nsw44z0v5d2emp8unhqz5em0d7cup75vrxhlqf6l9nzfqphk420',
  )
  assert(
    (await addrFromBech32.to_bech32()) ===
      'addr1qyfh4879pratq227f5z6qr48mvwa3acwvtyvgq5553jk8g7nsw44z0v5d2emp8unhqz5em0d7cup75vrxhlqf6l9nzfqphk420',
    'Address.to_bech32 with default prefix',
  )
  assert((await address.network_id()) === 0, 'address.network_id()')
}

export default test
