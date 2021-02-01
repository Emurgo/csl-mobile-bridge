// @flow

import {ByronAddress, Address} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * ByronAddress
 */

const test: () => void = async () => {
  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
  const address = await Address.from_bytes(baseAddrBytes)
  const addrBase58 =
    'Ae2tdPwUPEZHu3NZa6kCwet2msq4xrBXKHBDvogFKwMsF18Jca8JHLRBas7'
  const byronAddress = await ByronAddress.from_base58(addrBase58)
  assert(
    (await byronAddress.to_base58()) === addrBase58,
    'ByronAddress.to_base58 should match original input address',
  )
  const byronAddrFromAddr = await ByronAddress.from_address(address)
  const addrFromByronAddr = await byronAddress.to_address()
  assert(
    byronAddrFromAddr === undefined,
    'ByronAddress.from_address should return undefined on non-byron Address',
  )
  assert(
    !(await ByronAddress.is_valid(baseAddrHex)),
    'ByronAddress.is_valid should return false on non-byron Address',
  )
  assert(
    await ByronAddress.is_valid(addrBase58),
    'ByronAddress.is_valid should return true on valid address',
  )
  assert(
    (await (await ByronAddress.from_address(addrFromByronAddr)).to_base58()) ===
      addrBase58,
    'ByronAddress.to_address',
  )
  assert(
    (await byronAddress.byron_protocol_magic()) === 764824073,
    'ByronAddress.byron_protocol_magic()',
  )
  const byronAddressAttributesHex = Buffer.from(
    await byronAddress.attributes(),
    'hex',
  ).toString('hex')
  assert(
    byronAddressAttributesHex instanceof String ||
      typeof byronAddressAttributesHex === 'string',
    'ByronAddress::attributes()',
  )
}

export default test
