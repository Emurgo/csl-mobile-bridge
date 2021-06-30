// @flow

import {
  ByronAddress,
  Address,
  Bip32PublicKey,
} from '@emurgo/react-native-haskell-shelley'

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

  // icarus from key
  const bip32AccountKey = await Bip32PublicKey.from_bytes(
    Buffer.from(
      'fd5f660313245449df2c6d44e7276285cf1e2c5ba0bc8b4deda538cea2854684' +
        '659478fd609f99c5aa9a35db48de3a6b7a1f0c2561023e01a0e0e2877aa14ead',
      'hex',
    ),
  )
  const addrKey = await (await bip32AccountKey.derive(0)).derive(0)
  const byronAddrFromKey = await ByronAddress.icarus_from_key(
    addrKey,
    764824073,
  )
  assert(
    (await byronAddrFromKey.to_base58()) ===
      'Ae2tdPwUPEZG1E5qPwzH4XZqc9ToVzBC8n1YXwyojGSYbNnfAAZxx5Ckw25',
    'ByronAddress::icarus_from_key()',
  )
}

export default test
