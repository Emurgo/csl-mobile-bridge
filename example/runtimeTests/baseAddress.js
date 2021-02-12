// @flow

import {
  BaseAddress,
  Address,
  Ed25519KeyHash,
  StakeCredential,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * BaseAddress
 */

const test: () => void = async () => {
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex')
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes)
  const stakeCred = await StakeCredential.from_keyhash(ed25519KeyHash)

  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
  const address = await Address.from_bytes(baseAddrBytes)

  // create a BaseAddress from a payment credential & a stake credential
  const pymntAddr = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41c0a' // 28B
  const pymntAddrKeyHash = await Ed25519KeyHash.from_bytes(
    Buffer.from(pymntAddr, 'hex'),
  )
  const paymentCred = await StakeCredential.from_keyhash(pymntAddrKeyHash)
  const baseAddr = await BaseAddress.new(0, paymentCred, stakeCred)

  const pymntCredFromBaseAddr = await baseAddr.payment_cred()
  const pymntAddrFromPymntCred = await pymntCredFromBaseAddr.to_keyhash()
  assert(
    Buffer.from(await pymntAddrFromPymntCred.to_bytes()).toString('hex') ===
      pymntAddr,
    'BaseAddress:: -> payment_cred -> keyhash should match original input',
  )

  // create a BaseAddress from an Address
  const baseAddrFromAddr = await BaseAddress.from_address(address)
  assert(!!baseAddrFromAddr, 'baseAddress.from_address')
  const baseAddrToAddr = await baseAddrFromAddr.to_address()
  assert(
    Buffer.from(await baseAddrToAddr.to_bytes(), 'hex').toString('hex') ===
      Buffer.from(await address.to_bytes(), 'hex').toString('hex'),
    'baseAddress.to_address',
  )
}

export default test
