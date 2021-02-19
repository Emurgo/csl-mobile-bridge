// @flow

import {
  make_icarus_bootstrap_witness,
  make_vkey_witness,
  hash_transaction,
  min_ada_required,
  BootstrapWitness,
  TransactionHash,
  ByronAddress,
  Bip32PrivateKey,
  Vkeywitness,
  TransactionBody,
  Value,
  Coin,
  BigNum,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

const test: () => void = async () => {
  const hash32Hex =
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  const hash32Bytes = Buffer.from(hash32Hex, 'hex')
  const txHash = await TransactionHash.from_bytes(hash32Bytes)

  const addrBase58 =
    'Ae2tdPwUPEZHu3NZa6kCwet2msq4xrBXKHBDvogFKwMsF18Jca8JHLRBas7'
  const byronAddress = await ByronAddress.from_base58(addrBase58)

  const bip32PrivKeyBytes =
    '2001e30383cdb706f494829906e1d5090fcd67db66eba8c573a9e6f036161c59' +
    '5cbcccbf3b32e9b94e9cf1dfd29270af1f242f7d0bf1344c9b8034567ac2a7e1' +
    '15582aa9bf54e792ef62aba8ba3014c6a86c186140ad317fbfbba00929ec458b'
  const bip32PrivateKey = await Bip32PrivateKey.from_bytes(
    Buffer.from(bip32PrivKeyBytes, 'hex'),
  )
  const bodyHex =
    'a4008282582005ec4a4a7f4645fa66886cef2e34706907a3a7f9d8' +
    '8e0d48b313ad2cdf76fb5f008258206930f123df83e4178b0324ae' +
    '617b2028c0b38c6ff4660583a2abf1f7b08195fe00018182582b82' +
    'd818582183581ce3a1faa5b54bd1485a424d8f9b5e75296b328a2a' +
    '624ef1d2f4c7b480a0001a88e5cdab1913890219042803191c20'
  const txBody = await TransactionBody.from_bytes(Buffer.from(bodyHex, 'hex'))

  /**
   * make_icarus_bootstrap_witness()
   */
  const bootstrapWitness = await make_icarus_bootstrap_witness(
    txHash,
    byronAddress,
    bip32PrivateKey,
  )
  assert(
    bootstrapWitness instanceof BootstrapWitness,
    'make_icarus_bootstrap_witness should return instance of BootstrapWitness',
  )
  assert(
    bootstrapWitness.ptr !== undefined,
    'make_icarus_bootstrap_witness:: returns non-undefined',
  )

  /**
   * make_vkey_witness
   */
  const sk = await bip32PrivateKey.to_raw_key()
  const vkeywitness = await make_vkey_witness(txHash, sk)
  assert(
    vkeywitness instanceof Vkeywitness,
    'make_vkey_witness should return instance of Vkeywitness',
  )
  assert(
    vkeywitness.ptr !== undefined,
    'make_vkey_witness:: returns non-undefined',
  )
  assert(
    await vkeywitness.signature(),
    'make_vkey_witness::witness::signature()',
  )

  /**
   * hash_transaction
   */
  const hash = await hash_transaction(txBody)
  assert(
    hash instanceof TransactionHash,
    'hash_transaction should return instance of TransactionHash',
  )
  assert(hash.ptr !== undefined, 'hash_transaction:: returns non-undefined')

  /**
   * min_ada_required
   */
  const value = await Value.new(await Coin.from_str('200'))
  const minUtxoVal = await Coin.from_str('1000000')
  const minAda = await min_ada_required(value, minUtxoVal)
  assert(
    minAda instanceof BigNum,
    'min_ada_required should return instance of BigNum',
  )
  assert(minAda.ptr !== undefined, 'min_ada_required:: returns non-undefined')
}

export default test
