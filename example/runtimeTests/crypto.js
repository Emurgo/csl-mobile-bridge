// @flow

import {
  Vkey,
  Ed25519KeyHash,
  ScriptHash,
  TransactionHash,
  PublicKey,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

const test: () => void = async () => {
  // ------------------------------------------------
  // --------------------- Vkey ---------------------
  const pkeyBech32 =
    'ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2'
  const publicKey = await PublicKey.from_bech32(pkeyBech32)
  const vkey = await Vkey.new(publicKey)
  assert(vkey instanceof Vkey, 'Vkey::new()')

  // ------------------------------------------------
  // ---------------- Ed25519KeyHash ----------------
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex')
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes)
  const ed25519KeyHashToBytes = await ed25519KeyHash.to_bytes()
  assert(
    Buffer.from(ed25519KeyHashToBytes).toString('hex') === keyHashHex,
    'Ed25519KeyHash.to_bytes should match original input address',
  )

  // ------------------------------------------------
  // ------------------- ScriptHash -----------------
  const scriptHash = await ScriptHash.from_bytes(keyHashBytes)
  const scriptHashToBytes = await scriptHash.to_bytes()
  assert(
    Buffer.from(scriptHashToBytes).toString('hex') === keyHashHex,
    'ScriptHash.to_bytes should match original input address',
  )

  // ------------------------------------------------
  // --------------- TransactionHash ----------------
  const hash32Hex =
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  const hash32Bytes = Buffer.from(hash32Hex, 'hex')
  const txHash = await TransactionHash.from_bytes(hash32Bytes)
  const txHashToBytes = await txHash.to_bytes()
  assert(
    Buffer.from(txHashToBytes).toString('hex') === hash32Hex,
    'TransactionHash.to_bytes should match original input address',
  )
}

export default test
