// @flow

import {
  StakeCredential,
  Ed25519KeyHash,
  ScriptHash,
} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

/**
 * StakeCredential
 */

const test: () => void = async () => {
  // ------------------------------------------------
  // --------------- StakeCredential ----------------
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex')
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes)

  const stakeCred = await StakeCredential.from_keyhash(ed25519KeyHash)
  const ed25519KeyHashOrig = await stakeCred.to_keyhash()
  const stakeCredBytes = await stakeCred.to_bytes()
  const stakeCredFromBytes = await StakeCredential.from_bytes(
    Buffer.from(stakeCredBytes, 'hex'),
  )
  assert(
    Buffer.from(await ed25519KeyHashOrig.to_bytes()).toString('hex') ===
      keyHashHex,
    'StakeCredential:: -> to_keyhash -> to_bytes should match original input',
  )
  assert((await stakeCred.kind()) === 0, 'StakeCredential:: kind should match')
  assert(
    Buffer.from(
      await (await stakeCredFromBytes.to_keyhash()).to_bytes(),
    ).toString('hex') === keyHashHex,
    'StakeCredential -> to_bytes -> from_bytes -> to_keyhash -> should match',
  )

  const scriptHash = await ScriptHash.from_bytes(keyHashBytes)
  assert(
    (await stakeCred.to_scripthash()) == null,
    'StakeCredential::to_scripthash should be null for Ed25519KeyHash',
  )
  const stakeCredFromScriptHash = await StakeCredential.from_scripthash(
    scriptHash,
  )
  assert(
    (await stakeCredFromScriptHash.to_keyhash()) == null,
    'StakeCredential::to_keyhash should be null for ScriptHash',
  )
  assert(
    Buffer.from(
      await (await stakeCredFromScriptHash.to_scripthash()).to_bytes(),
    ).toString('hex') === keyHashHex,
    'StakeCredential::to_scripthash',
  )
}

export default test
