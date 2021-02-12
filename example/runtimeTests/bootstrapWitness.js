// @flow
/* eslint-disable  max-len */

import {
  BootstrapWitness,
  BootstrapWitnesses,
  PublicKey,
  Bip32PublicKey,
  Vkey,
  Ed25519Signature,
  ByronAddress,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * BootstrapWitness
 */

const test: () => void = async () => {
  // ------------------------------------------------
  // --------------- BootstrapWitness ---------------
  const _publicKey = await PublicKey.from_bytes(
    Buffer.from(
      '42cfdc53da2220ba52ce62f8e20ab9bb99857a3fceacf43d676d7987ad909b53',
      'hex',
    ),
  )
  const _bip32PubKey = await Bip32PublicKey.from_bytes(
    Buffer.from(
      '42cfdc53da2220ba52ce62f8e20ab9bb99857a3fceacf43d676d7987ad909b53ed75534e0d0ee8fce835eb2e7c67c5caec18a9c894388d9a046380edebbfc46d',
      'hex',
    ),
  )

  const _vkey = await Vkey.new(_publicKey)
  const _signature = await Ed25519Signature.from_bytes(
    Buffer.from(
      '00469b3a56dab16881a5a1b9a9415ba183979e919ae05b1475eca670df85a14bc7004375744570f02eb07729b5a9d39a3a61eec372183e2e5ea14649cea8970b',
      'hex',
    ),
  )
  // const _chaincode = Buffer.from(
  //   '15582aa9bf54e792ef62aba8ba3014c6a86c186140ad317fbfbba00929ec458b',
  //   'hex',
  // )
  const _chaincode = await _bip32PubKey.chaincode()

  const _addr = await ByronAddress.from_base58(
    'Ae2tdPwUPEZG1E5qPwzH4XZqc9ToVzBC8n1YXwyojGSYbNnfAAZxx5Ckw25',
  )
  const _attributes = await _addr.attributes()
  // const _attributes = Buffer.from('a0', 'hex')

  const _bootStrapWitness = await BootstrapWitness.new(
    _vkey,
    _signature,
    _chaincode,
    _attributes,
  )
  assert(
    _bootStrapWitness instanceof BootstrapWitness,
    'BootstrapWitness::new()',
  )

  const _bootStrapWitnessToBytes = await _bootStrapWitness.to_bytes()
  const _bootStrapWitnessFromBytes = await BootstrapWitness.from_bytes(
    _bootStrapWitnessToBytes,
  )
  const _bootStrapWitnessFromBytesToBytes = await _bootStrapWitnessFromBytes.to_bytes()
  assert(
    Buffer.from(_bootStrapWitnessToBytes).toString('hex') ===
      Buffer.from(_bootStrapWitnessFromBytesToBytes).toString('hex'),
    'BootstrapWitness::from_bytes/to_bytes',
  )

  // ------------------------------------------------
  // -------------- BootstrapWitnesses --------------
  const bootstrapWits = await BootstrapWitnesses.new()
  assert(
    (await bootstrapWits.len()) === 0,
    'BootstrapWitnesses.len() should return 0',
  )
  await bootstrapWits.add(_bootStrapWitness)
  assert(
    (await bootstrapWits.len()) === 1,
    'BootstrapWitnesses.len() should return 1',
  )
}

export default test
