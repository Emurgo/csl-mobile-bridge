// @flow

import {
  Certificate,
  Certificates,
  Ed25519KeyHash,
  StakeRegistration,
  StakeDeregistration,
  StakeCredential,
  StakeDelegation,
} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

const test: () => void = async () => {
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex')
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes)

  const stakeCred = await StakeCredential.from_keyhash(ed25519KeyHash)
  const stakeReg = await StakeRegistration.new(stakeCred)
  const stakeDereg = await StakeDeregistration.new(stakeCred)
  const poolKeyHash = await Ed25519KeyHash.from_bytes(
    Buffer.from(
      '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce43dcd',
      'hex',
    ),
  )
  const stakeDelegation = await StakeDelegation.new(stakeCred, poolKeyHash)
  // ------------------------------------------------
  // ------------------ Certificate -----------------
  const cert = await Certificate.new_stake_registration(stakeReg)
  const certHex = Buffer.from(await cert.to_bytes(), 'hex').toString('hex')
  const _cert = await Certificate.from_bytes(Buffer.from(certHex, 'hex'))
  assert(
    Buffer.from(await _cert.to_bytes(), 'hex').toString('hex') === certHex,
    'Certificate::new_stake_registration()',
  )
  assert(
    (await cert.as_stake_registration()) instanceof StakeRegistration,
    'Certificate::as_stake_registration()',
  )
  assert(
    (await cert.as_stake_deregistration()) == null,
    'Certificate::as_stake_deregistration() should be null for different cert',
  )
  const certDereg = await Certificate.new_stake_deregistration(stakeDereg)
  assert(certDereg, 'Certificate::new_stake_deregistration()')
  assert(
    (await certDereg.as_stake_deregistration()) instanceof StakeDeregistration,
    'Certificate::as_stake_deregistration()',
  )
  assert(
    (await certDereg.as_stake_delegation()) == null,
    'Certificate::as_stake_delegation() should be null for different cert',
  )
  const certDel = await Certificate.new_stake_delegation(stakeDelegation)
  assert(certDel, 'Certificate::new_stake_delegation()')
  assert(
    (await certDel.as_stake_delegation()) instanceof StakeDelegation,
    'Certificate::as_stake_delegation()',
  )
  assert(
    (await certDel.as_stake_registration()) == null,
    'Certificate::as_stake_registration() should be null for different cert',
  )

  // ------------------------------------------------
  // ----------------- Certificates -----------------
  const certs = await Certificates.new()
  assert((await certs.len()) === 0, 'Certificates.len() should return 0')
  await certs.add(cert)
  assert((await certs.len()) === 1, 'Certificates.len() should return 1')
  assert((await certs.get(0)) instanceof Certificate, 'Certificates::get()')
}

export default test
