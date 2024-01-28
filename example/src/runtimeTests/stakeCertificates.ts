import {
  Credential,
  Ed25519KeyHash,
  StakeDelegation,
  StakeDeregistration,
  StakeRegistration,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

const test = async () => {
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'; // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex');
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes);

  const stakeCred = await Credential.from_keyhash(ed25519KeyHash);
  // ------------------------------------------------
  // --------------- StakeRegistration --------------
  const stakeReg = await StakeRegistration.new(stakeCred);
  /* eslint-disable */
  assert(
    Buffer.from(
      await (await stakeReg.stake_credential()).to_bytes(),
    ).toString('hex') ===
      Buffer.from(await stakeCred.to_bytes()).toString('hex'),
    'StakeRegistration:: new() -> stake_credential()',
  )
  /* eslint-enable */
  const stakeRegHex = Buffer.from(stakeReg.to_bytes()).toString(
    'hex',
  );
  const _stakeReg = await StakeRegistration.from_bytes(
    Buffer.from(stakeRegHex, 'hex'),
  );
  assert(
    Buffer.from(_stakeReg.to_bytes()).toString('hex') ===
      stakeRegHex,
    'StakeRegistration::to/from_bytes()',
  );

  // ------------------------------------------------
  // -------------- StakeDeregistration -------------
  const stakeDereg = await StakeDeregistration.new(stakeCred);
  assert(
    Buffer.from(
      await (await stakeDereg.stake_credential()).to_bytes(),
    ).toString('hex') ===
      Buffer.from(await stakeCred.to_bytes()).toString('hex'),
    'StakeDeregistration:: new() -> stake_credential()',
  );
  const stakeDeregHex = Buffer.from(
    stakeDereg.to_bytes(),
  ).toString('hex');
  const _stakeDereg = await StakeDeregistration.from_bytes(
    Buffer.from(stakeDeregHex, 'hex'),
  );
  assert(
    Buffer.from(_stakeDereg.to_bytes()).toString('hex') ===
      stakeDeregHex,
    'StakeDeregistration::to/from_bytes()',
  );

  // ------------------------------------------------
  // ---------------- StakeDelegation ---------------
  const poolKeyHash = await Ed25519KeyHash.from_bytes(
    Buffer.from(
      '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce43dcd',
      'hex',
    ),
  );
  const stakeDelegation = await StakeDelegation.new(stakeCred, poolKeyHash);
  assert(
    Buffer.from(
      await (await stakeDelegation.stake_credential()).to_bytes(),
    ).toString('hex') ===
      Buffer.from(await stakeCred.to_bytes()).toString('hex'),
    'StakeDelegation:: new() -> stake_credential()',
  );
  assert(
    Buffer.from(
      await (await stakeDelegation.pool_keyhash()).to_bytes(),
    ).toString('hex') ===
      Buffer.from(await poolKeyHash.to_bytes()).toString('hex'),
    'StakeDelegation:: new() -> pool_keyhash()',
  );
  const stakeDelHex = Buffer.from(
    stakeDelegation.to_bytes()
  ).toString('hex');
  const _stakeDel = await StakeDelegation.from_bytes(
    Buffer.from(stakeDelHex, 'hex'),
  );
  assert(
    Buffer.from(await _stakeDel.to_bytes()).toString('hex') ===
      stakeDelHex,
    'StakeDeregistration::to/from_bytes()',
  );
};

export default test;
