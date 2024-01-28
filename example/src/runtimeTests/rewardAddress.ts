import {
  Address,
  Credential,
  Ed25519KeyHash,
  RewardAddress,
  RewardAddresses,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * RewardAddress
 */

const test = async () => {
  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf';
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex');
  const address = await Address.from_bytes(baseAddrBytes);

  const pymntAddr = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41c0a'; // 28B
  const pymntAddrKeyHash = await Ed25519KeyHash.from_bytes(
    Buffer.from(pymntAddr, 'hex'),
  );
  const paymentCred = await Credential.from_keyhash(pymntAddrKeyHash);

  // ------------------------------------------------
  // ----------------- RewardAddress ------------------
  const rewardAddr = await RewardAddress.new(0, paymentCred);

  const pymntCredFromRewardAddr = await rewardAddr.payment_cred();
  const pymntAddrFromRewardPymntCred = await pymntCredFromRewardAddr.to_keyhash()!;
  assert(
    Buffer.from(pymntAddrFromRewardPymntCred.to_bytes()).toString(
      'hex',
    ) === pymntAddr,
    'RewardAddress:: -> payment_cred -> keyhash should match original input',
  );
  const rewardAddrFromAddr = await RewardAddress.from_address(
    await rewardAddr.to_address(),
  )!;
  assert(!!rewardAddrFromAddr, 'rewardAddress.from_address');
  const rewardAddrFromInvalidAddr = await RewardAddress.from_address(address);
  assert(
    rewardAddrFromInvalidAddr == null,
    'rewardAddress.from_address (invalid address)',
  );
  const rewardAddrToAddr = await rewardAddrFromAddr.to_address();
  assert(
    Buffer.from(rewardAddrToAddr.to_bytes()).toString('hex') ===
      Buffer.from( rewardAddr.to_address().to_bytes()).toString('hex'),
    'rewardAddress.to_address',
  );

  // ------------------------------------------------
  // ----------------- RewardAddresses ------------------
  const rewardAddresses = await RewardAddresses.new();
  assert(rewardAddresses instanceof RewardAddresses, 'RewardAddresses::new()');
  await rewardAddresses.add(rewardAddr);
  assert((await rewardAddresses.len()) === 1, 'RewardAddresses::len()');
  assert(
    (await rewardAddresses.get(0)) instanceof RewardAddress,
    'RewardAddresses::get()',
  );
};

export default test;
