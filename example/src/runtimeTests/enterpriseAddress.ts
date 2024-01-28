import {
  Credential,
  Ed25519KeyHash,
  EnterpriseAddress,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * EnterpriseAddress
 */

const test = async () => {
  const pymntHash = '1ba2b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41c0a'; // 28B
  const pymntHashPtr = await Ed25519KeyHash.from_bytes(
    Buffer.from(pymntHash, 'hex'),
  );
  const paymentCred = await Credential.from_keyhash(pymntHashPtr);
  const networkId = 0;
  const enterpriseAddr = await EnterpriseAddress.new(networkId, paymentCred);

  assert(
    enterpriseAddr instanceof EnterpriseAddress,
    'Expected instance of EnterpriseAddress',
  );
};

export default test;
