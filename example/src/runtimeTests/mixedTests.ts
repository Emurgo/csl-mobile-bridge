/* eslint-disable max-len */

import {
  Address,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

const test = async () => {
  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf';
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex');
  const address = Address.from_bytes(baseAddrBytes);
  const bytes = address.to_bytes();
  assert(Buffer.from(bytes).toString('hex') === baseAddrHex, 'Address.to_bytes() should match original input value');
  const hex = address.to_hex();
  assert(hex === baseAddrHex, 'Address.to_hex() should match original input value');
  address.free();


};

export default test;
