import {
  Bip32PrivateKey,
  Ed25519Signature,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * PrivateKey
 */

const test = async () => {
  // start from Bip32PrivateKey
  const bip32PrvKeyHex =
    '20afd5ff1f7f551c481b7e3f3541f7c63f5f6bcb293af92565af3deea0bcd648' +
    '1a6e7b8acbe38f3906c63ccbe8b2d9b876572651ac5d2afc0aca284d9412bb1b' +
    '4839bf02e1d990056d0f06af22ce4bcca52ac00f1074324aab96bbaaaccf290d';
  const _bip32PrivateKey = await Bip32PrivateKey.from_bytes(
    Buffer.from(bip32PrvKeyHex, 'hex'),
  );
  // get PrivateKey from Bip32PrivateKey
  const privateKey = await _bip32PrivateKey.to_raw_key();
  assert(
    (await (await privateKey.to_public()).as_bytes()).length === 32,
    'PrivateKey::to_public()',
  );

  const message = 'df89a15e8c';
  const signature = await privateKey.sign(Buffer.from(message, 'hex'));
  assert(signature instanceof Ed25519Signature, 'signature instanceof Ed25519Signature');
};

export default test;
