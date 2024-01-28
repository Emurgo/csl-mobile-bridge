import {
  decrypt_with_password,
  encrypt_with_password,
} from '@emurgo/csl-mobile-bridge';

import {assert} from '../util';

/**
 * emip3 - encryption/decryption
 */

const test = async () => {
  const password = '70617373776f7264';
  const salt =
    '50515253c0c1c2c3c4c5c6c750515253c0c1c2c3c4c5c6c750515253c0c1c2c3';
  const nonce = '50515253c0c1c2c3c4c5c6c7';
  const data = '736f6d65206461746120746f20656e6372797074';

  const encryptedData = await encrypt_with_password(password, salt, nonce, data);
  const decryptedData = await decrypt_with_password(password, encryptedData);
  assert(
    decryptedData === data,
    'emip3::encrypt/decrypt_with_password: decrypted data should match original input data',
  );
};

export default test;
