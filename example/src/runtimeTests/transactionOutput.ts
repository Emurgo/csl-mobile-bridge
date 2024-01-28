import {
  Address,
  BigNum,
  TransactionOutput,
  Value,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * TransactionOutput
 */

const test = async () => {
  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf';
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex');

  // ------------------------------------------------
  // -------------- TransactionOutput ---------------
  const amountStr = '1000000';
  const amount = await Value.new(await BigNum.from_str(amountStr));
  const recipientAddr = await Address.from_bytes(baseAddrBytes);
  const txOutput = await TransactionOutput.new(recipientAddr, amount);
  assert(
    txOutput instanceof TransactionOutput,
    'TransactionOutput.new should return instance of TransactionOutput',
  );
  assert(
    (await (await (await txOutput.amount()).coin()).to_str()) === amountStr,
    'TransactionOutput::amount()',
  );
  const outputAddrHex = Buffer.from(
    await (await txOutput.address()).to_bytes(),
  ).toString('hex');
  assert(
    outputAddrHex ===
      Buffer.from(await recipientAddr.to_bytes()).toString('hex'),
    'TransactionOutput::address()',
  );
};

export default test;
