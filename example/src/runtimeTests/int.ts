import {BigNum, Int} from '@emurgo/csl-mobile-bridge';

import {assert} from '../util';

const test = async () => {
  const bigNumStr = '123';
  const bigNumPtr = await BigNum.from_str(bigNumStr);

  const intPtr = await Int.new(bigNumPtr);
  assert((await intPtr.as_i32()) === 123, 'Int.as_i32()');
};

export default test;
