// @flow

import {BigNum} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

const bigNum: () => void = async () => {
  const bigNumStr = '1000000'
  const bigNumPtr = await BigNum.from_str(bigNumStr)
  assert(
    (await bigNumPtr.to_str()) === bigNumStr,
    'BigNum.to_str() should match original input value',
  )
  const bigNum2 = await BigNum.from_str('500')
  assert(
    (await (await bigNumPtr.checked_add(bigNum2)).to_str()) === '1000500',
    'BigNum.checked_add()',
  )
  assert(
    (await (await bigNumPtr.checked_sub(bigNum2)).to_str()) === '999500',
    'BigNum.checked_sub()',
  )
  assert((await bigNumPtr.compare(bigNum2)) === 1, 'BigNum.compare()')
}

export default bigNum
