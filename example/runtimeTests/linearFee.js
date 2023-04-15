// @flow

import {LinearFee, BigNum} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'

/**
 * LinearFee
 */

const test: () => void = async () => {
  const coeffStr = '44'
  const constStr = '155381'
  const coeff = await BigNum.from_str(coeffStr)
  const constant = await BigNum.from_str(constStr)
  const fee = await LinearFee.new(coeff, constant)
  assert(
    (await (await fee.coefficient()).to_str()) === coeffStr,
    'LinearFee.coefficient() should match original input',
  )
  assert(
    (await (await fee.constant()).to_str()) === constStr,
    'LinearFee.constant() should match original input',
  )
}

export default test
