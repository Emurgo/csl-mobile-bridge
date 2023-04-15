import {
  BigNum,
  PlutusData,
  PlutusDataKind,
} from '@emurgo/csl-mobile-bridge'

import {assert} from '../util'
import {BigInt} from '../../index';

const test: () => void = async () => {
  //check enum equality
  let plutusData = await PlutusData.new_integer(await BigInt.from_str('444'))
  assert(
    (await plutusData.kind()) === PlutusDataKind.Integer,
    'PlutusData::kind()',
  )

  //check u32 array roundtrip
  let u32Array = new Uint32Array([1, 2, 3, 4, 5])
  //TODO: add block deserialization/serialization test with invalid txs
}

export default test
