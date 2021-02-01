// @flow

import {TransactionBody} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * TransactionBody
 */

const test: () => void = async () => {
  const bodyHex =
    'a4008282582005ec4a4a7f4645fa66886cef2e34706907a3a7f9d8' +
    '8e0d48b313ad2cdf76fb5f008258206930f123df83e4178b0324ae' +
    '617b2028c0b38c6ff4660583a2abf1f7b08195fe00018182582b82' +
    'd818582183581ce3a1faa5b54bd1485a424d8f9b5e75296b328a2a' +
    '624ef1d2f4c7b480a0001a88e5cdab1913890219042803191c20'
  const txBody = await TransactionBody.from_bytes(Buffer.from(bodyHex, 'hex'))
  const inputs = await txBody.inputs()
  assert(await inputs.len(), 'transactionBody::inputs.len()')
}

export default test
