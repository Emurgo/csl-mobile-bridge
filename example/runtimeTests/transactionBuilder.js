// @flow

import {
  TransactionBuilder,
  BigNum,
  LinearFee,
  Ed25519KeyHash,
  Address,
  ByronAddress,
  RewardAddress,
  RewardAddresses,
  TransactionOutput,
  TransactionHash,
  TransactionInput,
  Withdrawals,
  Certificates,
  Value,
  Coin,
  StakeCredential,
  StakeRegistration,
  Certificate,
  GeneralTransactionMetadata,
  AuxiliaryData,
} from '@emurgo/react-native-haskell-shelley'

import {assert} from '../util'

/**
 * TransactionBuilder
 */

const test: () => void = async () => {
  // note: changing some of the function parameters will result in some tests
  // failing. Same happens if more inputs/outputs/certificates — or anything
  // that will change the tx size — are added
  const coeffStr = '44'
  const constStr = '155381'
  const coeff = await BigNum.from_str(coeffStr)
  const constant = await BigNum.from_str(constStr)
  const fee = await LinearFee.new(coeff, constant)
  const minUtxoVal = await BigNum.from_str('1000000')
  const poolDeposit = await BigNum.from_str('2000000')
  const keyDeposit = await BigNum.from_str('3000000')
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex')
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes)

  const stakeCred = await StakeCredential.from_keyhash(ed25519KeyHash)
  const stakeReg = await StakeRegistration.new(stakeCred)
  const cert = await Certificate.new_stake_registration(stakeReg)

  const hash32Hex =
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
  const hash32Bytes = Buffer.from(hash32Hex, 'hex')
  const txHash = await TransactionHash.from_bytes(hash32Bytes)
  const txInput = await TransactionInput.new(txHash, 0)

  const addrBase58 =
    'Ae2tdPwUPEZHu3NZa6kCwet2msq4xrBXKHBDvogFKwMsF18Jca8JHLRBas7'
  const byronAddress = await ByronAddress.from_base58(addrBase58)

  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
  const amountStr = '1000000'
  const amount = await Value.new(await Coin.from_str(amountStr))
  const recipientAddr = await Address.from_bytes(baseAddrBytes)
  const txOutput = await TransactionOutput.new(recipientAddr, amount)

  const certs = await Certificates.new()
  await certs.add(cert)

  /**
   * TransactionBuilder
   */
  const txBuilder = await TransactionBuilder.new(
    fee,
    minUtxoVal,
    poolDeposit,
    keyDeposit,
  )
  await txBuilder.add_key_input(
    ed25519KeyHash,
    txInput,
    await Value.new(await Coin.from_str('1000000')),
  )
  await txBuilder.add_bootstrap_input(
    byronAddress,
    txInput,
    await Value.new(await Coin.from_str('1000000')),
  )
  await txBuilder.add_output(txOutput)
  // commented out so that we can test add_change_if_needed(), which
  // throws if fee has been previously set
  // await txBuilder.set_fee(await BigNum.from_str('500000'))
  const TTL = 10
  await txBuilder.set_ttl(TTL)

  // add an empty metadata object
  const metadata = await GeneralTransactionMetadata.new()
  const auxiliaryData = await AuxiliaryData.new(metadata)
  await txBuilder.set_auxiliary_data(auxiliaryData)

  const explicitIn = await txBuilder.get_explicit_input()
  const explicitInCoin = await explicitIn.coin()
  assert(
    (await explicitInCoin.to_str()) === '2000000',
    'TransactionBuilder::get_explicit_input()',
  )

  const implicitIn = await txBuilder.get_implicit_input()
  const implicitInCoin = await implicitIn.coin()
  assert(
    parseInt(await implicitInCoin.to_str(), 10) === 0,
    'TransactionBuilder::get_implicit_input()',
  )

  const explicitOut = await txBuilder.get_explicit_output()
  const explicitOutCoin = await explicitOut.coin()
  assert(
    (await explicitOutCoin.to_str()) === '1000000',
    'TransactionBuilder::get_explicit_output()',
  )
  const changeAddrHex =
    '00' +
    '0000b04c3aa051f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c084c54bd4059ead2d2e426ac89fa4b3ce41cbf'
  const change = await Address.from_bytes(Buffer.from(changeAddrHex, 'hex'))
  assert(
    (await txBuilder.add_change_if_needed(change)) === false,
    'TransactionBuilder::add_change_if_needed()',
  )

  let txBodyFromBuilder = await txBuilder.build()

  assert(
    (await (await txBuilder.min_fee()).to_str()) === '174477',
    'TransactionBuilder::min_fee()',
  )
  assert(
    (await (await txBuilder.get_deposit()).to_str()) === '0',
    'TransactionBuilder::get_fee_or_calc()',
  )
  assert(
    (await (await txBuilder.get_fee_if_set()).to_str()) === '1000000',
    'TransactionBuilder::get_fee_or_calc()',
  )
  await txBuilder.set_certs(certs)

  const feeForOutput = await (
    await txBuilder.fee_for_output(
      await TransactionOutput.new(
        await Address.from_bytes(baseAddrBytes),
        // largest possible CBOR value
        // note: this slightly over-estimates by a few bytes
        await Value.new(await Coin.from_str((0x100000000).toString())),
      ),
    )
  ).to_str()
  assert(
    feeForOutput instanceof String || typeof feeForOutput === 'string',
    'TransactionBuilder::fee_for_output()',
  )

  // ------------------------------------------------
  // -------------- TransactionInputs ---------------
  const inputs = await txBodyFromBuilder.inputs()
  assert((await inputs.len()) === 2, 'TransactionInputs::len()')
  const input = await inputs.get(0)
  assert(input instanceof TransactionInput, 'TransactionInputs::get()')

  // ------------------------------------------------
  // -------------- TransactionOutputs --------------
  const outputs = await txBodyFromBuilder.outputs()
  assert((await outputs.len()) === 1, 'TransactionOutputs::len()')
  const output = await outputs.get(0)
  assert(output instanceof TransactionOutput, 'TransactionOutputs::get()')

  // ------------------------------------------------
  // ------------------ Withdrawals -----------------
  const withdrawals = await Withdrawals.new()
  assert((await withdrawals.len()) === 0, 'Withdrawals::len()')
  const withdrawalAddr = await RewardAddress.from_address(
    await Address.from_bech32(
      'addr1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8sxy9w7g',
    ),
  )
  // returns coin
  const _oldAmount = await withdrawals.insert(
    withdrawalAddr,
    await BigNum.from_str('10000000'),
  )
  assert(_oldAmount == null, 'Withdrawals::insert()')
  assert((await withdrawals.len()) === 1, 'Withdrawals::len() should be 1')
  assert((await withdrawals.get(withdrawalAddr)) != null, 'Withdrawals::get()')
  assert(
    (await (await withdrawals.get(withdrawalAddr)).to_str()) === '10000000',
    'Withdrawals::get()',
  )

  const randomAddr = await RewardAddress.from_address(
    await Address.from_bech32(
      'addr1uyvxhwsjarwzr67sutmer7dplwx0jl2czzsp8cvku0wjftgtt8ge9',
    ),
  )
  assert(
    (await withdrawals.get(randomAddr)) == null,
    'Withdrawals::get() must be null for invalid key address',
  )
  assert(
    (await withdrawals.keys()) instanceof RewardAddresses,
    'Withdrawals::keys()',
  )

  // ------------------------------------------------
  // --------------- TransactionBody ----------------
  // addditional TransactionBody tests using previous
  // outputs
  await txBuilder.set_certs(certs)
  await txBuilder.set_withdrawals(withdrawals)

  // re-generate tx body
  txBodyFromBuilder = await txBuilder.build()

  const feeFromTxBody = await txBodyFromBuilder.fee()
  assert(await feeFromTxBody.to_str(), 'TransactionBody::fee()')

  const ttlFromTxBody = await txBodyFromBuilder.ttl()
  assert(ttlFromTxBody === TTL, 'TransactionBody::ttl()')

  const withdrawalsFromTxBody = await txBodyFromBuilder.withdrawals()
  assert(
    (await (await withdrawalsFromTxBody.get(withdrawalAddr)).to_str()) ===
      '10000000',
    'TransactionBody::withdrawals() -> Withdrawals::get()',
  )

  const certsFromTxBody = await txBodyFromBuilder.certs()
  assert(
    (await certsFromTxBody.len()) === 1,
    'TransactionBody::certs() -> Certificates::len()',
  )
}

export default test
