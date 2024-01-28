import {
  Address,
  AuxiliaryData,
  BigNum,
  ByronAddress,
  Certificate,
  Certificates,
  Credential,
  Ed25519KeyHash,
  ExUnitPrices,
  GeneralTransactionMetadata,
  LinearFee,
  RewardAddress,
  RewardAddresses,
  StakeRegistration,
  TransactionBuilder,
  TransactionBuilderConfigBuilder,
  TransactionHash,
  TransactionInput,
  TransactionOutput,
  UnitInterval,
  Value,
  Withdrawals,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * TransactionBuilder
 */

const test = async () => {
  // note: changing some of the function parameters will result in some tests
  // failing. Same happens if more inputs/outputs/certificates — or anything
  // that will change the tx size — are added
  const coeffStr = '44';
  const constStr = '155381';
  const coeff = await BigNum.from_str(coeffStr);
  const constant = await BigNum.from_str(constStr);
  const fee = await LinearFee.new(coeff, constant);
  const poolDeposit = await BigNum.from_str('2000000');
  const keyDeposit = await BigNum.from_str('3000000');
  const keyHashHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'; // 28B
  const keyHashBytes = Buffer.from(keyHashHex, 'hex');
  const ed25519KeyHash = await Ed25519KeyHash.from_bytes(keyHashBytes);

  const stakeCred = await Credential.from_keyhash(ed25519KeyHash);
  const stakeReg = await StakeRegistration.new(stakeCred);
  const cert = await Certificate.new_stake_registration(stakeReg);

  const hash32Hex =
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf';
  const hash32Bytes = Buffer.from(hash32Hex, 'hex');
  const txHash = await TransactionHash.from_bytes(hash32Bytes);
  const txInput = await TransactionInput.new(txHash, 0);
  const txInput2 = await TransactionInput.new(txHash, 1);

  const addrBase58 =
    'Ae2tdPwUPEZHu3NZa6kCwet2msq4xrBXKHBDvogFKwMsF18Jca8JHLRBas7';
  const byronAddress = await ByronAddress.from_base58(addrBase58);

  const baseAddrHex =
    '00' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf';
  const baseAddrBytes = Buffer.from(baseAddrHex, 'hex');
  const amountStr = '1000000';
  const amount = await Value.new(await BigNum.from_str(amountStr));
  const recipientAddr = await Address.from_bytes(baseAddrBytes);
  const txOutput = await TransactionOutput.new(recipientAddr, amount);

  const certs = await Certificates.new();
  await certs.add(cert);
  const memPrice = await UnitInterval.new(
    await BigNum.from_str('11'),
    await BigNum.from_str('333'),
  );

  const stepPrice = await UnitInterval.new(
    await BigNum.from_str('77'),
    await BigNum.from_str('999'),
  );

  let configBuilder = await TransactionBuilderConfigBuilder.new();
  configBuilder = await configBuilder.fee_algo(fee);
  configBuilder = await configBuilder.coins_per_utxo_byte(
    await BigNum.from_str('11'),
  );
  configBuilder = await configBuilder.ex_unit_prices(
    await ExUnitPrices.new(memPrice, stepPrice),
  );
  configBuilder = await configBuilder.pool_deposit(poolDeposit);
  configBuilder = await configBuilder.key_deposit(keyDeposit);
  configBuilder = await configBuilder.max_value_size(7000);
  configBuilder = await configBuilder.max_tx_size(888888);
  const config = await configBuilder.build();
  /**
   * TransactionBuilder
   */
  const txBuilder = await TransactionBuilder.new(config);

  await txBuilder.add_key_input(
    ed25519KeyHash,
    txInput,
    await Value.new(await BigNum.from_str('1000000')),
  );
  await txBuilder.add_bootstrap_input(
    byronAddress,
    txInput2,
    await Value.new(await BigNum.from_str('1000000')),
  );
  await txBuilder.add_output(txOutput);
  // commented out so that we can test add_change_if_needed(), which
  // throws if fee has been previously set
  // await txBuilder.set_fee(await BigNum.from_str('500000'))

  const TTL = 10;

  // add an empty metadata object
  const metadata = await GeneralTransactionMetadata.new();
  const auxiliaryData = await AuxiliaryData.new();
  auxiliaryData.set_metadata(metadata);
  await txBuilder.set_auxiliary_data(auxiliaryData);

  const explicitIn = await txBuilder.get_explicit_input();
  const explicitInCoin = await explicitIn.coin();
  assert(
    (await explicitInCoin.to_str()) === '2000000',
    'TransactionBuilder::get_explicit_input()',
  );

  const implicitIn = await txBuilder.get_implicit_input();
  const implicitInCoin = await implicitIn.coin();
  assert(
    parseInt(await implicitInCoin.to_str(), 10) === 0,
    'TransactionBuilder::get_implicit_input()',
  );

  const explicitOut = await txBuilder.get_explicit_output();
  const explicitOutCoin = await explicitOut.coin();
  assert(
    (await explicitOutCoin.to_str()) === '1000000',
    'TransactionBuilder::get_explicit_output()',
  );
  const changeAddrHex =
    '00' +
    '0000b04c3aa051f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
    '0000b03c3aa052f51c084c54bd4059ead2d2e426ac89fa4b3ce41cbf';
  const change = await Address.from_bytes(Buffer.from(changeAddrHex, 'hex'));
  assert(
    (await txBuilder.add_change_if_needed(change)) === true,
    'TransactionBuilder::add_change_if_needed()',
  );

  const txFromBuilder = await txBuilder.build_tx();
  let txBodyFromBuilder = await txFromBuilder.body();
  const txWitnessSetFromBuilder = await txFromBuilder.witness_set();

  assert(
    (await txWitnessSetFromBuilder.native_scripts()) == null,
    'Transaction::native_scripts()',
  );

  console.log('minfee: ', txBuilder.min_fee().to_str());
  assert(
    (await (await txBuilder.min_fee()).to_str()) === '177293',
    'TransactionBuilder::min_fee()',
  );
  assert(
    (await (await txBuilder.get_deposit()).to_str()) === '0',
    'TransactionBuilder::get_deposit()',
  );
  assert(
    txBuilder.get_fee_if_set()!.to_str() === '177293',
    'TransactionBuilder::get_fee_if_set()',
  );
  await txBuilder.set_certs(certs);

  const feeForOutput = await (
    await txBuilder.fee_for_output(
      await TransactionOutput.new(
        await Address.from_bytes(baseAddrBytes),
        // largest possible CBOR value
        // note: this slightly over-estimates by a few bytes
        await Value.new(await BigNum.from_str((0x100000000).toString())),
      ),
    )
  ).to_str();
  assert(
    typeof feeForOutput === 'string',
    'TransactionBuilder::fee_for_output()',
  );

  // ------------------------------------------------
  // -------------- TransactionInputs ---------------
  const inputs = await txBodyFromBuilder.inputs();
  assert((await inputs.len()) === 2, 'TransactionInputs::len()');
  const input = await inputs.get(0);
  assert(input instanceof TransactionInput, 'TransactionInputs::get()');

  // ------------------------------------------------
  // -------------- TransactionOutputs --------------
  const outputs = await txBodyFromBuilder.outputs();
  assert((await outputs.len()) === 2, 'TransactionOutputs::len()');
  const output = await outputs.get(0);
  assert(output instanceof TransactionOutput, 'TransactionOutputs::get()');

  // ------------------------------------------------
  // ------------------ Withdrawals -----------------
  const withdrawals = await Withdrawals.new();
  assert((await withdrawals.len()) === 0, 'Withdrawals::len()');
  const withdrawalAddr = await RewardAddress.from_address(
    await Address.from_bech32(
      'addr1u8pcjgmx7962w6hey5hhsd502araxp26kdtgagakhaqtq8sxy9w7g',
    ),
  )!;
  // returns coin
  const _oldAmount = await withdrawals.insert(
    withdrawalAddr,
    await BigNum.from_str('10000000'),
  );
  assert(_oldAmount == null, 'Withdrawals::insert()');
  assert((await withdrawals.len()) === 1, 'Withdrawals::len() should be 1');
  assert((await withdrawals.get(withdrawalAddr)) != null, 'Withdrawals::get()');
  assert(
    withdrawals.get(withdrawalAddr)!.to_str() === '10000000',
    'Withdrawals::get()',
  );

  const randomAddr = await RewardAddress.from_address(
    await Address.from_bech32(
      'addr1uyvxhwsjarwzr67sutmer7dplwx0jl2czzsp8cvku0wjftgtt8ge9',
    ),
  )!;
  assert(
    (await withdrawals.get(randomAddr)) == null,
    'Withdrawals::get() must be null for invalid key address',
  );
  assert(
    (await withdrawals.keys()) instanceof RewardAddresses,
    'Withdrawals::keys()',
  );

  let ttlFromTxBody = await txBodyFromBuilder.ttl();
  assert(ttlFromTxBody == null, 'TransactionBody::ttl()');

  let ttlFromTxBodyBigNum = await txBodyFromBuilder.ttl_bignum();
  assert(ttlFromTxBodyBigNum == null, 'TransactionBody::ttl_bignum()');

  // ------------------------------------------------
  // --------------- TransactionBody ----------------
  // addditional TransactionBody tests using previous
  // outputs
  await txBuilder.set_certs(certs);
  await txBuilder.set_withdrawals(withdrawals);
  await txBuilder.set_ttl(TTL);

  // re-generate tx body
  txBodyFromBuilder = await txBuilder.build();

  const feeFromTxBody = await txBodyFromBuilder.fee();
  assert(await feeFromTxBody.to_str(), 'TransactionBody::fee()');

  ttlFromTxBody = await txBodyFromBuilder.ttl();
  assert(ttlFromTxBody === TTL, 'TransactionBody::ttl()');

  const withdrawalsFromTxBody = await txBodyFromBuilder.withdrawals()!;
  assert(
    withdrawalsFromTxBody.get(withdrawalAddr)!.to_str() ===
      '10000000',
    'TransactionBody::withdrawals() -> Withdrawals::get()',
  );

  const certsFromTxBody = await txBodyFromBuilder.certs();
  assert(
    (await certsFromTxBody!.len()) === 1,
    'TransactionBody::certs() -> Certificates::len()',
  );
};

export default test;
