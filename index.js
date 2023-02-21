/* eslint-disable max-len */
import { NativeModules } from 'react-native';
import { decode as base64_decode, encode as base64_encode } from 'base-64';

const { HaskellShelley } = NativeModules;

// export default HaskellShelley;

function uint8ArrayFromB64(base64_string) {
  return Uint8Array.from(base64_decode(base64_string), c => c.charCodeAt(0));
}

function b64FromUint8Array(uint8Array) {
  return base64_encode(String.fromCharCode.apply(null, uint8Array));
}

function uint32ArrayToBase64(uint32Array) {
  const uint8Array = new Uint8Array(uint32Array.length * 4);
  const dataView = new DataView(uint8Array.buffer);
  for (let i = 0; i < uint32Array.length; i++) {
    dataView.setUint32(i * 4, uint32Array[i], true);
  }
  return b64FromUint8Array(uint8Array);
}

function base64ToUint32Array(base64String) {
  const uint8Array = uint8ArrayFromB64(base64String);
  const dataView = new DataView(uint8Array.buffer);
  const uint32Array = new Uint32Array(uint8Array.length / 4);
  for (let i = 0; i < uint32Array.length; i++) {
    uint32Array[i] = dataView.getUint32(i * 4, true);
  }
  return uint32Array;
}

class Ptr {
  static _wrap(ptr, klass) {
    if (ptr === '0' || ptr == null) {
      return undefined;
    }
    const obj = Object.create(klass.prototype);
    obj.ptr = ptr;
    return obj;
  }

  static _assertClass(ptr, klass) {
    if (!(ptr instanceof klass)) {
      throw new Error(`expected instance of ${klass.name}`);
    }
    return ptr.ptr;
  }

  static _assertOptionalClass(ptr, klass) {
    if (ptr == null) {
      return ptr;
    }
    if (!(ptr instanceof klass)) {
      throw new Error(`expected instance of ${klass.name}`);
    }
    return ptr.ptr;
  }

  constructor() {
    throw new Error("Can't be initialized with constructor");
  }

  /**
  * Frees the pointer
  * @returns {Promise<void>}
  */
  async free() {
    if (!this.ptr) {
      return;
    }
    const ptr = this.ptr;
    this.ptr = null;
    await HaskellShelley.ptrFree(ptr);
  }
}

export class GeneralTransactionMetadata extends Ptr {
}


export class TransactionBatch extends Ptr {
}


export class Strings extends Ptr {
}


export class Update extends Ptr {
}


export class PoolParams extends Ptr {
}


export class PlutusScript extends Ptr {
}


export class TransactionOutputs extends Ptr {
}


export class KESVKey extends Ptr {
}


export class MultiAsset extends Ptr {
}


export class MintAssets extends Ptr {
}


export class PlutusList extends Ptr {
}


export class VRFCert extends Ptr {
}


export class Mint extends Ptr {
}


export class GenesisHash extends Ptr {
}


export class RewardAddress extends Ptr {
}


export class LinearFee extends Ptr {
}


export class TransactionOutputAmountBuilder extends Ptr {
}


export class PlutusWitness extends Ptr {
}


export class Block extends Ptr {
}


export class ScriptNOfK extends Ptr {
}


export class TxBuilderConstants extends Ptr {
}


export class MIRToStakeCredentials extends Ptr {
}


export class VRFKeyHash extends Ptr {
}


export class NetworkInfo extends Ptr {
}


export class TransactionInputs extends Ptr {
}


export class Assets extends Ptr {
}


export class PublicKeys extends Ptr {
}


export class Certificate extends Ptr {
}


export class AuxiliaryDataHash extends Ptr {
}


export class TimelockStart extends Ptr {
}


export class TransactionBuilder extends Ptr {
}


export class PrivateKey extends Ptr {
}


export class TransactionUnspentOutputs extends Ptr {
}


export class PlutusScriptSource extends Ptr {
}


export class BaseAddress extends Ptr {
}


export class URL extends Ptr {
}


export class MintsAssets extends Ptr {
}


export class SingleHostName extends Ptr {
}


export class TransactionBuilderConfigBuilder extends Ptr {
}


export class NetworkId extends Ptr {
}


export class Costmdls extends Ptr {
}


export class Address extends Ptr {
}


export class Relays extends Ptr {
}


export class Value extends Ptr {
}


export class AssetNames extends Ptr {
}


export class Ed25519KeyHashes extends Ptr {
}


export class ByronAddress extends Ptr {
}


export class RewardAddresses extends Ptr {
}


export class Redeemer extends Ptr {
}


export class RedeemerTag extends Ptr {
}


export class Bip32PublicKey extends Ptr {
}


export class ProposedProtocolParameterUpdates extends Ptr {
}


export class TransactionUnspentOutput extends Ptr {
}


export class PlutusScripts extends Ptr {
}


export class ScriptAll extends Ptr {
}


export class ProtocolVersion extends Ptr {
}


export class MultiHostName extends Ptr {
}


export class Ed25519Signature extends Ptr {
}


export class Vkeys extends Ptr {
}


export class TransactionBuilderConfig extends Ptr {
}


export class Ipv4 extends Ptr {
}


export class PointerAddress extends Ptr {
}


export class DatumSource extends Ptr {
}


export class MoveInstantaneousRewardsCert extends Ptr {
}


export class StakeDeregistration extends Ptr {
}


export class ScriptHashes extends Ptr {
}


export class AuxiliaryData extends Ptr {
}


export class UnitInterval extends Ptr {
}


export class MetadataList extends Ptr {
}


export class GenesisKeyDelegation extends Ptr {
}


export class StakeDelegation extends Ptr {
}


export class GenesisHashes extends Ptr {
}


export class Language extends Ptr {
}


export class MintBuilder extends Ptr {
}


export class BlockHash extends Ptr {
}


export class ExUnits extends Ptr {
}


export class PublicKey extends Ptr {
}


export class OperationalCert extends Ptr {
}


export class DataHash extends Ptr {
}


export class Redeemers extends Ptr {
}


export class TransactionOutput extends Ptr {
}


export class MintWitness extends Ptr {
}


export class Nonce extends Ptr {
}


export class LegacyDaedalusPrivateKey extends Ptr {
}


export class EnterpriseAddress extends Ptr {
}


export class Transaction extends Ptr {
}


export class BootstrapWitnesses extends Ptr {
}


export class StakeCredentials extends Ptr {
}


export class Relay extends Ptr {
}


export class TxInputsBuilder extends Ptr {
}


export class BigNum extends Ptr {
}


export class ScriptHash extends Ptr {
}


export class Languages extends Ptr {
}


export class Vkey extends Ptr {
}


export class ExUnitPrices extends Ptr {
}


export class TransactionWitnessSets extends Ptr {
}


export class BigInt extends Ptr {
}


export class Certificates extends Ptr {
}


export class PlutusWitnesses extends Ptr {
}


export class ScriptAny extends Ptr {
}


export class Pointer extends Ptr {
}


export class FixedTransaction extends Ptr {
}


export class ScriptPubkey extends Ptr {
}


export class ProtocolParamUpdate extends Ptr {
}


export class KESSignature extends Ptr {
}


export class StakeCredential extends Ptr {
}


export class TransactionMetadatum extends Ptr {
}


export class VRFVKey extends Ptr {
}


export class InputsWithScriptWitness extends Ptr {
}


export class ConstrPlutusData extends Ptr {
}


export class PoolMetadata extends Ptr {
}


export class TransactionOutputBuilder extends Ptr {
}


export class Withdrawals extends Ptr {
}


export class PlutusMap extends Ptr {
}


export class CostModel extends Ptr {
}


export class Header extends Ptr {
}


export class PoolMetadataHash extends Ptr {
}


export class DNSRecordAorAAAA extends Ptr {
}


export class TransactionMetadatumLabels extends Ptr {
}


export class HeaderBody extends Ptr {
}


export class Vkeywitness extends Ptr {
}


export class PlutusData extends Ptr {
}


export class Int extends Ptr {
}


export class TransactionInput extends Ptr {
}


export class DNSRecordSRV extends Ptr {
}


export class Ed25519KeyHash extends Ptr {
}


export class SingleHostAddr extends Ptr {
}


export class TransactionHash extends Ptr {
}


export class MoveInstantaneousReward extends Ptr {
}


export class TimelockExpiry extends Ptr {
}


export class BootstrapWitness extends Ptr {
}


export class NativeScripts extends Ptr {
}


export class TransactionWitnessSet extends Ptr {
}


export class MetadataMap extends Ptr {
}


export class NativeScript extends Ptr {
}


export class GenesisDelegateHash extends Ptr {
}


export class Ipv6 extends Ptr {
}


export class TransactionBody extends Ptr {
}


export class TransactionBodies extends Ptr {
}


export class TransactionBatchList extends Ptr {
}


export class Vkeywitnesses extends Ptr {
}


export class AssetName extends Ptr {
}


export class AuxiliaryDataSet extends Ptr {
}


export class PoolRetirement extends Ptr {
}


export class ScriptRef extends Ptr {
}


export class InputWithScriptWitness extends Ptr {
}


export class Bip32PrivateKey extends Ptr {
}


export class StakeRegistration extends Ptr {
}


export class PoolRegistration extends Ptr {
}


export class ScriptDataHash extends Ptr {
}


export class DataCost extends Ptr {
}


export const encode_json_str_to_native_script = async (json, self_xpub, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToNativeScript(json, self_xpub, schema);
  return Ptr._wrap(ret, NativeScript);
};


export const min_script_fee = async (tx, ex_unit_prices) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.minScriptFee(txPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_ada_required = async (assets, has_data_hash, coins_per_utxo_word) => {
  const assetsPtr = Ptr._assertClass(assets, Value);
  const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
  const ret = await HaskellShelley.minAdaRequired(assetsPtr, has_data_hash, coins_per_utxo_wordPtr);
  return Ptr._wrap(ret, BigNum);
};


export const hash_transaction = async (tx_body) => {
  const tx_bodyPtr = Ptr._assertClass(tx_body, TransactionBody);
  const ret = await HaskellShelley.hashTransaction(tx_bodyPtr);
  return Ptr._wrap(ret, TransactionHash);
};


export const make_daedalus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, LegacyDaedalusPrivateKey);
  const ret = await HaskellShelley.makeDaedalusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const decode_plutus_datum_to_json_str = async (datum, schema) => {
  const datumPtr = Ptr._assertClass(datum, PlutusData);
  const ret = await HaskellShelley.decodePlutusDatumToJsonStr(datumPtr, schema);
  return ret;
};


export const decode_arbitrary_bytes_from_metadatum = async (metadata) => {
  const metadataPtr = Ptr._assertClass(metadata, TransactionMetadatum);
  const ret = await HaskellShelley.decodeArbitraryBytesFromMetadatum(metadataPtr);
  return uint8ArrayFromB64(ret);
};


export const decode_metadatum_to_json_str = async (metadatum, schema) => {
  const metadatumPtr = Ptr._assertClass(metadatum, TransactionMetadatum);
  const ret = await HaskellShelley.decodeMetadatumToJsonStr(metadatumPtr, schema);
  return ret;
};


export const hash_auxiliary_data = async (auxiliary_data) => {
  const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
  const ret = await HaskellShelley.hashAuxiliaryData(auxiliary_dataPtr);
  return Ptr._wrap(ret, AuxiliaryDataHash);
};


export const encode_arbitrary_bytes_as_metadatum = async (bytes) => {
  const ret = await HaskellShelley.encodeArbitraryBytesAsMetadatum(b64FromUint8Array(bytes));
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const get_implicit_input = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.getImplicitInput(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, Value);
};


export const create_send_all = async (address, utxos, config) => {
  const addressPtr = Ptr._assertClass(address, Address);
  const utxosPtr = Ptr._assertClass(utxos, TransactionUnspentOutputs);
  const configPtr = Ptr._assertClass(config, TransactionBuilderConfig);
  const ret = await HaskellShelley.createSendAll(addressPtr, utxosPtr, configPtr);
  return Ptr._wrap(ret, TransactionBatchList);
};


export const min_ada_for_output = async (output, data_cost) => {
  const outputPtr = Ptr._assertClass(output, TransactionOutput);
  const data_costPtr = Ptr._assertClass(data_cost, DataCost);
  const ret = await HaskellShelley.minAdaForOutput(outputPtr, data_costPtr);
  return Ptr._wrap(ret, BigNum);
};


export const encrypt_with_password = async (password, salt, nonce, data) => {
  const ret = await HaskellShelley.encryptWithPassword(password, salt, nonce, data);
  return ret;
};


export const make_vkey_witness = async (tx_body_hash, sk) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await HaskellShelley.makeVkeyWitness(tx_body_hashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
};


export const encode_json_str_to_metadatum = async (json, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToMetadatum(json, schema);
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const make_icarus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await HaskellShelley.makeIcarusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const decrypt_with_password = async (password, data) => {
  const ret = await HaskellShelley.decryptWithPassword(password, data);
  return ret;
};


export const min_fee = async (tx, linear_fee) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const linear_feePtr = Ptr._assertClass(linear_fee, LinearFee);
  const ret = await HaskellShelley.minFee(txPtr, linear_feePtr);
  return Ptr._wrap(ret, BigNum);
};


export const get_deposit = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.getDeposit(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, BigNum);
};


export const hash_script_data = async (redeemers, cost_models, datums) => {
  const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
  const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
  const datumsPtr = Ptr._assertOptionalClass(datums, PlutusList);
  if(datums == null) {
    const ret = await HaskellShelley.hashScriptData(redeemersPtr, cost_modelsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
  if(datums != null) {
    const ret = await HaskellShelley.hashScriptDataWithDatums(redeemersPtr, cost_modelsPtr, datumsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
};


export const calculate_ex_units_ceil_cost = async (ex_units, ex_unit_prices) => {
  const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.calculateExUnitsCeilCost(ex_unitsPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const hash_plutus_data = async (plutus_data) => {
  const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
  const ret = await HaskellShelley.hashPlutusData(plutus_dataPtr);
  return Ptr._wrap(ret, DataHash);
};


export const encode_json_str_to_plutus_datum = async (json, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToPlutusDatum(json, schema);
  return Ptr._wrap(ret, PlutusData);
};


export const NetworkIdKind = Object.freeze({
  Testnet: 0,
  Mainnet: 1,
});


export const PlutusDatumSchema = Object.freeze({
  BasicConversions: 0,
  DetailedSchema: 1,
});


export const TransactionMetadatumKind = Object.freeze({
  MetadataMap: 0,
  MetadataList: 1,
  Int: 2,
  Bytes: 3,
  Text: 4,
});


export const StakeCredKind = Object.freeze({
  Key: 0,
  Script: 1,
});


export const CoinSelectionStrategyCIP2 = Object.freeze({
  LargestFirst: 0,
  RandomImprove: 1,
  LargestFirstMultiAsset: 2,
  RandomImproveMultiAsset: 3,
});


export const PlutusDataKind = Object.freeze({
  ConstrPlutusData: 0,
  Map: 1,
  List: 2,
  Integer: 3,
  Bytes: 4,
});


export const MIRPot = Object.freeze({
  Reserves: 0,
  Treasury: 1,
});


export const NativeScriptKind = Object.freeze({
  ScriptPubkey: 0,
  ScriptAll: 1,
  ScriptAny: 2,
  ScriptNOfK: 3,
  TimelockStart: 4,
  TimelockExpiry: 5,
});


export const MIRKind = Object.freeze({
  ToOtherPot: 0,
  ToStakeCredentials: 1,
});


export const RelayKind = Object.freeze({
  SingleHostAddr: 0,
  SingleHostName: 1,
  MultiHostName: 2,
});


export const MetadataJsonSchema = Object.freeze({
  NoConversions: 0,
  BasicConversions: 1,
  DetailedSchema: 2,
});


export const RedeemerTagKind = Object.freeze({
  Spend: 0,
  Mint: 1,
  Cert: 2,
  Reward: 3,
});


export const LanguageKind = Object.freeze({
  PlutusV1: 0,
  PlutusV2: 1,
});


export const CertificateKind = Object.freeze({
  StakeRegistration: 0,
  StakeDeregistration: 1,
  StakeDelegation: 2,
  PoolRegistration: 3,
  PoolRetirement: 4,
  GenesisKeyDelegation: 5,
  MoveInstantaneousRewardsCert: 6,
});


export const ScriptHashNamespace = Object.freeze({
  NativeScript: 0,
  PlutusScript: 1,
  PlutusScriptV2: 2,
});


export const ScriptSchema = Object.freeze({
  Wallet: 0,
  Node: 1,
});


