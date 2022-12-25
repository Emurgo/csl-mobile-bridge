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
    if (ptr === '0') {
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

export class Certificate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificate);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Certificate);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration(stake_registration) {
    const stake_registrationPtr = Ptr._assertClass(stake_registration, StakeRegistration);
    const ret = await HaskellShelley.new_stake_registration(stake_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_deregistration(stake_deregistration) {
    const stake_deregistrationPtr = Ptr._assertClass(stake_deregistration, StakeDeregistration);
    const ret = await HaskellShelley.new_stake_deregistration(stake_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_delegation(stake_delegation) {
    const stake_delegationPtr = Ptr._assertClass(stake_delegation, StakeDelegation);
    const ret = await HaskellShelley.new_stake_delegation(stake_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_registration(pool_registration) {
    const pool_registrationPtr = Ptr._assertClass(pool_registration, PoolRegistration);
    const ret = await HaskellShelley.new_pool_registration(pool_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_retirement(pool_retirement) {
    const pool_retirementPtr = Ptr._assertClass(pool_retirement, PoolRetirement);
    const ret = await HaskellShelley.new_pool_retirement(pool_retirementPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_genesis_key_delegation(genesis_key_delegation) {
    const genesis_key_delegationPtr = Ptr._assertClass(genesis_key_delegation, GenesisKeyDelegation);
    const ret = await HaskellShelley.new_genesis_key_delegation(genesis_key_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert) {
    const move_instantaneous_rewards_certPtr = Ptr._assertClass(move_instantaneous_rewards_cert, MoveInstantaneousRewardsCert);
    const ret = await HaskellShelley.new_move_instantaneous_rewards_cert(move_instantaneous_rewards_certPtr);
    return Ptr._wrap(ret, Certificate);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_stake_registration() {
    const ret = await HaskellShelley.as_stake_registration(this.ptr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async as_stake_deregistration() {
    const ret = await HaskellShelley.as_stake_deregistration(this.ptr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async as_stake_delegation() {
    const ret = await HaskellShelley.as_stake_delegation(this.ptr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async as_pool_registration() {
    const ret = await HaskellShelley.as_pool_registration(this.ptr);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async as_pool_retirement() {
    const ret = await HaskellShelley.as_pool_retirement(this.ptr);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async as_genesis_key_delegation() {
    const ret = await HaskellShelley.as_genesis_key_delegation(this.ptr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async as_move_instantaneous_rewards_cert() {
    const ret = await HaskellShelley.as_move_instantaneous_rewards_cert(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class TransactionWitnessSet extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  set_vkeys(vkeys) {
    const vkeysPtr = Ptr._assertClass(vkeys, Vkeywitnesses);
    const ret = HaskellShelley.set_vkeys(this.ptr, vkeysPtr);
    return ret;
  }

  async vkeys() {
    const ret = await HaskellShelley.vkeys(this.ptr);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.set_native_scripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_bootstraps(bootstraps) {
    const bootstrapsPtr = Ptr._assertClass(bootstraps, BootstrapWitnesses);
    const ret = HaskellShelley.set_bootstraps(this.ptr, bootstrapsPtr);
    return ret;
  }

  async bootstraps() {
    const ret = await HaskellShelley.bootstraps(this.ptr);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.set_plutus_scripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.plutus_scripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_data(plutus_data) {
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusList);
    const ret = HaskellShelley.set_plutus_data(this.ptr, plutus_dataPtr);
    return ret;
  }

  async plutus_data() {
    const ret = await HaskellShelley.plutus_data(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_redeemers(redeemers) {
    const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
    const ret = HaskellShelley.set_redeemers(this.ptr, redeemersPtr);
    return ret;
  }

  async redeemers() {
    const ret = await HaskellShelley.redeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

}


export class Address extends Ptr {
  static async from_bytes(data) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(data));
    return Ptr._wrap(ret, Address);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Address);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Address);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    if(prefix == null) {
      const ret = await HaskellShelley.to_bech32(this.ptr);
      return ret;
    }
    if(prefix != null) {
      const ret = await HaskellShelley.to_bech32_with_prefix(this.ptr, prefix);
      return ret;
    }
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, Address);
  }

  async network_id() {
    const ret = await HaskellShelley.network_id(this.ptr);
    return ret;
  }

}


export class Block extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Block);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Block);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Block);
  }

  async header() {
    const ret = await HaskellShelley.header(this.ptr);
    return Ptr._wrap(ret, Header);
  }

  async transaction_bodies() {
    const ret = await HaskellShelley.transaction_bodies(this.ptr);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async transaction_witness_sets() {
    const ret = await HaskellShelley.transaction_witness_sets(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async auxiliary_data_set() {
    const ret = await HaskellShelley.auxiliary_data_set(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async invalid_transactions() {
    const ret = await HaskellShelley.invalid_transactions(this.ptr);
    return base64ToUint32Array(ret);
  }

  static async new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions) {
    const headerPtr = Ptr._assertClass(header, Header);
    const transaction_bodiesPtr = Ptr._assertClass(transaction_bodies, TransactionBodies);
    const transaction_witness_setsPtr = Ptr._assertClass(transaction_witness_sets, TransactionWitnessSets);
    const auxiliary_data_setPtr = Ptr._assertClass(auxiliary_data_set, AuxiliaryDataSet);
    const ret = await HaskellShelley.new(headerPtr, transaction_bodiesPtr, transaction_witness_setsPtr, auxiliary_data_setPtr, uint32ArrayToBase64(invalid_transactions));
    return Ptr._wrap(ret, Block);
  }

}


export class Vkeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Vkeys);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Vkey);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkey);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class Ipv4 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv4);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Ipv4);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Ipv4);
  }

  static async new(data) {
    const ret = await HaskellShelley.new(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv4);
  }

  async ip() {
    const ret = await HaskellShelley.ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Certificates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificates);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Certificates);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Certificates);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Certificates);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Certificate);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Certificate);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class ProtocolVersion extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async major() {
    const ret = await HaskellShelley.major(this.ptr);
    return ret;
  }

  async minor() {
    const ret = await HaskellShelley.minor(this.ptr);
    return ret;
  }

  static async new(major, minor) {
    const ret = await HaskellShelley.new(major, minor);
    return Ptr._wrap(ret, ProtocolVersion);
  }

}


export class MetadataList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataList);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MetadataList);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MetadataList);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionMetadatum);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionMetadatumLabels extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, BigNum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BigNum);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionBody);
  }

  async inputs() {
    const ret = await HaskellShelley.inputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async outputs() {
    const ret = await HaskellShelley.outputs(this.ptr);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async fee() {
    const ret = await HaskellShelley.fee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async ttl() {
    const ret = await HaskellShelley.ttl(this.ptr);
    return ret;
  }

  async ttl_bignum() {
    const ret = await HaskellShelley.ttl_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ttl(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.set_ttl(this.ptr, ttlPtr);
    return ret;
  }

  remove_ttl() {
    const ret = HaskellShelley.remove_ttl(this.ptr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.set_certs(this.ptr, certsPtr);
    return ret;
  }

  async certs() {
    const ret = await HaskellShelley.certs(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.set_withdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async withdrawals() {
    const ret = await HaskellShelley.withdrawals(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

  set_update(update) {
    const updatePtr = Ptr._assertClass(update, Update);
    const ret = HaskellShelley.set_update(this.ptr, updatePtr);
    return ret;
  }

  async update() {
    const ret = await HaskellShelley.update(this.ptr);
    return Ptr._wrap(ret, Update);
  }

  set_auxiliary_data_hash(auxiliary_data_hash) {
    const auxiliary_data_hashPtr = Ptr._assertClass(auxiliary_data_hash, AuxiliaryDataHash);
    const ret = HaskellShelley.set_auxiliary_data_hash(this.ptr, auxiliary_data_hashPtr);
    return ret;
  }

  async auxiliary_data_hash() {
    const ret = await HaskellShelley.auxiliary_data_hash(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.set_validity_start_interval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.set_validity_start_interval_bignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  async validity_start_interval_bignum() {
    const ret = await HaskellShelley.validity_start_interval_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async validity_start_interval() {
    const ret = await HaskellShelley.validity_start_interval(this.ptr);
    return ret;
  }

  set_mint(mint) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const ret = HaskellShelley.set_mint(this.ptr, mintPtr);
    return ret;
  }

  async mint() {
    const ret = await HaskellShelley.mint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async multiassets() {
    const ret = await HaskellShelley.multiassets(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  set_reference_inputs(reference_inputs) {
    const reference_inputsPtr = Ptr._assertClass(reference_inputs, TransactionInputs);
    const ret = HaskellShelley.set_reference_inputs(this.ptr, reference_inputsPtr);
    return ret;
  }

  async reference_inputs() {
    const ret = await HaskellShelley.reference_inputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_script_data_hash(script_data_hash) {
    const script_data_hashPtr = Ptr._assertClass(script_data_hash, ScriptDataHash);
    const ret = HaskellShelley.set_script_data_hash(this.ptr, script_data_hashPtr);
    return ret;
  }

  async script_data_hash() {
    const ret = await HaskellShelley.script_data_hash(this.ptr);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TransactionInputs);
    const ret = HaskellShelley.set_collateral(this.ptr, collateralPtr);
    return ret;
  }

  async collateral() {
    const ret = await HaskellShelley.collateral(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_required_signers(required_signers) {
    const required_signersPtr = Ptr._assertClass(required_signers, Ed25519KeyHashes);
    const ret = HaskellShelley.set_required_signers(this.ptr, required_signersPtr);
    return ret;
  }

  async required_signers() {
    const ret = await HaskellShelley.required_signers(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  set_network_id(network_id) {
    const network_idPtr = Ptr._assertClass(network_id, NetworkId);
    const ret = HaskellShelley.set_network_id(this.ptr, network_idPtr);
    return ret;
  }

  async network_id() {
    const ret = await HaskellShelley.network_id(this.ptr);
    return Ptr._wrap(ret, NetworkId);
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.set_collateral_return(this.ptr, collateral_returnPtr);
    return ret;
  }

  async collateral_return() {
    const ret = await HaskellShelley.collateral_return(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.set_total_collateral(this.ptr, total_collateralPtr);
    return ret;
  }

  async total_collateral() {
    const ret = await HaskellShelley.total_collateral(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(inputs, outputs, fee, ttl) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    if(ttl == null) {
      const ret = await HaskellShelley.new(inputsPtr, outputsPtr, feePtr);
      return Ptr._wrap(ret, TransactionBody);
    }
    if(ttl != null) {
      const ret = await HaskellShelley.new_with_ttl(inputsPtr, outputsPtr, feePtr, ttl);
      return Ptr._wrap(ret, TransactionBody);
    }
  }

  static async new_tx_body(inputs, outputs, fee) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = await HaskellShelley.new_tx_body(inputsPtr, outputsPtr, feePtr);
    return Ptr._wrap(ret, TransactionBody);
  }

}


export class GenesisHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, GenesisHash);
  }

}


export class TransactionInput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionInput);
  }

  async transaction_id() {
    const ret = await HaskellShelley.transaction_id(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await HaskellShelley.index(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await HaskellShelley.new(transaction_idPtr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class PlutusScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new(bytes) {
    const ret = await HaskellShelley.new(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v2(bytes) {
    const ret = await HaskellShelley.new_v2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.new_with_version(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async bytes() {
    const ret = await HaskellShelley.bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes_v2(bytes) {
    const ret = await HaskellShelley.from_bytes_v2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.from_bytes_with_version(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_hex_with_version(hex_str, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.from_hex_with_version(hex_str, languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async hash() {
    const ret = await HaskellShelley.hash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async language_version() {
    const ret = await HaskellShelley.language_version(this.ptr);
    return Ptr._wrap(ret, Language);
  }

}


export class PoolMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async url() {
    const ret = await HaskellShelley.url(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async pool_metadata_hash() {
    const ret = await HaskellShelley.pool_metadata_hash(this.ptr);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  static async new(url, pool_metadata_hash) {
    const urlPtr = Ptr._assertClass(url, URL);
    const pool_metadata_hashPtr = Ptr._assertClass(pool_metadata_hash, PoolMetadataHash);
    const ret = await HaskellShelley.new(urlPtr, pool_metadata_hashPtr);
    return Ptr._wrap(ret, PoolMetadata);
  }

}


export class TransactionBuilder extends Ptr {
  add_inputs_from(inputs, strategy) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const ret = HaskellShelley.add_inputs_from(this.ptr, inputsPtr, strategy);
    return ret;
  }

  set_inputs(inputs) {
    const inputsPtr = Ptr._assertClass(inputs, TxInputsBuilder);
    const ret = HaskellShelley.set_inputs(this.ptr, inputsPtr);
    return ret;
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TxInputsBuilder);
    const ret = HaskellShelley.set_collateral(this.ptr, collateralPtr);
    return ret;
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.set_collateral_return(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_collateral_return_and_total(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.set_collateral_return_and_total(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.set_total_collateral(this.ptr, total_collateralPtr);
    return ret;
  }

  set_total_collateral_and_return(total_collateral, return_address) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const return_addressPtr = Ptr._assertClass(return_address, Address);
    const ret = HaskellShelley.set_total_collateral_and_return(this.ptr, total_collateralPtr, return_addressPtr);
    return ret;
  }

  add_reference_input(reference_input) {
    const reference_inputPtr = Ptr._assertClass(reference_input, TransactionInput);
    const ret = HaskellShelley.add_reference_input(this.ptr, reference_inputPtr);
    return ret;
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_key_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_script_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_script_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_native_script_input(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_plutus_script_input(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_bootstrap_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_input(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async count_missing_input_scripts() {
    const ret = await HaskellShelley.count_missing_input_scripts(this.ptr);
    return ret;
  }

  async add_required_native_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, NativeScripts);
    const ret = await HaskellShelley.add_required_native_input_scripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_plutus_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, PlutusWitnesses);
    const ret = await HaskellShelley.add_required_plutus_input_scripts(this.ptr, scriptsPtr);
    return ret;
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.get_native_input_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.get_plutus_input_scripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async fee_for_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.fee_for_input(this.ptr, addressPtr, inputPtr, amountPtr);
    return Ptr._wrap(ret, BigNum);
  }

  add_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = HaskellShelley.add_output(this.ptr, outputPtr);
    return ret;
  }

  async fee_for_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.fee_for_output(this.ptr, outputPtr);
    return Ptr._wrap(ret, BigNum);
  }

  set_fee(fee) {
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = HaskellShelley.set_fee(this.ptr, feePtr);
    return ret;
  }

  set_ttl(ttl) {
    const ret = HaskellShelley.set_ttl(this.ptr, ttl);
    return ret;
  }

  set_ttl_bignum(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.set_ttl_bignum(this.ptr, ttlPtr);
    return ret;
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.set_validity_start_interval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.set_validity_start_interval_bignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.set_certs(this.ptr, certsPtr);
    return ret;
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.set_withdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async get_auxiliary_data() {
    const ret = await HaskellShelley.get_auxiliary_data(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_auxiliary_data(auxiliary_data) {
    const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
    const ret = HaskellShelley.set_auxiliary_data(this.ptr, auxiliary_dataPtr);
    return ret;
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.set_metadata(this.ptr, metadataPtr);
    return ret;
  }

  add_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valPtr = Ptr._assertClass(val, TransactionMetadatum);
    const ret = HaskellShelley.add_metadatum(this.ptr, keyPtr, valPtr);
    return ret;
  }

  add_json_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.add_json_metadatum(this.ptr, keyPtr, val);
    return ret;
  }

  add_json_metadatum_with_schema(key, val, schema) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.add_json_metadatum_with_schema(this.ptr, keyPtr, val, schema);
    return ret;
  }

  set_mint_builder(mint_builder) {
    const mint_builderPtr = Ptr._assertClass(mint_builder, MintBuilder);
    const ret = HaskellShelley.set_mint_builder(this.ptr, mint_builderPtr);
    return ret;
  }

  async get_mint_builder() {
    const ret = await HaskellShelley.get_mint_builder(this.ptr);
    return Ptr._wrap(ret, MintBuilder);
  }

  set_mint(mint, mint_scripts) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const mint_scriptsPtr = Ptr._assertClass(mint_scripts, NativeScripts);
    const ret = HaskellShelley.set_mint(this.ptr, mintPtr, mint_scriptsPtr);
    return ret;
  }

  async get_mint() {
    const ret = await HaskellShelley.get_mint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_mint_scripts() {
    const ret = await HaskellShelley.get_mint_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_mint_asset(policy_script, mint_assets) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = HaskellShelley.set_mint_asset(this.ptr, policy_scriptPtr, mint_assetsPtr);
    return ret;
  }

  add_mint_asset(policy_script, asset_name, amount) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.add_mint_asset(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr);
    return ret;
  }

  add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const output_coinPtr = Ptr._assertClass(output_coin, BigNum);
    const ret = HaskellShelley.add_mint_asset_and_output(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr, output_coinPtr);
    return ret;
  }

  add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const ret = HaskellShelley.add_mint_asset_and_output_min_required_coin(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr);
    return ret;
  }

  static async new(cfg) {
    const cfgPtr = Ptr._assertClass(cfg, TransactionBuilderConfig);
    const ret = await HaskellShelley.new(cfgPtr);
    return Ptr._wrap(ret, TransactionBuilder);
  }

  async get_reference_inputs() {
    const ret = await HaskellShelley.get_reference_inputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_explicit_input() {
    const ret = await HaskellShelley.get_explicit_input(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_implicit_input() {
    const ret = await HaskellShelley.get_implicit_input(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_input() {
    const ret = await HaskellShelley.get_total_input(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_output() {
    const ret = await HaskellShelley.get_total_output(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_explicit_output() {
    const ret = await HaskellShelley.get_explicit_output(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_deposit() {
    const ret = await HaskellShelley.get_deposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_fee_if_set() {
    const ret = await HaskellShelley.get_fee_if_set(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async add_change_if_needed(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.add_change_if_needed(this.ptr, addressPtr);
    return ret;
  }

  calc_script_data_hash(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.calc_script_data_hash(this.ptr, cost_modelsPtr);
    return ret;
  }

  set_script_data_hash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptDataHash);
    const ret = HaskellShelley.set_script_data_hash(this.ptr, hashPtr);
    return ret;
  }

  remove_script_data_hash() {
    const ret = HaskellShelley.remove_script_data_hash(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.add_required_signer(this.ptr, keyPtr);
    return ret;
  }

  async full_size() {
    const ret = await HaskellShelley.full_size(this.ptr);
    return ret;
  }

  async output_sizes() {
    const ret = await HaskellShelley.output_sizes(this.ptr);
    return base64ToUint32Array(ret);
  }

  async build() {
    const ret = await HaskellShelley.build(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async build_tx() {
    const ret = await HaskellShelley.build_tx(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async build_tx_unsafe() {
    const ret = await HaskellShelley.build_tx_unsafe(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async min_fee() {
    const ret = await HaskellShelley.min_fee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class TransactionOutputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionOutput);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class InputsWithScriptWitness extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, InputsWithScriptWitness);
  }

  add(input) {
    const inputPtr = Ptr._assertClass(input, InputWithScriptWitness);
    const ret = HaskellShelley.add(this.ptr, inputPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

}


export class PoolRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async pool_params() {
    const ret = await HaskellShelley.pool_params(this.ptr);
    return Ptr._wrap(ret, PoolParams);
  }

  static async new(pool_params) {
    const pool_paramsPtr = Ptr._assertClass(pool_params, PoolParams);
    const ret = await HaskellShelley.new(pool_paramsPtr);
    return Ptr._wrap(ret, PoolRegistration);
  }

}


export class TransactionUnspentOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  static async new(input, output) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.new(inputPtr, outputPtr);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async input() {
    const ret = await HaskellShelley.input(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

  async output() {
    const ret = await HaskellShelley.output(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class MintAssets extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MintAssets);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.new_from_entry(keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, Int);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class Vkeywitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Vkeywitness);
  }

  static async new(vkey, signature) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.new(vkeyPtr, signaturePtr);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async vkey() {
    const ret = await HaskellShelley.vkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.signature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class Redeemer extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemer);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Redeemer);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Redeemer);
  }

  async tag() {
    const ret = await HaskellShelley.tag(this.ptr);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async index() {
    const ret = await HaskellShelley.index(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.data(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async ex_units() {
    const ret = await HaskellShelley.ex_units(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  static async new(tag, index, data, ex_units) {
    const tagPtr = Ptr._assertClass(tag, RedeemerTag);
    const indexPtr = Ptr._assertClass(index, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
    const ret = await HaskellShelley.new(tagPtr, indexPtr, dataPtr, ex_unitsPtr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class SingleHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, SingleHostName);
  }

  async port() {
    const ret = await HaskellShelley.port(this.ptr);
    return ret;
  }

  async dns_name() {
    const ret = await HaskellShelley.dns_name(this.ptr);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(port, dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordAorAAAA);
    if(port == null) {
      const ret = await HaskellShelley.new(dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
    if(port != null) {
      const ret = await HaskellShelley.new_with_port(port, dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
  }

}


export class Relays extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relays);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Relays);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Relays);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Relays);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Relay);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Relay);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class Costmdls extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Costmdls);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Costmdls);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Costmdls);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Costmdls);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, Language);
    const valuePtr = Ptr._assertClass(value, CostModel);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, CostModel);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, Language);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, CostModel);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, Languages);
  }

  async retain_language_versions(languages) {
    const languagesPtr = Ptr._assertClass(languages, Languages);
    const ret = await HaskellShelley.retain_language_versions(this.ptr, languagesPtr);
    return Ptr._wrap(ret, Costmdls);
  }

}


export class RedeemerTag extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_spend() {
    const ret = await HaskellShelley.new_spend();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_mint() {
    const ret = await HaskellShelley.new_mint();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_cert() {
    const ret = await HaskellShelley.new_cert();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_reward() {
    const ret = await HaskellShelley.new_reward();
    return Ptr._wrap(ret, RedeemerTag);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

}


export class ScriptDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, ScriptDataHash);
  }

}


export class CostModel extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CostModel);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, CostModel);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, CostModel);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, CostModel);
  }

  async set(operation, cost) {
    const costPtr = Ptr._assertClass(cost, Int);
    const ret = await HaskellShelley.set(this.ptr, operation, costPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(operation) {
    const ret = await HaskellShelley.get(this.ptr, operation);
    return Ptr._wrap(ret, Int);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

}


export class Ed25519Signature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32() {
    const ret = await HaskellShelley.to_bech32(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.from_bech32(bech32_str);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_hex(input) {
    const ret = await HaskellShelley.from_hex(input);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class Bip32PrivateKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.derive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  static async from_128_xprv(bytes) {
    const ret = await HaskellShelley.from_128_xprv(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_128_xprv() {
    const ret = await HaskellShelley.to_128_xprv(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async generate_ed25519_bip32() {
    const ret = await HaskellShelley.generate_ed25519_bip32();
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.to_raw_key(this.ptr);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_public() {
    const ret = await HaskellShelley.to_public(this.ptr);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.from_bech32(bech32_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.to_bech32(this.ptr);
    return ret;
  }

  static async from_bip39_entropy(entropy, password) {
    const ret = await HaskellShelley.from_bip39_entropy(b64FromUint8Array(entropy), b64FromUint8Array(password));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async chaincode() {
    const ret = await HaskellShelley.chaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

}


export class Vkeywitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Vkeywitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkeywitness);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionMetadatum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, MetadataMap);
    const ret = await HaskellShelley.new_map(mapPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, MetadataList);
    const ret = await HaskellShelley.new_list(listPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_int(int) {
    const intPtr = Ptr._assertClass(int, Int);
    const ret = await HaskellShelley.new_int(intPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.new_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_text(text) {
    const ret = await HaskellShelley.new_text(text);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_map() {
    const ret = await HaskellShelley.as_map(this.ptr);
    return Ptr._wrap(ret, MetadataMap);
  }

  async as_list() {
    const ret = await HaskellShelley.as_list(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

  async as_int() {
    const ret = await HaskellShelley.as_int(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async as_text() {
    const ret = await HaskellShelley.as_text(this.ptr);
    return ret;
  }

}


export class RewardAddresses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, RewardAddresses);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, RewardAddress);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, RewardAddress);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusList);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, PlutusList);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, PlutusData);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusData);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, TransactionHash);
  }

}


export class PoolParams extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolParams);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PoolParams);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, PoolParams);
  }

  async operator() {
    const ret = await HaskellShelley.operator(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.vrf_keyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async pledge() {
    const ret = await HaskellShelley.pledge(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cost() {
    const ret = await HaskellShelley.cost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async margin() {
    const ret = await HaskellShelley.margin(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async reward_account() {
    const ret = await HaskellShelley.reward_account(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async pool_owners() {
    const ret = await HaskellShelley.pool_owners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async relays() {
    const ret = await HaskellShelley.relays(this.ptr);
    return Ptr._wrap(ret, Relays);
  }

  async pool_metadata() {
    const ret = await HaskellShelley.pool_metadata(this.ptr);
    return Ptr._wrap(ret, PoolMetadata);
  }

  static async new(operator, vrf_keyhash, pledge, cost, margin, reward_account, pool_owners, relays, pool_metadata) {
    const operatorPtr = Ptr._assertClass(operator, Ed25519KeyHash);
    const vrf_keyhashPtr = Ptr._assertClass(vrf_keyhash, VRFKeyHash);
    const pledgePtr = Ptr._assertClass(pledge, BigNum);
    const costPtr = Ptr._assertClass(cost, BigNum);
    const marginPtr = Ptr._assertClass(margin, UnitInterval);
    const reward_accountPtr = Ptr._assertClass(reward_account, RewardAddress);
    const pool_ownersPtr = Ptr._assertClass(pool_owners, Ed25519KeyHashes);
    const relaysPtr = Ptr._assertClass(relays, Relays);
    const pool_metadataPtr = Ptr._assertOptionalClass(pool_metadata, PoolMetadata);
    if(pool_metadata == null) {
      const ret = await HaskellShelley.new(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr);
      return Ptr._wrap(ret, PoolParams);
    }
    if(pool_metadata != null) {
      const ret = await HaskellShelley.new_with_pool_metadata(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr, pool_metadataPtr);
      return Ptr._wrap(ret, PoolParams);
    }
  }

}


export class AuxiliaryDataSet extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(tx_index, data) {
    const dataPtr = Ptr._assertClass(data, AuxiliaryData);
    const ret = await HaskellShelley.insert(this.ptr, tx_index, dataPtr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async get(tx_index) {
    const ret = await HaskellShelley.get(this.ptr, tx_index);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async indices() {
    const ret = await HaskellShelley.indices(this.ptr);
    return base64ToUint32Array(ret);
  }

}


export class GenesisKeyDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async genesishash() {
    const ret = await HaskellShelley.genesishash(this.ptr);
    return Ptr._wrap(ret, GenesisHash);
  }

  async genesis_delegate_hash() {
    const ret = await HaskellShelley.genesis_delegate_hash(this.ptr);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.vrf_keyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  static async new(genesishash, genesis_delegate_hash, vrf_keyhash) {
    const genesishashPtr = Ptr._assertClass(genesishash, GenesisHash);
    const genesis_delegate_hashPtr = Ptr._assertClass(genesis_delegate_hash, GenesisDelegateHash);
    const vrf_keyhashPtr = Ptr._assertClass(vrf_keyhash, VRFKeyHash);
    const ret = await HaskellShelley.new(genesishashPtr, genesis_delegate_hashPtr, vrf_keyhashPtr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

}


export class URL extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, URL);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, URL);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, URL);
  }

  static async new(url) {
    const ret = await HaskellShelley.new(url);
    return Ptr._wrap(ret, URL);
  }

  async url() {
    const ret = await HaskellShelley.url(this.ptr);
    return ret;
  }

}


export class ConstrPlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async alternative() {
    const ret = await HaskellShelley.alternative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.data(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new(alternative, data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusList);
    const ret = await HaskellShelley.new(alternativePtr, dataPtr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

}


export class DNSRecordSRV extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.new(dns_name);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async record() {
    const ret = await HaskellShelley.record(this.ptr);
    return ret;
  }

}


export class EnterpriseAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const ret = await HaskellShelley.new(network, paymentPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.payment_cred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await HaskellShelley.to_address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.from_address(addrPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

}


export class BlockHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BlockHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, BlockHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, BlockHash);
  }

}


export class VRFKeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, VRFKeyHash);
  }

}


export class TransactionBuilderConfig extends Ptr {
}


export class StakeDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stake_credential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.pool_keyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(stake_credential, pool_keyhash) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.new(stake_credentialPtr, pool_keyhashPtr);
    return Ptr._wrap(ret, StakeDelegation);
  }

}


export class Mint extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Mint);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Mint);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Mint);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Mint);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.new_from_entry(keyPtr, valuePtr);
    return Ptr._wrap(ret, Mint);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get_all(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await HaskellShelley.get_all(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintsAssets);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async as_positive_multiasset() {
    const ret = await HaskellShelley.as_positive_multiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  async as_negative_multiasset() {
    const ret = await HaskellShelley.as_negative_multiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class StakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeCredentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, StakeCredentials);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, StakeCredentials);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, StakeCredentials);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, StakeCredential);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, StakeCredential);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class MetadataMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MetadataMap);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MetadataMap);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_str(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.insert_str(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_i32(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.insert_i32(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_str(key) {
    const ret = await HaskellShelley.get_str(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_i32(key) {
    const ret = await HaskellShelley.get_i32(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async has(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.has(this.ptr, keyPtr);
    return ret;
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

}


export class VRFCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, VRFCert);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, VRFCert);
  }

  async output() {
    const ret = await HaskellShelley.output(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async proof() {
    const ret = await HaskellShelley.proof(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(output, proof) {
    const ret = await HaskellShelley.new(b64FromUint8Array(output), b64FromUint8Array(proof));
    return Ptr._wrap(ret, VRFCert);
  }

}


export class BigNum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigNum);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, BigNum);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, BigNum);
  }

  static async from_str(string) {
    const ret = await HaskellShelley.from_str(string);
    return Ptr._wrap(ret, BigNum);
  }

  async to_str() {
    const ret = await HaskellShelley.to_str(this.ptr);
    return ret;
  }

  static async zero() {
    const ret = await HaskellShelley.zero();
    return Ptr._wrap(ret, BigNum);
  }

  static async one() {
    const ret = await HaskellShelley.one();
    return Ptr._wrap(ret, BigNum);
  }

  async is_zero() {
    const ret = await HaskellShelley.is_zero(this.ptr);
    return ret;
  }

  async div_floor(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.div_floor(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_mul(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.checked_mul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_add(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.checked_add(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.checked_sub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async clamped_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.clamped_sub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.compare(this.ptr, rhs_valuePtr);
    return ret;
  }

  async less_than(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.less_than(this.ptr, rhs_valuePtr);
    return ret;
  }

  static async max(a, b) {
    const aPtr = Ptr._assertClass(a, BigNum);
    const bPtr = Ptr._assertClass(b, BigNum);
    const ret = await HaskellShelley.max(aPtr, bPtr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class Withdrawals extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Withdrawals);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Withdrawals);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

}


export class MoveInstantaneousReward extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_other_pot(pot, amount) {
    const amountPtr = Ptr._assertClass(amount, BigNum);
    const ret = await HaskellShelley.new_to_other_pot(pot, amountPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_stake_creds(pot, amounts) {
    const amountsPtr = Ptr._assertClass(amounts, MIRToStakeCredentials);
    const ret = await HaskellShelley.new_to_stake_creds(pot, amountsPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async pot() {
    const ret = await HaskellShelley.pot(this.ptr);
    return ret;
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_to_other_pot() {
    const ret = await HaskellShelley.as_to_other_pot(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_to_stake_creds() {
    const ret = await HaskellShelley.as_to_stake_creds(this.ptr);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

}


export class Ipv6 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv6);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Ipv6);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(data) {
    const ret = await HaskellShelley.new(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv6);
  }

  async ip() {
    const ret = await HaskellShelley.ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Vkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Vkey);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Vkey);
  }

  static async new(pk) {
    const pkPtr = Ptr._assertClass(pk, PublicKey);
    const ret = await HaskellShelley.new(pkPtr);
    return Ptr._wrap(ret, Vkey);
  }

  async public_key() {
    const ret = await HaskellShelley.public_key(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class TransactionUnspentOutputs extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionUnspentOutput);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class ProposedProtocolParameterUpdates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const valuePtr = Ptr._assertClass(value, ProtocolParamUpdate);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, GenesisHashes);
  }

}


export class TransactionOutputAmountBuilder extends Ptr {
  async with_value(amount) {
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.with_value(this.ptr, amountPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.with_coin(this.ptr, coinPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin_and_asset(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.with_coin_and_asset(this.ptr, coinPtr, multiassetPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin(multiasset, coins_per_utxo_word) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
    const ret = await HaskellShelley.with_asset_and_min_required_coin(this.ptr, multiassetPtr, coins_per_utxo_wordPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const data_costPtr = Ptr._assertClass(data_cost, DataCost);
    const ret = await HaskellShelley.with_asset_and_min_required_coin_by_utxo_cost(this.ptr, multiassetPtr, data_costPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async build() {
    const ret = await HaskellShelley.build(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class AssetNames extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetNames);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, AssetNames);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, AssetNames);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, AssetNames);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, AssetName);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, AssetName);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class GeneralTransactionMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

}


export class TransactionInputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionInputs);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionInputs);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionInput);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.to_option(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class Update extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Update);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Update);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Update);
  }

  async proposed_protocol_parameter_updates() {
    const ret = await HaskellShelley.proposed_protocol_parameter_updates(this.ptr);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async epoch() {
    const ret = await HaskellShelley.epoch(this.ptr);
    return ret;
  }

  static async new(proposed_protocol_parameter_updates, epoch) {
    const proposed_protocol_parameter_updatesPtr = Ptr._assertClass(proposed_protocol_parameter_updates, ProposedProtocolParameterUpdates);
    const ret = await HaskellShelley.new(proposed_protocol_parameter_updatesPtr, epoch);
    return Ptr._wrap(ret, Update);
  }

}


export class LinearFee extends Ptr {
  async constant() {
    const ret = await HaskellShelley.constant(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async coefficient() {
    const ret = await HaskellShelley.coefficient(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(coefficient, constant) {
    const coefficientPtr = Ptr._assertClass(coefficient, BigNum);
    const constantPtr = Ptr._assertClass(constant, BigNum);
    const ret = await HaskellShelley.new(coefficientPtr, constantPtr);
    return Ptr._wrap(ret, LinearFee);
  }

}


export class Strings extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Strings);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return ret;
  }

  add(elem) {
    const ret = HaskellShelley.add(this.ptr, elem);
    return ret;
  }

}


export class TimelockStart extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TimelockStart);
  }

  async slot() {
    const ret = await HaskellShelley.slot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.slot_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.new(slot);
    return Ptr._wrap(ret, TimelockStart);
  }

  static async new_timelockstart(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.new_timelockstart(slotPtr);
    return Ptr._wrap(ret, TimelockStart);
  }

}


export class Ed25519KeyHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.to_option(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class MultiAsset extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, MultiAsset);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MultiAsset);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(policy_id, assets) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const assetsPtr = Ptr._assertClass(assets, Assets);
    const ret = await HaskellShelley.insert(this.ptr, policy_idPtr, assetsPtr);
    return Ptr._wrap(ret, Assets);
  }

  async get(policy_id) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const ret = await HaskellShelley.get(this.ptr, policy_idPtr);
    return Ptr._wrap(ret, Assets);
  }

  async set_asset(policy_id, asset_name, value) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.set_asset(this.ptr, policy_idPtr, asset_namePtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_asset(policy_id, asset_name) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const ret = await HaskellShelley.get_asset(this.ptr, policy_idPtr, asset_namePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async sub(rhs_ma) {
    const rhs_maPtr = Ptr._assertClass(rhs_ma, MultiAsset);
    const ret = await HaskellShelley.sub(this.ptr, rhs_maPtr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class KESSignature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESSignature);
  }

}


export class PublicKeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, PublicKeys);
  }

  async size() {
    const ret = await HaskellShelley.size(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, PublicKey);
  }

  add(key) {
    const keyPtr = Ptr._assertClass(key, PublicKey);
    const ret = HaskellShelley.add(this.ptr, keyPtr);
    return ret;
  }

}


export class ScriptHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptHashes);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, ScriptHashes);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, ScriptHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, ScriptHash);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class Header extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Header);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Header);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Header);
  }

  async header_body() {
    const ret = await HaskellShelley.header_body(this.ptr);
    return Ptr._wrap(ret, HeaderBody);
  }

  async body_signature() {
    const ret = await HaskellShelley.body_signature(this.ptr);
    return Ptr._wrap(ret, KESSignature);
  }

  static async new(header_body, body_signature) {
    const header_bodyPtr = Ptr._assertClass(header_body, HeaderBody);
    const body_signaturePtr = Ptr._assertClass(body_signature, KESSignature);
    const ret = await HaskellShelley.new(header_bodyPtr, body_signaturePtr);
    return Ptr._wrap(ret, Header);
  }

}


export class DNSRecordAorAAAA extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.new(dns_name);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async record() {
    const ret = await HaskellShelley.record(this.ptr);
    return ret;
  }

}


export class PoolMetadataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

}


export class InputWithScriptWitness extends Ptr {
  static async new_with_native_script_witness(input, witness) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const witnessPtr = Ptr._assertClass(witness, NativeScript);
    const ret = await HaskellShelley.new_with_native_script_witness(inputPtr, witnessPtr);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  static async new_with_plutus_witness(input, witness) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = await HaskellShelley.new_with_plutus_witness(inputPtr, witnessPtr);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  async input() {
    const ret = await HaskellShelley.input(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class PlutusScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const ret = await HaskellShelley.new(scriptPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input(script_hash, input) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await HaskellShelley.new_ref_input(script_hashPtr, inputPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input_with_lang_ver(script_hash, input, lang_ver) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const lang_verPtr = Ptr._assertClass(lang_ver, Language);
    const ret = await HaskellShelley.new_ref_input_with_lang_ver(script_hashPtr, inputPtr, lang_verPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

}


export class PlutusWitness extends Ptr {
  static async new(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.new(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const datumPtr = Ptr._assertClass(datum, DatumSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.new_with_ref(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.new_without_datum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  async script() {
    const ret = await HaskellShelley.script(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async datum() {
    const ret = await HaskellShelley.datum(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async redeemer() {
    const ret = await HaskellShelley.redeemer(this.ptr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class PrivateKey extends Ptr {
  async to_public() {
    const ret = await HaskellShelley.to_public(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async generate_ed25519() {
    const ret = await HaskellShelley.generate_ed25519();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async generate_ed25519extended() {
    const ret = await HaskellShelley.generate_ed25519extended();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.from_bech32(bech32_str);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.to_bech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_extended_bytes(bytes) {
    const ret = await HaskellShelley.from_extended_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_normal_bytes(bytes) {
    const ret = await HaskellShelley.from_normal_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  async sign(message) {
    const ret = await HaskellShelley.sign(this.ptr, b64FromUint8Array(message));
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PrivateKey);
  }

}


export class Language extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Language);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Language);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v1() {
    const ret = await HaskellShelley.new_plutus_v1();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v2() {
    const ret = await HaskellShelley.new_plutus_v2();
    return Ptr._wrap(ret, Language);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

}


export class ScriptAll extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptAll);
  }

  async native_scripts() {
    const ret = await HaskellShelley.native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.new(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAll);
  }

}


export class OperationalCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, OperationalCert);
  }

  async hot_vkey() {
    const ret = await HaskellShelley.hot_vkey(this.ptr);
    return Ptr._wrap(ret, KESVKey);
  }

  async sequence_number() {
    const ret = await HaskellShelley.sequence_number(this.ptr);
    return ret;
  }

  async kes_period() {
    const ret = await HaskellShelley.kes_period(this.ptr);
    return ret;
  }

  async sigma() {
    const ret = await HaskellShelley.sigma(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async new(hot_vkey, sequence_number, kes_period, sigma) {
    const hot_vkeyPtr = Ptr._assertClass(hot_vkey, KESVKey);
    const sigmaPtr = Ptr._assertClass(sigma, Ed25519Signature);
    const ret = await HaskellShelley.new(hot_vkeyPtr, sequence_number, kes_period, sigmaPtr);
    return Ptr._wrap(ret, OperationalCert);
  }

}


export class PlutusWitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, PlutusWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusWitness);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, ScriptHash);
  }

}


export class StakeRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stake_credential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const ret = await HaskellShelley.new(stake_credentialPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

}


export class TransactionBuilderConfigBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async fee_algo(fee_algo) {
    const fee_algoPtr = Ptr._assertClass(fee_algo, LinearFee);
    const ret = await HaskellShelley.fee_algo(this.ptr, fee_algoPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_word(coins_per_utxo_word) {
    const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
    const ret = await HaskellShelley.coins_per_utxo_word(this.ptr, coins_per_utxo_wordPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_byte(coins_per_utxo_byte) {
    const coins_per_utxo_bytePtr = Ptr._assertClass(coins_per_utxo_byte, BigNum);
    const ret = await HaskellShelley.coins_per_utxo_byte(this.ptr, coins_per_utxo_bytePtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async ex_unit_prices(ex_unit_prices) {
    const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
    const ret = await HaskellShelley.ex_unit_prices(this.ptr, ex_unit_pricesPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = await HaskellShelley.pool_deposit(this.ptr, pool_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.key_deposit(this.ptr, key_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_value_size(max_value_size) {
    const ret = await HaskellShelley.max_value_size(this.ptr, max_value_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_tx_size(max_tx_size) {
    const ret = await HaskellShelley.max_tx_size(this.ptr, max_tx_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async prefer_pure_change(prefer_pure_change) {
    const ret = await HaskellShelley.prefer_pure_change(this.ptr, prefer_pure_change);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async build() {
    const ret = await HaskellShelley.build(this.ptr);
    return Ptr._wrap(ret, TransactionBuilderConfig);
  }

}


export class Assets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Assets);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Assets);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Assets);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Assets);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class UnitInterval extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, UnitInterval);
  }

  async numerator() {
    const ret = await HaskellShelley.numerator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async denominator() {
    const ret = await HaskellShelley.denominator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(numerator, denominator) {
    const numeratorPtr = Ptr._assertClass(numerator, BigNum);
    const denominatorPtr = Ptr._assertClass(denominator, BigNum);
    const ret = await HaskellShelley.new(numeratorPtr, denominatorPtr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class KESVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, KESVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, KESVKey);
  }

}


export class MultiHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, MultiHostName);
  }

  async dns_name() {
    const ret = await HaskellShelley.dns_name(this.ptr);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordSRV);
    const ret = await HaskellShelley.new(dns_namePtr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class LegacyDaedalusPrivateKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, LegacyDaedalusPrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async chaincode() {
    const ret = await HaskellShelley.chaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Nonce extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Nonce);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Nonce);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Nonce);
  }

  static async new_identity() {
    const ret = await HaskellShelley.new_identity();
    return Ptr._wrap(ret, Nonce);
  }

  static async new_from_hash(hash) {
    const ret = await HaskellShelley.new_from_hash(b64FromUint8Array(hash));
    return Ptr._wrap(ret, Nonce);
  }

  async get_hash() {
    const ret = await HaskellShelley.get_hash(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class BaseAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const stakePtr = Ptr._assertClass(stake, StakeCredential);
    const ret = await HaskellShelley.new(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.payment_cred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async stake_cred() {
    const ret = await HaskellShelley.stake_cred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await HaskellShelley.to_address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.from_address(addrPtr);
    return Ptr._wrap(ret, BaseAddress);
  }

}


export class ExUnitPrices extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async mem_price() {
    const ret = await HaskellShelley.mem_price(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async step_price() {
    const ret = await HaskellShelley.step_price(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  static async new(mem_price, step_price) {
    const mem_pricePtr = Ptr._assertClass(mem_price, UnitInterval);
    const step_pricePtr = Ptr._assertClass(step_price, UnitInterval);
    const ret = await HaskellShelley.new(mem_pricePtr, step_pricePtr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

}


export class AssetName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetName);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, AssetName);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, AssetName);
  }

  static async new(name) {
    const ret = await HaskellShelley.new(b64FromUint8Array(name));
    return Ptr._wrap(ret, AssetName);
  }

  async name() {
    const ret = await HaskellShelley.name(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class NativeScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, NativeScript);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, NativeScript);
  }

  async hash() {
    const ret = await HaskellShelley.hash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new_script_pubkey(script_pubkey) {
    const script_pubkeyPtr = Ptr._assertClass(script_pubkey, ScriptPubkey);
    const ret = await HaskellShelley.new_script_pubkey(script_pubkeyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_all(script_all) {
    const script_allPtr = Ptr._assertClass(script_all, ScriptAll);
    const ret = await HaskellShelley.new_script_all(script_allPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_any(script_any) {
    const script_anyPtr = Ptr._assertClass(script_any, ScriptAny);
    const ret = await HaskellShelley.new_script_any(script_anyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_n_of_k(script_n_of_k) {
    const script_n_of_kPtr = Ptr._assertClass(script_n_of_k, ScriptNOfK);
    const ret = await HaskellShelley.new_script_n_of_k(script_n_of_kPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_start(timelock_start) {
    const timelock_startPtr = Ptr._assertClass(timelock_start, TimelockStart);
    const ret = await HaskellShelley.new_timelock_start(timelock_startPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_expiry(timelock_expiry) {
    const timelock_expiryPtr = Ptr._assertClass(timelock_expiry, TimelockExpiry);
    const ret = await HaskellShelley.new_timelock_expiry(timelock_expiryPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_script_pubkey() {
    const ret = await HaskellShelley.as_script_pubkey(this.ptr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async as_script_all() {
    const ret = await HaskellShelley.as_script_all(this.ptr);
    return Ptr._wrap(ret, ScriptAll);
  }

  async as_script_any() {
    const ret = await HaskellShelley.as_script_any(this.ptr);
    return Ptr._wrap(ret, ScriptAny);
  }

  async as_script_n_of_k() {
    const ret = await HaskellShelley.as_script_n_of_k(this.ptr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async as_timelock_start() {
    const ret = await HaskellShelley.as_timelock_start(this.ptr);
    return Ptr._wrap(ret, TimelockStart);
  }

  async as_timelock_expiry() {
    const ret = await HaskellShelley.as_timelock_expiry(this.ptr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async get_required_signers() {
    const ret = await HaskellShelley.get_required_signers(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class ByronAddress extends Ptr {
  async to_base58() {
    const ret = await HaskellShelley.to_base58(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ByronAddress);
  }

  async byron_protocol_magic() {
    const ret = await HaskellShelley.byron_protocol_magic(this.ptr);
    return ret;
  }

  async attributes() {
    const ret = await HaskellShelley.attributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async network_id() {
    const ret = await HaskellShelley.network_id(this.ptr);
    return ret;
  }

  static async from_base58(s) {
    const ret = await HaskellShelley.from_base58(s);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async icarus_from_key(key, protocol_magic) {
    const keyPtr = Ptr._assertClass(key, Bip32PublicKey);
    const ret = await HaskellShelley.icarus_from_key(keyPtr, protocol_magic);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async is_valid(s) {
    const ret = await HaskellShelley.is_valid(s);
    return ret;
  }

  async to_address() {
    const ret = await HaskellShelley.to_address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.from_address(addrPtr);
    return Ptr._wrap(ret, ByronAddress);
  }

}


export class BigInt extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigInt);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, BigInt);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, BigInt);
  }

  async is_zero() {
    const ret = await HaskellShelley.is_zero(this.ptr);
    return ret;
  }

  async as_u64() {
    const ret = await HaskellShelley.as_u64(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_int() {
    const ret = await HaskellShelley.as_int(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  static async from_str(text) {
    const ret = await HaskellShelley.from_str(text);
    return Ptr._wrap(ret, BigInt);
  }

  async to_str() {
    const ret = await HaskellShelley.to_str(this.ptr);
    return ret;
  }

  async add(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.add(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async mul(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.mul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  static async one() {
    const ret = await HaskellShelley.one();
    return Ptr._wrap(ret, BigInt);
  }

  async increment() {
    const ret = await HaskellShelley.increment(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async div_ceil(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.div_ceil(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

}


export class Pointer extends Ptr {
  static async new(slot, tx_index, cert_index) {
    const ret = await HaskellShelley.new(slot, tx_index, cert_index);
    return Ptr._wrap(ret, Pointer);
  }

  static async new_pointer(slot, tx_index, cert_index) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const tx_indexPtr = Ptr._assertClass(tx_index, BigNum);
    const cert_indexPtr = Ptr._assertClass(cert_index, BigNum);
    const ret = await HaskellShelley.new_pointer(slotPtr, tx_indexPtr, cert_indexPtr);
    return Ptr._wrap(ret, Pointer);
  }

  async slot() {
    const ret = await HaskellShelley.slot(this.ptr);
    return ret;
  }

  async tx_index() {
    const ret = await HaskellShelley.tx_index(this.ptr);
    return ret;
  }

  async cert_index() {
    const ret = await HaskellShelley.cert_index(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.slot_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async tx_index_bignum() {
    const ret = await HaskellShelley.tx_index_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cert_index_bignum() {
    const ret = await HaskellShelley.cert_index_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class ProtocolParamUpdate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  set_minfee_a(minfee_a) {
    const minfee_aPtr = Ptr._assertClass(minfee_a, BigNum);
    const ret = HaskellShelley.set_minfee_a(this.ptr, minfee_aPtr);
    return ret;
  }

  async minfee_a() {
    const ret = await HaskellShelley.minfee_a(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_minfee_b(minfee_b) {
    const minfee_bPtr = Ptr._assertClass(minfee_b, BigNum);
    const ret = HaskellShelley.set_minfee_b(this.ptr, minfee_bPtr);
    return ret;
  }

  async minfee_b() {
    const ret = await HaskellShelley.minfee_b(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_block_body_size(max_block_body_size) {
    const ret = HaskellShelley.set_max_block_body_size(this.ptr, max_block_body_size);
    return ret;
  }

  async max_block_body_size() {
    const ret = await HaskellShelley.max_block_body_size(this.ptr);
    return ret;
  }

  set_max_tx_size(max_tx_size) {
    const ret = HaskellShelley.set_max_tx_size(this.ptr, max_tx_size);
    return ret;
  }

  async max_tx_size() {
    const ret = await HaskellShelley.max_tx_size(this.ptr);
    return ret;
  }

  set_max_block_header_size(max_block_header_size) {
    const ret = HaskellShelley.set_max_block_header_size(this.ptr, max_block_header_size);
    return ret;
  }

  async max_block_header_size() {
    const ret = await HaskellShelley.max_block_header_size(this.ptr);
    return ret;
  }

  set_key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = HaskellShelley.set_key_deposit(this.ptr, key_depositPtr);
    return ret;
  }

  async key_deposit() {
    const ret = await HaskellShelley.key_deposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = HaskellShelley.set_pool_deposit(this.ptr, pool_depositPtr);
    return ret;
  }

  async pool_deposit() {
    const ret = await HaskellShelley.pool_deposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_epoch(max_epoch) {
    const ret = HaskellShelley.set_max_epoch(this.ptr, max_epoch);
    return ret;
  }

  async max_epoch() {
    const ret = await HaskellShelley.max_epoch(this.ptr);
    return ret;
  }

  set_n_opt(n_opt) {
    const ret = HaskellShelley.set_n_opt(this.ptr, n_opt);
    return ret;
  }

  async n_opt() {
    const ret = await HaskellShelley.n_opt(this.ptr);
    return ret;
  }

  set_pool_pledge_influence(pool_pledge_influence) {
    const pool_pledge_influencePtr = Ptr._assertClass(pool_pledge_influence, UnitInterval);
    const ret = HaskellShelley.set_pool_pledge_influence(this.ptr, pool_pledge_influencePtr);
    return ret;
  }

  async pool_pledge_influence() {
    const ret = await HaskellShelley.pool_pledge_influence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_expansion_rate(expansion_rate) {
    const expansion_ratePtr = Ptr._assertClass(expansion_rate, UnitInterval);
    const ret = HaskellShelley.set_expansion_rate(this.ptr, expansion_ratePtr);
    return ret;
  }

  async expansion_rate() {
    const ret = await HaskellShelley.expansion_rate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_treasury_growth_rate(treasury_growth_rate) {
    const treasury_growth_ratePtr = Ptr._assertClass(treasury_growth_rate, UnitInterval);
    const ret = HaskellShelley.set_treasury_growth_rate(this.ptr, treasury_growth_ratePtr);
    return ret;
  }

  async treasury_growth_rate() {
    const ret = await HaskellShelley.treasury_growth_rate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async d() {
    const ret = await HaskellShelley.d(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async extra_entropy() {
    const ret = await HaskellShelley.extra_entropy(this.ptr);
    return Ptr._wrap(ret, Nonce);
  }

  set_protocol_version(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = HaskellShelley.set_protocol_version(this.ptr, protocol_versionPtr);
    return ret;
  }

  async protocol_version() {
    const ret = await HaskellShelley.protocol_version(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  set_min_pool_cost(min_pool_cost) {
    const min_pool_costPtr = Ptr._assertClass(min_pool_cost, BigNum);
    const ret = HaskellShelley.set_min_pool_cost(this.ptr, min_pool_costPtr);
    return ret;
  }

  async min_pool_cost() {
    const ret = await HaskellShelley.min_pool_cost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ada_per_utxo_byte(ada_per_utxo_byte) {
    const ada_per_utxo_bytePtr = Ptr._assertClass(ada_per_utxo_byte, BigNum);
    const ret = HaskellShelley.set_ada_per_utxo_byte(this.ptr, ada_per_utxo_bytePtr);
    return ret;
  }

  async ada_per_utxo_byte() {
    const ret = await HaskellShelley.ada_per_utxo_byte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_cost_models(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.set_cost_models(this.ptr, cost_modelsPtr);
    return ret;
  }

  async cost_models() {
    const ret = await HaskellShelley.cost_models(this.ptr);
    return Ptr._wrap(ret, Costmdls);
  }

  set_execution_costs(execution_costs) {
    const execution_costsPtr = Ptr._assertClass(execution_costs, ExUnitPrices);
    const ret = HaskellShelley.set_execution_costs(this.ptr, execution_costsPtr);
    return ret;
  }

  async execution_costs() {
    const ret = await HaskellShelley.execution_costs(this.ptr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  set_max_tx_ex_units(max_tx_ex_units) {
    const max_tx_ex_unitsPtr = Ptr._assertClass(max_tx_ex_units, ExUnits);
    const ret = HaskellShelley.set_max_tx_ex_units(this.ptr, max_tx_ex_unitsPtr);
    return ret;
  }

  async max_tx_ex_units() {
    const ret = await HaskellShelley.max_tx_ex_units(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_block_ex_units(max_block_ex_units) {
    const max_block_ex_unitsPtr = Ptr._assertClass(max_block_ex_units, ExUnits);
    const ret = HaskellShelley.set_max_block_ex_units(this.ptr, max_block_ex_unitsPtr);
    return ret;
  }

  async max_block_ex_units() {
    const ret = await HaskellShelley.max_block_ex_units(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_value_size(max_value_size) {
    const ret = HaskellShelley.set_max_value_size(this.ptr, max_value_size);
    return ret;
  }

  async max_value_size() {
    const ret = await HaskellShelley.max_value_size(this.ptr);
    return ret;
  }

  set_collateral_percentage(collateral_percentage) {
    const ret = HaskellShelley.set_collateral_percentage(this.ptr, collateral_percentage);
    return ret;
  }

  async collateral_percentage() {
    const ret = await HaskellShelley.collateral_percentage(this.ptr);
    return ret;
  }

  set_max_collateral_inputs(max_collateral_inputs) {
    const ret = HaskellShelley.set_max_collateral_inputs(this.ptr, max_collateral_inputs);
    return ret;
  }

  async max_collateral_inputs() {
    const ret = await HaskellShelley.max_collateral_inputs(this.ptr);
    return ret;
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

}


export class DataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, DataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, DataHash);
  }

}


export class TransactionOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async address() {
    const ret = await HaskellShelley.address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  async amount() {
    const ret = await HaskellShelley.amount(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async data_hash() {
    const ret = await HaskellShelley.data_hash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async plutus_data() {
    const ret = await HaskellShelley.plutus_data(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async script_ref() {
    const ret = await HaskellShelley.script_ref(this.ptr);
    return Ptr._wrap(ret, ScriptRef);
  }

  set_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = HaskellShelley.set_script_ref(this.ptr, script_refPtr);
    return ret;
  }

  set_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = HaskellShelley.set_plutus_data(this.ptr, dataPtr);
    return ret;
  }

  set_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = HaskellShelley.set_data_hash(this.ptr, data_hashPtr);
    return ret;
  }

  async has_plutus_data() {
    const ret = await HaskellShelley.has_plutus_data(this.ptr);
    return ret;
  }

  async has_data_hash() {
    const ret = await HaskellShelley.has_data_hash(this.ptr);
    return ret;
  }

  async has_script_ref() {
    const ret = await HaskellShelley.has_script_ref(this.ptr);
    return ret;
  }

  static async new(address, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.new(addressPtr, amountPtr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class Redeemers extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemers);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Redeemers);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Redeemers);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Redeemer);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Redeemer);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

  async total_ex_units() {
    const ret = await HaskellShelley.total_ex_units(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class NativeScripts extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, NativeScripts);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, NativeScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, NativeScript);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TxBuilderConstants extends Ptr {
  static async plutus_default_cost_models() {
    const ret = await HaskellShelley.plutus_default_cost_models();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_alonzo_cost_models() {
    const ret = await HaskellShelley.plutus_alonzo_cost_models();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_vasil_cost_models() {
    const ret = await HaskellShelley.plutus_vasil_cost_models();
    return Ptr._wrap(ret, Costmdls);
  }

}


export class PlutusMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PlutusMap);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, PlutusMap);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const valuePtr = Ptr._assertClass(value, PlutusData);
    const ret = await HaskellShelley.insert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const ret = await HaskellShelley.get(this.ptr, keyPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

}


export class PoolRetirement extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.pool_keyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async epoch() {
    const ret = await HaskellShelley.epoch(this.ptr);
    return ret;
  }

  static async new(pool_keyhash, epoch) {
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.new(pool_keyhashPtr, epoch);
    return Ptr._wrap(ret, PoolRetirement);
  }

}


export class Int extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Int);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Int);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Int);
  }

  static async new(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.new(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_negative(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.new_negative(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_i32(x) {
    const ret = await HaskellShelley.new_i32(x);
    return Ptr._wrap(ret, Int);
  }

  async is_positive() {
    const ret = await HaskellShelley.is_positive(this.ptr);
    return ret;
  }

  async as_positive() {
    const ret = await HaskellShelley.as_positive(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_negative() {
    const ret = await HaskellShelley.as_negative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_i32() {
    const ret = await HaskellShelley.as_i32(this.ptr);
    return ret;
  }

  async as_i32_or_nothing() {
    const ret = await HaskellShelley.as_i32_or_nothing(this.ptr);
    return ret;
  }

  async as_i32_or_fail() {
    const ret = await HaskellShelley.as_i32_or_fail(this.ptr);
    return ret;
  }

  async to_str() {
    const ret = await HaskellShelley.to_str(this.ptr);
    return ret;
  }

  static async from_str(string) {
    const ret = await HaskellShelley.from_str(string);
    return Ptr._wrap(ret, Int);
  }

}


export class PlutusScripts extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, PlutusScripts);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, PlutusScripts);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, PlutusScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusScript);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class TimelockExpiry extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async slot() {
    const ret = await HaskellShelley.slot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.slot_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.new(slot);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  static async new_timelockexpiry(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.new_timelockexpiry(slotPtr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

}


export class MintWitness extends Ptr {
  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await HaskellShelley.new_native_script(native_scriptPtr);
    return Ptr._wrap(ret, MintWitness);
  }

  static async new_plutus_script(plutus_script, redeemer) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.new_plutus_script(plutus_scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, MintWitness);
  }

}


export class StakeCredential extends Ptr {
  static async from_keyhash(hash) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const ret = await HaskellShelley.from_keyhash(hashPtr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async from_scripthash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const ret = await HaskellShelley.from_scripthash(hashPtr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_keyhash() {
    const ret = await HaskellShelley.to_keyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_scripthash() {
    const ret = await HaskellShelley.to_scripthash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, StakeCredential);
  }

}


export class MintBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MintBuilder);
  }

  add_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.add_asset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  set_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.set_asset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.build(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.get_native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.get_plutus_witnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_redeeemers() {
    const ret = await HaskellShelley.get_redeeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.has_plutus_scripts(this.ptr);
    return ret;
  }

  async has_native_scripts() {
    const ret = await HaskellShelley.has_native_scripts(this.ptr);
    return ret;
  }

}


export class TransactionWitnessSets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionWitnessSet);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class Languages extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, Languages);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, Language);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Language);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

  static async list() {
    const ret = await HaskellShelley.list();
    return Ptr._wrap(ret, Languages);
  }

}


export class DatumSource extends Ptr {
  static async new(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = await HaskellShelley.new(datumPtr);
    return Ptr._wrap(ret, DatumSource);
  }

  static async new_ref_input(input) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await HaskellShelley.new_ref_input(inputPtr);
    return Ptr._wrap(ret, DatumSource);
  }

}


export class StakeDeregistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stake_credential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const ret = await HaskellShelley.new(stake_credentialPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

}


export class TxInputsBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TxInputsBuilder);
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_key_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_script_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_script_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_native_script_input(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_plutus_script_input(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_bootstrap_input(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.add_input(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async count_missing_input_scripts() {
    const ret = await HaskellShelley.count_missing_input_scripts(this.ptr);
    return ret;
  }

  async add_required_native_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, NativeScripts);
    const ret = await HaskellShelley.add_required_native_input_scripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_plutus_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, PlutusWitnesses);
    const ret = await HaskellShelley.add_required_plutus_input_scripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_script_input_witnesses(inputs_with_wit) {
    const inputs_with_witPtr = Ptr._assertClass(inputs_with_wit, InputsWithScriptWitness);
    const ret = await HaskellShelley.add_required_script_input_witnesses(this.ptr, inputs_with_witPtr);
    return ret;
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.get_ref_inputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.get_native_input_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.get_plutus_input_scripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.add_required_signer(this.ptr, keyPtr);
    return ret;
  }

  add_required_signers(keys) {
    const keysPtr = Ptr._assertClass(keys, Ed25519KeyHashes);
    const ret = HaskellShelley.add_required_signers(this.ptr, keysPtr);
    return ret;
  }

  async total_value() {
    const ret = await HaskellShelley.total_value(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async inputs() {
    const ret = await HaskellShelley.inputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async inputs_option() {
    const ret = await HaskellShelley.inputs_option(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class Value extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Value);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Value);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Value);
  }

  static async new(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.new(coinPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_from_assets(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.new_from_assets(multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_with_assets(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.new_with_assets(coinPtr, multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async zero() {
    const ret = await HaskellShelley.zero();
    return Ptr._wrap(ret, Value);
  }

  async is_zero() {
    const ret = await HaskellShelley.is_zero(this.ptr);
    return ret;
  }

  async coin() {
    const ret = await HaskellShelley.coin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = HaskellShelley.set_coin(this.ptr, coinPtr);
    return ret;
  }

  async multiasset() {
    const ret = await HaskellShelley.multiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  set_multiasset(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = HaskellShelley.set_multiasset(this.ptr, multiassetPtr);
    return ret;
  }

  async checked_add(rhs) {
    const rhsPtr = Ptr._assertClass(rhs, Value);
    const ret = await HaskellShelley.checked_add(this.ptr, rhsPtr);
    return Ptr._wrap(ret, Value);
  }

  async checked_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.checked_sub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async clamped_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.clamped_sub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.compare(this.ptr, rhs_valuePtr);
    return ret;
  }

}


export class Bip32PublicKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.derive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.to_raw_key(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.from_bech32(bech32_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.to_bech32(this.ptr);
    return ret;
  }

  async chaincode() {
    const ret = await HaskellShelley.chaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

}


export class AuxiliaryData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async metadata() {
    const ret = await HaskellShelley.metadata(this.ptr);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.set_metadata(this.ptr, metadataPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.set_native_scripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.plutus_scripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.set_plutus_scripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

}


export class ScriptNOfK extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async n() {
    const ret = await HaskellShelley.n(this.ptr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(n, native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.new(n, native_scriptsPtr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

}


export class ScriptRef extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await HaskellShelley.new_native_script(native_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_plutus_script(plutus_script) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScript);
    const ret = await HaskellShelley.new_plutus_script(plutus_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  async is_native_script() {
    const ret = await HaskellShelley.is_native_script(this.ptr);
    return ret;
  }

  async is_plutus_script() {
    const ret = await HaskellShelley.is_plutus_script(this.ptr);
    return ret;
  }

  async native_script() {
    const ret = await HaskellShelley.native_script(this.ptr);
    return Ptr._wrap(ret, NativeScript);
  }

  async plutus_script() {
    const ret = await HaskellShelley.plutus_script(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

}


export class TransactionBodies extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, TransactionBodies);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionBodies);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, TransactionBody);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionBody);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class NetworkId extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NetworkId);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, NetworkId);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, NetworkId);
  }

  static async testnet() {
    const ret = await HaskellShelley.testnet();
    return Ptr._wrap(ret, NetworkId);
  }

  static async mainnet() {
    const ret = await HaskellShelley.mainnet();
    return Ptr._wrap(ret, NetworkId);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

}


export class DataCost extends Ptr {
  static async new_coins_per_word(coins_per_word) {
    const coins_per_wordPtr = Ptr._assertClass(coins_per_word, BigNum);
    const ret = await HaskellShelley.new_coins_per_word(coins_per_wordPtr);
    return Ptr._wrap(ret, DataCost);
  }

  static async new_coins_per_byte(coins_per_byte) {
    const coins_per_bytePtr = Ptr._assertClass(coins_per_byte, BigNum);
    const ret = await HaskellShelley.new_coins_per_byte(coins_per_bytePtr);
    return Ptr._wrap(ret, DataCost);
  }

  async coins_per_byte() {
    const ret = await HaskellShelley.coins_per_byte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class PublicKey extends Ptr {
  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.from_bech32(bech32_str);
    return Ptr._wrap(ret, PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.to_bech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PublicKey);
  }

  async verify(data, signature) {
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.verify(this.ptr, b64FromUint8Array(data), signaturePtr);
    return ret;
  }

  async hash() {
    const ret = await HaskellShelley.hash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class GenesisHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, GenesisHashes);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, GenesisHashes);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, GenesisHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, GenesisHash);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class HeaderBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, HeaderBody);
  }

  async block_number() {
    const ret = await HaskellShelley.block_number(this.ptr);
    return ret;
  }

  async slot() {
    const ret = await HaskellShelley.slot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.slot_bignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async prev_hash() {
    const ret = await HaskellShelley.prev_hash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async issuer_vkey() {
    const ret = await HaskellShelley.issuer_vkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async vrf_vkey() {
    const ret = await HaskellShelley.vrf_vkey(this.ptr);
    return Ptr._wrap(ret, VRFVKey);
  }

  async has_nonce_and_leader_vrf() {
    const ret = await HaskellShelley.has_nonce_and_leader_vrf(this.ptr);
    return ret;
  }

  async nonce_vrf_or_nothing() {
    const ret = await HaskellShelley.nonce_vrf_or_nothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async leader_vrf_or_nothing() {
    const ret = await HaskellShelley.leader_vrf_or_nothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async has_vrf_result() {
    const ret = await HaskellShelley.has_vrf_result(this.ptr);
    return ret;
  }

  async vrf_result_or_nothing() {
    const ret = await HaskellShelley.vrf_result_or_nothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async block_body_size() {
    const ret = await HaskellShelley.block_body_size(this.ptr);
    return ret;
  }

  async block_body_hash() {
    const ret = await HaskellShelley.block_body_hash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async operational_cert() {
    const ret = await HaskellShelley.operational_cert(this.ptr);
    return Ptr._wrap(ret, OperationalCert);
  }

  async protocol_version() {
    const ret = await HaskellShelley.protocol_version(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  static async new(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version) {
    const prev_hashPtr = Ptr._assertOptionalClass(prev_hash, BlockHash);
    const issuer_vkeyPtr = Ptr._assertClass(issuer_vkey, Vkey);
    const vrf_vkeyPtr = Ptr._assertClass(vrf_vkey, VRFVKey);
    const vrf_resultPtr = Ptr._assertClass(vrf_result, VRFCert);
    const block_body_hashPtr = Ptr._assertClass(block_body_hash, BlockHash);
    const operational_certPtr = Ptr._assertClass(operational_cert, OperationalCert);
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    if(prev_hash == null) {
      const ret = await HaskellShelley.new(block_number, slot, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.new_with_prev_hash(block_number, slot, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
  }

  static async new_headerbody(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const prev_hashPtr = Ptr._assertOptionalClass(prev_hash, BlockHash);
    const issuer_vkeyPtr = Ptr._assertClass(issuer_vkey, Vkey);
    const vrf_vkeyPtr = Ptr._assertClass(vrf_vkey, VRFVKey);
    const vrf_resultPtr = Ptr._assertClass(vrf_result, VRFCert);
    const block_body_hashPtr = Ptr._assertClass(block_body_hash, BlockHash);
    const operational_certPtr = Ptr._assertClass(operational_cert, OperationalCert);
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    if(prev_hash == null) {
      const ret = await HaskellShelley.new_headerbody(block_number, slotPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.new_headerbody_with_prev_hash(block_number, slotPtr, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
  }

}


export class MIRToStakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async insert(cred, delta) {
    const credPtr = Ptr._assertClass(cred, StakeCredential);
    const deltaPtr = Ptr._assertClass(delta, Int);
    const ret = await HaskellShelley.insert(this.ptr, credPtr, deltaPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(cred) {
    const credPtr = Ptr._assertClass(cred, StakeCredential);
    const ret = await HaskellShelley.get(this.ptr, credPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.keys(this.ptr);
    return Ptr._wrap(ret, StakeCredentials);
  }

}


export class SingleHostAddr extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async port() {
    const ret = await HaskellShelley.port(this.ptr);
    return ret;
  }

  async ipv4() {
    const ret = await HaskellShelley.ipv4(this.ptr);
    return Ptr._wrap(ret, Ipv4);
  }

  async ipv6() {
    const ret = await HaskellShelley.ipv6(this.ptr);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(port, ipv4, ipv6) {
    const ipv4Ptr = Ptr._assertOptionalClass(ipv4, Ipv4);
    const ipv6Ptr = Ptr._assertOptionalClass(ipv6, Ipv6);
    if(port == null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.new();
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.new_with_port(port);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.new_with_ipv4(ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.new_with_port_ipv4(port, ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.new_with_ipv6(ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.new_with_port_ipv6(port, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.new_with_ipv4_ipv6(ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.new_with_port_ipv4_ipv6(port, ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
  }

}


export class MoveInstantaneousRewardsCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async move_instantaneous_reward() {
    const ret = await HaskellShelley.move_instantaneous_reward(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new(move_instantaneous_reward) {
    const move_instantaneous_rewardPtr = Ptr._assertClass(move_instantaneous_reward, MoveInstantaneousReward);
    const ret = await HaskellShelley.new(move_instantaneous_rewardPtr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class GenesisDelegateHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

}


export class Transaction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Transaction);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Transaction);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Transaction);
  }

  async body() {
    const ret = await HaskellShelley.body(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async witness_set() {
    const ret = await HaskellShelley.witness_set(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async is_valid() {
    const ret = await HaskellShelley.is_valid(this.ptr);
    return ret;
  }

  async auxiliary_data() {
    const ret = await HaskellShelley.auxiliary_data(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_is_valid(valid) {
    const ret = HaskellShelley.set_is_valid(this.ptr, valid);
    return ret;
  }

  static async new(body, witness_set, auxiliary_data) {
    const bodyPtr = Ptr._assertClass(body, TransactionBody);
    const witness_setPtr = Ptr._assertClass(witness_set, TransactionWitnessSet);
    const auxiliary_dataPtr = Ptr._assertOptionalClass(auxiliary_data, AuxiliaryData);
    if(auxiliary_data == null) {
      const ret = await HaskellShelley.new(bodyPtr, witness_setPtr);
      return Ptr._wrap(ret, Transaction);
    }
    if(auxiliary_data != null) {
      const ret = await HaskellShelley.new_with_auxiliary_data(bodyPtr, witness_setPtr, auxiliary_dataPtr);
      return Ptr._wrap(ret, Transaction);
    }
  }

}


export class VRFVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, VRFVKey);
  }

}


export class TransactionOutputBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.with_address(this.ptr, addressPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await HaskellShelley.with_data_hash(this.ptr, data_hashPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await HaskellShelley.with_plutus_data(this.ptr, dataPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = await HaskellShelley.with_script_ref(this.ptr, script_refPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async next() {
    const ret = await HaskellShelley.next(this.ptr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

}


export class NetworkInfo extends Ptr {
  static async new(network_id, protocol_magic) {
    const ret = await HaskellShelley.new(network_id, protocol_magic);
    return Ptr._wrap(ret, NetworkInfo);
  }

  async network_id() {
    const ret = await HaskellShelley.network_id(this.ptr);
    return ret;
  }

  async protocol_magic() {
    const ret = await HaskellShelley.protocol_magic(this.ptr);
    return ret;
  }

  static async testnet() {
    const ret = await HaskellShelley.testnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async mainnet() {
    const ret = await HaskellShelley.mainnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

}


export class Ed25519KeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class BootstrapWitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async vkey() {
    const ret = await HaskellShelley.vkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.signature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async chain_code() {
    const ret = await HaskellShelley.chain_code(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async attributes() {
    const ret = await HaskellShelley.attributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(vkey, signature, chain_code, attributes) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.new(vkeyPtr, signaturePtr, b64FromUint8Array(chain_code), b64FromUint8Array(attributes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

}


export class RewardAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const ret = await HaskellShelley.new(network, paymentPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.payment_cred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await HaskellShelley.to_address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.from_address(addrPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

}


export class AuxiliaryDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.to_bech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.from_bech32(bech_str);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.from_hex(hex);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

}


export class BootstrapWitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.new();
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.len(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.get(this.ptr, index);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BootstrapWitness);
    const ret = HaskellShelley.add(this.ptr, elemPtr);
    return ret;
  }

}


export class ExUnits extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnits);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ExUnits);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ExUnits);
  }

  async mem() {
    const ret = await HaskellShelley.mem(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async steps() {
    const ret = await HaskellShelley.steps(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(mem, steps) {
    const memPtr = Ptr._assertClass(mem, BigNum);
    const stepsPtr = Ptr._assertClass(steps, BigNum);
    const ret = await HaskellShelley.new(memPtr, stepsPtr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class Relay extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relay);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, Relay);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_addr(single_host_addr) {
    const single_host_addrPtr = Ptr._assertClass(single_host_addr, SingleHostAddr);
    const ret = await HaskellShelley.new_single_host_addr(single_host_addrPtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_name(single_host_name) {
    const single_host_namePtr = Ptr._assertClass(single_host_name, SingleHostName);
    const ret = await HaskellShelley.new_single_host_name(single_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_multi_host_name(multi_host_name) {
    const multi_host_namePtr = Ptr._assertClass(multi_host_name, MultiHostName);
    const ret = await HaskellShelley.new_multi_host_name(multi_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_single_host_addr() {
    const ret = await HaskellShelley.as_single_host_addr(this.ptr);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async as_single_host_name() {
    const ret = await HaskellShelley.as_single_host_name(this.ptr);
    return Ptr._wrap(ret, SingleHostName);
  }

  async as_multi_host_name() {
    const ret = await HaskellShelley.as_multi_host_name(this.ptr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class MintsAssets extends Ptr {
}


export class ScriptAny extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptAny);
  }

  async native_scripts() {
    const ret = await HaskellShelley.native_scripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.new(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAny);
  }

}


export class ScriptPubkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_json() {
    const ret = await HaskellShelley.to_json(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.from_json(json);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async addr_keyhash() {
    const ret = await HaskellShelley.addr_keyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(addr_keyhash) {
    const addr_keyhashPtr = Ptr._assertClass(addr_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.new(addr_keyhashPtr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

}


export class PointerAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const stakePtr = Ptr._assertClass(stake, Pointer);
    const ret = await HaskellShelley.new(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, PointerAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.payment_cred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async stake_pointer() {
    const ret = await HaskellShelley.stake_pointer(this.ptr);
    return Ptr._wrap(ret, Pointer);
  }

  async to_address() {
    const ret = await HaskellShelley.to_address(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.from_address(addrPtr);
    return Ptr._wrap(ret, PointerAddress);
  }

}


export class PlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.to_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.from_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.to_hex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.from_hex(hex_str);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_constr_plutus_data(constr_plutus_data) {
    const constr_plutus_dataPtr = Ptr._assertClass(constr_plutus_data, ConstrPlutusData);
    const ret = await HaskellShelley.new_constr_plutus_data(constr_plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_empty_constr_plutus_data(alternative) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const ret = await HaskellShelley.new_empty_constr_plutus_data(alternativePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, PlutusMap);
    const ret = await HaskellShelley.new_map(mapPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, PlutusList);
    const ret = await HaskellShelley.new_list(listPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_integer(integer) {
    const integerPtr = Ptr._assertClass(integer, BigInt);
    const ret = await HaskellShelley.new_integer(integerPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.new_bytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async kind() {
    const ret = await HaskellShelley.kind(this.ptr);
    return ret;
  }

  async as_constr_plutus_data() {
    const ret = await HaskellShelley.as_constr_plutus_data(this.ptr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async as_map() {
    const ret = await HaskellShelley.as_map(this.ptr);
    return Ptr._wrap(ret, PlutusMap);
  }

  async as_list() {
    const ret = await HaskellShelley.as_list(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  async as_integer() {
    const ret = await HaskellShelley.as_integer(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async as_bytes() {
    const ret = await HaskellShelley.as_bytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_json(schema) {
    const ret = await HaskellShelley.to_json(this.ptr, schema);
    return ret;
  }

  static async from_json(json, schema) {
    const ret = await HaskellShelley.from_json(json, schema);
    return Ptr._wrap(ret, PlutusData);
  }

}


export const hash_plutus_data = async (plutus_data) => {
  const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
  const ret = await HaskellShelley.hash_plutus_data(plutus_dataPtr);
  return Ptr._wrap(ret, DataHash);
};


export const calculate_ex_units_ceil_cost = async (ex_units, ex_unit_prices) => {
  const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.calculate_ex_units_ceil_cost(ex_unitsPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const make_daedalus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, LegacyDaedalusPrivateKey);
  const ret = await HaskellShelley.make_daedalus_bootstrap_witness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const encrypt_with_password = async (password, salt, nonce, data) => {
  const ret = await HaskellShelley.encrypt_with_password(password, salt, nonce, data);
  return ret;
};


export const decode_metadatum_to_json_str = async (metadatum, schema) => {
  const metadatumPtr = Ptr._assertClass(metadatum, TransactionMetadatum);
  const ret = await HaskellShelley.decode_metadatum_to_json_str(metadatumPtr, schema);
  return ret;
};


export const hash_script_data = async (redeemers, cost_models, datums) => {
  const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
  const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
  const datumsPtr = Ptr._assertOptionalClass(datums, PlutusList);
  if(datums == null) {
    const ret = await HaskellShelley.hash_script_data(redeemersPtr, cost_modelsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
  if(datums != null) {
    const ret = await HaskellShelley.hash_script_data_with_datums(redeemersPtr, cost_modelsPtr, datumsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
};


export const decode_arbitrary_bytes_from_metadatum = async (metadata) => {
  const metadataPtr = Ptr._assertClass(metadata, TransactionMetadatum);
  const ret = await HaskellShelley.decode_arbitrary_bytes_from_metadatum(metadataPtr);
  return uint8ArrayFromB64(ret);
};


export const get_implicit_input = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.get_implicit_input(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, Value);
};


export const min_fee = async (tx, linear_fee) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const linear_feePtr = Ptr._assertClass(linear_fee, LinearFee);
  const ret = await HaskellShelley.min_fee(txPtr, linear_feePtr);
  return Ptr._wrap(ret, BigNum);
};


export const get_deposit = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.get_deposit(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, BigNum);
};


export const encode_json_str_to_native_script = async (json, self_xpub, schema) => {
  const ret = await HaskellShelley.encode_json_str_to_native_script(json, self_xpub, schema);
  return Ptr._wrap(ret, NativeScript);
};


export const make_vkey_witness = async (tx_body_hash, sk) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await HaskellShelley.make_vkey_witness(tx_body_hashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
};


export const encode_json_str_to_plutus_datum = async (json, schema) => {
  const ret = await HaskellShelley.encode_json_str_to_plutus_datum(json, schema);
  return Ptr._wrap(ret, PlutusData);
};


export const decode_plutus_datum_to_json_str = async (datum, schema) => {
  const datumPtr = Ptr._assertClass(datum, PlutusData);
  const ret = await HaskellShelley.decode_plutus_datum_to_json_str(datumPtr, schema);
  return ret;
};


export const make_icarus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await HaskellShelley.make_icarus_bootstrap_witness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const decrypt_with_password = async (password, data) => {
  const ret = await HaskellShelley.decrypt_with_password(password, data);
  return ret;
};


export const hash_auxiliary_data = async (auxiliary_data) => {
  const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
  const ret = await HaskellShelley.hash_auxiliary_data(auxiliary_dataPtr);
  return Ptr._wrap(ret, AuxiliaryDataHash);
};


export const min_script_fee = async (tx, ex_unit_prices) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.min_script_fee(txPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_ada_required = async (assets, has_data_hash, coins_per_utxo_word) => {
  const assetsPtr = Ptr._assertClass(assets, Value);
  const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
  const ret = await HaskellShelley.min_ada_required(assetsPtr, has_data_hash, coins_per_utxo_wordPtr);
  return Ptr._wrap(ret, BigNum);
};


export const hash_transaction = async (tx_body) => {
  const tx_bodyPtr = Ptr._assertClass(tx_body, TransactionBody);
  const ret = await HaskellShelley.hash_transaction(tx_bodyPtr);
  return Ptr._wrap(ret, TransactionHash);
};


export const min_ada_for_output = async (output, data_cost) => {
  const outputPtr = Ptr._assertClass(output, TransactionOutput);
  const data_costPtr = Ptr._assertClass(data_cost, DataCost);
  const ret = await HaskellShelley.min_ada_for_output(outputPtr, data_costPtr);
  return Ptr._wrap(ret, BigNum);
};


export const encode_arbitrary_bytes_as_metadatum = async (bytes) => {
  const ret = await HaskellShelley.encode_arbitrary_bytes_as_metadatum(b64FromUint8Array(bytes));
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_metadatum = async (json, schema) => {
  const ret = await HaskellShelley.encode_json_str_to_metadatum(json, schema);
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const NetworkIdKind = Object.freeze({
  Testnet: 0,
  Mainnet: 1,
});


export const ScriptHashNamespace = Object.freeze({
  NativeScript: 0,
  PlutusScript: 1,
  PlutusScriptV2: 2,
});


export const PlutusDataKind = Object.freeze({
  ConstrPlutusData: 0,
  Map: 1,
  List: 2,
  Integer: 3,
  Bytes: 4,
});


export const PlutusDatumSchema = Object.freeze({
  BasicConversions: 0,
  DetailedSchema: 1,
});


export const NativeScriptKind = Object.freeze({
  ScriptPubkey: 0,
  ScriptAll: 1,
  ScriptAny: 2,
  ScriptNOfK: 3,
  TimelockStart: 4,
  TimelockExpiry: 5,
});


export const MetadataJsonSchema = Object.freeze({
  NoConversions: 0,
  BasicConversions: 1,
  DetailedSchema: 2,
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


export const RelayKind = Object.freeze({
  SingleHostAddr: 0,
  SingleHostName: 1,
  MultiHostName: 2,
});


export const ScriptSchema = Object.freeze({
  Wallet: 0,
  Node: 1,
});


export const StakeCredKind = Object.freeze({
  Key: 0,
  Script: 1,
});


export const TransactionMetadatumKind = Object.freeze({
  MetadataMap: 0,
  MetadataList: 1,
  Int: 2,
  Bytes: 3,
  Text: 4,
});


export const LanguageKind = Object.freeze({
  PlutusV1: 0,
  PlutusV2: 1,
});


export const MIRPot = Object.freeze({
  Reserves: 0,
  Treasury: 1,
});


export const MIRKind = Object.freeze({
  ToOtherPot: 0,
  ToStakeCredentials: 1,
});


export const CoinSelectionStrategyCIP2 = Object.freeze({
  LargestFirst: 0,
  RandomImprove: 1,
  LargestFirstMultiAsset: 2,
  RandomImproveMultiAsset: 3,
});


export const RedeemerTagKind = Object.freeze({
  Spend: 0,
  Mint: 1,
  Cert: 2,
  Reward: 3,
});


