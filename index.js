/* eslint-disable max-len */
import { NativeModules } from 'react-native';
import { decode as base64_decode, encode as base64_encode } from 'base-64';

const { CslMobileBridge } = NativeModules;

// export default CslMobileBridge;

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
    await CslMobileBridge.ptrFree(ptr);
  }
}

export class Address extends Ptr {
  static async from_bytes(data) {
    const ret = await CslMobileBridge.addressFromBytes(b64FromUint8Array(data));
    return Ptr._wrap(ret, Address);
  }

  async to_json() {
    const ret = await CslMobileBridge.addressToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.addressFromJson(json);
    return Ptr._wrap(ret, Address);
  }

  async to_hex() {
    const ret = await CslMobileBridge.addressToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.addressFromHex(hex_str);
    return Ptr._wrap(ret, Address);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.addressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    if(prefix == null) {
      const ret = await CslMobileBridge.addressToBech32(this.ptr);
      return ret;
    }
    if(prefix != null) {
      const ret = await CslMobileBridge.addressToBech32WithPrefix(this.ptr, prefix);
      return ret;
    }
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.addressFromBech32(bech_str);
    return Ptr._wrap(ret, Address);
  }

  async network_id() {
    const ret = await CslMobileBridge.addressNetworkId(this.ptr);
    return ret;
  }

}


export class AssetName extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.assetNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.assetNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetName);
  }

  async to_hex() {
    const ret = await CslMobileBridge.assetNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.assetNameFromHex(hex_str);
    return Ptr._wrap(ret, AssetName);
  }

  async to_json() {
    const ret = await CslMobileBridge.assetNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.assetNameFromJson(json);
    return Ptr._wrap(ret, AssetName);
  }

  static async new(name) {
    const ret = await CslMobileBridge.assetNameNew(b64FromUint8Array(name));
    return Ptr._wrap(ret, AssetName);
  }

  async name() {
    const ret = await CslMobileBridge.assetNameName(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class AssetNames extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.assetNamesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.assetNamesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetNames);
  }

  async to_hex() {
    const ret = await CslMobileBridge.assetNamesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.assetNamesFromHex(hex_str);
    return Ptr._wrap(ret, AssetNames);
  }

  async to_json() {
    const ret = await CslMobileBridge.assetNamesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.assetNamesFromJson(json);
    return Ptr._wrap(ret, AssetNames);
  }

  static async new() {
    const ret = await CslMobileBridge.assetNamesNew();
    return Ptr._wrap(ret, AssetNames);
  }

  async len() {
    const ret = await CslMobileBridge.assetNamesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.assetNamesGet(this.ptr, index);
    return Ptr._wrap(ret, AssetName);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, AssetName);
    const ret = CslMobileBridge.assetNamesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Assets extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.assetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.assetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Assets);
  }

  async to_hex() {
    const ret = await CslMobileBridge.assetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.assetsFromHex(hex_str);
    return Ptr._wrap(ret, Assets);
  }

  async to_json() {
    const ret = await CslMobileBridge.assetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.assetsFromJson(json);
    return Ptr._wrap(ret, Assets);
  }

  static async new() {
    const ret = await CslMobileBridge.assetsNew();
    return Ptr._wrap(ret, Assets);
  }

  async len() {
    const ret = await CslMobileBridge.assetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await CslMobileBridge.assetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await CslMobileBridge.assetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await CslMobileBridge.assetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class AuxiliaryData extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.auxiliaryDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.auxiliaryDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_hex() {
    const ret = await CslMobileBridge.auxiliaryDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.auxiliaryDataFromHex(hex_str);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_json() {
    const ret = await CslMobileBridge.auxiliaryDataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.auxiliaryDataFromJson(json);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  static async new() {
    const ret = await CslMobileBridge.auxiliaryDataNew();
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async metadata() {
    const ret = await CslMobileBridge.auxiliaryDataMetadata(this.ptr);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = CslMobileBridge.auxiliaryDataSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await CslMobileBridge.auxiliaryDataNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = CslMobileBridge.auxiliaryDataSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await CslMobileBridge.auxiliaryDataPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = CslMobileBridge.auxiliaryDataSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async prefer_alonzo_format() {
    const ret = await CslMobileBridge.auxiliaryDataPreferAlonzoFormat(this.ptr);
    return ret;
  }

  set_prefer_alonzo_format(prefer) {
    const ret = CslMobileBridge.auxiliaryDataSetPreferAlonzoFormat(this.ptr, prefer);
    return ret;
  }

}


export class AuxiliaryDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.auxiliaryDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.auxiliaryDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.auxiliaryDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.auxiliaryDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.auxiliaryDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.auxiliaryDataHashFromHex(hex);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

}


export class AuxiliaryDataSet extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.auxiliaryDataSetNew();
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async len() {
    const ret = await CslMobileBridge.auxiliaryDataSetLen(this.ptr);
    return ret;
  }

  async insert(tx_index, data) {
    const dataPtr = Ptr._assertClass(data, AuxiliaryData);
    const ret = await CslMobileBridge.auxiliaryDataSetInsert(this.ptr, tx_index, dataPtr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async get(tx_index) {
    const ret = await CslMobileBridge.auxiliaryDataSetGet(this.ptr, tx_index);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async indices() {
    const ret = await CslMobileBridge.auxiliaryDataSetIndices(this.ptr);
    return base64ToUint32Array(ret);
  }

}


export class BaseAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const stakePtr = Ptr._assertClass(stake, StakeCredential);
    const ret = await CslMobileBridge.baseAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  async payment_cred() {
    const ret = await CslMobileBridge.baseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async stake_cred() {
    const ret = await CslMobileBridge.baseAddressStakeCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await CslMobileBridge.baseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await CslMobileBridge.baseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, BaseAddress);
  }

}


export class BigInt extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.bigIntToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.bigIntFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigInt);
  }

  async to_hex() {
    const ret = await CslMobileBridge.bigIntToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.bigIntFromHex(hex_str);
    return Ptr._wrap(ret, BigInt);
  }

  async to_json() {
    const ret = await CslMobileBridge.bigIntToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.bigIntFromJson(json);
    return Ptr._wrap(ret, BigInt);
  }

  async is_zero() {
    const ret = await CslMobileBridge.bigIntIsZero(this.ptr);
    return ret;
  }

  async as_u64() {
    const ret = await CslMobileBridge.bigIntAsU64(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_int() {
    const ret = await CslMobileBridge.bigIntAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  static async from_str(text) {
    const ret = await CslMobileBridge.bigIntFromStr(text);
    return Ptr._wrap(ret, BigInt);
  }

  async to_str() {
    const ret = await CslMobileBridge.bigIntToStr(this.ptr);
    return ret;
  }

  async add(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await CslMobileBridge.bigIntAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async mul(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await CslMobileBridge.bigIntMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  static async one() {
    const ret = await CslMobileBridge.bigIntOne();
    return Ptr._wrap(ret, BigInt);
  }

  async increment() {
    const ret = await CslMobileBridge.bigIntIncrement(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async div_ceil(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await CslMobileBridge.bigIntDivCeil(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

}


export class BigNum extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.bigNumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.bigNumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigNum);
  }

  async to_hex() {
    const ret = await CslMobileBridge.bigNumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.bigNumFromHex(hex_str);
    return Ptr._wrap(ret, BigNum);
  }

  async to_json() {
    const ret = await CslMobileBridge.bigNumToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.bigNumFromJson(json);
    return Ptr._wrap(ret, BigNum);
  }

  static async from_str(string) {
    const ret = await CslMobileBridge.bigNumFromStr(string);
    return Ptr._wrap(ret, BigNum);
  }

  async to_str() {
    const ret = await CslMobileBridge.bigNumToStr(this.ptr);
    return ret;
  }

  static async zero() {
    const ret = await CslMobileBridge.bigNumZero();
    return Ptr._wrap(ret, BigNum);
  }

  static async one() {
    const ret = await CslMobileBridge.bigNumOne();
    return Ptr._wrap(ret, BigNum);
  }

  async is_zero() {
    const ret = await CslMobileBridge.bigNumIsZero(this.ptr);
    return ret;
  }

  async div_floor(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await CslMobileBridge.bigNumDivFloor(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_mul(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await CslMobileBridge.bigNumCheckedMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_add(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await CslMobileBridge.bigNumCheckedAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await CslMobileBridge.bigNumCheckedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async clamped_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await CslMobileBridge.bigNumClampedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await CslMobileBridge.bigNumCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

  async less_than(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await CslMobileBridge.bigNumLessThan(this.ptr, rhs_valuePtr);
    return ret;
  }

  static async max_value() {
    const ret = await CslMobileBridge.bigNumMaxValue();
    return Ptr._wrap(ret, BigNum);
  }

  static async max(a, b) {
    const aPtr = Ptr._assertClass(a, BigNum);
    const bPtr = Ptr._assertClass(b, BigNum);
    const ret = await CslMobileBridge.bigNumMax(aPtr, bPtr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class Bip32PrivateKey extends Ptr {
  async derive(index) {
    const ret = await CslMobileBridge.bip32PrivateKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  static async from_128_xprv(bytes) {
    const ret = await CslMobileBridge.bip32PrivateKeyFrom_128Xprv(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_128_xprv() {
    const ret = await CslMobileBridge.bip32PrivateKeyTo_128Xprv(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async generate_ed25519_bip32() {
    const ret = await CslMobileBridge.bip32PrivateKeyGenerateEd25519Bip32();
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_raw_key() {
    const ret = await CslMobileBridge.bip32PrivateKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_public() {
    const ret = await CslMobileBridge.bip32PrivateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.bip32PrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async as_bytes() {
    const ret = await CslMobileBridge.bip32PrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await CslMobileBridge.bip32PrivateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_bech32() {
    const ret = await CslMobileBridge.bip32PrivateKeyToBech32(this.ptr);
    return ret;
  }

  static async from_bip39_entropy(entropy, password) {
    const ret = await CslMobileBridge.bip32PrivateKeyFromBip39Entropy(b64FromUint8Array(entropy), b64FromUint8Array(password));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async chaincode() {
    const ret = await CslMobileBridge.bip32PrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await CslMobileBridge.bip32PrivateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.bip32PrivateKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

}


export class Bip32PublicKey extends Ptr {
  async derive(index) {
    const ret = await CslMobileBridge.bip32PublicKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_raw_key() {
    const ret = await CslMobileBridge.bip32PublicKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.bip32PublicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async as_bytes() {
    const ret = await CslMobileBridge.bip32PublicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await CslMobileBridge.bip32PublicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_bech32() {
    const ret = await CslMobileBridge.bip32PublicKeyToBech32(this.ptr);
    return ret;
  }

  async chaincode() {
    const ret = await CslMobileBridge.bip32PublicKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await CslMobileBridge.bip32PublicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.bip32PublicKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

}


export class Block extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.blockToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.blockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Block);
  }

  async to_hex() {
    const ret = await CslMobileBridge.blockToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.blockFromHex(hex_str);
    return Ptr._wrap(ret, Block);
  }

  async to_json() {
    const ret = await CslMobileBridge.blockToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.blockFromJson(json);
    return Ptr._wrap(ret, Block);
  }

  async header() {
    const ret = await CslMobileBridge.blockHeader(this.ptr);
    return Ptr._wrap(ret, Header);
  }

  async transaction_bodies() {
    const ret = await CslMobileBridge.blockTransactionBodies(this.ptr);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async transaction_witness_sets() {
    const ret = await CslMobileBridge.blockTransactionWitnessSets(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async auxiliary_data_set() {
    const ret = await CslMobileBridge.blockAuxiliaryDataSet(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async invalid_transactions() {
    const ret = await CslMobileBridge.blockInvalidTransactions(this.ptr);
    return base64ToUint32Array(ret);
  }

  static async new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions) {
    const headerPtr = Ptr._assertClass(header, Header);
    const transaction_bodiesPtr = Ptr._assertClass(transaction_bodies, TransactionBodies);
    const transaction_witness_setsPtr = Ptr._assertClass(transaction_witness_sets, TransactionWitnessSets);
    const auxiliary_data_setPtr = Ptr._assertClass(auxiliary_data_set, AuxiliaryDataSet);
    const ret = await CslMobileBridge.blockNew(headerPtr, transaction_bodiesPtr, transaction_witness_setsPtr, auxiliary_data_setPtr, uint32ArrayToBase64(invalid_transactions));
    return Ptr._wrap(ret, Block);
  }

}


export class BlockHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.blockHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BlockHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.blockHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.blockHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.blockHashFromBech32(bech_str);
    return Ptr._wrap(ret, BlockHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.blockHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.blockHashFromHex(hex);
    return Ptr._wrap(ret, BlockHash);
  }

}


export class BootstrapWitness extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.bootstrapWitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.bootstrapWitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_hex() {
    const ret = await CslMobileBridge.bootstrapWitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.bootstrapWitnessFromHex(hex_str);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_json() {
    const ret = await CslMobileBridge.bootstrapWitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.bootstrapWitnessFromJson(json);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async vkey() {
    const ret = await CslMobileBridge.bootstrapWitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await CslMobileBridge.bootstrapWitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async chain_code() {
    const ret = await CslMobileBridge.bootstrapWitnessChainCode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async attributes() {
    const ret = await CslMobileBridge.bootstrapWitnessAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(vkey, signature, chain_code, attributes) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await CslMobileBridge.bootstrapWitnessNew(vkeyPtr, signaturePtr, b64FromUint8Array(chain_code), b64FromUint8Array(attributes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

}


export class BootstrapWitnesses extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.bootstrapWitnessesNew();
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async len() {
    const ret = await CslMobileBridge.bootstrapWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.bootstrapWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BootstrapWitness);
    const ret = CslMobileBridge.bootstrapWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ByronAddress extends Ptr {
  async to_base58() {
    const ret = await CslMobileBridge.byronAddressToBase58(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await CslMobileBridge.byronAddressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.byronAddressFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ByronAddress);
  }

  async byron_protocol_magic() {
    const ret = await CslMobileBridge.byronAddressByronProtocolMagic(this.ptr);
    return ret;
  }

  async attributes() {
    const ret = await CslMobileBridge.byronAddressAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async network_id() {
    const ret = await CslMobileBridge.byronAddressNetworkId(this.ptr);
    return ret;
  }

  static async from_base58(s) {
    const ret = await CslMobileBridge.byronAddressFromBase58(s);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async icarus_from_key(key, protocol_magic) {
    const keyPtr = Ptr._assertClass(key, Bip32PublicKey);
    const ret = await CslMobileBridge.byronAddressIcarusFromKey(keyPtr, protocol_magic);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async is_valid(s) {
    const ret = await CslMobileBridge.byronAddressIsValid(s);
    return ret;
  }

  async to_address() {
    const ret = await CslMobileBridge.byronAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await CslMobileBridge.byronAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, ByronAddress);
  }

}


export class Certificate extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.certificateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.certificateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificate);
  }

  async to_hex() {
    const ret = await CslMobileBridge.certificateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.certificateFromHex(hex_str);
    return Ptr._wrap(ret, Certificate);
  }

  async to_json() {
    const ret = await CslMobileBridge.certificateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.certificateFromJson(json);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration(stake_registration) {
    const stake_registrationPtr = Ptr._assertClass(stake_registration, StakeRegistration);
    const ret = await CslMobileBridge.certificateNewStakeRegistration(stake_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_deregistration(stake_deregistration) {
    const stake_deregistrationPtr = Ptr._assertClass(stake_deregistration, StakeDeregistration);
    const ret = await CslMobileBridge.certificateNewStakeDeregistration(stake_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_delegation(stake_delegation) {
    const stake_delegationPtr = Ptr._assertClass(stake_delegation, StakeDelegation);
    const ret = await CslMobileBridge.certificateNewStakeDelegation(stake_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_registration(pool_registration) {
    const pool_registrationPtr = Ptr._assertClass(pool_registration, PoolRegistration);
    const ret = await CslMobileBridge.certificateNewPoolRegistration(pool_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_retirement(pool_retirement) {
    const pool_retirementPtr = Ptr._assertClass(pool_retirement, PoolRetirement);
    const ret = await CslMobileBridge.certificateNewPoolRetirement(pool_retirementPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_genesis_key_delegation(genesis_key_delegation) {
    const genesis_key_delegationPtr = Ptr._assertClass(genesis_key_delegation, GenesisKeyDelegation);
    const ret = await CslMobileBridge.certificateNewGenesisKeyDelegation(genesis_key_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert) {
    const move_instantaneous_rewards_certPtr = Ptr._assertClass(move_instantaneous_rewards_cert, MoveInstantaneousRewardsCert);
    const ret = await CslMobileBridge.certificateNewMoveInstantaneousRewardsCert(move_instantaneous_rewards_certPtr);
    return Ptr._wrap(ret, Certificate);
  }

  async kind() {
    const ret = await CslMobileBridge.certificateKind(this.ptr);
    return ret;
  }

  async as_stake_registration() {
    const ret = await CslMobileBridge.certificateAsStakeRegistration(this.ptr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async as_stake_deregistration() {
    const ret = await CslMobileBridge.certificateAsStakeDeregistration(this.ptr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async as_stake_delegation() {
    const ret = await CslMobileBridge.certificateAsStakeDelegation(this.ptr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async as_pool_registration() {
    const ret = await CslMobileBridge.certificateAsPoolRegistration(this.ptr);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async as_pool_retirement() {
    const ret = await CslMobileBridge.certificateAsPoolRetirement(this.ptr);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async as_genesis_key_delegation() {
    const ret = await CslMobileBridge.certificateAsGenesisKeyDelegation(this.ptr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async as_move_instantaneous_rewards_cert() {
    const ret = await CslMobileBridge.certificateAsMoveInstantaneousRewardsCert(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class Certificates extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.certificatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.certificatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificates);
  }

  async to_hex() {
    const ret = await CslMobileBridge.certificatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.certificatesFromHex(hex_str);
    return Ptr._wrap(ret, Certificates);
  }

  async to_json() {
    const ret = await CslMobileBridge.certificatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.certificatesFromJson(json);
    return Ptr._wrap(ret, Certificates);
  }

  static async new() {
    const ret = await CslMobileBridge.certificatesNew();
    return Ptr._wrap(ret, Certificates);
  }

  async len() {
    const ret = await CslMobileBridge.certificatesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.certificatesGet(this.ptr, index);
    return Ptr._wrap(ret, Certificate);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Certificate);
    const ret = CslMobileBridge.certificatesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ConstrPlutusData extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.constrPlutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.constrPlutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async to_hex() {
    const ret = await CslMobileBridge.constrPlutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.constrPlutusDataFromHex(hex_str);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async alternative() {
    const ret = await CslMobileBridge.constrPlutusDataAlternative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await CslMobileBridge.constrPlutusDataData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new(alternative, data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusList);
    const ret = await CslMobileBridge.constrPlutusDataNew(alternativePtr, dataPtr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

}


export class CostModel extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.costModelToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.costModelFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CostModel);
  }

  async to_hex() {
    const ret = await CslMobileBridge.costModelToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.costModelFromHex(hex_str);
    return Ptr._wrap(ret, CostModel);
  }

  async to_json() {
    const ret = await CslMobileBridge.costModelToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.costModelFromJson(json);
    return Ptr._wrap(ret, CostModel);
  }

  static async new() {
    const ret = await CslMobileBridge.costModelNew();
    return Ptr._wrap(ret, CostModel);
  }

  async set(operation, cost) {
    const costPtr = Ptr._assertClass(cost, Int);
    const ret = await CslMobileBridge.costModelSet(this.ptr, operation, costPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(operation) {
    const ret = await CslMobileBridge.costModelGet(this.ptr, operation);
    return Ptr._wrap(ret, Int);
  }

  async len() {
    const ret = await CslMobileBridge.costModelLen(this.ptr);
    return ret;
  }

}


export class Costmdls extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.costmdlsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.costmdlsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Costmdls);
  }

  async to_hex() {
    const ret = await CslMobileBridge.costmdlsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.costmdlsFromHex(hex_str);
    return Ptr._wrap(ret, Costmdls);
  }

  async to_json() {
    const ret = await CslMobileBridge.costmdlsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.costmdlsFromJson(json);
    return Ptr._wrap(ret, Costmdls);
  }

  static async new() {
    const ret = await CslMobileBridge.costmdlsNew();
    return Ptr._wrap(ret, Costmdls);
  }

  async len() {
    const ret = await CslMobileBridge.costmdlsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, Language);
    const valuePtr = Ptr._assertClass(value, CostModel);
    const ret = await CslMobileBridge.costmdlsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, CostModel);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, Language);
    const ret = await CslMobileBridge.costmdlsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, CostModel);
  }

  async keys() {
    const ret = await CslMobileBridge.costmdlsKeys(this.ptr);
    return Ptr._wrap(ret, Languages);
  }

  async retain_language_versions(languages) {
    const languagesPtr = Ptr._assertClass(languages, Languages);
    const ret = await CslMobileBridge.costmdlsRetainLanguageVersions(this.ptr, languagesPtr);
    return Ptr._wrap(ret, Costmdls);
  }

}


export class DNSRecordAorAAAA extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.dNSRecordAorAAAAToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.dNSRecordAorAAAAFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_hex() {
    const ret = await CslMobileBridge.dNSRecordAorAAAAToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.dNSRecordAorAAAAFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_json() {
    const ret = await CslMobileBridge.dNSRecordAorAAAAToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.dNSRecordAorAAAAFromJson(json);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(dns_name) {
    const ret = await CslMobileBridge.dNSRecordAorAAAANew(dns_name);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async record() {
    const ret = await CslMobileBridge.dNSRecordAorAAAARecord(this.ptr);
    return ret;
  }

}


export class DNSRecordSRV extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.dNSRecordSRVToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.dNSRecordSRVFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_hex() {
    const ret = await CslMobileBridge.dNSRecordSRVToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.dNSRecordSRVFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_json() {
    const ret = await CslMobileBridge.dNSRecordSRVToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.dNSRecordSRVFromJson(json);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const ret = await CslMobileBridge.dNSRecordSRVNew(dns_name);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async record() {
    const ret = await CslMobileBridge.dNSRecordSRVRecord(this.ptr);
    return ret;
  }

}


export class DataCost extends Ptr {
  static async new_coins_per_word(coins_per_word) {
    const coins_per_wordPtr = Ptr._assertClass(coins_per_word, BigNum);
    const ret = await CslMobileBridge.dataCostNewCoinsPerWord(coins_per_wordPtr);
    return Ptr._wrap(ret, DataCost);
  }

  static async new_coins_per_byte(coins_per_byte) {
    const coins_per_bytePtr = Ptr._assertClass(coins_per_byte, BigNum);
    const ret = await CslMobileBridge.dataCostNewCoinsPerByte(coins_per_bytePtr);
    return Ptr._wrap(ret, DataCost);
  }

  async coins_per_byte() {
    const ret = await CslMobileBridge.dataCostCoinsPerByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class DataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.dataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DataHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.dataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.dataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.dataHashFromBech32(bech_str);
    return Ptr._wrap(ret, DataHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.dataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.dataHashFromHex(hex);
    return Ptr._wrap(ret, DataHash);
  }

}


export class DatumSource extends Ptr {
  static async new(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = await CslMobileBridge.datumSourceNew(datumPtr);
    return Ptr._wrap(ret, DatumSource);
  }

  static async new_ref_input(input) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await CslMobileBridge.datumSourceNewRefInput(inputPtr);
    return Ptr._wrap(ret, DatumSource);
  }

}


export class Ed25519KeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.ed25519KeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.ed25519KeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.ed25519KeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.ed25519KeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.ed25519KeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.ed25519KeyHashFromHex(hex);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class Ed25519KeyHashes extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.ed25519KeyHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.ed25519KeyHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_hex() {
    const ret = await CslMobileBridge.ed25519KeyHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.ed25519KeyHashesFromHex(hex_str);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_json() {
    const ret = await CslMobileBridge.ed25519KeyHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.ed25519KeyHashesFromJson(json);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  static async new() {
    const ret = await CslMobileBridge.ed25519KeyHashesNew();
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async len() {
    const ret = await CslMobileBridge.ed25519KeyHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.ed25519KeyHashesGet(this.ptr, index);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = CslMobileBridge.ed25519KeyHashesAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await CslMobileBridge.ed25519KeyHashesToOption(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class Ed25519Signature extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.ed25519SignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32() {
    const ret = await CslMobileBridge.ed25519SignatureToBech32(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await CslMobileBridge.ed25519SignatureToHex(this.ptr);
    return ret;
  }

  static async from_bech32(bech32_str) {
    const ret = await CslMobileBridge.ed25519SignatureFromBech32(bech32_str);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_hex(input) {
    const ret = await CslMobileBridge.ed25519SignatureFromHex(input);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.ed25519SignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class EnterpriseAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const ret = await CslMobileBridge.enterpriseAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

  async payment_cred() {
    const ret = await CslMobileBridge.enterpriseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await CslMobileBridge.enterpriseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await CslMobileBridge.enterpriseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

}


export class ExUnitPrices extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.exUnitPricesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.exUnitPricesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_hex() {
    const ret = await CslMobileBridge.exUnitPricesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.exUnitPricesFromHex(hex_str);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_json() {
    const ret = await CslMobileBridge.exUnitPricesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.exUnitPricesFromJson(json);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async mem_price() {
    const ret = await CslMobileBridge.exUnitPricesMemPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async step_price() {
    const ret = await CslMobileBridge.exUnitPricesStepPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  static async new(mem_price, step_price) {
    const mem_pricePtr = Ptr._assertClass(mem_price, UnitInterval);
    const step_pricePtr = Ptr._assertClass(step_price, UnitInterval);
    const ret = await CslMobileBridge.exUnitPricesNew(mem_pricePtr, step_pricePtr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

}


export class ExUnits extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.exUnitsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.exUnitsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnits);
  }

  async to_hex() {
    const ret = await CslMobileBridge.exUnitsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.exUnitsFromHex(hex_str);
    return Ptr._wrap(ret, ExUnits);
  }

  async to_json() {
    const ret = await CslMobileBridge.exUnitsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.exUnitsFromJson(json);
    return Ptr._wrap(ret, ExUnits);
  }

  async mem() {
    const ret = await CslMobileBridge.exUnitsMem(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async steps() {
    const ret = await CslMobileBridge.exUnitsSteps(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(mem, steps) {
    const memPtr = Ptr._assertClass(mem, BigNum);
    const stepsPtr = Ptr._assertClass(steps, BigNum);
    const ret = await CslMobileBridge.exUnitsNew(memPtr, stepsPtr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class FixedTransaction extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.fixedTransactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.fixedTransactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedTransaction);
  }

  async to_hex() {
    const ret = await CslMobileBridge.fixedTransactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.fixedTransactionFromHex(hex_str);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new(raw_body, raw_witness_set, is_valid) {
    const ret = await CslMobileBridge.fixedTransactionNew(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new_with_auxiliary(raw_body, raw_witness_set, raw_auxiliary_data, is_valid) {
    const ret = await CslMobileBridge.fixedTransactionNewWithAuxiliary(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), b64FromUint8Array(raw_auxiliary_data), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  async body() {
    const ret = await CslMobileBridge.fixedTransactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async raw_body() {
    const ret = await CslMobileBridge.fixedTransactionRawBody(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_body(raw_body) {
    const ret = CslMobileBridge.fixedTransactionSetBody(this.ptr, b64FromUint8Array(raw_body));
    return ret;
  }

  set_witness_set(raw_witness_set) {
    const ret = CslMobileBridge.fixedTransactionSetWitnessSet(this.ptr, b64FromUint8Array(raw_witness_set));
    return ret;
  }

  async witness_set() {
    const ret = await CslMobileBridge.fixedTransactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async raw_witness_set() {
    const ret = await CslMobileBridge.fixedTransactionRawWitnessSet(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_is_valid(valid) {
    const ret = CslMobileBridge.fixedTransactionSetIsValid(this.ptr, valid);
    return ret;
  }

  async is_valid() {
    const ret = await CslMobileBridge.fixedTransactionIsValid(this.ptr);
    return ret;
  }

  set_auxiliary_data(raw_auxiliary_data) {
    const ret = CslMobileBridge.fixedTransactionSetAuxiliaryData(this.ptr, b64FromUint8Array(raw_auxiliary_data));
    return ret;
  }

  async auxiliary_data() {
    const ret = await CslMobileBridge.fixedTransactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async raw_auxiliary_data() {
    const ret = await CslMobileBridge.fixedTransactionRawAuxiliaryData(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class GeneralTransactionMetadata extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.generalTransactionMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.generalTransactionMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_hex() {
    const ret = await CslMobileBridge.generalTransactionMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.generalTransactionMetadataFromHex(hex_str);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_json() {
    const ret = await CslMobileBridge.generalTransactionMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.generalTransactionMetadataFromJson(json);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  static async new() {
    const ret = await CslMobileBridge.generalTransactionMetadataNew();
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async len() {
    const ret = await CslMobileBridge.generalTransactionMetadataLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await CslMobileBridge.generalTransactionMetadataInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = await CslMobileBridge.generalTransactionMetadataGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async keys() {
    const ret = await CslMobileBridge.generalTransactionMetadataKeys(this.ptr);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

}


export class GenesisDelegateHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.genesisDelegateHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.genesisDelegateHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.genesisDelegateHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.genesisDelegateHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.genesisDelegateHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.genesisDelegateHashFromHex(hex);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

}


export class GenesisHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.genesisHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.genesisHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.genesisHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.genesisHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.genesisHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.genesisHashFromHex(hex);
    return Ptr._wrap(ret, GenesisHash);
  }

}


export class GenesisHashes extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.genesisHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.genesisHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_hex() {
    const ret = await CslMobileBridge.genesisHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.genesisHashesFromHex(hex_str);
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_json() {
    const ret = await CslMobileBridge.genesisHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.genesisHashesFromJson(json);
    return Ptr._wrap(ret, GenesisHashes);
  }

  static async new() {
    const ret = await CslMobileBridge.genesisHashesNew();
    return Ptr._wrap(ret, GenesisHashes);
  }

  async len() {
    const ret = await CslMobileBridge.genesisHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.genesisHashesGet(this.ptr, index);
    return Ptr._wrap(ret, GenesisHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, GenesisHash);
    const ret = CslMobileBridge.genesisHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class GenesisKeyDelegation extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.genesisKeyDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.genesisKeyDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_hex() {
    const ret = await CslMobileBridge.genesisKeyDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.genesisKeyDelegationFromHex(hex_str);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_json() {
    const ret = await CslMobileBridge.genesisKeyDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.genesisKeyDelegationFromJson(json);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async genesishash() {
    const ret = await CslMobileBridge.genesisKeyDelegationGenesishash(this.ptr);
    return Ptr._wrap(ret, GenesisHash);
  }

  async genesis_delegate_hash() {
    const ret = await CslMobileBridge.genesisKeyDelegationGenesisDelegateHash(this.ptr);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async vrf_keyhash() {
    const ret = await CslMobileBridge.genesisKeyDelegationVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  static async new(genesishash, genesis_delegate_hash, vrf_keyhash) {
    const genesishashPtr = Ptr._assertClass(genesishash, GenesisHash);
    const genesis_delegate_hashPtr = Ptr._assertClass(genesis_delegate_hash, GenesisDelegateHash);
    const vrf_keyhashPtr = Ptr._assertClass(vrf_keyhash, VRFKeyHash);
    const ret = await CslMobileBridge.genesisKeyDelegationNew(genesishashPtr, genesis_delegate_hashPtr, vrf_keyhashPtr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

}


export class Header extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.headerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.headerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Header);
  }

  async to_hex() {
    const ret = await CslMobileBridge.headerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.headerFromHex(hex_str);
    return Ptr._wrap(ret, Header);
  }

  async to_json() {
    const ret = await CslMobileBridge.headerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.headerFromJson(json);
    return Ptr._wrap(ret, Header);
  }

  async header_body() {
    const ret = await CslMobileBridge.headerHeaderBody(this.ptr);
    return Ptr._wrap(ret, HeaderBody);
  }

  async body_signature() {
    const ret = await CslMobileBridge.headerBodySignature(this.ptr);
    return Ptr._wrap(ret, KESSignature);
  }

  static async new(header_body, body_signature) {
    const header_bodyPtr = Ptr._assertClass(header_body, HeaderBody);
    const body_signaturePtr = Ptr._assertClass(body_signature, KESSignature);
    const ret = await CslMobileBridge.headerNew(header_bodyPtr, body_signaturePtr);
    return Ptr._wrap(ret, Header);
  }

}


export class HeaderBody extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.headerBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.headerBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_hex() {
    const ret = await CslMobileBridge.headerBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.headerBodyFromHex(hex_str);
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_json() {
    const ret = await CslMobileBridge.headerBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.headerBodyFromJson(json);
    return Ptr._wrap(ret, HeaderBody);
  }

  async block_number() {
    const ret = await CslMobileBridge.headerBodyBlockNumber(this.ptr);
    return ret;
  }

  async slot() {
    const ret = await CslMobileBridge.headerBodySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await CslMobileBridge.headerBodySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async prev_hash() {
    const ret = await CslMobileBridge.headerBodyPrevHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async issuer_vkey() {
    const ret = await CslMobileBridge.headerBodyIssuerVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async vrf_vkey() {
    const ret = await CslMobileBridge.headerBodyVrfVkey(this.ptr);
    return Ptr._wrap(ret, VRFVKey);
  }

  async has_nonce_and_leader_vrf() {
    const ret = await CslMobileBridge.headerBodyHasNonceAndLeaderVrf(this.ptr);
    return ret;
  }

  async nonce_vrf_or_nothing() {
    const ret = await CslMobileBridge.headerBodyNonceVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async leader_vrf_or_nothing() {
    const ret = await CslMobileBridge.headerBodyLeaderVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async has_vrf_result() {
    const ret = await CslMobileBridge.headerBodyHasVrfResult(this.ptr);
    return ret;
  }

  async vrf_result_or_nothing() {
    const ret = await CslMobileBridge.headerBodyVrfResultOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async block_body_size() {
    const ret = await CslMobileBridge.headerBodyBlockBodySize(this.ptr);
    return ret;
  }

  async block_body_hash() {
    const ret = await CslMobileBridge.headerBodyBlockBodyHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async operational_cert() {
    const ret = await CslMobileBridge.headerBodyOperationalCert(this.ptr);
    return Ptr._wrap(ret, OperationalCert);
  }

  async protocol_version() {
    const ret = await CslMobileBridge.headerBodyProtocolVersion(this.ptr);
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
      const ret = await CslMobileBridge.headerBodyNew(block_number, slot, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await CslMobileBridge.headerBodyNewWithPrevHash(block_number, slot, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
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
      const ret = await CslMobileBridge.headerBodyNewHeaderbody(block_number, slotPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await CslMobileBridge.headerBodyNewHeaderbodyWithPrevHash(block_number, slotPtr, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
  }

}


export class InputWithScriptWitness extends Ptr {
  static async new_with_native_script_witness(input, witness) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const witnessPtr = Ptr._assertClass(witness, NativeScript);
    const ret = await CslMobileBridge.inputWithScriptWitnessNewWithNativeScriptWitness(inputPtr, witnessPtr);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  static async new_with_plutus_witness(input, witness) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = await CslMobileBridge.inputWithScriptWitnessNewWithPlutusWitness(inputPtr, witnessPtr);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  async input() {
    const ret = await CslMobileBridge.inputWithScriptWitnessInput(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class InputsWithScriptWitness extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.inputsWithScriptWitnessNew();
    return Ptr._wrap(ret, InputsWithScriptWitness);
  }

  add(input) {
    const inputPtr = Ptr._assertClass(input, InputWithScriptWitness);
    const ret = CslMobileBridge.inputsWithScriptWitnessAdd(this.ptr, inputPtr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.inputsWithScriptWitnessGet(this.ptr, index);
    return Ptr._wrap(ret, InputWithScriptWitness);
  }

  async len() {
    const ret = await CslMobileBridge.inputsWithScriptWitnessLen(this.ptr);
    return ret;
  }

}


export class Int extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.intToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.intFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Int);
  }

  async to_hex() {
    const ret = await CslMobileBridge.intToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.intFromHex(hex_str);
    return Ptr._wrap(ret, Int);
  }

  async to_json() {
    const ret = await CslMobileBridge.intToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.intFromJson(json);
    return Ptr._wrap(ret, Int);
  }

  static async new(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await CslMobileBridge.intNew(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_negative(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await CslMobileBridge.intNewNegative(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_i32(x) {
    const ret = await CslMobileBridge.intNewI32(x);
    return Ptr._wrap(ret, Int);
  }

  async is_positive() {
    const ret = await CslMobileBridge.intIsPositive(this.ptr);
    return ret;
  }

  async as_positive() {
    const ret = await CslMobileBridge.intAsPositive(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_negative() {
    const ret = await CslMobileBridge.intAsNegative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_i32() {
    const ret = await CslMobileBridge.intAsI32(this.ptr);
    return ret;
  }

  async as_i32_or_nothing() {
    const ret = await CslMobileBridge.intAsI32OrNothing(this.ptr);
    return ret;
  }

  async as_i32_or_fail() {
    const ret = await CslMobileBridge.intAsI32OrFail(this.ptr);
    return ret;
  }

  async to_str() {
    const ret = await CslMobileBridge.intToStr(this.ptr);
    return ret;
  }

  static async from_str(string) {
    const ret = await CslMobileBridge.intFromStr(string);
    return Ptr._wrap(ret, Int);
  }

}


export class Ipv4 extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.ipv4ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.ipv4FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv4);
  }

  async to_hex() {
    const ret = await CslMobileBridge.ipv4ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.ipv4FromHex(hex_str);
    return Ptr._wrap(ret, Ipv4);
  }

  async to_json() {
    const ret = await CslMobileBridge.ipv4ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.ipv4FromJson(json);
    return Ptr._wrap(ret, Ipv4);
  }

  static async new(data) {
    const ret = await CslMobileBridge.ipv4New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv4);
  }

  async ip() {
    const ret = await CslMobileBridge.ipv4Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Ipv6 extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.ipv6ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.ipv6FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv6);
  }

  async to_hex() {
    const ret = await CslMobileBridge.ipv6ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.ipv6FromHex(hex_str);
    return Ptr._wrap(ret, Ipv6);
  }

  async to_json() {
    const ret = await CslMobileBridge.ipv6ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.ipv6FromJson(json);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(data) {
    const ret = await CslMobileBridge.ipv6New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv6);
  }

  async ip() {
    const ret = await CslMobileBridge.ipv6Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class KESSignature extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.kESSignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.kESSignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESSignature);
  }

}


export class KESVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.kESVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESVKey);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.kESVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.kESVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.kESVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, KESVKey);
  }

  async to_hex() {
    const ret = await CslMobileBridge.kESVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.kESVKeyFromHex(hex);
    return Ptr._wrap(ret, KESVKey);
  }

}


export class Language extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.languageToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.languageFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Language);
  }

  async to_hex() {
    const ret = await CslMobileBridge.languageToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.languageFromHex(hex_str);
    return Ptr._wrap(ret, Language);
  }

  async to_json() {
    const ret = await CslMobileBridge.languageToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.languageFromJson(json);
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v1() {
    const ret = await CslMobileBridge.languageNewPlutusV1();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v2() {
    const ret = await CslMobileBridge.languageNewPlutusV2();
    return Ptr._wrap(ret, Language);
  }

  async kind() {
    const ret = await CslMobileBridge.languageKind(this.ptr);
    return ret;
  }

}


export class Languages extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.languagesNew();
    return Ptr._wrap(ret, Languages);
  }

  async len() {
    const ret = await CslMobileBridge.languagesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.languagesGet(this.ptr, index);
    return Ptr._wrap(ret, Language);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Language);
    const ret = CslMobileBridge.languagesAdd(this.ptr, elemPtr);
    return ret;
  }

  static async list() {
    const ret = await CslMobileBridge.languagesList();
    return Ptr._wrap(ret, Languages);
  }

}


export class LegacyDaedalusPrivateKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.legacyDaedalusPrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, LegacyDaedalusPrivateKey);
  }

  async as_bytes() {
    const ret = await CslMobileBridge.legacyDaedalusPrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async chaincode() {
    const ret = await CslMobileBridge.legacyDaedalusPrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class LinearFee extends Ptr {
  async constant() {
    const ret = await CslMobileBridge.linearFeeConstant(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async coefficient() {
    const ret = await CslMobileBridge.linearFeeCoefficient(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(coefficient, constant) {
    const coefficientPtr = Ptr._assertClass(coefficient, BigNum);
    const constantPtr = Ptr._assertClass(constant, BigNum);
    const ret = await CslMobileBridge.linearFeeNew(coefficientPtr, constantPtr);
    return Ptr._wrap(ret, LinearFee);
  }

}


export class MIRToStakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.mIRToStakeCredentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_hex() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.mIRToStakeCredentialsFromHex(hex_str);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_json() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.mIRToStakeCredentialsFromJson(json);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  static async new() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsNew();
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async len() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsLen(this.ptr);
    return ret;
  }

  async insert(cred, delta) {
    const credPtr = Ptr._assertClass(cred, StakeCredential);
    const deltaPtr = Ptr._assertClass(delta, Int);
    const ret = await CslMobileBridge.mIRToStakeCredentialsInsert(this.ptr, credPtr, deltaPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(cred) {
    const credPtr = Ptr._assertClass(cred, StakeCredential);
    const ret = await CslMobileBridge.mIRToStakeCredentialsGet(this.ptr, credPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await CslMobileBridge.mIRToStakeCredentialsKeys(this.ptr);
    return Ptr._wrap(ret, StakeCredentials);
  }

}


export class MetadataList extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.metadataListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.metadataListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataList);
  }

  async to_hex() {
    const ret = await CslMobileBridge.metadataListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.metadataListFromHex(hex_str);
    return Ptr._wrap(ret, MetadataList);
  }

  static async new() {
    const ret = await CslMobileBridge.metadataListNew();
    return Ptr._wrap(ret, MetadataList);
  }

  async len() {
    const ret = await CslMobileBridge.metadataListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.metadataListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionMetadatum);
    const ret = CslMobileBridge.metadataListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class MetadataMap extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.metadataMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.metadataMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataMap);
  }

  async to_hex() {
    const ret = await CslMobileBridge.metadataMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.metadataMapFromHex(hex_str);
    return Ptr._wrap(ret, MetadataMap);
  }

  static async new() {
    const ret = await CslMobileBridge.metadataMapNew();
    return Ptr._wrap(ret, MetadataMap);
  }

  async len() {
    const ret = await CslMobileBridge.metadataMapLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await CslMobileBridge.metadataMapInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_str(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await CslMobileBridge.metadataMapInsertStr(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_i32(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await CslMobileBridge.metadataMapInsertI32(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await CslMobileBridge.metadataMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_str(key) {
    const ret = await CslMobileBridge.metadataMapGetStr(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_i32(key) {
    const ret = await CslMobileBridge.metadataMapGetI32(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async has(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await CslMobileBridge.metadataMapHas(this.ptr, keyPtr);
    return ret;
  }

  async keys() {
    const ret = await CslMobileBridge.metadataMapKeys(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

}


export class Mint extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.mintToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.mintFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Mint);
  }

  async to_hex() {
    const ret = await CslMobileBridge.mintToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.mintFromHex(hex_str);
    return Ptr._wrap(ret, Mint);
  }

  async to_json() {
    const ret = await CslMobileBridge.mintToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.mintFromJson(json);
    return Ptr._wrap(ret, Mint);
  }

  static async new() {
    const ret = await CslMobileBridge.mintNew();
    return Ptr._wrap(ret, Mint);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await CslMobileBridge.mintNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, Mint);
  }

  async len() {
    const ret = await CslMobileBridge.mintLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await CslMobileBridge.mintInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await CslMobileBridge.mintGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get_all(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await CslMobileBridge.mintGetAll(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintsAssets);
  }

  async keys() {
    const ret = await CslMobileBridge.mintKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async as_positive_multiasset() {
    const ret = await CslMobileBridge.mintAsPositiveMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  async as_negative_multiasset() {
    const ret = await CslMobileBridge.mintAsNegativeMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MintAssets extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.mintAssetsNew();
    return Ptr._wrap(ret, MintAssets);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await CslMobileBridge.mintAssetsNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await CslMobileBridge.mintAssetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await CslMobileBridge.mintAssetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, Int);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await CslMobileBridge.mintAssetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await CslMobileBridge.mintAssetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class MintBuilder extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.mintBuilderNew();
    return Ptr._wrap(ret, MintBuilder);
  }

  add_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = CslMobileBridge.mintBuilderAddAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  set_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = CslMobileBridge.mintBuilderSetAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  async build() {
    const ret = await CslMobileBridge.mintBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_native_scripts() {
    const ret = await CslMobileBridge.mintBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_witnesses() {
    const ret = await CslMobileBridge.mintBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await CslMobileBridge.mintBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_redeeemers() {
    const ret = await CslMobileBridge.mintBuilderGetRedeeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  async has_plutus_scripts() {
    const ret = await CslMobileBridge.mintBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async has_native_scripts() {
    const ret = await CslMobileBridge.mintBuilderHasNativeScripts(this.ptr);
    return ret;
  }

}


export class MintWitness extends Ptr {
  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await CslMobileBridge.mintWitnessNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, MintWitness);
  }

  static async new_plutus_script(plutus_script, redeemer) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await CslMobileBridge.mintWitnessNewPlutusScript(plutus_scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, MintWitness);
  }

}


export class MintsAssets extends Ptr {
}


export class MoveInstantaneousReward extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.moveInstantaneousRewardToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.moveInstantaneousRewardFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_hex() {
    const ret = await CslMobileBridge.moveInstantaneousRewardToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.moveInstantaneousRewardFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_json() {
    const ret = await CslMobileBridge.moveInstantaneousRewardToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.moveInstantaneousRewardFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_other_pot(pot, amount) {
    const amountPtr = Ptr._assertClass(amount, BigNum);
    const ret = await CslMobileBridge.moveInstantaneousRewardNewToOtherPot(pot, amountPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_stake_creds(pot, amounts) {
    const amountsPtr = Ptr._assertClass(amounts, MIRToStakeCredentials);
    const ret = await CslMobileBridge.moveInstantaneousRewardNewToStakeCreds(pot, amountsPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async pot() {
    const ret = await CslMobileBridge.moveInstantaneousRewardPot(this.ptr);
    return ret;
  }

  async kind() {
    const ret = await CslMobileBridge.moveInstantaneousRewardKind(this.ptr);
    return ret;
  }

  async as_to_other_pot() {
    const ret = await CslMobileBridge.moveInstantaneousRewardAsToOtherPot(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_to_stake_creds() {
    const ret = await CslMobileBridge.moveInstantaneousRewardAsToStakeCreds(this.ptr);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

}


export class MoveInstantaneousRewardsCert extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_hex() {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_json() {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async move_instantaneous_reward() {
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertMoveInstantaneousReward(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new(move_instantaneous_reward) {
    const move_instantaneous_rewardPtr = Ptr._assertClass(move_instantaneous_reward, MoveInstantaneousReward);
    const ret = await CslMobileBridge.moveInstantaneousRewardsCertNew(move_instantaneous_rewardPtr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class MultiAsset extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.multiAssetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.multiAssetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_hex() {
    const ret = await CslMobileBridge.multiAssetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.multiAssetFromHex(hex_str);
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_json() {
    const ret = await CslMobileBridge.multiAssetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.multiAssetFromJson(json);
    return Ptr._wrap(ret, MultiAsset);
  }

  static async new() {
    const ret = await CslMobileBridge.multiAssetNew();
    return Ptr._wrap(ret, MultiAsset);
  }

  async len() {
    const ret = await CslMobileBridge.multiAssetLen(this.ptr);
    return ret;
  }

  async insert(policy_id, assets) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const assetsPtr = Ptr._assertClass(assets, Assets);
    const ret = await CslMobileBridge.multiAssetInsert(this.ptr, policy_idPtr, assetsPtr);
    return Ptr._wrap(ret, Assets);
  }

  async get(policy_id) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const ret = await CslMobileBridge.multiAssetGet(this.ptr, policy_idPtr);
    return Ptr._wrap(ret, Assets);
  }

  async set_asset(policy_id, asset_name, value) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await CslMobileBridge.multiAssetSetAsset(this.ptr, policy_idPtr, asset_namePtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_asset(policy_id, asset_name) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const ret = await CslMobileBridge.multiAssetGetAsset(this.ptr, policy_idPtr, asset_namePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await CslMobileBridge.multiAssetKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async sub(rhs_ma) {
    const rhs_maPtr = Ptr._assertClass(rhs_ma, MultiAsset);
    const ret = await CslMobileBridge.multiAssetSub(this.ptr, rhs_maPtr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MultiHostName extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.multiHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.multiHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_hex() {
    const ret = await CslMobileBridge.multiHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.multiHostNameFromHex(hex_str);
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_json() {
    const ret = await CslMobileBridge.multiHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.multiHostNameFromJson(json);
    return Ptr._wrap(ret, MultiHostName);
  }

  async dns_name() {
    const ret = await CslMobileBridge.multiHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordSRV);
    const ret = await CslMobileBridge.multiHostNameNew(dns_namePtr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class NativeScript extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.nativeScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.nativeScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScript);
  }

  async to_hex() {
    const ret = await CslMobileBridge.nativeScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.nativeScriptFromHex(hex_str);
    return Ptr._wrap(ret, NativeScript);
  }

  async to_json() {
    const ret = await CslMobileBridge.nativeScriptToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.nativeScriptFromJson(json);
    return Ptr._wrap(ret, NativeScript);
  }

  async hash() {
    const ret = await CslMobileBridge.nativeScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new_script_pubkey(script_pubkey) {
    const script_pubkeyPtr = Ptr._assertClass(script_pubkey, ScriptPubkey);
    const ret = await CslMobileBridge.nativeScriptNewScriptPubkey(script_pubkeyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_all(script_all) {
    const script_allPtr = Ptr._assertClass(script_all, ScriptAll);
    const ret = await CslMobileBridge.nativeScriptNewScriptAll(script_allPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_any(script_any) {
    const script_anyPtr = Ptr._assertClass(script_any, ScriptAny);
    const ret = await CslMobileBridge.nativeScriptNewScriptAny(script_anyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_n_of_k(script_n_of_k) {
    const script_n_of_kPtr = Ptr._assertClass(script_n_of_k, ScriptNOfK);
    const ret = await CslMobileBridge.nativeScriptNewScriptNOfK(script_n_of_kPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_start(timelock_start) {
    const timelock_startPtr = Ptr._assertClass(timelock_start, TimelockStart);
    const ret = await CslMobileBridge.nativeScriptNewTimelockStart(timelock_startPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_expiry(timelock_expiry) {
    const timelock_expiryPtr = Ptr._assertClass(timelock_expiry, TimelockExpiry);
    const ret = await CslMobileBridge.nativeScriptNewTimelockExpiry(timelock_expiryPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  async kind() {
    const ret = await CslMobileBridge.nativeScriptKind(this.ptr);
    return ret;
  }

  async as_script_pubkey() {
    const ret = await CslMobileBridge.nativeScriptAsScriptPubkey(this.ptr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async as_script_all() {
    const ret = await CslMobileBridge.nativeScriptAsScriptAll(this.ptr);
    return Ptr._wrap(ret, ScriptAll);
  }

  async as_script_any() {
    const ret = await CslMobileBridge.nativeScriptAsScriptAny(this.ptr);
    return Ptr._wrap(ret, ScriptAny);
  }

  async as_script_n_of_k() {
    const ret = await CslMobileBridge.nativeScriptAsScriptNOfK(this.ptr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async as_timelock_start() {
    const ret = await CslMobileBridge.nativeScriptAsTimelockStart(this.ptr);
    return Ptr._wrap(ret, TimelockStart);
  }

  async as_timelock_expiry() {
    const ret = await CslMobileBridge.nativeScriptAsTimelockExpiry(this.ptr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async get_required_signers() {
    const ret = await CslMobileBridge.nativeScriptGetRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class NativeScripts extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.nativeScriptsNew();
    return Ptr._wrap(ret, NativeScripts);
  }

  async len() {
    const ret = await CslMobileBridge.nativeScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.nativeScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, NativeScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, NativeScript);
    const ret = CslMobileBridge.nativeScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class NetworkId extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.networkIdToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.networkIdFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NetworkId);
  }

  async to_hex() {
    const ret = await CslMobileBridge.networkIdToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.networkIdFromHex(hex_str);
    return Ptr._wrap(ret, NetworkId);
  }

  async to_json() {
    const ret = await CslMobileBridge.networkIdToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.networkIdFromJson(json);
    return Ptr._wrap(ret, NetworkId);
  }

  static async testnet() {
    const ret = await CslMobileBridge.networkIdTestnet();
    return Ptr._wrap(ret, NetworkId);
  }

  static async mainnet() {
    const ret = await CslMobileBridge.networkIdMainnet();
    return Ptr._wrap(ret, NetworkId);
  }

  async kind() {
    const ret = await CslMobileBridge.networkIdKind(this.ptr);
    return ret;
  }

}


export class NetworkInfo extends Ptr {
  static async new(network_id, protocol_magic) {
    const ret = await CslMobileBridge.networkInfoNew(network_id, protocol_magic);
    return Ptr._wrap(ret, NetworkInfo);
  }

  async network_id() {
    const ret = await CslMobileBridge.networkInfoNetworkId(this.ptr);
    return ret;
  }

  async protocol_magic() {
    const ret = await CslMobileBridge.networkInfoProtocolMagic(this.ptr);
    return ret;
  }

  static async testnet_preview() {
    const ret = await CslMobileBridge.networkInfoTestnetPreview();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async testnet_preprod() {
    const ret = await CslMobileBridge.networkInfoTestnetPreprod();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async testnet() {
    const ret = await CslMobileBridge.networkInfoTestnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async mainnet() {
    const ret = await CslMobileBridge.networkInfoMainnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

}


export class Nonce extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.nonceToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.nonceFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Nonce);
  }

  async to_hex() {
    const ret = await CslMobileBridge.nonceToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.nonceFromHex(hex_str);
    return Ptr._wrap(ret, Nonce);
  }

  async to_json() {
    const ret = await CslMobileBridge.nonceToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.nonceFromJson(json);
    return Ptr._wrap(ret, Nonce);
  }

  static async new_identity() {
    const ret = await CslMobileBridge.nonceNewIdentity();
    return Ptr._wrap(ret, Nonce);
  }

  static async new_from_hash(hash) {
    const ret = await CslMobileBridge.nonceNewFromHash(b64FromUint8Array(hash));
    return Ptr._wrap(ret, Nonce);
  }

  async get_hash() {
    const ret = await CslMobileBridge.nonceGetHash(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class OperationalCert extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.operationalCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.operationalCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_hex() {
    const ret = await CslMobileBridge.operationalCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.operationalCertFromHex(hex_str);
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_json() {
    const ret = await CslMobileBridge.operationalCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.operationalCertFromJson(json);
    return Ptr._wrap(ret, OperationalCert);
  }

  async hot_vkey() {
    const ret = await CslMobileBridge.operationalCertHotVkey(this.ptr);
    return Ptr._wrap(ret, KESVKey);
  }

  async sequence_number() {
    const ret = await CslMobileBridge.operationalCertSequenceNumber(this.ptr);
    return ret;
  }

  async kes_period() {
    const ret = await CslMobileBridge.operationalCertKesPeriod(this.ptr);
    return ret;
  }

  async sigma() {
    const ret = await CslMobileBridge.operationalCertSigma(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async new(hot_vkey, sequence_number, kes_period, sigma) {
    const hot_vkeyPtr = Ptr._assertClass(hot_vkey, KESVKey);
    const sigmaPtr = Ptr._assertClass(sigma, Ed25519Signature);
    const ret = await CslMobileBridge.operationalCertNew(hot_vkeyPtr, sequence_number, kes_period, sigmaPtr);
    return Ptr._wrap(ret, OperationalCert);
  }

}


export class PlutusData extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.plutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.plutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async to_hex() {
    const ret = await CslMobileBridge.plutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.plutusDataFromHex(hex_str);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_constr_plutus_data(constr_plutus_data) {
    const constr_plutus_dataPtr = Ptr._assertClass(constr_plutus_data, ConstrPlutusData);
    const ret = await CslMobileBridge.plutusDataNewConstrPlutusData(constr_plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_empty_constr_plutus_data(alternative) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const ret = await CslMobileBridge.plutusDataNewEmptyConstrPlutusData(alternativePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, PlutusMap);
    const ret = await CslMobileBridge.plutusDataNewMap(mapPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, PlutusList);
    const ret = await CslMobileBridge.plutusDataNewList(listPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_integer(integer) {
    const integerPtr = Ptr._assertClass(integer, BigInt);
    const ret = await CslMobileBridge.plutusDataNewInteger(integerPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_bytes(bytes) {
    const ret = await CslMobileBridge.plutusDataNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async kind() {
    const ret = await CslMobileBridge.plutusDataKind(this.ptr);
    return ret;
  }

  async as_constr_plutus_data() {
    const ret = await CslMobileBridge.plutusDataAsConstrPlutusData(this.ptr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async as_map() {
    const ret = await CslMobileBridge.plutusDataAsMap(this.ptr);
    return Ptr._wrap(ret, PlutusMap);
  }

  async as_list() {
    const ret = await CslMobileBridge.plutusDataAsList(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  async as_integer() {
    const ret = await CslMobileBridge.plutusDataAsInteger(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async as_bytes() {
    const ret = await CslMobileBridge.plutusDataAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_json(schema) {
    const ret = await CslMobileBridge.plutusDataToJson(this.ptr, schema);
    return ret;
  }

  static async from_json(json, schema) {
    const ret = await CslMobileBridge.plutusDataFromJson(json, schema);
    return Ptr._wrap(ret, PlutusData);
  }

}


export class PlutusList extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.plutusListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.plutusListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusList);
  }

  async to_hex() {
    const ret = await CslMobileBridge.plutusListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.plutusListFromHex(hex_str);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new() {
    const ret = await CslMobileBridge.plutusListNew();
    return Ptr._wrap(ret, PlutusList);
  }

  async len() {
    const ret = await CslMobileBridge.plutusListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.plutusListGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusData);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusData);
    const ret = CslMobileBridge.plutusListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusMap extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.plutusMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.plutusMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusMap);
  }

  async to_hex() {
    const ret = await CslMobileBridge.plutusMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.plutusMapFromHex(hex_str);
    return Ptr._wrap(ret, PlutusMap);
  }

  static async new() {
    const ret = await CslMobileBridge.plutusMapNew();
    return Ptr._wrap(ret, PlutusMap);
  }

  async len() {
    const ret = await CslMobileBridge.plutusMapLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const valuePtr = Ptr._assertClass(value, PlutusData);
    const ret = await CslMobileBridge.plutusMapInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const ret = await CslMobileBridge.plutusMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async keys() {
    const ret = await CslMobileBridge.plutusMapKeys(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

}


export class PlutusScript extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.plutusScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.plutusScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  async to_hex() {
    const ret = await CslMobileBridge.plutusScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.plutusScriptFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new(bytes) {
    const ret = await CslMobileBridge.plutusScriptNew(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v2(bytes) {
    const ret = await CslMobileBridge.plutusScriptNewV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await CslMobileBridge.plutusScriptNewWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async bytes() {
    const ret = await CslMobileBridge.plutusScriptBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes_v2(bytes) {
    const ret = await CslMobileBridge.plutusScriptFromBytesV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await CslMobileBridge.plutusScriptFromBytesWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_hex_with_version(hex_str, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await CslMobileBridge.plutusScriptFromHexWithVersion(hex_str, languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async hash() {
    const ret = await CslMobileBridge.plutusScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async language_version() {
    const ret = await CslMobileBridge.plutusScriptLanguageVersion(this.ptr);
    return Ptr._wrap(ret, Language);
  }

}


export class PlutusScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const ret = await CslMobileBridge.plutusScriptSourceNew(scriptPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input(script_hash, input) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await CslMobileBridge.plutusScriptSourceNewRefInput(script_hashPtr, inputPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input_with_lang_ver(script_hash, input, lang_ver) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const lang_verPtr = Ptr._assertClass(lang_ver, Language);
    const ret = await CslMobileBridge.plutusScriptSourceNewRefInputWithLangVer(script_hashPtr, inputPtr, lang_verPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

}


export class PlutusScripts extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.plutusScriptsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.plutusScriptsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_hex() {
    const ret = await CslMobileBridge.plutusScriptsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.plutusScriptsFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_json() {
    const ret = await CslMobileBridge.plutusScriptsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.plutusScriptsFromJson(json);
    return Ptr._wrap(ret, PlutusScripts);
  }

  static async new() {
    const ret = await CslMobileBridge.plutusScriptsNew();
    return Ptr._wrap(ret, PlutusScripts);
  }

  async len() {
    const ret = await CslMobileBridge.plutusScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.plutusScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusScript);
    const ret = CslMobileBridge.plutusScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusWitness extends Ptr {
  static async new(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await CslMobileBridge.plutusWitnessNew(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const datumPtr = Ptr._assertClass(datum, DatumSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await CslMobileBridge.plutusWitnessNewWithRef(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await CslMobileBridge.plutusWitnessNewWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await CslMobileBridge.plutusWitnessNewWithRefWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  async script() {
    const ret = await CslMobileBridge.plutusWitnessScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async datum() {
    const ret = await CslMobileBridge.plutusWitnessDatum(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async redeemer() {
    const ret = await CslMobileBridge.plutusWitnessRedeemer(this.ptr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class PlutusWitnesses extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.plutusWitnessesNew();
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await CslMobileBridge.plutusWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.plutusWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusWitness);
    const ret = CslMobileBridge.plutusWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Pointer extends Ptr {
  static async new(slot, tx_index, cert_index) {
    const ret = await CslMobileBridge.pointerNew(slot, tx_index, cert_index);
    return Ptr._wrap(ret, Pointer);
  }

  static async new_pointer(slot, tx_index, cert_index) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const tx_indexPtr = Ptr._assertClass(tx_index, BigNum);
    const cert_indexPtr = Ptr._assertClass(cert_index, BigNum);
    const ret = await CslMobileBridge.pointerNewPointer(slotPtr, tx_indexPtr, cert_indexPtr);
    return Ptr._wrap(ret, Pointer);
  }

  async slot() {
    const ret = await CslMobileBridge.pointerSlot(this.ptr);
    return ret;
  }

  async tx_index() {
    const ret = await CslMobileBridge.pointerTxIndex(this.ptr);
    return ret;
  }

  async cert_index() {
    const ret = await CslMobileBridge.pointerCertIndex(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await CslMobileBridge.pointerSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async tx_index_bignum() {
    const ret = await CslMobileBridge.pointerTxIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cert_index_bignum() {
    const ret = await CslMobileBridge.pointerCertIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class PointerAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const stakePtr = Ptr._assertClass(stake, Pointer);
    const ret = await CslMobileBridge.pointerAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, PointerAddress);
  }

  async payment_cred() {
    const ret = await CslMobileBridge.pointerAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async stake_pointer() {
    const ret = await CslMobileBridge.pointerAddressStakePointer(this.ptr);
    return Ptr._wrap(ret, Pointer);
  }

  async to_address() {
    const ret = await CslMobileBridge.pointerAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await CslMobileBridge.pointerAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, PointerAddress);
  }

}


export class PoolMetadata extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.poolMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.poolMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_hex() {
    const ret = await CslMobileBridge.poolMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.poolMetadataFromHex(hex_str);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_json() {
    const ret = await CslMobileBridge.poolMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.poolMetadataFromJson(json);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async url() {
    const ret = await CslMobileBridge.poolMetadataUrl(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async pool_metadata_hash() {
    const ret = await CslMobileBridge.poolMetadataPoolMetadataHash(this.ptr);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  static async new(url, pool_metadata_hash) {
    const urlPtr = Ptr._assertClass(url, URL);
    const pool_metadata_hashPtr = Ptr._assertClass(pool_metadata_hash, PoolMetadataHash);
    const ret = await CslMobileBridge.poolMetadataNew(urlPtr, pool_metadata_hashPtr);
    return Ptr._wrap(ret, PoolMetadata);
  }

}


export class PoolMetadataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.poolMetadataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.poolMetadataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.poolMetadataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.poolMetadataHashFromBech32(bech_str);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.poolMetadataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.poolMetadataHashFromHex(hex);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

}


export class PoolParams extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.poolParamsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.poolParamsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolParams);
  }

  async to_hex() {
    const ret = await CslMobileBridge.poolParamsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.poolParamsFromHex(hex_str);
    return Ptr._wrap(ret, PoolParams);
  }

  async to_json() {
    const ret = await CslMobileBridge.poolParamsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.poolParamsFromJson(json);
    return Ptr._wrap(ret, PoolParams);
  }

  async operator() {
    const ret = await CslMobileBridge.poolParamsOperator(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async vrf_keyhash() {
    const ret = await CslMobileBridge.poolParamsVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async pledge() {
    const ret = await CslMobileBridge.poolParamsPledge(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cost() {
    const ret = await CslMobileBridge.poolParamsCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async margin() {
    const ret = await CslMobileBridge.poolParamsMargin(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async reward_account() {
    const ret = await CslMobileBridge.poolParamsRewardAccount(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async pool_owners() {
    const ret = await CslMobileBridge.poolParamsPoolOwners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async relays() {
    const ret = await CslMobileBridge.poolParamsRelays(this.ptr);
    return Ptr._wrap(ret, Relays);
  }

  async pool_metadata() {
    const ret = await CslMobileBridge.poolParamsPoolMetadata(this.ptr);
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
      const ret = await CslMobileBridge.poolParamsNew(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr);
      return Ptr._wrap(ret, PoolParams);
    }
    if(pool_metadata != null) {
      const ret = await CslMobileBridge.poolParamsNewWithPoolMetadata(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr, pool_metadataPtr);
      return Ptr._wrap(ret, PoolParams);
    }
  }

}


export class PoolRegistration extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.poolRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.poolRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_hex() {
    const ret = await CslMobileBridge.poolRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.poolRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_json() {
    const ret = await CslMobileBridge.poolRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.poolRegistrationFromJson(json);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async pool_params() {
    const ret = await CslMobileBridge.poolRegistrationPoolParams(this.ptr);
    return Ptr._wrap(ret, PoolParams);
  }

  static async new(pool_params) {
    const pool_paramsPtr = Ptr._assertClass(pool_params, PoolParams);
    const ret = await CslMobileBridge.poolRegistrationNew(pool_paramsPtr);
    return Ptr._wrap(ret, PoolRegistration);
  }

}


export class PoolRetirement extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.poolRetirementToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.poolRetirementFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_hex() {
    const ret = await CslMobileBridge.poolRetirementToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.poolRetirementFromHex(hex_str);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_json() {
    const ret = await CslMobileBridge.poolRetirementToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.poolRetirementFromJson(json);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async pool_keyhash() {
    const ret = await CslMobileBridge.poolRetirementPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async epoch() {
    const ret = await CslMobileBridge.poolRetirementEpoch(this.ptr);
    return ret;
  }

  static async new(pool_keyhash, epoch) {
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await CslMobileBridge.poolRetirementNew(pool_keyhashPtr, epoch);
    return Ptr._wrap(ret, PoolRetirement);
  }

}


export class PrivateKey extends Ptr {
  async to_public() {
    const ret = await CslMobileBridge.privateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async generate_ed25519() {
    const ret = await CslMobileBridge.privateKeyGenerateEd25519();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async generate_ed25519extended() {
    const ret = await CslMobileBridge.privateKeyGenerateEd25519extended();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_bech32(bech32_str) {
    const ret = await CslMobileBridge.privateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_bech32() {
    const ret = await CslMobileBridge.privateKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await CslMobileBridge.privateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_extended_bytes(bytes) {
    const ret = await CslMobileBridge.privateKeyFromExtendedBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_normal_bytes(bytes) {
    const ret = await CslMobileBridge.privateKeyFromNormalBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  async sign(message) {
    const ret = await CslMobileBridge.privateKeySign(this.ptr, b64FromUint8Array(message));
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async to_hex() {
    const ret = await CslMobileBridge.privateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.privateKeyFromHex(hex_str);
    return Ptr._wrap(ret, PrivateKey);
  }

}


export class ProposedProtocolParameterUpdates extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_hex() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesFromHex(hex_str);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_json() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesFromJson(json);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  static async new() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesNew();
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async len() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const valuePtr = Ptr._assertClass(value, ProtocolParamUpdate);
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async keys() {
    const ret = await CslMobileBridge.proposedProtocolParameterUpdatesKeys(this.ptr);
    return Ptr._wrap(ret, GenesisHashes);
  }

}


export class ProtocolParamUpdate extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.protocolParamUpdateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.protocolParamUpdateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_hex() {
    const ret = await CslMobileBridge.protocolParamUpdateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.protocolParamUpdateFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_json() {
    const ret = await CslMobileBridge.protocolParamUpdateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.protocolParamUpdateFromJson(json);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  set_minfee_a(minfee_a) {
    const minfee_aPtr = Ptr._assertClass(minfee_a, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetMinfeeA(this.ptr, minfee_aPtr);
    return ret;
  }

  async minfee_a() {
    const ret = await CslMobileBridge.protocolParamUpdateMinfeeA(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_minfee_b(minfee_b) {
    const minfee_bPtr = Ptr._assertClass(minfee_b, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetMinfeeB(this.ptr, minfee_bPtr);
    return ret;
  }

  async minfee_b() {
    const ret = await CslMobileBridge.protocolParamUpdateMinfeeB(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_block_body_size(max_block_body_size) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxBlockBodySize(this.ptr, max_block_body_size);
    return ret;
  }

  async max_block_body_size() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxBlockBodySize(this.ptr);
    return ret;
  }

  set_max_tx_size(max_tx_size) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxTxSize(this.ptr, max_tx_size);
    return ret;
  }

  async max_tx_size() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxTxSize(this.ptr);
    return ret;
  }

  set_max_block_header_size(max_block_header_size) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxBlockHeaderSize(this.ptr, max_block_header_size);
    return ret;
  }

  async max_block_header_size() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxBlockHeaderSize(this.ptr);
    return ret;
  }

  set_key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetKeyDeposit(this.ptr, key_depositPtr);
    return ret;
  }

  async key_deposit() {
    const ret = await CslMobileBridge.protocolParamUpdateKeyDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetPoolDeposit(this.ptr, pool_depositPtr);
    return ret;
  }

  async pool_deposit() {
    const ret = await CslMobileBridge.protocolParamUpdatePoolDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_epoch(max_epoch) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxEpoch(this.ptr, max_epoch);
    return ret;
  }

  async max_epoch() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxEpoch(this.ptr);
    return ret;
  }

  set_n_opt(n_opt) {
    const ret = CslMobileBridge.protocolParamUpdateSetNOpt(this.ptr, n_opt);
    return ret;
  }

  async n_opt() {
    const ret = await CslMobileBridge.protocolParamUpdateNOpt(this.ptr);
    return ret;
  }

  set_pool_pledge_influence(pool_pledge_influence) {
    const pool_pledge_influencePtr = Ptr._assertClass(pool_pledge_influence, UnitInterval);
    const ret = CslMobileBridge.protocolParamUpdateSetPoolPledgeInfluence(this.ptr, pool_pledge_influencePtr);
    return ret;
  }

  async pool_pledge_influence() {
    const ret = await CslMobileBridge.protocolParamUpdatePoolPledgeInfluence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_expansion_rate(expansion_rate) {
    const expansion_ratePtr = Ptr._assertClass(expansion_rate, UnitInterval);
    const ret = CslMobileBridge.protocolParamUpdateSetExpansionRate(this.ptr, expansion_ratePtr);
    return ret;
  }

  async expansion_rate() {
    const ret = await CslMobileBridge.protocolParamUpdateExpansionRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_treasury_growth_rate(treasury_growth_rate) {
    const treasury_growth_ratePtr = Ptr._assertClass(treasury_growth_rate, UnitInterval);
    const ret = CslMobileBridge.protocolParamUpdateSetTreasuryGrowthRate(this.ptr, treasury_growth_ratePtr);
    return ret;
  }

  async treasury_growth_rate() {
    const ret = await CslMobileBridge.protocolParamUpdateTreasuryGrowthRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async d() {
    const ret = await CslMobileBridge.protocolParamUpdateD(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async extra_entropy() {
    const ret = await CslMobileBridge.protocolParamUpdateExtraEntropy(this.ptr);
    return Ptr._wrap(ret, Nonce);
  }

  set_protocol_version(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = CslMobileBridge.protocolParamUpdateSetProtocolVersion(this.ptr, protocol_versionPtr);
    return ret;
  }

  async protocol_version() {
    const ret = await CslMobileBridge.protocolParamUpdateProtocolVersion(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  set_min_pool_cost(min_pool_cost) {
    const min_pool_costPtr = Ptr._assertClass(min_pool_cost, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetMinPoolCost(this.ptr, min_pool_costPtr);
    return ret;
  }

  async min_pool_cost() {
    const ret = await CslMobileBridge.protocolParamUpdateMinPoolCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ada_per_utxo_byte(ada_per_utxo_byte) {
    const ada_per_utxo_bytePtr = Ptr._assertClass(ada_per_utxo_byte, BigNum);
    const ret = CslMobileBridge.protocolParamUpdateSetAdaPerUtxoByte(this.ptr, ada_per_utxo_bytePtr);
    return ret;
  }

  async ada_per_utxo_byte() {
    const ret = await CslMobileBridge.protocolParamUpdateAdaPerUtxoByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_cost_models(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = CslMobileBridge.protocolParamUpdateSetCostModels(this.ptr, cost_modelsPtr);
    return ret;
  }

  async cost_models() {
    const ret = await CslMobileBridge.protocolParamUpdateCostModels(this.ptr);
    return Ptr._wrap(ret, Costmdls);
  }

  set_execution_costs(execution_costs) {
    const execution_costsPtr = Ptr._assertClass(execution_costs, ExUnitPrices);
    const ret = CslMobileBridge.protocolParamUpdateSetExecutionCosts(this.ptr, execution_costsPtr);
    return ret;
  }

  async execution_costs() {
    const ret = await CslMobileBridge.protocolParamUpdateExecutionCosts(this.ptr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  set_max_tx_ex_units(max_tx_ex_units) {
    const max_tx_ex_unitsPtr = Ptr._assertClass(max_tx_ex_units, ExUnits);
    const ret = CslMobileBridge.protocolParamUpdateSetMaxTxExUnits(this.ptr, max_tx_ex_unitsPtr);
    return ret;
  }

  async max_tx_ex_units() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxTxExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_block_ex_units(max_block_ex_units) {
    const max_block_ex_unitsPtr = Ptr._assertClass(max_block_ex_units, ExUnits);
    const ret = CslMobileBridge.protocolParamUpdateSetMaxBlockExUnits(this.ptr, max_block_ex_unitsPtr);
    return ret;
  }

  async max_block_ex_units() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxBlockExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_value_size(max_value_size) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxValueSize(this.ptr, max_value_size);
    return ret;
  }

  async max_value_size() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxValueSize(this.ptr);
    return ret;
  }

  set_collateral_percentage(collateral_percentage) {
    const ret = CslMobileBridge.protocolParamUpdateSetCollateralPercentage(this.ptr, collateral_percentage);
    return ret;
  }

  async collateral_percentage() {
    const ret = await CslMobileBridge.protocolParamUpdateCollateralPercentage(this.ptr);
    return ret;
  }

  set_max_collateral_inputs(max_collateral_inputs) {
    const ret = CslMobileBridge.protocolParamUpdateSetMaxCollateralInputs(this.ptr, max_collateral_inputs);
    return ret;
  }

  async max_collateral_inputs() {
    const ret = await CslMobileBridge.protocolParamUpdateMaxCollateralInputs(this.ptr);
    return ret;
  }

  static async new() {
    const ret = await CslMobileBridge.protocolParamUpdateNew();
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

}


export class ProtocolVersion extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.protocolVersionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.protocolVersionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_hex() {
    const ret = await CslMobileBridge.protocolVersionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.protocolVersionFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_json() {
    const ret = await CslMobileBridge.protocolVersionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.protocolVersionFromJson(json);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async major() {
    const ret = await CslMobileBridge.protocolVersionMajor(this.ptr);
    return ret;
  }

  async minor() {
    const ret = await CslMobileBridge.protocolVersionMinor(this.ptr);
    return ret;
  }

  static async new(major, minor) {
    const ret = await CslMobileBridge.protocolVersionNew(major, minor);
    return Ptr._wrap(ret, ProtocolVersion);
  }

}


export class PublicKey extends Ptr {
  static async from_bech32(bech32_str) {
    const ret = await CslMobileBridge.publicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PublicKey);
  }

  async to_bech32() {
    const ret = await CslMobileBridge.publicKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await CslMobileBridge.publicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.publicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PublicKey);
  }

  async verify(data, signature) {
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await CslMobileBridge.publicKeyVerify(this.ptr, b64FromUint8Array(data), signaturePtr);
    return ret;
  }

  async hash() {
    const ret = await CslMobileBridge.publicKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.publicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.publicKeyFromHex(hex_str);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class PublicKeys extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.publicKeysNew();
    return Ptr._wrap(ret, PublicKeys);
  }

  async size() {
    const ret = await CslMobileBridge.publicKeysSize(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.publicKeysGet(this.ptr, index);
    return Ptr._wrap(ret, PublicKey);
  }

  add(key) {
    const keyPtr = Ptr._assertClass(key, PublicKey);
    const ret = CslMobileBridge.publicKeysAdd(this.ptr, keyPtr);
    return ret;
  }

}


export class Redeemer extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.redeemerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.redeemerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemer);
  }

  async to_hex() {
    const ret = await CslMobileBridge.redeemerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.redeemerFromHex(hex_str);
    return Ptr._wrap(ret, Redeemer);
  }

  async to_json() {
    const ret = await CslMobileBridge.redeemerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.redeemerFromJson(json);
    return Ptr._wrap(ret, Redeemer);
  }

  async tag() {
    const ret = await CslMobileBridge.redeemerTag(this.ptr);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async index() {
    const ret = await CslMobileBridge.redeemerIndex(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await CslMobileBridge.redeemerData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async ex_units() {
    const ret = await CslMobileBridge.redeemerExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  static async new(tag, index, data, ex_units) {
    const tagPtr = Ptr._assertClass(tag, RedeemerTag);
    const indexPtr = Ptr._assertClass(index, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
    const ret = await CslMobileBridge.redeemerNew(tagPtr, indexPtr, dataPtr, ex_unitsPtr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class RedeemerTag extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.redeemerTagToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.redeemerTagFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_hex() {
    const ret = await CslMobileBridge.redeemerTagToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.redeemerTagFromHex(hex_str);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_json() {
    const ret = await CslMobileBridge.redeemerTagToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.redeemerTagFromJson(json);
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_spend() {
    const ret = await CslMobileBridge.redeemerTagNewSpend();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_mint() {
    const ret = await CslMobileBridge.redeemerTagNewMint();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_cert() {
    const ret = await CslMobileBridge.redeemerTagNewCert();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_reward() {
    const ret = await CslMobileBridge.redeemerTagNewReward();
    return Ptr._wrap(ret, RedeemerTag);
  }

  async kind() {
    const ret = await CslMobileBridge.redeemerTagKind(this.ptr);
    return ret;
  }

}


export class Redeemers extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.redeemersToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.redeemersFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemers);
  }

  async to_hex() {
    const ret = await CslMobileBridge.redeemersToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.redeemersFromHex(hex_str);
    return Ptr._wrap(ret, Redeemers);
  }

  async to_json() {
    const ret = await CslMobileBridge.redeemersToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.redeemersFromJson(json);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await CslMobileBridge.redeemersNew();
    return Ptr._wrap(ret, Redeemers);
  }

  async len() {
    const ret = await CslMobileBridge.redeemersLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.redeemersGet(this.ptr, index);
    return Ptr._wrap(ret, Redeemer);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Redeemer);
    const ret = CslMobileBridge.redeemersAdd(this.ptr, elemPtr);
    return ret;
  }

  async total_ex_units() {
    const ret = await CslMobileBridge.redeemersTotalExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class Relay extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.relayToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.relayFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relay);
  }

  async to_hex() {
    const ret = await CslMobileBridge.relayToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.relayFromHex(hex_str);
    return Ptr._wrap(ret, Relay);
  }

  async to_json() {
    const ret = await CslMobileBridge.relayToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.relayFromJson(json);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_addr(single_host_addr) {
    const single_host_addrPtr = Ptr._assertClass(single_host_addr, SingleHostAddr);
    const ret = await CslMobileBridge.relayNewSingleHostAddr(single_host_addrPtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_name(single_host_name) {
    const single_host_namePtr = Ptr._assertClass(single_host_name, SingleHostName);
    const ret = await CslMobileBridge.relayNewSingleHostName(single_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_multi_host_name(multi_host_name) {
    const multi_host_namePtr = Ptr._assertClass(multi_host_name, MultiHostName);
    const ret = await CslMobileBridge.relayNewMultiHostName(multi_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  async kind() {
    const ret = await CslMobileBridge.relayKind(this.ptr);
    return ret;
  }

  async as_single_host_addr() {
    const ret = await CslMobileBridge.relayAsSingleHostAddr(this.ptr);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async as_single_host_name() {
    const ret = await CslMobileBridge.relayAsSingleHostName(this.ptr);
    return Ptr._wrap(ret, SingleHostName);
  }

  async as_multi_host_name() {
    const ret = await CslMobileBridge.relayAsMultiHostName(this.ptr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class Relays extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.relaysToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.relaysFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relays);
  }

  async to_hex() {
    const ret = await CslMobileBridge.relaysToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.relaysFromHex(hex_str);
    return Ptr._wrap(ret, Relays);
  }

  async to_json() {
    const ret = await CslMobileBridge.relaysToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.relaysFromJson(json);
    return Ptr._wrap(ret, Relays);
  }

  static async new() {
    const ret = await CslMobileBridge.relaysNew();
    return Ptr._wrap(ret, Relays);
  }

  async len() {
    const ret = await CslMobileBridge.relaysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.relaysGet(this.ptr, index);
    return Ptr._wrap(ret, Relay);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Relay);
    const ret = CslMobileBridge.relaysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class RewardAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const ret = await CslMobileBridge.rewardAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async payment_cred() {
    const ret = await CslMobileBridge.rewardAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_address() {
    const ret = await CslMobileBridge.rewardAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await CslMobileBridge.rewardAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

}


export class RewardAddresses extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.rewardAddressesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.rewardAddressesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_hex() {
    const ret = await CslMobileBridge.rewardAddressesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.rewardAddressesFromHex(hex_str);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_json() {
    const ret = await CslMobileBridge.rewardAddressesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.rewardAddressesFromJson(json);
    return Ptr._wrap(ret, RewardAddresses);
  }

  static async new() {
    const ret = await CslMobileBridge.rewardAddressesNew();
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await CslMobileBridge.rewardAddressesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.rewardAddressesGet(this.ptr, index);
    return Ptr._wrap(ret, RewardAddress);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, RewardAddress);
    const ret = CslMobileBridge.rewardAddressesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptAll extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptAllToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptAllFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptAllToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptAllFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptAllToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptAllFromJson(json);
    return Ptr._wrap(ret, ScriptAll);
  }

  async native_scripts() {
    const ret = await CslMobileBridge.scriptAllNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await CslMobileBridge.scriptAllNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAll);
  }

}


export class ScriptAny extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptAnyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptAnyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptAnyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptAnyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptAnyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptAnyFromJson(json);
    return Ptr._wrap(ret, ScriptAny);
  }

  async native_scripts() {
    const ret = await CslMobileBridge.scriptAnyNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await CslMobileBridge.scriptAnyNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAny);
  }

}


export class ScriptDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.scriptDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.scriptDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.scriptDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.scriptDataHashFromHex(hex);
    return Ptr._wrap(ret, ScriptDataHash);
  }

}


export class ScriptHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.scriptHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.scriptHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.scriptHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.scriptHashFromHex(hex);
    return Ptr._wrap(ret, ScriptHash);
  }

}


export class ScriptHashes extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptHashesFromHex(hex_str);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptHashesFromJson(json);
    return Ptr._wrap(ret, ScriptHashes);
  }

  static async new() {
    const ret = await CslMobileBridge.scriptHashesNew();
    return Ptr._wrap(ret, ScriptHashes);
  }

  async len() {
    const ret = await CslMobileBridge.scriptHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.scriptHashesGet(this.ptr, index);
    return Ptr._wrap(ret, ScriptHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, ScriptHash);
    const ret = CslMobileBridge.scriptHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptNOfK extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptNOfKToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptNOfKFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptNOfKToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptNOfKFromHex(hex_str);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptNOfKToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptNOfKFromJson(json);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async n() {
    const ret = await CslMobileBridge.scriptNOfKN(this.ptr);
    return ret;
  }

  async native_scripts() {
    const ret = await CslMobileBridge.scriptNOfKNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(n, native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await CslMobileBridge.scriptNOfKNew(n, native_scriptsPtr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

}


export class ScriptPubkey extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptPubkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptPubkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptPubkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptPubkeyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptPubkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptPubkeyFromJson(json);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async addr_keyhash() {
    const ret = await CslMobileBridge.scriptPubkeyAddrKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(addr_keyhash) {
    const addr_keyhashPtr = Ptr._assertClass(addr_keyhash, Ed25519KeyHash);
    const ret = await CslMobileBridge.scriptPubkeyNew(addr_keyhashPtr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

}


export class ScriptRef extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.scriptRefToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.scriptRefFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_hex() {
    const ret = await CslMobileBridge.scriptRefToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.scriptRefFromHex(hex_str);
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_json() {
    const ret = await CslMobileBridge.scriptRefToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.scriptRefFromJson(json);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await CslMobileBridge.scriptRefNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_plutus_script(plutus_script) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScript);
    const ret = await CslMobileBridge.scriptRefNewPlutusScript(plutus_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  async is_native_script() {
    const ret = await CslMobileBridge.scriptRefIsNativeScript(this.ptr);
    return ret;
  }

  async is_plutus_script() {
    const ret = await CslMobileBridge.scriptRefIsPlutusScript(this.ptr);
    return ret;
  }

  async native_script() {
    const ret = await CslMobileBridge.scriptRefNativeScript(this.ptr);
    return Ptr._wrap(ret, NativeScript);
  }

  async plutus_script() {
    const ret = await CslMobileBridge.scriptRefPlutusScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

}


export class SingleHostAddr extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.singleHostAddrToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.singleHostAddrFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_hex() {
    const ret = await CslMobileBridge.singleHostAddrToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.singleHostAddrFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_json() {
    const ret = await CslMobileBridge.singleHostAddrToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.singleHostAddrFromJson(json);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async port() {
    const ret = await CslMobileBridge.singleHostAddrPort(this.ptr);
    return ret;
  }

  async ipv4() {
    const ret = await CslMobileBridge.singleHostAddrIpv4(this.ptr);
    return Ptr._wrap(ret, Ipv4);
  }

  async ipv6() {
    const ret = await CslMobileBridge.singleHostAddrIpv6(this.ptr);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(port, ipv4, ipv6) {
    const ipv4Ptr = Ptr._assertOptionalClass(ipv4, Ipv4);
    const ipv6Ptr = Ptr._assertOptionalClass(ipv6, Ipv6);
    if(port == null && ipv4 == null && ipv6 == null) {
      const ret = await CslMobileBridge.singleHostAddrNew();
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 == null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithPort(port);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 == null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithIpv4(ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 == null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithPortIpv4(port, ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 == null && ipv6 != null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithIpv6(ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 != null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithPortIpv6(port, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 != null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithIpv4Ipv6(ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 != null) {
      const ret = await CslMobileBridge.singleHostAddrNewWithPortIpv4Ipv6(port, ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
  }

}


export class SingleHostName extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.singleHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.singleHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_hex() {
    const ret = await CslMobileBridge.singleHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.singleHostNameFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_json() {
    const ret = await CslMobileBridge.singleHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.singleHostNameFromJson(json);
    return Ptr._wrap(ret, SingleHostName);
  }

  async port() {
    const ret = await CslMobileBridge.singleHostNamePort(this.ptr);
    return ret;
  }

  async dns_name() {
    const ret = await CslMobileBridge.singleHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(port, dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordAorAAAA);
    if(port == null) {
      const ret = await CslMobileBridge.singleHostNameNew(dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
    if(port != null) {
      const ret = await CslMobileBridge.singleHostNameNewWithPort(port, dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
  }

}


export class StakeCredential extends Ptr {
  static async from_keyhash(hash) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const ret = await CslMobileBridge.stakeCredentialFromKeyhash(hashPtr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async from_scripthash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const ret = await CslMobileBridge.stakeCredentialFromScripthash(hashPtr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_keyhash() {
    const ret = await CslMobileBridge.stakeCredentialToKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_scripthash() {
    const ret = await CslMobileBridge.stakeCredentialToScripthash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async kind() {
    const ret = await CslMobileBridge.stakeCredentialKind(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await CslMobileBridge.stakeCredentialToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.stakeCredentialFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_hex() {
    const ret = await CslMobileBridge.stakeCredentialToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.stakeCredentialFromHex(hex_str);
    return Ptr._wrap(ret, StakeCredential);
  }

  async to_json() {
    const ret = await CslMobileBridge.stakeCredentialToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.stakeCredentialFromJson(json);
    return Ptr._wrap(ret, StakeCredential);
  }

}


export class StakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.stakeCredentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.stakeCredentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeCredentials);
  }

  async to_hex() {
    const ret = await CslMobileBridge.stakeCredentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.stakeCredentialsFromHex(hex_str);
    return Ptr._wrap(ret, StakeCredentials);
  }

  async to_json() {
    const ret = await CslMobileBridge.stakeCredentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.stakeCredentialsFromJson(json);
    return Ptr._wrap(ret, StakeCredentials);
  }

  static async new() {
    const ret = await CslMobileBridge.stakeCredentialsNew();
    return Ptr._wrap(ret, StakeCredentials);
  }

  async len() {
    const ret = await CslMobileBridge.stakeCredentialsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.stakeCredentialsGet(this.ptr, index);
    return Ptr._wrap(ret, StakeCredential);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, StakeCredential);
    const ret = CslMobileBridge.stakeCredentialsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class StakeDelegation extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.stakeDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.stakeDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_hex() {
    const ret = await CslMobileBridge.stakeDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.stakeDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_json() {
    const ret = await CslMobileBridge.stakeDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.stakeDelegationFromJson(json);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async stake_credential() {
    const ret = await CslMobileBridge.stakeDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  async pool_keyhash() {
    const ret = await CslMobileBridge.stakeDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(stake_credential, pool_keyhash) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await CslMobileBridge.stakeDelegationNew(stake_credentialPtr, pool_keyhashPtr);
    return Ptr._wrap(ret, StakeDelegation);
  }

}


export class StakeDeregistration extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.stakeDeregistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.stakeDeregistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_hex() {
    const ret = await CslMobileBridge.stakeDeregistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.stakeDeregistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_json() {
    const ret = await CslMobileBridge.stakeDeregistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.stakeDeregistrationFromJson(json);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async stake_credential() {
    const ret = await CslMobileBridge.stakeDeregistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const ret = await CslMobileBridge.stakeDeregistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

}


export class StakeRegistration extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.stakeRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.stakeRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_hex() {
    const ret = await CslMobileBridge.stakeRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.stakeRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_json() {
    const ret = await CslMobileBridge.stakeRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.stakeRegistrationFromJson(json);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async stake_credential() {
    const ret = await CslMobileBridge.stakeRegistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, StakeCredential);
    const ret = await CslMobileBridge.stakeRegistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

}


export class Strings extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.stringsNew();
    return Ptr._wrap(ret, Strings);
  }

  async len() {
    const ret = await CslMobileBridge.stringsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.stringsGet(this.ptr, index);
    return ret;
  }

  add(elem) {
    const ret = CslMobileBridge.stringsAdd(this.ptr, elem);
    return ret;
  }

}


export class TimelockExpiry extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.timelockExpiryToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.timelockExpiryFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_hex() {
    const ret = await CslMobileBridge.timelockExpiryToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.timelockExpiryFromHex(hex_str);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_json() {
    const ret = await CslMobileBridge.timelockExpiryToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.timelockExpiryFromJson(json);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async slot() {
    const ret = await CslMobileBridge.timelockExpirySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await CslMobileBridge.timelockExpirySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await CslMobileBridge.timelockExpiryNew(slot);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  static async new_timelockexpiry(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await CslMobileBridge.timelockExpiryNewTimelockexpiry(slotPtr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

}


export class TimelockStart extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.timelockStartToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.timelockStartFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_hex() {
    const ret = await CslMobileBridge.timelockStartToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.timelockStartFromHex(hex_str);
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_json() {
    const ret = await CslMobileBridge.timelockStartToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.timelockStartFromJson(json);
    return Ptr._wrap(ret, TimelockStart);
  }

  async slot() {
    const ret = await CslMobileBridge.timelockStartSlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await CslMobileBridge.timelockStartSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await CslMobileBridge.timelockStartNew(slot);
    return Ptr._wrap(ret, TimelockStart);
  }

  static async new_timelockstart(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await CslMobileBridge.timelockStartNewTimelockstart(slotPtr);
    return Ptr._wrap(ret, TimelockStart);
  }

}


export class Transaction extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Transaction);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionFromHex(hex_str);
    return Ptr._wrap(ret, Transaction);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionFromJson(json);
    return Ptr._wrap(ret, Transaction);
  }

  async body() {
    const ret = await CslMobileBridge.transactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async witness_set() {
    const ret = await CslMobileBridge.transactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async is_valid() {
    const ret = await CslMobileBridge.transactionIsValid(this.ptr);
    return ret;
  }

  async auxiliary_data() {
    const ret = await CslMobileBridge.transactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_is_valid(valid) {
    const ret = CslMobileBridge.transactionSetIsValid(this.ptr, valid);
    return ret;
  }

  static async new(body, witness_set, auxiliary_data) {
    const bodyPtr = Ptr._assertClass(body, TransactionBody);
    const witness_setPtr = Ptr._assertClass(witness_set, TransactionWitnessSet);
    const auxiliary_dataPtr = Ptr._assertOptionalClass(auxiliary_data, AuxiliaryData);
    if(auxiliary_data == null) {
      const ret = await CslMobileBridge.transactionNew(bodyPtr, witness_setPtr);
      return Ptr._wrap(ret, Transaction);
    }
    if(auxiliary_data != null) {
      const ret = await CslMobileBridge.transactionNewWithAuxiliaryData(bodyPtr, witness_setPtr, auxiliary_dataPtr);
      return Ptr._wrap(ret, Transaction);
    }
  }

}


export class TransactionBatch extends Ptr {
  async len() {
    const ret = await CslMobileBridge.transactionBatchLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionBatchGet(this.ptr, index);
    return Ptr._wrap(ret, Transaction);
  }

}


export class TransactionBatchList extends Ptr {
  async len() {
    const ret = await CslMobileBridge.transactionBatchListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionBatchListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBatch);
  }

}


export class TransactionBodies extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionBodiesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionBodiesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionBodiesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionBodiesFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionBodiesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionBodiesFromJson(json);
    return Ptr._wrap(ret, TransactionBodies);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionBodiesNew();
    return Ptr._wrap(ret, TransactionBodies);
  }

  async len() {
    const ret = await CslMobileBridge.transactionBodiesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionBodiesGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBody);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionBody);
    const ret = CslMobileBridge.transactionBodiesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionBody extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionBodyFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionBodyFromJson(json);
    return Ptr._wrap(ret, TransactionBody);
  }

  async inputs() {
    const ret = await CslMobileBridge.transactionBodyInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async outputs() {
    const ret = await CslMobileBridge.transactionBodyOutputs(this.ptr);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async fee() {
    const ret = await CslMobileBridge.transactionBodyFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async ttl() {
    const ret = await CslMobileBridge.transactionBodyTtl(this.ptr);
    return ret;
  }

  async ttl_bignum() {
    const ret = await CslMobileBridge.transactionBodyTtlBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ttl(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = CslMobileBridge.transactionBodySetTtl(this.ptr, ttlPtr);
    return ret;
  }

  remove_ttl() {
    const ret = CslMobileBridge.transactionBodyRemoveTtl(this.ptr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = CslMobileBridge.transactionBodySetCerts(this.ptr, certsPtr);
    return ret;
  }

  async certs() {
    const ret = await CslMobileBridge.transactionBodyCerts(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = CslMobileBridge.transactionBodySetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async withdrawals() {
    const ret = await CslMobileBridge.transactionBodyWithdrawals(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

  set_update(update) {
    const updatePtr = Ptr._assertClass(update, Update);
    const ret = CslMobileBridge.transactionBodySetUpdate(this.ptr, updatePtr);
    return ret;
  }

  async update() {
    const ret = await CslMobileBridge.transactionBodyUpdate(this.ptr);
    return Ptr._wrap(ret, Update);
  }

  set_auxiliary_data_hash(auxiliary_data_hash) {
    const auxiliary_data_hashPtr = Ptr._assertClass(auxiliary_data_hash, AuxiliaryDataHash);
    const ret = CslMobileBridge.transactionBodySetAuxiliaryDataHash(this.ptr, auxiliary_data_hashPtr);
    return ret;
  }

  async auxiliary_data_hash() {
    const ret = await CslMobileBridge.transactionBodyAuxiliaryDataHash(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = CslMobileBridge.transactionBodySetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = CslMobileBridge.transactionBodySetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  async validity_start_interval_bignum() {
    const ret = await CslMobileBridge.transactionBodyValidityStartIntervalBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async validity_start_interval() {
    const ret = await CslMobileBridge.transactionBodyValidityStartInterval(this.ptr);
    return ret;
  }

  set_mint(mint) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const ret = CslMobileBridge.transactionBodySetMint(this.ptr, mintPtr);
    return ret;
  }

  async mint() {
    const ret = await CslMobileBridge.transactionBodyMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async multiassets() {
    const ret = await CslMobileBridge.transactionBodyMultiassets(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  set_reference_inputs(reference_inputs) {
    const reference_inputsPtr = Ptr._assertClass(reference_inputs, TransactionInputs);
    const ret = CslMobileBridge.transactionBodySetReferenceInputs(this.ptr, reference_inputsPtr);
    return ret;
  }

  async reference_inputs() {
    const ret = await CslMobileBridge.transactionBodyReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_script_data_hash(script_data_hash) {
    const script_data_hashPtr = Ptr._assertClass(script_data_hash, ScriptDataHash);
    const ret = CslMobileBridge.transactionBodySetScriptDataHash(this.ptr, script_data_hashPtr);
    return ret;
  }

  async script_data_hash() {
    const ret = await CslMobileBridge.transactionBodyScriptDataHash(this.ptr);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TransactionInputs);
    const ret = CslMobileBridge.transactionBodySetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  async collateral() {
    const ret = await CslMobileBridge.transactionBodyCollateral(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_required_signers(required_signers) {
    const required_signersPtr = Ptr._assertClass(required_signers, Ed25519KeyHashes);
    const ret = CslMobileBridge.transactionBodySetRequiredSigners(this.ptr, required_signersPtr);
    return ret;
  }

  async required_signers() {
    const ret = await CslMobileBridge.transactionBodyRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  set_network_id(network_id) {
    const network_idPtr = Ptr._assertClass(network_id, NetworkId);
    const ret = CslMobileBridge.transactionBodySetNetworkId(this.ptr, network_idPtr);
    return ret;
  }

  async network_id() {
    const ret = await CslMobileBridge.transactionBodyNetworkId(this.ptr);
    return Ptr._wrap(ret, NetworkId);
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = CslMobileBridge.transactionBodySetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  async collateral_return() {
    const ret = await CslMobileBridge.transactionBodyCollateralReturn(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = CslMobileBridge.transactionBodySetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  async total_collateral() {
    const ret = await CslMobileBridge.transactionBodyTotalCollateral(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(inputs, outputs, fee, ttl) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    if(ttl == null) {
      const ret = await CslMobileBridge.transactionBodyNew(inputsPtr, outputsPtr, feePtr);
      return Ptr._wrap(ret, TransactionBody);
    }
    if(ttl != null) {
      const ret = await CslMobileBridge.transactionBodyNewWithTtl(inputsPtr, outputsPtr, feePtr, ttl);
      return Ptr._wrap(ret, TransactionBody);
    }
  }

  static async new_tx_body(inputs, outputs, fee) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = await CslMobileBridge.transactionBodyNewTxBody(inputsPtr, outputsPtr, feePtr);
    return Ptr._wrap(ret, TransactionBody);
  }

}


export class TransactionBuilder extends Ptr {
  add_inputs_from(inputs, strategy) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const ret = CslMobileBridge.transactionBuilderAddInputsFrom(this.ptr, inputsPtr, strategy);
    return ret;
  }

  set_inputs(inputs) {
    const inputsPtr = Ptr._assertClass(inputs, TxInputsBuilder);
    const ret = CslMobileBridge.transactionBuilderSetInputs(this.ptr, inputsPtr);
    return ret;
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TxInputsBuilder);
    const ret = CslMobileBridge.transactionBuilderSetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = CslMobileBridge.transactionBuilderSetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_collateral_return_and_total(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = CslMobileBridge.transactionBuilderSetCollateralReturnAndTotal(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = CslMobileBridge.transactionBuilderSetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  set_total_collateral_and_return(total_collateral, return_address) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const return_addressPtr = Ptr._assertClass(return_address, Address);
    const ret = CslMobileBridge.transactionBuilderSetTotalCollateralAndReturn(this.ptr, total_collateralPtr, return_addressPtr);
    return ret;
  }

  add_reference_input(reference_input) {
    const reference_inputPtr = Ptr._assertClass(reference_input, TransactionInput);
    const ret = CslMobileBridge.transactionBuilderAddReferenceInput(this.ptr, reference_inputPtr);
    return ret;
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_script_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddScriptInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddBootstrapInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.transactionBuilderAddInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async count_missing_input_scripts() {
    const ret = await CslMobileBridge.transactionBuilderCountMissingInputScripts(this.ptr);
    return ret;
  }

  async add_required_native_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, NativeScripts);
    const ret = await CslMobileBridge.transactionBuilderAddRequiredNativeInputScripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_plutus_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, PlutusWitnesses);
    const ret = await CslMobileBridge.transactionBuilderAddRequiredPlutusInputScripts(this.ptr, scriptsPtr);
    return ret;
  }

  async get_native_input_scripts() {
    const ret = await CslMobileBridge.transactionBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await CslMobileBridge.transactionBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async fee_for_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await CslMobileBridge.transactionBuilderFeeForInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return Ptr._wrap(ret, BigNum);
  }

  add_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = CslMobileBridge.transactionBuilderAddOutput(this.ptr, outputPtr);
    return ret;
  }

  async fee_for_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await CslMobileBridge.transactionBuilderFeeForOutput(this.ptr, outputPtr);
    return Ptr._wrap(ret, BigNum);
  }

  set_fee(fee) {
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = CslMobileBridge.transactionBuilderSetFee(this.ptr, feePtr);
    return ret;
  }

  set_ttl(ttl) {
    const ret = CslMobileBridge.transactionBuilderSetTtl(this.ptr, ttl);
    return ret;
  }

  set_ttl_bignum(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = CslMobileBridge.transactionBuilderSetTtlBignum(this.ptr, ttlPtr);
    return ret;
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = CslMobileBridge.transactionBuilderSetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = CslMobileBridge.transactionBuilderSetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = CslMobileBridge.transactionBuilderSetCerts(this.ptr, certsPtr);
    return ret;
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = CslMobileBridge.transactionBuilderSetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async get_auxiliary_data() {
    const ret = await CslMobileBridge.transactionBuilderGetAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_auxiliary_data(auxiliary_data) {
    const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
    const ret = CslMobileBridge.transactionBuilderSetAuxiliaryData(this.ptr, auxiliary_dataPtr);
    return ret;
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = CslMobileBridge.transactionBuilderSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  add_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valPtr = Ptr._assertClass(val, TransactionMetadatum);
    const ret = CslMobileBridge.transactionBuilderAddMetadatum(this.ptr, keyPtr, valPtr);
    return ret;
  }

  add_json_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = CslMobileBridge.transactionBuilderAddJsonMetadatum(this.ptr, keyPtr, val);
    return ret;
  }

  add_json_metadatum_with_schema(key, val, schema) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = CslMobileBridge.transactionBuilderAddJsonMetadatumWithSchema(this.ptr, keyPtr, val, schema);
    return ret;
  }

  set_mint_builder(mint_builder) {
    const mint_builderPtr = Ptr._assertClass(mint_builder, MintBuilder);
    const ret = CslMobileBridge.transactionBuilderSetMintBuilder(this.ptr, mint_builderPtr);
    return ret;
  }

  async get_mint_builder() {
    const ret = await CslMobileBridge.transactionBuilderGetMintBuilder(this.ptr);
    return Ptr._wrap(ret, MintBuilder);
  }

  set_mint(mint, mint_scripts) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const mint_scriptsPtr = Ptr._assertClass(mint_scripts, NativeScripts);
    const ret = CslMobileBridge.transactionBuilderSetMint(this.ptr, mintPtr, mint_scriptsPtr);
    return ret;
  }

  async get_mint() {
    const ret = await CslMobileBridge.transactionBuilderGetMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_mint_scripts() {
    const ret = await CslMobileBridge.transactionBuilderGetMintScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_mint_asset(policy_script, mint_assets) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = CslMobileBridge.transactionBuilderSetMintAsset(this.ptr, policy_scriptPtr, mint_assetsPtr);
    return ret;
  }

  add_mint_asset(policy_script, asset_name, amount) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = CslMobileBridge.transactionBuilderAddMintAsset(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr);
    return ret;
  }

  add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const output_coinPtr = Ptr._assertClass(output_coin, BigNum);
    const ret = CslMobileBridge.transactionBuilderAddMintAssetAndOutput(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr, output_coinPtr);
    return ret;
  }

  add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const ret = CslMobileBridge.transactionBuilderAddMintAssetAndOutputMinRequiredCoin(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr);
    return ret;
  }

  static async new(cfg) {
    const cfgPtr = Ptr._assertClass(cfg, TransactionBuilderConfig);
    const ret = await CslMobileBridge.transactionBuilderNew(cfgPtr);
    return Ptr._wrap(ret, TransactionBuilder);
  }

  async get_reference_inputs() {
    const ret = await CslMobileBridge.transactionBuilderGetReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_explicit_input() {
    const ret = await CslMobileBridge.transactionBuilderGetExplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_implicit_input() {
    const ret = await CslMobileBridge.transactionBuilderGetImplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_input() {
    const ret = await CslMobileBridge.transactionBuilderGetTotalInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_output() {
    const ret = await CslMobileBridge.transactionBuilderGetTotalOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_explicit_output() {
    const ret = await CslMobileBridge.transactionBuilderGetExplicitOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_deposit() {
    const ret = await CslMobileBridge.transactionBuilderGetDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_fee_if_set() {
    const ret = await CslMobileBridge.transactionBuilderGetFeeIfSet(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async add_change_if_needed(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await CslMobileBridge.transactionBuilderAddChangeIfNeeded(this.ptr, addressPtr);
    return ret;
  }

  calc_script_data_hash(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = CslMobileBridge.transactionBuilderCalcScriptDataHash(this.ptr, cost_modelsPtr);
    return ret;
  }

  set_script_data_hash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptDataHash);
    const ret = CslMobileBridge.transactionBuilderSetScriptDataHash(this.ptr, hashPtr);
    return ret;
  }

  remove_script_data_hash() {
    const ret = CslMobileBridge.transactionBuilderRemoveScriptDataHash(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = CslMobileBridge.transactionBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  async full_size() {
    const ret = await CslMobileBridge.transactionBuilderFullSize(this.ptr);
    return ret;
  }

  async output_sizes() {
    const ret = await CslMobileBridge.transactionBuilderOutputSizes(this.ptr);
    return base64ToUint32Array(ret);
  }

  async build() {
    const ret = await CslMobileBridge.transactionBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async build_tx() {
    const ret = await CslMobileBridge.transactionBuilderBuildTx(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async build_tx_unsafe() {
    const ret = await CslMobileBridge.transactionBuilderBuildTxUnsafe(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async min_fee() {
    const ret = await CslMobileBridge.transactionBuilderMinFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class TransactionBuilderConfig extends Ptr {
}


export class TransactionBuilderConfigBuilder extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderNew();
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async fee_algo(fee_algo) {
    const fee_algoPtr = Ptr._assertClass(fee_algo, LinearFee);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderFeeAlgo(this.ptr, fee_algoPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_word(coins_per_utxo_word) {
    const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderCoinsPerUtxoWord(this.ptr, coins_per_utxo_wordPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_byte(coins_per_utxo_byte) {
    const coins_per_utxo_bytePtr = Ptr._assertClass(coins_per_utxo_byte, BigNum);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderCoinsPerUtxoByte(this.ptr, coins_per_utxo_bytePtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async ex_unit_prices(ex_unit_prices) {
    const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderExUnitPrices(this.ptr, ex_unit_pricesPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderPoolDeposit(this.ptr, pool_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderKeyDeposit(this.ptr, key_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_value_size(max_value_size) {
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderMaxValueSize(this.ptr, max_value_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_tx_size(max_tx_size) {
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderMaxTxSize(this.ptr, max_tx_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async prefer_pure_change(prefer_pure_change) {
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderPreferPureChange(this.ptr, prefer_pure_change);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async build() {
    const ret = await CslMobileBridge.transactionBuilderConfigBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBuilderConfig);
  }

}


export class TransactionHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.transactionHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.transactionHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.transactionHashFromBech32(bech_str);
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.transactionHashFromHex(hex);
    return Ptr._wrap(ret, TransactionHash);
  }

}


export class TransactionInput extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionInputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionInputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionInputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionInputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionInputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionInputFromJson(json);
    return Ptr._wrap(ret, TransactionInput);
  }

  async transaction_id() {
    const ret = await CslMobileBridge.transactionInputTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await CslMobileBridge.transactionInputIndex(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await CslMobileBridge.transactionInputNew(transaction_idPtr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class TransactionInputs extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionInputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionInputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionInputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionInputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionInputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionInputsFromJson(json);
    return Ptr._wrap(ret, TransactionInputs);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionInputsNew();
    return Ptr._wrap(ret, TransactionInputs);
  }

  async len() {
    const ret = await CslMobileBridge.transactionInputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionInputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionInput);
    const ret = CslMobileBridge.transactionInputsAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await CslMobileBridge.transactionInputsToOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class TransactionMetadatum extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionMetadatumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionMetadatumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionMetadatumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionMetadatumFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, MetadataMap);
    const ret = await CslMobileBridge.transactionMetadatumNewMap(mapPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, MetadataList);
    const ret = await CslMobileBridge.transactionMetadatumNewList(listPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_int(int_value) {
    const int_valuePtr = Ptr._assertClass(int_value, Int);
    const ret = await CslMobileBridge.transactionMetadatumNewInt(int_valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_bytes(bytes) {
    const ret = await CslMobileBridge.transactionMetadatumNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_text(text) {
    const ret = await CslMobileBridge.transactionMetadatumNewText(text);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async kind() {
    const ret = await CslMobileBridge.transactionMetadatumKind(this.ptr);
    return ret;
  }

  async as_map() {
    const ret = await CslMobileBridge.transactionMetadatumAsMap(this.ptr);
    return Ptr._wrap(ret, MetadataMap);
  }

  async as_list() {
    const ret = await CslMobileBridge.transactionMetadatumAsList(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

  async as_int() {
    const ret = await CslMobileBridge.transactionMetadatumAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  async as_bytes() {
    const ret = await CslMobileBridge.transactionMetadatumAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async as_text() {
    const ret = await CslMobileBridge.transactionMetadatumAsText(this.ptr);
    return ret;
  }

}


export class TransactionMetadatumLabels extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionMetadatumLabelsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionMetadatumLabelsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionMetadatumLabelsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionMetadatumLabelsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionMetadatumLabelsNew();
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async len() {
    const ret = await CslMobileBridge.transactionMetadatumLabelsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionMetadatumLabelsGet(this.ptr, index);
    return Ptr._wrap(ret, BigNum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BigNum);
    const ret = CslMobileBridge.transactionMetadatumLabelsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionOutput extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionOutputFromJson(json);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async address() {
    const ret = await CslMobileBridge.transactionOutputAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  async amount() {
    const ret = await CslMobileBridge.transactionOutputAmount(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async data_hash() {
    const ret = await CslMobileBridge.transactionOutputDataHash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async plutus_data() {
    const ret = await CslMobileBridge.transactionOutputPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async script_ref() {
    const ret = await CslMobileBridge.transactionOutputScriptRef(this.ptr);
    return Ptr._wrap(ret, ScriptRef);
  }

  set_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = CslMobileBridge.transactionOutputSetScriptRef(this.ptr, script_refPtr);
    return ret;
  }

  set_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = CslMobileBridge.transactionOutputSetPlutusData(this.ptr, dataPtr);
    return ret;
  }

  set_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = CslMobileBridge.transactionOutputSetDataHash(this.ptr, data_hashPtr);
    return ret;
  }

  async has_plutus_data() {
    const ret = await CslMobileBridge.transactionOutputHasPlutusData(this.ptr);
    return ret;
  }

  async has_data_hash() {
    const ret = await CslMobileBridge.transactionOutputHasDataHash(this.ptr);
    return ret;
  }

  async has_script_ref() {
    const ret = await CslMobileBridge.transactionOutputHasScriptRef(this.ptr);
    return ret;
  }

  static async new(address, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await CslMobileBridge.transactionOutputNew(addressPtr, amountPtr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionOutputAmountBuilder extends Ptr {
  async with_value(amount) {
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await CslMobileBridge.transactionOutputAmountBuilderWithValue(this.ptr, amountPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await CslMobileBridge.transactionOutputAmountBuilderWithCoin(this.ptr, coinPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin_and_asset(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await CslMobileBridge.transactionOutputAmountBuilderWithCoinAndAsset(this.ptr, coinPtr, multiassetPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin(multiasset, coins_per_utxo_word) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
    const ret = await CslMobileBridge.transactionOutputAmountBuilderWithAssetAndMinRequiredCoin(this.ptr, multiassetPtr, coins_per_utxo_wordPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const data_costPtr = Ptr._assertClass(data_cost, DataCost);
    const ret = await CslMobileBridge.transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(this.ptr, multiassetPtr, data_costPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async build() {
    const ret = await CslMobileBridge.transactionOutputAmountBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionOutputBuilder extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.transactionOutputBuilderNew();
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await CslMobileBridge.transactionOutputBuilderWithAddress(this.ptr, addressPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await CslMobileBridge.transactionOutputBuilderWithDataHash(this.ptr, data_hashPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await CslMobileBridge.transactionOutputBuilderWithPlutusData(this.ptr, dataPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = await CslMobileBridge.transactionOutputBuilderWithScriptRef(this.ptr, script_refPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async next() {
    const ret = await CslMobileBridge.transactionOutputBuilderNext(this.ptr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

}


export class TransactionOutputs extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionOutputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionOutputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionOutputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionOutputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionOutputsNew();
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async len() {
    const ret = await CslMobileBridge.transactionOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionOutput);
    const ret = CslMobileBridge.transactionOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionUnspentOutput extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionUnspentOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionUnspentOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionUnspentOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionUnspentOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionUnspentOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionUnspentOutputFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  static async new(input, output) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await CslMobileBridge.transactionUnspentOutputNew(inputPtr, outputPtr);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async input() {
    const ret = await CslMobileBridge.transactionUnspentOutputInput(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

  async output() {
    const ret = await CslMobileBridge.transactionUnspentOutputOutput(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionUnspentOutputs extends Ptr {
  async to_json() {
    const ret = await CslMobileBridge.transactionUnspentOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionUnspentOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionUnspentOutputsNew();
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  async len() {
    const ret = await CslMobileBridge.transactionUnspentOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionUnspentOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionUnspentOutput);
    const ret = CslMobileBridge.transactionUnspentOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionWitnessSet extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionWitnessSetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionWitnessSetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionWitnessSetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionWitnessSetFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionWitnessSetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionWitnessSetFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  set_vkeys(vkeys) {
    const vkeysPtr = Ptr._assertClass(vkeys, Vkeywitnesses);
    const ret = CslMobileBridge.transactionWitnessSetSetVkeys(this.ptr, vkeysPtr);
    return ret;
  }

  async vkeys() {
    const ret = await CslMobileBridge.transactionWitnessSetVkeys(this.ptr);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = CslMobileBridge.transactionWitnessSetSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await CslMobileBridge.transactionWitnessSetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_bootstraps(bootstraps) {
    const bootstrapsPtr = Ptr._assertClass(bootstraps, BootstrapWitnesses);
    const ret = CslMobileBridge.transactionWitnessSetSetBootstraps(this.ptr, bootstrapsPtr);
    return ret;
  }

  async bootstraps() {
    const ret = await CslMobileBridge.transactionWitnessSetBootstraps(this.ptr);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = CslMobileBridge.transactionWitnessSetSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await CslMobileBridge.transactionWitnessSetPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_data(plutus_data) {
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusList);
    const ret = CslMobileBridge.transactionWitnessSetSetPlutusData(this.ptr, plutus_dataPtr);
    return ret;
  }

  async plutus_data() {
    const ret = await CslMobileBridge.transactionWitnessSetPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_redeemers(redeemers) {
    const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
    const ret = CslMobileBridge.transactionWitnessSetSetRedeemers(this.ptr, redeemersPtr);
    return ret;
  }

  async redeemers() {
    const ret = await CslMobileBridge.transactionWitnessSetRedeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionWitnessSetNew();
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

}


export class TransactionWitnessSets extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.transactionWitnessSetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.transactionWitnessSetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_hex() {
    const ret = await CslMobileBridge.transactionWitnessSetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.transactionWitnessSetsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_json() {
    const ret = await CslMobileBridge.transactionWitnessSetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.transactionWitnessSetsFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  static async new() {
    const ret = await CslMobileBridge.transactionWitnessSetsNew();
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async len() {
    const ret = await CslMobileBridge.transactionWitnessSetsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.transactionWitnessSetsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionWitnessSet);
    const ret = CslMobileBridge.transactionWitnessSetsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TxBuilderConstants extends Ptr {
  static async plutus_default_cost_models() {
    const ret = await CslMobileBridge.txBuilderConstantsPlutusDefaultCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_alonzo_cost_models() {
    const ret = await CslMobileBridge.txBuilderConstantsPlutusAlonzoCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_vasil_cost_models() {
    const ret = await CslMobileBridge.txBuilderConstantsPlutusVasilCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

}


export class TxInputsBuilder extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.txInputsBuilderNew();
    return Ptr._wrap(ret, TxInputsBuilder);
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_script_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddScriptInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddBootstrapInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = CslMobileBridge.txInputsBuilderAddInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async count_missing_input_scripts() {
    const ret = await CslMobileBridge.txInputsBuilderCountMissingInputScripts(this.ptr);
    return ret;
  }

  async add_required_native_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, NativeScripts);
    const ret = await CslMobileBridge.txInputsBuilderAddRequiredNativeInputScripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_plutus_input_scripts(scripts) {
    const scriptsPtr = Ptr._assertClass(scripts, PlutusWitnesses);
    const ret = await CslMobileBridge.txInputsBuilderAddRequiredPlutusInputScripts(this.ptr, scriptsPtr);
    return ret;
  }

  async add_required_script_input_witnesses(inputs_with_wit) {
    const inputs_with_witPtr = Ptr._assertClass(inputs_with_wit, InputsWithScriptWitness);
    const ret = await CslMobileBridge.txInputsBuilderAddRequiredScriptInputWitnesses(this.ptr, inputs_with_witPtr);
    return ret;
  }

  async get_ref_inputs() {
    const ret = await CslMobileBridge.txInputsBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_input_scripts() {
    const ret = await CslMobileBridge.txInputsBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await CslMobileBridge.txInputsBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await CslMobileBridge.txInputsBuilderLen(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = CslMobileBridge.txInputsBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  add_required_signers(keys) {
    const keysPtr = Ptr._assertClass(keys, Ed25519KeyHashes);
    const ret = CslMobileBridge.txInputsBuilderAddRequiredSigners(this.ptr, keysPtr);
    return ret;
  }

  async total_value() {
    const ret = await CslMobileBridge.txInputsBuilderTotalValue(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async inputs() {
    const ret = await CslMobileBridge.txInputsBuilderInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async inputs_option() {
    const ret = await CslMobileBridge.txInputsBuilderInputsOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class URL extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.uRLToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.uRLFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, URL);
  }

  async to_hex() {
    const ret = await CslMobileBridge.uRLToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.uRLFromHex(hex_str);
    return Ptr._wrap(ret, URL);
  }

  async to_json() {
    const ret = await CslMobileBridge.uRLToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.uRLFromJson(json);
    return Ptr._wrap(ret, URL);
  }

  static async new(url) {
    const ret = await CslMobileBridge.uRLNew(url);
    return Ptr._wrap(ret, URL);
  }

  async url() {
    const ret = await CslMobileBridge.uRLUrl(this.ptr);
    return ret;
  }

}


export class UnitInterval extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.unitIntervalToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.unitIntervalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_hex() {
    const ret = await CslMobileBridge.unitIntervalToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.unitIntervalFromHex(hex_str);
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_json() {
    const ret = await CslMobileBridge.unitIntervalToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.unitIntervalFromJson(json);
    return Ptr._wrap(ret, UnitInterval);
  }

  async numerator() {
    const ret = await CslMobileBridge.unitIntervalNumerator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async denominator() {
    const ret = await CslMobileBridge.unitIntervalDenominator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(numerator, denominator) {
    const numeratorPtr = Ptr._assertClass(numerator, BigNum);
    const denominatorPtr = Ptr._assertClass(denominator, BigNum);
    const ret = await CslMobileBridge.unitIntervalNew(numeratorPtr, denominatorPtr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class Update extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.updateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.updateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Update);
  }

  async to_hex() {
    const ret = await CslMobileBridge.updateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.updateFromHex(hex_str);
    return Ptr._wrap(ret, Update);
  }

  async to_json() {
    const ret = await CslMobileBridge.updateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.updateFromJson(json);
    return Ptr._wrap(ret, Update);
  }

  async proposed_protocol_parameter_updates() {
    const ret = await CslMobileBridge.updateProposedProtocolParameterUpdates(this.ptr);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async epoch() {
    const ret = await CslMobileBridge.updateEpoch(this.ptr);
    return ret;
  }

  static async new(proposed_protocol_parameter_updates, epoch) {
    const proposed_protocol_parameter_updatesPtr = Ptr._assertClass(proposed_protocol_parameter_updates, ProposedProtocolParameterUpdates);
    const ret = await CslMobileBridge.updateNew(proposed_protocol_parameter_updatesPtr, epoch);
    return Ptr._wrap(ret, Update);
  }

}


export class VRFCert extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.vRFCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vRFCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFCert);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vRFCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.vRFCertFromHex(hex_str);
    return Ptr._wrap(ret, VRFCert);
  }

  async to_json() {
    const ret = await CslMobileBridge.vRFCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.vRFCertFromJson(json);
    return Ptr._wrap(ret, VRFCert);
  }

  async output() {
    const ret = await CslMobileBridge.vRFCertOutput(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async proof() {
    const ret = await CslMobileBridge.vRFCertProof(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(output, proof) {
    const ret = await CslMobileBridge.vRFCertNew(b64FromUint8Array(output), b64FromUint8Array(proof));
    return Ptr._wrap(ret, VRFCert);
  }

}


export class VRFKeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vRFKeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.vRFKeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.vRFKeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.vRFKeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vRFKeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.vRFKeyHashFromHex(hex);
    return Ptr._wrap(ret, VRFKeyHash);
  }

}


export class VRFVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vRFVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_bytes() {
    const ret = await CslMobileBridge.vRFVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await CslMobileBridge.vRFVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await CslMobileBridge.vRFVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vRFVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await CslMobileBridge.vRFVKeyFromHex(hex);
    return Ptr._wrap(ret, VRFVKey);
  }

}


export class Value extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.valueToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.valueFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Value);
  }

  async to_hex() {
    const ret = await CslMobileBridge.valueToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.valueFromHex(hex_str);
    return Ptr._wrap(ret, Value);
  }

  async to_json() {
    const ret = await CslMobileBridge.valueToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.valueFromJson(json);
    return Ptr._wrap(ret, Value);
  }

  static async new(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await CslMobileBridge.valueNew(coinPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_from_assets(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await CslMobileBridge.valueNewFromAssets(multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_with_assets(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await CslMobileBridge.valueNewWithAssets(coinPtr, multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async zero() {
    const ret = await CslMobileBridge.valueZero();
    return Ptr._wrap(ret, Value);
  }

  async is_zero() {
    const ret = await CslMobileBridge.valueIsZero(this.ptr);
    return ret;
  }

  async coin() {
    const ret = await CslMobileBridge.valueCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = CslMobileBridge.valueSetCoin(this.ptr, coinPtr);
    return ret;
  }

  async multiasset() {
    const ret = await CslMobileBridge.valueMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  set_multiasset(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = CslMobileBridge.valueSetMultiasset(this.ptr, multiassetPtr);
    return ret;
  }

  async checked_add(rhs) {
    const rhsPtr = Ptr._assertClass(rhs, Value);
    const ret = await CslMobileBridge.valueCheckedAdd(this.ptr, rhsPtr);
    return Ptr._wrap(ret, Value);
  }

  async checked_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await CslMobileBridge.valueCheckedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async clamped_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await CslMobileBridge.valueClampedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await CslMobileBridge.valueCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

}


export class Vkey extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.vkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkey);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.vkeyFromHex(hex_str);
    return Ptr._wrap(ret, Vkey);
  }

  async to_json() {
    const ret = await CslMobileBridge.vkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.vkeyFromJson(json);
    return Ptr._wrap(ret, Vkey);
  }

  static async new(pk) {
    const pkPtr = Ptr._assertClass(pk, PublicKey);
    const ret = await CslMobileBridge.vkeyNew(pkPtr);
    return Ptr._wrap(ret, Vkey);
  }

  async public_key() {
    const ret = await CslMobileBridge.vkeyPublicKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class Vkeys extends Ptr {
  static async new() {
    const ret = await CslMobileBridge.vkeysNew();
    return Ptr._wrap(ret, Vkeys);
  }

  async len() {
    const ret = await CslMobileBridge.vkeysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.vkeysGet(this.ptr, index);
    return Ptr._wrap(ret, Vkey);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkey);
    const ret = CslMobileBridge.vkeysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Vkeywitness extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.vkeywitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vkeywitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vkeywitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.vkeywitnessFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_json() {
    const ret = await CslMobileBridge.vkeywitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.vkeywitnessFromJson(json);
    return Ptr._wrap(ret, Vkeywitness);
  }

  static async new(vkey, signature) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await CslMobileBridge.vkeywitnessNew(vkeyPtr, signaturePtr);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async vkey() {
    const ret = await CslMobileBridge.vkeywitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await CslMobileBridge.vkeywitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class Vkeywitnesses extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.vkeywitnessesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.vkeywitnessesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_hex() {
    const ret = await CslMobileBridge.vkeywitnessesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.vkeywitnessesFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_json() {
    const ret = await CslMobileBridge.vkeywitnessesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.vkeywitnessesFromJson(json);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  static async new() {
    const ret = await CslMobileBridge.vkeywitnessesNew();
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async len() {
    const ret = await CslMobileBridge.vkeywitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await CslMobileBridge.vkeywitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, Vkeywitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkeywitness);
    const ret = CslMobileBridge.vkeywitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Withdrawals extends Ptr {
  async to_bytes() {
    const ret = await CslMobileBridge.withdrawalsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await CslMobileBridge.withdrawalsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_hex() {
    const ret = await CslMobileBridge.withdrawalsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await CslMobileBridge.withdrawalsFromHex(hex_str);
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_json() {
    const ret = await CslMobileBridge.withdrawalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await CslMobileBridge.withdrawalsFromJson(json);
    return Ptr._wrap(ret, Withdrawals);
  }

  static async new() {
    const ret = await CslMobileBridge.withdrawalsNew();
    return Ptr._wrap(ret, Withdrawals);
  }

  async len() {
    const ret = await CslMobileBridge.withdrawalsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await CslMobileBridge.withdrawalsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await CslMobileBridge.withdrawalsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await CslMobileBridge.withdrawalsKeys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

}


export const calculate_ex_units_ceil_cost = async (ex_units, ex_unit_prices) => {
  const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await CslMobileBridge.calculateExUnitsCeilCost(ex_unitsPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const create_send_all = async (address, utxos, config) => {
  const addressPtr = Ptr._assertClass(address, Address);
  const utxosPtr = Ptr._assertClass(utxos, TransactionUnspentOutputs);
  const configPtr = Ptr._assertClass(config, TransactionBuilderConfig);
  const ret = await CslMobileBridge.createSendAll(addressPtr, utxosPtr, configPtr);
  return Ptr._wrap(ret, TransactionBatchList);
};


export const decode_arbitrary_bytes_from_metadatum = async (metadata) => {
  const metadataPtr = Ptr._assertClass(metadata, TransactionMetadatum);
  const ret = await CslMobileBridge.decodeArbitraryBytesFromMetadatum(metadataPtr);
  return uint8ArrayFromB64(ret);
};


export const decode_metadatum_to_json_str = async (metadatum, schema) => {
  const metadatumPtr = Ptr._assertClass(metadatum, TransactionMetadatum);
  const ret = await CslMobileBridge.decodeMetadatumToJsonStr(metadatumPtr, schema);
  return ret;
};


export const decode_plutus_datum_to_json_str = async (datum, schema) => {
  const datumPtr = Ptr._assertClass(datum, PlutusData);
  const ret = await CslMobileBridge.decodePlutusDatumToJsonStr(datumPtr, schema);
  return ret;
};


export const decrypt_with_password = async (password, data) => {
  const ret = await CslMobileBridge.decryptWithPassword(password, data);
  return ret;
};


export const encode_arbitrary_bytes_as_metadatum = async (bytes) => {
  const ret = await CslMobileBridge.encodeArbitraryBytesAsMetadatum(b64FromUint8Array(bytes));
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_metadatum = async (json, schema) => {
  const ret = await CslMobileBridge.encodeJsonStrToMetadatum(json, schema);
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_native_script = async (json, self_xpub, schema) => {
  const ret = await CslMobileBridge.encodeJsonStrToNativeScript(json, self_xpub, schema);
  return Ptr._wrap(ret, NativeScript);
};


export const encode_json_str_to_plutus_datum = async (json, schema) => {
  const ret = await CslMobileBridge.encodeJsonStrToPlutusDatum(json, schema);
  return Ptr._wrap(ret, PlutusData);
};


export const encrypt_with_password = async (password, salt, nonce, data) => {
  const ret = await CslMobileBridge.encryptWithPassword(password, salt, nonce, data);
  return ret;
};


export const get_deposit = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await CslMobileBridge.getDeposit(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, BigNum);
};


export const get_implicit_input = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await CslMobileBridge.getImplicitInput(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, Value);
};


export const hash_auxiliary_data = async (auxiliary_data) => {
  const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
  const ret = await CslMobileBridge.hashAuxiliaryData(auxiliary_dataPtr);
  return Ptr._wrap(ret, AuxiliaryDataHash);
};


export const hash_plutus_data = async (plutus_data) => {
  const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
  const ret = await CslMobileBridge.hashPlutusData(plutus_dataPtr);
  return Ptr._wrap(ret, DataHash);
};


export const hash_script_data = async (redeemers, cost_models, datums) => {
  const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
  const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
  const datumsPtr = Ptr._assertOptionalClass(datums, PlutusList);
  if(datums == null) {
    const ret = await CslMobileBridge.hashScriptData(redeemersPtr, cost_modelsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
  if(datums != null) {
    const ret = await CslMobileBridge.hashScriptDataWithDatums(redeemersPtr, cost_modelsPtr, datumsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
};


export const hash_transaction = async (tx_body) => {
  const tx_bodyPtr = Ptr._assertClass(tx_body, TransactionBody);
  const ret = await CslMobileBridge.hashTransaction(tx_bodyPtr);
  return Ptr._wrap(ret, TransactionHash);
};


export const make_daedalus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, LegacyDaedalusPrivateKey);
  const ret = await CslMobileBridge.makeDaedalusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const make_icarus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await CslMobileBridge.makeIcarusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const make_vkey_witness = async (tx_body_hash, sk) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await CslMobileBridge.makeVkeyWitness(tx_body_hashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
};


export const min_ada_for_output = async (output, data_cost) => {
  const outputPtr = Ptr._assertClass(output, TransactionOutput);
  const data_costPtr = Ptr._assertClass(data_cost, DataCost);
  const ret = await CslMobileBridge.minAdaForOutput(outputPtr, data_costPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_ada_required = async (assets, has_data_hash, coins_per_utxo_word) => {
  const assetsPtr = Ptr._assertClass(assets, Value);
  const coins_per_utxo_wordPtr = Ptr._assertClass(coins_per_utxo_word, BigNum);
  const ret = await CslMobileBridge.minAdaRequired(assetsPtr, has_data_hash, coins_per_utxo_wordPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_fee = async (tx, linear_fee) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const linear_feePtr = Ptr._assertClass(linear_fee, LinearFee);
  const ret = await CslMobileBridge.minFee(txPtr, linear_feePtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_script_fee = async (tx, ex_unit_prices) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await CslMobileBridge.minScriptFee(txPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const CertificateKind = Object.freeze({
  StakeRegistration: 0,
  StakeDeregistration: 1,
  StakeDelegation: 2,
  PoolRegistration: 3,
  PoolRetirement: 4,
  GenesisKeyDelegation: 5,
  MoveInstantaneousRewardsCert: 6,
});


export const CoinSelectionStrategyCIP2 = Object.freeze({
  LargestFirst: 0,
  RandomImprove: 1,
  LargestFirstMultiAsset: 2,
  RandomImproveMultiAsset: 3,
});


export const LanguageKind = Object.freeze({
  PlutusV1: 0,
  PlutusV2: 1,
});


export const MIRKind = Object.freeze({
  ToOtherPot: 0,
  ToStakeCredentials: 1,
});


export const MIRPot = Object.freeze({
  Reserves: 0,
  Treasury: 1,
});


export const MetadataJsonSchema = Object.freeze({
  NoConversions: 0,
  BasicConversions: 1,
  DetailedSchema: 2,
});


export const NativeScriptKind = Object.freeze({
  ScriptPubkey: 0,
  ScriptAll: 1,
  ScriptAny: 2,
  ScriptNOfK: 3,
  TimelockStart: 4,
  TimelockExpiry: 5,
});


export const NetworkIdKind = Object.freeze({
  Testnet: 0,
  Mainnet: 1,
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


export const RedeemerTagKind = Object.freeze({
  Spend: 0,
  Mint: 1,
  Cert: 2,
  Reward: 3,
});


export const RelayKind = Object.freeze({
  SingleHostAddr: 0,
  SingleHostName: 1,
  MultiHostName: 2,
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


