/* eslint-disable max-len */
import { NativeModules } from 'react-native';
import { decode as base64_decode, encode as base64_encode } from 'base-64';

const { HaskellShelley } = NativeModules;

// export default HaskellShelley;

function uint8ArrayFromB64(base64_string) {
  if (base64_string == null) {
    return undefined;
  }
  return Uint8Array.from(base64_decode(base64_string), c => c.charCodeAt(0));
}

function b64FromUint8Array(uint8Array) {
  if (uint8Array == null) {
    return undefined;
  }
  return base64_encode(String.fromCharCode.apply(null, uint8Array));
}

function uint32ArrayToBase64(uint32Array) {
  if (uint32Array == null) {
    return undefined;
  }
  const uint8Array = new Uint8Array(uint32Array.length * 4);
  const dataView = new DataView(uint8Array.buffer);
  for (let i = 0; i < uint32Array.length; i++) {
    dataView.setUint32(i * 4, uint32Array[i], true);
  }
  return b64FromUint8Array(uint8Array);
}

function base64ToUint32Array(base64String) {
  if (base64String == null) {
    return undefined;
  }
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

export class Address extends Ptr {
  static async from_bytes(data) {
    const ret = await HaskellShelley.csl_bridge_addressFromBytes(b64FromUint8Array(data));
    return Ptr._wrap(ret, Address);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_addressToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_addressFromJson(json);
    return Ptr._wrap(ret, Address);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_addressKind(this.ptr);
    return ret;
  }

  async payment_cred() {
    const ret = await HaskellShelley.csl_bridge_addressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async is_malformed() {
    const ret = await HaskellShelley.csl_bridge_addressIsMalformed(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_addressToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_addressFromHex(hex_str);
    return Ptr._wrap(ret, Address);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_addressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    if(prefix == null) {
      const ret = await HaskellShelley.csl_bridge_addressToBech32(this.ptr);
      return ret;
    }
    if(prefix != null) {
      const ret = await HaskellShelley.csl_bridge_addressToBech32WithPrefix(this.ptr, prefix);
      return ret;
    }
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_addressFromBech32(bech_str);
    return Ptr._wrap(ret, Address);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_addressNetworkId(this.ptr);
    return ret;
  }

}


export class Anchor extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_anchorToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_anchorFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Anchor);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_anchorToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_anchorFromHex(hex_str);
    return Ptr._wrap(ret, Anchor);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_anchorToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_anchorFromJson(json);
    return Ptr._wrap(ret, Anchor);
  }

  async url() {
    const ret = await HaskellShelley.csl_bridge_anchorUrl(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async anchor_data_hash() {
    const ret = await HaskellShelley.csl_bridge_anchorAnchorDataHash(this.ptr);
    return Ptr._wrap(ret, AnchorDataHash);
  }

  static async new(anchor_url, anchor_data_hash) {
    const anchor_urlPtr = Ptr._assertClass(anchor_url, URL);
    const anchor_data_hashPtr = Ptr._assertClass(anchor_data_hash, AnchorDataHash);
    const ret = await HaskellShelley.csl_bridge_anchorNew(anchor_urlPtr, anchor_data_hashPtr);
    return Ptr._wrap(ret, Anchor);
  }

}


export class AnchorDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AnchorDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, AnchorDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_anchorDataHashFromHex(hex);
    return Ptr._wrap(ret, AnchorDataHash);
  }

}


export class AssetName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_assetNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_assetNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetName);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_assetNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_assetNameFromHex(hex_str);
    return Ptr._wrap(ret, AssetName);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_assetNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_assetNameFromJson(json);
    return Ptr._wrap(ret, AssetName);
  }

  static async new(name) {
    const ret = await HaskellShelley.csl_bridge_assetNameNew(b64FromUint8Array(name));
    return Ptr._wrap(ret, AssetName);
  }

  async name() {
    const ret = await HaskellShelley.csl_bridge_assetNameName(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class AssetNames extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_assetNamesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_assetNamesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetNames);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_assetNamesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_assetNamesFromHex(hex_str);
    return Ptr._wrap(ret, AssetNames);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_assetNamesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_assetNamesFromJson(json);
    return Ptr._wrap(ret, AssetNames);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_assetNamesNew();
    return Ptr._wrap(ret, AssetNames);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_assetNamesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_assetNamesGet(this.ptr, index);
    return Ptr._wrap(ret, AssetName);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, AssetName);
    const ret = HaskellShelley.csl_bridge_assetNamesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Assets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_assetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_assetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Assets);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_assetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_assetsFromHex(hex_str);
    return Ptr._wrap(ret, Assets);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_assetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_assetsFromJson(json);
    return Ptr._wrap(ret, Assets);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_assetsNew();
    return Ptr._wrap(ret, Assets);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_assetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.csl_bridge_assetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.csl_bridge_assetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_assetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class AuxiliaryData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataFromHex(hex_str);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataFromJson(json);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataNew();
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async metadata() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataMetadata(this.ptr);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.csl_bridge_auxiliaryDataSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.csl_bridge_auxiliaryDataSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.csl_bridge_auxiliaryDataSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async prefer_alonzo_format() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataPreferAlonzoFormat(this.ptr);
    return ret;
  }

  set_prefer_alonzo_format(prefer) {
    const ret = HaskellShelley.csl_bridge_auxiliaryDataSetPreferAlonzoFormat(this.ptr, prefer);
    return ret;
  }

}


export class AuxiliaryDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataHashFromHex(hex);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

}


export class AuxiliaryDataSet extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataSetNew();
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataSetLen(this.ptr);
    return ret;
  }

  async insert(tx_index, data) {
    const dataPtr = Ptr._assertClass(data, AuxiliaryData);
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataSetInsert(this.ptr, tx_index, dataPtr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async get(tx_index) {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataSetGet(this.ptr, tx_index);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async indices() {
    const ret = await HaskellShelley.csl_bridge_auxiliaryDataSetIndices(this.ptr);
    return base64ToUint32Array(ret);
  }

}


export class BaseAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const stakePtr = Ptr._assertClass(stake, Credential);
    const ret = await HaskellShelley.csl_bridge_baseAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.csl_bridge_baseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async stake_cred() {
    const ret = await HaskellShelley.csl_bridge_baseAddressStakeCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_baseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_baseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_baseAddressNetworkId(this.ptr);
    return ret;
  }

}


export class BigInt extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_bigIntToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bigIntFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigInt);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bigIntToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bigIntFromHex(hex_str);
    return Ptr._wrap(ret, BigInt);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_bigIntToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_bigIntFromJson(json);
    return Ptr._wrap(ret, BigInt);
  }

  async is_zero() {
    const ret = await HaskellShelley.csl_bridge_bigIntIsZero(this.ptr);
    return ret;
  }

  async as_u64() {
    const ret = await HaskellShelley.csl_bridge_bigIntAsU64(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_int() {
    const ret = await HaskellShelley.csl_bridge_bigIntAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  static async from_str(text) {
    const ret = await HaskellShelley.csl_bridge_bigIntFromStr(text);
    return Ptr._wrap(ret, BigInt);
  }

  async to_str() {
    const ret = await HaskellShelley.csl_bridge_bigIntToStr(this.ptr);
    return ret;
  }

  async add(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.csl_bridge_bigIntAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async sub(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.csl_bridge_bigIntSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async mul(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.csl_bridge_bigIntMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async pow(exp) {
    const ret = await HaskellShelley.csl_bridge_bigIntPow(this.ptr, exp);
    return Ptr._wrap(ret, BigInt);
  }

  static async one() {
    const ret = await HaskellShelley.csl_bridge_bigIntOne();
    return Ptr._wrap(ret, BigInt);
  }

  static async zero() {
    const ret = await HaskellShelley.csl_bridge_bigIntZero();
    return Ptr._wrap(ret, BigInt);
  }

  async abs() {
    const ret = await HaskellShelley.csl_bridge_bigIntAbs(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async increment() {
    const ret = await HaskellShelley.csl_bridge_bigIntIncrement(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async div_ceil(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.csl_bridge_bigIntDivCeil(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async div_floor(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.csl_bridge_bigIntDivFloor(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

}


export class BigNum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_bigNumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bigNumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigNum);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bigNumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bigNumFromHex(hex_str);
    return Ptr._wrap(ret, BigNum);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_bigNumToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_bigNumFromJson(json);
    return Ptr._wrap(ret, BigNum);
  }

  static async from_str(string) {
    const ret = await HaskellShelley.csl_bridge_bigNumFromStr(string);
    return Ptr._wrap(ret, BigNum);
  }

  async to_str() {
    const ret = await HaskellShelley.csl_bridge_bigNumToStr(this.ptr);
    return ret;
  }

  static async zero() {
    const ret = await HaskellShelley.csl_bridge_bigNumZero();
    return Ptr._wrap(ret, BigNum);
  }

  static async one() {
    const ret = await HaskellShelley.csl_bridge_bigNumOne();
    return Ptr._wrap(ret, BigNum);
  }

  async is_zero() {
    const ret = await HaskellShelley.csl_bridge_bigNumIsZero(this.ptr);
    return ret;
  }

  async div_floor(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumDivFloor(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_mul(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumCheckedMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_add(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumCheckedAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumCheckedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async clamped_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumClampedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

  async less_than(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumLessThan(this.ptr, rhs_valuePtr);
    return ret;
  }

  static async max_value() {
    const ret = await HaskellShelley.csl_bridge_bigNumMaxValue();
    return Ptr._wrap(ret, BigNum);
  }

  static async max(a, b) {
    const aPtr = Ptr._assertClass(a, BigNum);
    const bPtr = Ptr._assertClass(b, BigNum);
    const ret = await HaskellShelley.csl_bridge_bigNumMax(aPtr, bPtr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class Bip32PrivateKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  static async from_128_xprv(bytes) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyFrom_128Xprv(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_128_xprv() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyTo_128Xprv(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async generate_ed25519_bip32() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyGenerateEd25519Bip32();
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_public() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyToBech32(this.ptr);
    return ret;
  }

  static async from_bip39_entropy(entropy, password) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyFromBip39Entropy(b64FromUint8Array(entropy), b64FromUint8Array(password));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async chaincode() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bip32PrivateKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

}


export class Bip32PublicKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyToBech32(this.ptr);
    return ret;
  }

  async chaincode() {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bip32PublicKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

}


export class Block extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_blockToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_blockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Block);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_blockToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_blockFromHex(hex_str);
    return Ptr._wrap(ret, Block);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_blockToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_blockFromJson(json);
    return Ptr._wrap(ret, Block);
  }

  async header() {
    const ret = await HaskellShelley.csl_bridge_blockHeader(this.ptr);
    return Ptr._wrap(ret, Header);
  }

  async transaction_bodies() {
    const ret = await HaskellShelley.csl_bridge_blockTransactionBodies(this.ptr);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async transaction_witness_sets() {
    const ret = await HaskellShelley.csl_bridge_blockTransactionWitnessSets(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async auxiliary_data_set() {
    const ret = await HaskellShelley.csl_bridge_blockAuxiliaryDataSet(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async invalid_transactions() {
    const ret = await HaskellShelley.csl_bridge_blockInvalidTransactions(this.ptr);
    return base64ToUint32Array(ret);
  }

  static async new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions) {
    const headerPtr = Ptr._assertClass(header, Header);
    const transaction_bodiesPtr = Ptr._assertClass(transaction_bodies, TransactionBodies);
    const transaction_witness_setsPtr = Ptr._assertClass(transaction_witness_sets, TransactionWitnessSets);
    const auxiliary_data_setPtr = Ptr._assertClass(auxiliary_data_set, AuxiliaryDataSet);
    const ret = await HaskellShelley.csl_bridge_blockNew(headerPtr, transaction_bodiesPtr, transaction_witness_setsPtr, auxiliary_data_setPtr, uint32ArrayToBase64(invalid_transactions));
    return Ptr._wrap(ret, Block);
  }

}


export class BlockHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_blockHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BlockHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_blockHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_blockHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_blockHashFromBech32(bech_str);
    return Ptr._wrap(ret, BlockHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_blockHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_blockHashFromHex(hex);
    return Ptr._wrap(ret, BlockHash);
  }

}


export class BootstrapWitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessFromHex(hex_str);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessFromJson(json);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async vkey() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async chain_code() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessChainCode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async attributes() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(vkey, signature, chain_code, attributes) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessNew(vkeyPtr, signaturePtr, b64FromUint8Array(chain_code), b64FromUint8Array(attributes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

}


export class BootstrapWitnesses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesFromHex(hex_str);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesFromJson(json);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesNew();
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, BootstrapWitness);
    const ret = await HaskellShelley.csl_bridge_bootstrapWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ByronAddress extends Ptr {
  async to_base58() {
    const ret = await HaskellShelley.csl_bridge_byronAddressToBase58(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_byronAddressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_byronAddressFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ByronAddress);
  }

  async byron_protocol_magic() {
    const ret = await HaskellShelley.csl_bridge_byronAddressByronProtocolMagic(this.ptr);
    return ret;
  }

  async attributes() {
    const ret = await HaskellShelley.csl_bridge_byronAddressAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_byronAddressNetworkId(this.ptr);
    return ret;
  }

  static async from_base58(s) {
    const ret = await HaskellShelley.csl_bridge_byronAddressFromBase58(s);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async icarus_from_key(key, protocol_magic) {
    const keyPtr = Ptr._assertClass(key, Bip32PublicKey);
    const ret = await HaskellShelley.csl_bridge_byronAddressIcarusFromKey(keyPtr, protocol_magic);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async is_valid(s) {
    const ret = await HaskellShelley.csl_bridge_byronAddressIsValid(s);
    return ret;
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_byronAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_byronAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, ByronAddress);
  }

}


export class Certificate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_certificateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_certificateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificate);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_certificateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_certificateFromHex(hex_str);
    return Ptr._wrap(ret, Certificate);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_certificateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_certificateFromJson(json);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration(stake_registration) {
    const stake_registrationPtr = Ptr._assertClass(stake_registration, StakeRegistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeRegistration(stake_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_reg_cert(stake_registration) {
    const stake_registrationPtr = Ptr._assertClass(stake_registration, StakeRegistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewRegCert(stake_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_deregistration(stake_deregistration) {
    const stake_deregistrationPtr = Ptr._assertClass(stake_deregistration, StakeDeregistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeDeregistration(stake_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_unreg_cert(stake_deregistration) {
    const stake_deregistrationPtr = Ptr._assertClass(stake_deregistration, StakeDeregistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewUnregCert(stake_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_delegation(stake_delegation) {
    const stake_delegationPtr = Ptr._assertClass(stake_delegation, StakeDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeDelegation(stake_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_registration(pool_registration) {
    const pool_registrationPtr = Ptr._assertClass(pool_registration, PoolRegistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewPoolRegistration(pool_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_retirement(pool_retirement) {
    const pool_retirementPtr = Ptr._assertClass(pool_retirement, PoolRetirement);
    const ret = await HaskellShelley.csl_bridge_certificateNewPoolRetirement(pool_retirementPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_genesis_key_delegation(genesis_key_delegation) {
    const genesis_key_delegationPtr = Ptr._assertClass(genesis_key_delegation, GenesisKeyDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewGenesisKeyDelegation(genesis_key_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert) {
    const move_instantaneous_rewards_certPtr = Ptr._assertClass(move_instantaneous_rewards_cert, MoveInstantaneousRewardsCert);
    const ret = await HaskellShelley.csl_bridge_certificateNewMoveInstantaneousRewardsCert(move_instantaneous_rewards_certPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_committee_hot_auth(committee_hot_auth) {
    const committee_hot_authPtr = Ptr._assertClass(committee_hot_auth, CommitteeHotAuth);
    const ret = await HaskellShelley.csl_bridge_certificateNewCommitteeHotAuth(committee_hot_authPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_committee_cold_resign(committee_cold_resign) {
    const committee_cold_resignPtr = Ptr._assertClass(committee_cold_resign, CommitteeColdResign);
    const ret = await HaskellShelley.csl_bridge_certificateNewCommitteeColdResign(committee_cold_resignPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_deregistration(drep_deregistration) {
    const drep_deregistrationPtr = Ptr._assertClass(drep_deregistration, DRepDeregistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewDrepDeregistration(drep_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_registration(drep_registration) {
    const drep_registrationPtr = Ptr._assertClass(drep_registration, DRepRegistration);
    const ret = await HaskellShelley.csl_bridge_certificateNewDrepRegistration(drep_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_update(drep_update) {
    const drep_updatePtr = Ptr._assertClass(drep_update, DRepUpdate);
    const ret = await HaskellShelley.csl_bridge_certificateNewDrepUpdate(drep_updatePtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_and_vote_delegation(stake_and_vote_delegation) {
    const stake_and_vote_delegationPtr = Ptr._assertClass(stake_and_vote_delegation, StakeAndVoteDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeAndVoteDelegation(stake_and_vote_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration_and_delegation(stake_registration_and_delegation) {
    const stake_registration_and_delegationPtr = Ptr._assertClass(stake_registration_and_delegation, StakeRegistrationAndDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeRegistrationAndDelegation(stake_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_vote_registration_and_delegation(stake_vote_registration_and_delegation) {
    const stake_vote_registration_and_delegationPtr = Ptr._assertClass(stake_vote_registration_and_delegation, StakeVoteRegistrationAndDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewStakeVoteRegistrationAndDelegation(stake_vote_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_vote_delegation(vote_delegation) {
    const vote_delegationPtr = Ptr._assertClass(vote_delegation, VoteDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewVoteDelegation(vote_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_vote_registration_and_delegation(vote_registration_and_delegation) {
    const vote_registration_and_delegationPtr = Ptr._assertClass(vote_registration_and_delegation, VoteRegistrationAndDelegation);
    const ret = await HaskellShelley.csl_bridge_certificateNewVoteRegistrationAndDelegation(vote_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_certificateKind(this.ptr);
    return ret;
  }

  async as_stake_registration() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeRegistration(this.ptr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async as_reg_cert() {
    const ret = await HaskellShelley.csl_bridge_certificateAsRegCert(this.ptr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async as_stake_deregistration() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeDeregistration(this.ptr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async as_unreg_cert() {
    const ret = await HaskellShelley.csl_bridge_certificateAsUnregCert(this.ptr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async as_stake_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeDelegation(this.ptr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async as_pool_registration() {
    const ret = await HaskellShelley.csl_bridge_certificateAsPoolRegistration(this.ptr);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async as_pool_retirement() {
    const ret = await HaskellShelley.csl_bridge_certificateAsPoolRetirement(this.ptr);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async as_genesis_key_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsGenesisKeyDelegation(this.ptr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async as_move_instantaneous_rewards_cert() {
    const ret = await HaskellShelley.csl_bridge_certificateAsMoveInstantaneousRewardsCert(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async as_committee_hot_auth() {
    const ret = await HaskellShelley.csl_bridge_certificateAsCommitteeHotAuth(this.ptr);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async as_committee_cold_resign() {
    const ret = await HaskellShelley.csl_bridge_certificateAsCommitteeColdResign(this.ptr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async as_drep_deregistration() {
    const ret = await HaskellShelley.csl_bridge_certificateAsDrepDeregistration(this.ptr);
    return Ptr._wrap(ret, DRepDeregistration);
  }

  async as_drep_registration() {
    const ret = await HaskellShelley.csl_bridge_certificateAsDrepRegistration(this.ptr);
    return Ptr._wrap(ret, DRepRegistration);
  }

  async as_drep_update() {
    const ret = await HaskellShelley.csl_bridge_certificateAsDrepUpdate(this.ptr);
    return Ptr._wrap(ret, DRepUpdate);
  }

  async as_stake_and_vote_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeAndVoteDelegation(this.ptr);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async as_stake_registration_and_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async as_stake_vote_registration_and_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsStakeVoteRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async as_vote_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsVoteDelegation(this.ptr);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async as_vote_registration_and_delegation() {
    const ret = await HaskellShelley.csl_bridge_certificateAsVoteRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async has_required_script_witness() {
    const ret = await HaskellShelley.csl_bridge_certificateHasRequiredScriptWitness(this.ptr);
    return ret;
  }

}


export class Certificates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_certificatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_certificatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificates);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_certificatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_certificatesFromHex(hex_str);
    return Ptr._wrap(ret, Certificates);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_certificatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_certificatesFromJson(json);
    return Ptr._wrap(ret, Certificates);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_certificatesNew();
    return Ptr._wrap(ret, Certificates);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_certificatesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_certificatesGet(this.ptr, index);
    return Ptr._wrap(ret, Certificate);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, Certificate);
    const ret = await HaskellShelley.csl_bridge_certificatesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class CertificatesBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderNew();
    return Ptr._wrap(ret, CertificatesBuilder);
  }

  add(cert) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const ret = HaskellShelley.csl_bridge_certificatesBuilderAdd(this.ptr, certPtr);
    return ret;
  }

  add_with_plutus_witness(cert, witness) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.csl_bridge_certificatesBuilderAddWithPlutusWitness(this.ptr, certPtr, witnessPtr);
    return ret;
  }

  add_with_native_script(cert, native_script_source) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.csl_bridge_certificatesBuilderAddWithNativeScript(this.ptr, certPtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_certificates_refund(pool_deposit, key_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderGetCertificatesRefund(this.ptr, pool_depositPtr, key_depositPtr);
    return Ptr._wrap(ret, Value);
  }

  async get_certificates_deposit(pool_deposit, key_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderGetCertificatesDeposit(this.ptr, pool_depositPtr, key_depositPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_certificatesBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

}


export class ChangeConfig extends Ptr {
  static async new(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.csl_bridge_changeConfigNew(addressPtr);
    return Ptr._wrap(ret, ChangeConfig);
  }

  async change_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.csl_bridge_changeConfigChangeAddress(this.ptr, addressPtr);
    return Ptr._wrap(ret, ChangeConfig);
  }

  async change_plutus_data(plutus_data) {
    const plutus_dataPtr = Ptr._assertClass(plutus_data, OutputDatum);
    const ret = await HaskellShelley.csl_bridge_changeConfigChangePlutusData(this.ptr, plutus_dataPtr);
    return Ptr._wrap(ret, ChangeConfig);
  }

  async change_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = await HaskellShelley.csl_bridge_changeConfigChangeScriptRef(this.ptr, script_refPtr);
    return Ptr._wrap(ret, ChangeConfig);
  }

}


export class Committee extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_committeeToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_committeeFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Committee);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_committeeToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_committeeFromHex(hex_str);
    return Ptr._wrap(ret, Committee);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_committeeToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_committeeFromJson(json);
    return Ptr._wrap(ret, Committee);
  }

  static async new(quorum_threshold) {
    const quorum_thresholdPtr = Ptr._assertClass(quorum_threshold, UnitInterval);
    const ret = await HaskellShelley.csl_bridge_committeeNew(quorum_thresholdPtr);
    return Ptr._wrap(ret, Committee);
  }

  async members_keys() {
    const ret = await HaskellShelley.csl_bridge_committeeMembersKeys(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

  async quorum_threshold() {
    const ret = await HaskellShelley.csl_bridge_committeeQuorumThreshold(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  add_member(committee_cold_credential, epoch) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const ret = HaskellShelley.csl_bridge_committeeAddMember(this.ptr, committee_cold_credentialPtr, epoch);
    return ret;
  }

  async get_member_epoch(committee_cold_credential) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_committeeGetMemberEpoch(this.ptr, committee_cold_credentialPtr);
    return ret;
  }

}


export class CommitteeColdResign extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignFromHex(hex_str);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignFromJson(json);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async committee_cold_credential() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignCommitteeColdCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(committee_cold_credential) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_committeeColdResignNew(committee_cold_credentialPtr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  static async new_with_anchor(committee_cold_credential, anchor) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.csl_bridge_committeeColdResignNewWithAnchor(committee_cold_credentialPtr, anchorPtr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_committeeColdResignHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class CommitteeHotAuth extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthFromHex(hex_str);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthFromJson(json);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async committee_cold_credential() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthCommitteeColdCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async committee_hot_credential() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthCommitteeHotCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  static async new(committee_cold_credential, committee_hot_credential) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const committee_hot_credentialPtr = Ptr._assertClass(committee_hot_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthNew(committee_cold_credentialPtr, committee_hot_credentialPtr);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_committeeHotAuthHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Constitution extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_constitutionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_constitutionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Constitution);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_constitutionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_constitutionFromHex(hex_str);
    return Ptr._wrap(ret, Constitution);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_constitutionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_constitutionFromJson(json);
    return Ptr._wrap(ret, Constitution);
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_constitutionAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  async script_hash() {
    const ret = await HaskellShelley.csl_bridge_constitutionScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(anchor) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.csl_bridge_constitutionNew(anchorPtr);
    return Ptr._wrap(ret, Constitution);
  }

  static async new_with_script_hash(anchor, script_hash) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_constitutionNewWithScriptHash(anchorPtr, script_hashPtr);
    return Ptr._wrap(ret, Constitution);
  }

}


export class ConstrPlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataFromHex(hex_str);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async alternative() {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataAlternative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new(alternative, data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusList);
    const ret = await HaskellShelley.csl_bridge_constrPlutusDataNew(alternativePtr, dataPtr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

}


export class CostModel extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_costModelToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_costModelFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CostModel);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_costModelToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_costModelFromHex(hex_str);
    return Ptr._wrap(ret, CostModel);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_costModelToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_costModelFromJson(json);
    return Ptr._wrap(ret, CostModel);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_costModelNew();
    return Ptr._wrap(ret, CostModel);
  }

  async set(operation, cost) {
    const costPtr = Ptr._assertClass(cost, Int);
    const ret = await HaskellShelley.csl_bridge_costModelSet(this.ptr, operation, costPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(operation) {
    const ret = await HaskellShelley.csl_bridge_costModelGet(this.ptr, operation);
    return Ptr._wrap(ret, Int);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_costModelLen(this.ptr);
    return ret;
  }

}


export class Costmdls extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_costmdlsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_costmdlsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Costmdls);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_costmdlsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_costmdlsFromHex(hex_str);
    return Ptr._wrap(ret, Costmdls);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_costmdlsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_costmdlsFromJson(json);
    return Ptr._wrap(ret, Costmdls);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_costmdlsNew();
    return Ptr._wrap(ret, Costmdls);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_costmdlsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, Language);
    const valuePtr = Ptr._assertClass(value, CostModel);
    const ret = await HaskellShelley.csl_bridge_costmdlsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, CostModel);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, Language);
    const ret = await HaskellShelley.csl_bridge_costmdlsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, CostModel);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_costmdlsKeys(this.ptr);
    return Ptr._wrap(ret, Languages);
  }

  async retain_language_versions(languages) {
    const languagesPtr = Ptr._assertClass(languages, Languages);
    const ret = await HaskellShelley.csl_bridge_costmdlsRetainLanguageVersions(this.ptr, languagesPtr);
    return Ptr._wrap(ret, Costmdls);
  }

}


export class Credential extends Ptr {
  static async from_keyhash(hash) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_credentialFromKeyhash(hashPtr);
    return Ptr._wrap(ret, Credential);
  }

  static async from_scripthash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_credentialFromScripthash(hashPtr);
    return Ptr._wrap(ret, Credential);
  }

  async to_keyhash() {
    const ret = await HaskellShelley.csl_bridge_credentialToKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_scripthash() {
    const ret = await HaskellShelley.csl_bridge_credentialToScripthash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_credentialKind(this.ptr);
    return ret;
  }

  async has_script_hash() {
    const ret = await HaskellShelley.csl_bridge_credentialHasScriptHash(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_credentialToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_credentialFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Credential);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_credentialToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_credentialFromHex(hex_str);
    return Ptr._wrap(ret, Credential);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_credentialToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_credentialFromJson(json);
    return Ptr._wrap(ret, Credential);
  }

}


export class Credentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_credentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_credentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Credentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_credentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_credentialsFromHex(hex_str);
    return Ptr._wrap(ret, Credentials);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_credentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_credentialsFromJson(json);
    return Ptr._wrap(ret, Credentials);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_credentialsNew();
    return Ptr._wrap(ret, Credentials);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_credentialsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_credentialsGet(this.ptr, index);
    return Ptr._wrap(ret, Credential);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, Credential);
    const ret = await HaskellShelley.csl_bridge_credentialsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class DNSRecordAorAAAA extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAAFromJson(json);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAANew(dns_name);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async record() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordAorAAAARecord(this.ptr);
    return ret;
  }

}


export class DNSRecordSRV extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVFromJson(json);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVNew(dns_name);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async record() {
    const ret = await HaskellShelley.csl_bridge_dNSRecordSRVRecord(this.ptr);
    return ret;
  }

}


export class DRep extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dRepToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dRepFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRep);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dRepToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dRepFromHex(hex_str);
    return Ptr._wrap(ret, DRep);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dRepToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dRepFromJson(json);
    return Ptr._wrap(ret, DRep);
  }

  static async new_key_hash(key_hash) {
    const key_hashPtr = Ptr._assertClass(key_hash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_dRepNewKeyHash(key_hashPtr);
    return Ptr._wrap(ret, DRep);
  }

  static async new_script_hash(script_hash) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_dRepNewScriptHash(script_hashPtr);
    return Ptr._wrap(ret, DRep);
  }

  static async new_always_abstain() {
    const ret = await HaskellShelley.csl_bridge_dRepNewAlwaysAbstain();
    return Ptr._wrap(ret, DRep);
  }

  static async new_always_no_confidence() {
    const ret = await HaskellShelley.csl_bridge_dRepNewAlwaysNoConfidence();
    return Ptr._wrap(ret, DRep);
  }

  static async new_from_credential(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.csl_bridge_dRepNewFromCredential(credPtr);
    return Ptr._wrap(ret, DRep);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_dRepKind(this.ptr);
    return ret;
  }

  async to_key_hash() {
    const ret = await HaskellShelley.csl_bridge_dRepToKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_script_hash() {
    const ret = await HaskellShelley.csl_bridge_dRepToScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_dRepToBech32(this.ptr);
    return ret;
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_dRepFromBech32(bech32_str);
    return Ptr._wrap(ret, DRep);
  }

}


export class DRepDeregistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRepDeregistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationFromHex(hex_str);
    return Ptr._wrap(ret, DRepDeregistration);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationFromJson(json);
    return Ptr._wrap(ret, DRepDeregistration);
  }

  async voting_credential() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(voting_credential, coin) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationNew(voting_credentialPtr, coinPtr);
    return Ptr._wrap(ret, DRepDeregistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_dRepDeregistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DRepRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRepRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, DRepRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationFromJson(json);
    return Ptr._wrap(ret, DRepRegistration);
  }

  async voting_credential() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(voting_credential, coin) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationNew(voting_credentialPtr, coinPtr);
    return Ptr._wrap(ret, DRepRegistration);
  }

  static async new_with_anchor(voting_credential, coin, anchor) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationNewWithAnchor(voting_credentialPtr, coinPtr, anchorPtr);
    return Ptr._wrap(ret, DRepRegistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_dRepRegistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DRepUpdate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRepUpdate);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateFromHex(hex_str);
    return Ptr._wrap(ret, DRepUpdate);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateFromJson(json);
    return Ptr._wrap(ret, DRepUpdate);
  }

  async voting_credential() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(voting_credential) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_dRepUpdateNew(voting_credentialPtr);
    return Ptr._wrap(ret, DRepUpdate);
  }

  static async new_with_anchor(voting_credential, anchor) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.csl_bridge_dRepUpdateNewWithAnchor(voting_credentialPtr, anchorPtr);
    return Ptr._wrap(ret, DRepUpdate);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_dRepUpdateHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DRepVotingThresholds extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRepVotingThresholds);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsFromHex(hex_str);
    return Ptr._wrap(ret, DRepVotingThresholds);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsFromJson(json);
    return Ptr._wrap(ret, DRepVotingThresholds);
  }

  static async new(motion_no_confidence, committee_normal, committee_no_confidence, update_constitution, hard_fork_initiation, pp_network_group, pp_economic_group, pp_technical_group, pp_governance_group, treasury_withdrawal) {
    const motion_no_confidencePtr = Ptr._assertClass(motion_no_confidence, UnitInterval);
    const committee_normalPtr = Ptr._assertClass(committee_normal, UnitInterval);
    const committee_no_confidencePtr = Ptr._assertClass(committee_no_confidence, UnitInterval);
    const update_constitutionPtr = Ptr._assertClass(update_constitution, UnitInterval);
    const hard_fork_initiationPtr = Ptr._assertClass(hard_fork_initiation, UnitInterval);
    const pp_network_groupPtr = Ptr._assertClass(pp_network_group, UnitInterval);
    const pp_economic_groupPtr = Ptr._assertClass(pp_economic_group, UnitInterval);
    const pp_technical_groupPtr = Ptr._assertClass(pp_technical_group, UnitInterval);
    const pp_governance_groupPtr = Ptr._assertClass(pp_governance_group, UnitInterval);
    const treasury_withdrawalPtr = Ptr._assertClass(treasury_withdrawal, UnitInterval);
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsNew(motion_no_confidencePtr, committee_normalPtr, committee_no_confidencePtr, update_constitutionPtr, hard_fork_initiationPtr, pp_network_groupPtr, pp_economic_groupPtr, pp_technical_groupPtr, pp_governance_groupPtr, treasury_withdrawalPtr);
    return Ptr._wrap(ret, DRepVotingThresholds);
  }

  set_motion_no_confidence(motion_no_confidence) {
    const motion_no_confidencePtr = Ptr._assertClass(motion_no_confidence, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetMotionNoConfidence(this.ptr, motion_no_confidencePtr);
    return ret;
  }

  set_committee_normal(committee_normal) {
    const committee_normalPtr = Ptr._assertClass(committee_normal, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetCommitteeNormal(this.ptr, committee_normalPtr);
    return ret;
  }

  set_committee_no_confidence(committee_no_confidence) {
    const committee_no_confidencePtr = Ptr._assertClass(committee_no_confidence, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetCommitteeNoConfidence(this.ptr, committee_no_confidencePtr);
    return ret;
  }

  set_update_constitution(update_constitution) {
    const update_constitutionPtr = Ptr._assertClass(update_constitution, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetUpdateConstitution(this.ptr, update_constitutionPtr);
    return ret;
  }

  set_hard_fork_initiation(hard_fork_initiation) {
    const hard_fork_initiationPtr = Ptr._assertClass(hard_fork_initiation, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetHardForkInitiation(this.ptr, hard_fork_initiationPtr);
    return ret;
  }

  set_pp_network_group(pp_network_group) {
    const pp_network_groupPtr = Ptr._assertClass(pp_network_group, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetPpNetworkGroup(this.ptr, pp_network_groupPtr);
    return ret;
  }

  set_pp_economic_group(pp_economic_group) {
    const pp_economic_groupPtr = Ptr._assertClass(pp_economic_group, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetPpEconomicGroup(this.ptr, pp_economic_groupPtr);
    return ret;
  }

  set_pp_technical_group(pp_technical_group) {
    const pp_technical_groupPtr = Ptr._assertClass(pp_technical_group, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetPpTechnicalGroup(this.ptr, pp_technical_groupPtr);
    return ret;
  }

  set_pp_governance_group(pp_governance_group) {
    const pp_governance_groupPtr = Ptr._assertClass(pp_governance_group, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetPpGovernanceGroup(this.ptr, pp_governance_groupPtr);
    return ret;
  }

  set_treasury_withdrawal(treasury_withdrawal) {
    const treasury_withdrawalPtr = Ptr._assertClass(treasury_withdrawal, UnitInterval);
    const ret = HaskellShelley.csl_bridge_dRepVotingThresholdsSetTreasuryWithdrawal(this.ptr, treasury_withdrawalPtr);
    return ret;
  }

  async motion_no_confidence() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsMotionNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_normal() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsCommitteeNormal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_no_confidence() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsCommitteeNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async update_constitution() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsUpdateConstitution(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async hard_fork_initiation() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsHardForkInitiation(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_network_group() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsPpNetworkGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_economic_group() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsPpEconomicGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_technical_group() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsPpTechnicalGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_governance_group() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsPpGovernanceGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async treasury_withdrawal() {
    const ret = await HaskellShelley.csl_bridge_dRepVotingThresholdsTreasuryWithdrawal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class DataCost extends Ptr {
  static async new_coins_per_byte(coins_per_byte) {
    const coins_per_bytePtr = Ptr._assertClass(coins_per_byte, BigNum);
    const ret = await HaskellShelley.csl_bridge_dataCostNewCoinsPerByte(coins_per_bytePtr);
    return Ptr._wrap(ret, DataCost);
  }

  async coins_per_byte() {
    const ret = await HaskellShelley.csl_bridge_dataCostCoinsPerByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class DataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_dataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_dataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_dataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_dataHashFromBech32(bech_str);
    return Ptr._wrap(ret, DataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_dataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_dataHashFromHex(hex);
    return Ptr._wrap(ret, DataHash);
  }

}


export class DatumSource extends Ptr {
  static async new(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = await HaskellShelley.csl_bridge_datumSourceNew(datumPtr);
    return Ptr._wrap(ret, DatumSource);
  }

  static async new_ref_input(input) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await HaskellShelley.csl_bridge_datumSourceNewRefInput(inputPtr);
    return Ptr._wrap(ret, DatumSource);
  }

}


export class Ed25519KeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashFromHex(hex);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class Ed25519KeyHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesFromHex(hex_str);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesFromJson(json);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesNew();
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesGet(this.ptr, index);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesAdd(this.ptr, elemPtr);
    return ret;
  }

  async contains(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesContains(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.csl_bridge_ed25519KeyHashesToOption(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class Ed25519Signature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureToBech32(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureToHex(this.ptr);
    return ret;
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureFromBech32(bech32_str);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_hex(input) {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureFromHex(input);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_ed25519SignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class EnterpriseAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const ret = await HaskellShelley.csl_bridge_enterpriseAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.csl_bridge_enterpriseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_enterpriseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_enterpriseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_enterpriseAddressNetworkId(this.ptr);
    return ret;
  }

}


export class ExUnitPrices extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesFromHex(hex_str);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesFromJson(json);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async mem_price() {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesMemPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async step_price() {
    const ret = await HaskellShelley.csl_bridge_exUnitPricesStepPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  static async new(mem_price, step_price) {
    const mem_pricePtr = Ptr._assertClass(mem_price, UnitInterval);
    const step_pricePtr = Ptr._assertClass(step_price, UnitInterval);
    const ret = await HaskellShelley.csl_bridge_exUnitPricesNew(mem_pricePtr, step_pricePtr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

}


export class ExUnits extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_exUnitsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_exUnitsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnits);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_exUnitsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_exUnitsFromHex(hex_str);
    return Ptr._wrap(ret, ExUnits);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_exUnitsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_exUnitsFromJson(json);
    return Ptr._wrap(ret, ExUnits);
  }

  async mem() {
    const ret = await HaskellShelley.csl_bridge_exUnitsMem(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async steps() {
    const ret = await HaskellShelley.csl_bridge_exUnitsSteps(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(mem, steps) {
    const memPtr = Ptr._assertClass(mem, BigNum);
    const stepsPtr = Ptr._assertClass(steps, BigNum);
    const ret = await HaskellShelley.csl_bridge_exUnitsNew(memPtr, stepsPtr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class FixedBlock extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_fixedBlockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedBlock);
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_fixedBlockFromHex(hex_str);
    return Ptr._wrap(ret, FixedBlock);
  }

  async header() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockHeader(this.ptr);
    return Ptr._wrap(ret, Header);
  }

  async transaction_bodies() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockTransactionBodies(this.ptr);
    return Ptr._wrap(ret, FixedTransactionBodies);
  }

  async transaction_witness_sets() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockTransactionWitnessSets(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async auxiliary_data_set() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockAuxiliaryDataSet(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async invalid_transactions() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockInvalidTransactions(this.ptr);
    return base64ToUint32Array(ret);
  }

  async block_hash() {
    const ret = await HaskellShelley.csl_bridge_fixedBlockBlockHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

}


export class FixedTransaction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedTransaction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionFromHex(hex_str);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new(raw_body, raw_witness_set, is_valid) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionNew(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new_with_auxiliary(raw_body, raw_witness_set, raw_auxiliary_data, is_valid) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionNewWithAuxiliary(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), b64FromUint8Array(raw_auxiliary_data), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  async body() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async raw_body() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionRawBody(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_body(raw_body) {
    const ret = HaskellShelley.csl_bridge_fixedTransactionSetBody(this.ptr, b64FromUint8Array(raw_body));
    return ret;
  }

  set_witness_set(raw_witness_set) {
    const ret = HaskellShelley.csl_bridge_fixedTransactionSetWitnessSet(this.ptr, b64FromUint8Array(raw_witness_set));
    return ret;
  }

  async witness_set() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async raw_witness_set() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionRawWitnessSet(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_is_valid(valid) {
    const ret = HaskellShelley.csl_bridge_fixedTransactionSetIsValid(this.ptr, valid);
    return ret;
  }

  async is_valid() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionIsValid(this.ptr);
    return ret;
  }

  set_auxiliary_data(raw_auxiliary_data) {
    const ret = HaskellShelley.csl_bridge_fixedTransactionSetAuxiliaryData(this.ptr, b64FromUint8Array(raw_auxiliary_data));
    return ret;
  }

  async auxiliary_data() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async raw_auxiliary_data() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionRawAuxiliaryData(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class FixedTransactionBodies extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodiesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedTransactionBodies);
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodiesFromHex(hex_str);
    return Ptr._wrap(ret, FixedTransactionBodies);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodiesNew();
    return Ptr._wrap(ret, FixedTransactionBodies);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodiesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodiesGet(this.ptr, index);
    return Ptr._wrap(ret, FixedTransactionBody);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, FixedTransactionBody);
    const ret = HaskellShelley.csl_bridge_fixedTransactionBodiesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class FixedTransactionBody extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedTransactionBody);
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodyFromHex(hex_str);
    return Ptr._wrap(ret, FixedTransactionBody);
  }

  async transaction_body() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodyTransactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async tx_hash() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodyTxHash(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async original_bytes() {
    const ret = await HaskellShelley.csl_bridge_fixedTransactionBodyOriginalBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class FixedVersionedBlock extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_fixedVersionedBlockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedVersionedBlock);
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_fixedVersionedBlockFromHex(hex_str);
    return Ptr._wrap(ret, FixedVersionedBlock);
  }

  async block() {
    const ret = await HaskellShelley.csl_bridge_fixedVersionedBlockBlock(this.ptr);
    return Ptr._wrap(ret, FixedBlock);
  }

  async era() {
    const ret = await HaskellShelley.csl_bridge_fixedVersionedBlockEra(this.ptr);
    return ret;
  }

}


export class GeneralTransactionMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataFromHex(hex_str);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataFromJson(json);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataNew();
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_generalTransactionMetadataKeys(this.ptr);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

}


export class GenesisDelegateHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_genesisDelegateHashFromHex(hex);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

}


export class GenesisHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_genesisHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_genesisHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_genesisHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_genesisHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_genesisHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_genesisHashFromHex(hex);
    return Ptr._wrap(ret, GenesisHash);
  }

}


export class GenesisHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_genesisHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_genesisHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_genesisHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_genesisHashesFromHex(hex_str);
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_genesisHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_genesisHashesFromJson(json);
    return Ptr._wrap(ret, GenesisHashes);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_genesisHashesNew();
    return Ptr._wrap(ret, GenesisHashes);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_genesisHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_genesisHashesGet(this.ptr, index);
    return Ptr._wrap(ret, GenesisHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, GenesisHash);
    const ret = HaskellShelley.csl_bridge_genesisHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class GenesisKeyDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationFromHex(hex_str);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationFromJson(json);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async genesishash() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationGenesishash(this.ptr);
    return Ptr._wrap(ret, GenesisHash);
  }

  async genesis_delegate_hash() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationGenesisDelegateHash(this.ptr);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  static async new(genesishash, genesis_delegate_hash, vrf_keyhash) {
    const genesishashPtr = Ptr._assertClass(genesishash, GenesisHash);
    const genesis_delegate_hashPtr = Ptr._assertClass(genesis_delegate_hash, GenesisDelegateHash);
    const vrf_keyhashPtr = Ptr._assertClass(vrf_keyhash, VRFKeyHash);
    const ret = await HaskellShelley.csl_bridge_genesisKeyDelegationNew(genesishashPtr, genesis_delegate_hashPtr, vrf_keyhashPtr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

}


export class GovernanceAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_governanceActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_governanceActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GovernanceAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_governanceActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_governanceActionFromHex(hex_str);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_governanceActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_governanceActionFromJson(json);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_parameter_change_action(parameter_change_action) {
    const parameter_change_actionPtr = Ptr._assertClass(parameter_change_action, ParameterChangeAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewParameterChangeAction(parameter_change_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_hard_fork_initiation_action(hard_fork_initiation_action) {
    const hard_fork_initiation_actionPtr = Ptr._assertClass(hard_fork_initiation_action, HardForkInitiationAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewHardForkInitiationAction(hard_fork_initiation_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_treasury_withdrawals_action(treasury_withdrawals_action) {
    const treasury_withdrawals_actionPtr = Ptr._assertClass(treasury_withdrawals_action, TreasuryWithdrawalsAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewTreasuryWithdrawalsAction(treasury_withdrawals_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_no_confidence_action(no_confidence_action) {
    const no_confidence_actionPtr = Ptr._assertClass(no_confidence_action, NoConfidenceAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewNoConfidenceAction(no_confidence_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_new_committee_action(new_committee_action) {
    const new_committee_actionPtr = Ptr._assertClass(new_committee_action, UpdateCommitteeAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewNewCommitteeAction(new_committee_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_new_constitution_action(new_constitution_action) {
    const new_constitution_actionPtr = Ptr._assertClass(new_constitution_action, NewConstitutionAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewNewConstitutionAction(new_constitution_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_info_action(info_action) {
    const info_actionPtr = Ptr._assertClass(info_action, InfoAction);
    const ret = await HaskellShelley.csl_bridge_governanceActionNewInfoAction(info_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_governanceActionKind(this.ptr);
    return ret;
  }

  async as_parameter_change_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsParameterChangeAction(this.ptr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async as_hard_fork_initiation_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsHardForkInitiationAction(this.ptr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async as_treasury_withdrawals_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsTreasuryWithdrawalsAction(this.ptr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async as_no_confidence_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsNoConfidenceAction(this.ptr);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async as_new_committee_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsNewCommitteeAction(this.ptr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async as_new_constitution_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsNewConstitutionAction(this.ptr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async as_info_action() {
    const ret = await HaskellShelley.csl_bridge_governanceActionAsInfoAction(this.ptr);
    return Ptr._wrap(ret, InfoAction);
  }

}


export class GovernanceActionId extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdFromHex(hex_str);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdFromJson(json);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async transaction_id() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdIndex(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await HaskellShelley.csl_bridge_governanceActionIdNew(transaction_idPtr, index);
    return Ptr._wrap(ret, GovernanceActionId);
  }

}


export class GovernanceActionIds extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdsFromJson(json);
    return Ptr._wrap(ret, GovernanceActionIds);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdsNew();
    return Ptr._wrap(ret, GovernanceActionIds);
  }

  add(governance_action_id) {
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const ret = HaskellShelley.csl_bridge_governanceActionIdsAdd(this.ptr, governance_action_idPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdsGet(this.ptr, index);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_governanceActionIdsLen(this.ptr);
    return ret;
  }

}


export class HardForkInitiationAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionFromHex(hex_str);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionFromJson(json);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async protocol_version() {
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionProtocolVersion(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  static async new(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionNew(protocol_versionPtr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  static async new_with_action_id(gov_action_id, protocol_version) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = await HaskellShelley.csl_bridge_hardForkInitiationActionNewWithActionId(gov_action_idPtr, protocol_versionPtr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

}


export class Header extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_headerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_headerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Header);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_headerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_headerFromHex(hex_str);
    return Ptr._wrap(ret, Header);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_headerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_headerFromJson(json);
    return Ptr._wrap(ret, Header);
  }

  async header_body() {
    const ret = await HaskellShelley.csl_bridge_headerHeaderBody(this.ptr);
    return Ptr._wrap(ret, HeaderBody);
  }

  async body_signature() {
    const ret = await HaskellShelley.csl_bridge_headerBodySignature(this.ptr);
    return Ptr._wrap(ret, KESSignature);
  }

  static async new(header_body, body_signature) {
    const header_bodyPtr = Ptr._assertClass(header_body, HeaderBody);
    const body_signaturePtr = Ptr._assertClass(body_signature, KESSignature);
    const ret = await HaskellShelley.csl_bridge_headerNew(header_bodyPtr, body_signaturePtr);
    return Ptr._wrap(ret, Header);
  }

}


export class HeaderBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_headerBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_headerBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_headerBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_headerBodyFromHex(hex_str);
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_headerBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_headerBodyFromJson(json);
    return Ptr._wrap(ret, HeaderBody);
  }

  async block_number() {
    const ret = await HaskellShelley.csl_bridge_headerBodyBlockNumber(this.ptr);
    return ret;
  }

  async slot() {
    const ret = await HaskellShelley.csl_bridge_headerBodySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.csl_bridge_headerBodySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async prev_hash() {
    const ret = await HaskellShelley.csl_bridge_headerBodyPrevHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async issuer_vkey() {
    const ret = await HaskellShelley.csl_bridge_headerBodyIssuerVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async vrf_vkey() {
    const ret = await HaskellShelley.csl_bridge_headerBodyVrfVkey(this.ptr);
    return Ptr._wrap(ret, VRFVKey);
  }

  async has_nonce_and_leader_vrf() {
    const ret = await HaskellShelley.csl_bridge_headerBodyHasNonceAndLeaderVrf(this.ptr);
    return ret;
  }

  async nonce_vrf_or_nothing() {
    const ret = await HaskellShelley.csl_bridge_headerBodyNonceVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async leader_vrf_or_nothing() {
    const ret = await HaskellShelley.csl_bridge_headerBodyLeaderVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async has_vrf_result() {
    const ret = await HaskellShelley.csl_bridge_headerBodyHasVrfResult(this.ptr);
    return ret;
  }

  async vrf_result_or_nothing() {
    const ret = await HaskellShelley.csl_bridge_headerBodyVrfResultOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async block_body_size() {
    const ret = await HaskellShelley.csl_bridge_headerBodyBlockBodySize(this.ptr);
    return ret;
  }

  async block_body_hash() {
    const ret = await HaskellShelley.csl_bridge_headerBodyBlockBodyHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async operational_cert() {
    const ret = await HaskellShelley.csl_bridge_headerBodyOperationalCert(this.ptr);
    return Ptr._wrap(ret, OperationalCert);
  }

  async protocol_version() {
    const ret = await HaskellShelley.csl_bridge_headerBodyProtocolVersion(this.ptr);
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
      const ret = await HaskellShelley.csl_bridge_headerBodyNew(block_number, slot, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.csl_bridge_headerBodyNewWithPrevHash(block_number, slot, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
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
      const ret = await HaskellShelley.csl_bridge_headerBodyNewHeaderbody(block_number, slotPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.csl_bridge_headerBodyNewHeaderbodyWithPrevHash(block_number, slotPtr, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
  }

}


export class InfoAction extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_infoActionNew();
    return Ptr._wrap(ret, InfoAction);
  }

}


export class Int extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_intToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_intFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Int);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_intToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_intFromHex(hex_str);
    return Ptr._wrap(ret, Int);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_intToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_intFromJson(json);
    return Ptr._wrap(ret, Int);
  }

  static async new(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.csl_bridge_intNew(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_negative(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.csl_bridge_intNewNegative(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_i32(x) {
    const ret = await HaskellShelley.csl_bridge_intNewI32(x);
    return Ptr._wrap(ret, Int);
  }

  async is_positive() {
    const ret = await HaskellShelley.csl_bridge_intIsPositive(this.ptr);
    return ret;
  }

  async as_positive() {
    const ret = await HaskellShelley.csl_bridge_intAsPositive(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_negative() {
    const ret = await HaskellShelley.csl_bridge_intAsNegative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_i32() {
    const ret = await HaskellShelley.csl_bridge_intAsI32(this.ptr);
    return ret;
  }

  async as_i32_or_nothing() {
    const ret = await HaskellShelley.csl_bridge_intAsI32OrNothing(this.ptr);
    return ret;
  }

  async as_i32_or_fail() {
    const ret = await HaskellShelley.csl_bridge_intAsI32OrFail(this.ptr);
    return ret;
  }

  async to_str() {
    const ret = await HaskellShelley.csl_bridge_intToStr(this.ptr);
    return ret;
  }

  static async from_str(string) {
    const ret = await HaskellShelley.csl_bridge_intFromStr(string);
    return Ptr._wrap(ret, Int);
  }

}


export class Ipv4 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_ipv4ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_ipv4FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv4);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_ipv4ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_ipv4FromHex(hex_str);
    return Ptr._wrap(ret, Ipv4);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_ipv4ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_ipv4FromJson(json);
    return Ptr._wrap(ret, Ipv4);
  }

  static async new(data) {
    const ret = await HaskellShelley.csl_bridge_ipv4New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv4);
  }

  async ip() {
    const ret = await HaskellShelley.csl_bridge_ipv4Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Ipv6 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_ipv6ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_ipv6FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv6);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_ipv6ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_ipv6FromHex(hex_str);
    return Ptr._wrap(ret, Ipv6);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_ipv6ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_ipv6FromJson(json);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(data) {
    const ret = await HaskellShelley.csl_bridge_ipv6New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv6);
  }

  async ip() {
    const ret = await HaskellShelley.csl_bridge_ipv6Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class KESSignature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_kESSignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_kESSignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESSignature);
  }

}


export class KESVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_kESVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_kESVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_kESVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_kESVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, KESVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_kESVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_kESVKeyFromHex(hex);
    return Ptr._wrap(ret, KESVKey);
  }

}


export class Language extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_languageToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_languageFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Language);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_languageToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_languageFromHex(hex_str);
    return Ptr._wrap(ret, Language);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_languageToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_languageFromJson(json);
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v1() {
    const ret = await HaskellShelley.csl_bridge_languageNewPlutusV1();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v2() {
    const ret = await HaskellShelley.csl_bridge_languageNewPlutusV2();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v3() {
    const ret = await HaskellShelley.csl_bridge_languageNewPlutusV3();
    return Ptr._wrap(ret, Language);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_languageKind(this.ptr);
    return ret;
  }

}


export class Languages extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_languagesNew();
    return Ptr._wrap(ret, Languages);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_languagesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_languagesGet(this.ptr, index);
    return Ptr._wrap(ret, Language);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Language);
    const ret = HaskellShelley.csl_bridge_languagesAdd(this.ptr, elemPtr);
    return ret;
  }

  static async list() {
    const ret = await HaskellShelley.csl_bridge_languagesList();
    return Ptr._wrap(ret, Languages);
  }

}


export class LegacyDaedalusPrivateKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_legacyDaedalusPrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, LegacyDaedalusPrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_legacyDaedalusPrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async chaincode() {
    const ret = await HaskellShelley.csl_bridge_legacyDaedalusPrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class LinearFee extends Ptr {
  async constant() {
    const ret = await HaskellShelley.csl_bridge_linearFeeConstant(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async coefficient() {
    const ret = await HaskellShelley.csl_bridge_linearFeeCoefficient(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(coefficient, constant) {
    const coefficientPtr = Ptr._assertClass(coefficient, BigNum);
    const constantPtr = Ptr._assertClass(constant, BigNum);
    const ret = await HaskellShelley.csl_bridge_linearFeeNew(coefficientPtr, constantPtr);
    return Ptr._wrap(ret, LinearFee);
  }

}


export class MIRToStakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsFromHex(hex_str);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsFromJson(json);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsNew();
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsLen(this.ptr);
    return ret;
  }

  async insert(cred, delta) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const deltaPtr = Ptr._assertClass(delta, Int);
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsInsert(this.ptr, credPtr, deltaPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsGet(this.ptr, credPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_mIRToStakeCredentialsKeys(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

}


export class MalformedAddress extends Ptr {
  async original_bytes() {
    const ret = await HaskellShelley.csl_bridge_malformedAddressOriginalBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_malformedAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_malformedAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, MalformedAddress);
  }

}


export class MetadataList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_metadataListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_metadataListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataList);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_metadataListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_metadataListFromHex(hex_str);
    return Ptr._wrap(ret, MetadataList);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_metadataListNew();
    return Ptr._wrap(ret, MetadataList);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_metadataListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_metadataListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionMetadatum);
    const ret = HaskellShelley.csl_bridge_metadataListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class MetadataMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_metadataMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_metadataMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_metadataMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_metadataMapFromHex(hex_str);
    return Ptr._wrap(ret, MetadataMap);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_metadataMapNew();
    return Ptr._wrap(ret, MetadataMap);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_metadataMapLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_metadataMapInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_str(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_metadataMapInsertStr(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_i32(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_metadataMapInsertI32(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_metadataMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_str(key) {
    const ret = await HaskellShelley.csl_bridge_metadataMapGetStr(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_i32(key) {
    const ret = await HaskellShelley.csl_bridge_metadataMapGetI32(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async has(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.csl_bridge_metadataMapHas(this.ptr, keyPtr);
    return ret;
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_metadataMapKeys(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

}


export class Mint extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_mintToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_mintFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Mint);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_mintToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_mintFromHex(hex_str);
    return Ptr._wrap(ret, Mint);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_mintToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_mintFromJson(json);
    return Ptr._wrap(ret, Mint);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_mintNew();
    return Ptr._wrap(ret, Mint);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.csl_bridge_mintNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, Mint);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_mintLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.csl_bridge_mintInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_mintGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintsAssets);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_mintKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async as_positive_multiasset() {
    const ret = await HaskellShelley.csl_bridge_mintAsPositiveMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  async as_negative_multiasset() {
    const ret = await HaskellShelley.csl_bridge_mintAsNegativeMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MintAssets extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_mintAssetsNew();
    return Ptr._wrap(ret, MintAssets);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.csl_bridge_mintAssetsNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_mintAssetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.csl_bridge_mintAssetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, Int);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.csl_bridge_mintAssetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_mintAssetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class MintBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderNew();
    return Ptr._wrap(ret, MintBuilder);
  }

  add_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.csl_bridge_mintBuilderAddAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  set_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.csl_bridge_mintBuilderSetAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_redeemers() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderGetRedeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async has_native_scripts() {
    const ret = await HaskellShelley.csl_bridge_mintBuilderHasNativeScripts(this.ptr);
    return ret;
  }

}


export class MintWitness extends Ptr {
  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScriptSource);
    const ret = await HaskellShelley.csl_bridge_mintWitnessNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, MintWitness);
  }

  static async new_plutus_script(plutus_script, redeemer) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.csl_bridge_mintWitnessNewPlutusScript(plutus_scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, MintWitness);
  }

}


export class MintsAssets extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.csl_bridge_mintsAssetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_mintsAssetsFromJson(json);
    return Ptr._wrap(ret, MintsAssets);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_mintsAssetsNew();
    return Ptr._wrap(ret, MintsAssets);
  }

  add(mint_assets) {
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = HaskellShelley.csl_bridge_mintsAssetsAdd(this.ptr, mint_assetsPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_mintsAssetsGet(this.ptr, index);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_mintsAssetsLen(this.ptr);
    return ret;
  }

}


export class MoveInstantaneousReward extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_other_pot(pot, amount) {
    const amountPtr = Ptr._assertClass(amount, BigNum);
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardNewToOtherPot(pot, amountPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_stake_creds(pot, amounts) {
    const amountsPtr = Ptr._assertClass(amounts, MIRToStakeCredentials);
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardNewToStakeCreds(pot, amountsPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async pot() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardPot(this.ptr);
    return ret;
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardKind(this.ptr);
    return ret;
  }

  async as_to_other_pot() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardAsToOtherPot(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_to_stake_creds() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardAsToStakeCreds(this.ptr);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

}


export class MoveInstantaneousRewardsCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async move_instantaneous_reward() {
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertMoveInstantaneousReward(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new(move_instantaneous_reward) {
    const move_instantaneous_rewardPtr = Ptr._assertClass(move_instantaneous_reward, MoveInstantaneousReward);
    const ret = await HaskellShelley.csl_bridge_moveInstantaneousRewardsCertNew(move_instantaneous_rewardPtr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class MultiAsset extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_multiAssetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_multiAssetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_multiAssetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_multiAssetFromHex(hex_str);
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_multiAssetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_multiAssetFromJson(json);
    return Ptr._wrap(ret, MultiAsset);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_multiAssetNew();
    return Ptr._wrap(ret, MultiAsset);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_multiAssetLen(this.ptr);
    return ret;
  }

  async insert(policy_id, assets) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const assetsPtr = Ptr._assertClass(assets, Assets);
    const ret = await HaskellShelley.csl_bridge_multiAssetInsert(this.ptr, policy_idPtr, assetsPtr);
    return Ptr._wrap(ret, Assets);
  }

  async get(policy_id) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_multiAssetGet(this.ptr, policy_idPtr);
    return Ptr._wrap(ret, Assets);
  }

  async set_asset(policy_id, asset_name, value) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.csl_bridge_multiAssetSetAsset(this.ptr, policy_idPtr, asset_namePtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_asset(policy_id, asset_name) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const ret = await HaskellShelley.csl_bridge_multiAssetGetAsset(this.ptr, policy_idPtr, asset_namePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_multiAssetKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async sub(rhs_ma) {
    const rhs_maPtr = Ptr._assertClass(rhs_ma, MultiAsset);
    const ret = await HaskellShelley.csl_bridge_multiAssetSub(this.ptr, rhs_maPtr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MultiHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_multiHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_multiHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_multiHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_multiHostNameFromHex(hex_str);
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_multiHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_multiHostNameFromJson(json);
    return Ptr._wrap(ret, MultiHostName);
  }

  async dns_name() {
    const ret = await HaskellShelley.csl_bridge_multiHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordSRV);
    const ret = await HaskellShelley.csl_bridge_multiHostNameNew(dns_namePtr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class NativeScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptFromHex(hex_str);
    return Ptr._wrap(ret, NativeScript);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptFromJson(json);
    return Ptr._wrap(ret, NativeScript);
  }

  async hash() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new_script_pubkey(script_pubkey) {
    const script_pubkeyPtr = Ptr._assertClass(script_pubkey, ScriptPubkey);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewScriptPubkey(script_pubkeyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_all(script_all) {
    const script_allPtr = Ptr._assertClass(script_all, ScriptAll);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewScriptAll(script_allPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_any(script_any) {
    const script_anyPtr = Ptr._assertClass(script_any, ScriptAny);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewScriptAny(script_anyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_n_of_k(script_n_of_k) {
    const script_n_of_kPtr = Ptr._assertClass(script_n_of_k, ScriptNOfK);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewScriptNOfK(script_n_of_kPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_start(timelock_start) {
    const timelock_startPtr = Ptr._assertClass(timelock_start, TimelockStart);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewTimelockStart(timelock_startPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_expiry(timelock_expiry) {
    const timelock_expiryPtr = Ptr._assertClass(timelock_expiry, TimelockExpiry);
    const ret = await HaskellShelley.csl_bridge_nativeScriptNewTimelockExpiry(timelock_expiryPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptKind(this.ptr);
    return ret;
  }

  async as_script_pubkey() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsScriptPubkey(this.ptr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async as_script_all() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsScriptAll(this.ptr);
    return Ptr._wrap(ret, ScriptAll);
  }

  async as_script_any() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsScriptAny(this.ptr);
    return Ptr._wrap(ret, ScriptAny);
  }

  async as_script_n_of_k() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsScriptNOfK(this.ptr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async as_timelock_start() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsTimelockStart(this.ptr);
    return Ptr._wrap(ret, TimelockStart);
  }

  async as_timelock_expiry() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptAsTimelockExpiry(this.ptr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async get_required_signers() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptGetRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class NativeScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const ret = await HaskellShelley.csl_bridge_nativeScriptSourceNew(scriptPtr);
    return Ptr._wrap(ret, NativeScriptSource);
  }

  static async new_ref_input(script_hash, input, script_size) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await HaskellShelley.csl_bridge_nativeScriptSourceNewRefInput(script_hashPtr, inputPtr, script_size);
    return Ptr._wrap(ret, NativeScriptSource);
  }

  set_required_signers(key_hashes) {
    const key_hashesPtr = Ptr._assertClass(key_hashes, Ed25519KeyHashes);
    const ret = HaskellShelley.csl_bridge_nativeScriptSourceSetRequiredSigners(this.ptr, key_hashesPtr);
    return ret;
  }

  async get_ref_script_size() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptSourceGetRefScriptSize(this.ptr);
    return ret;
  }

}


export class NativeScripts extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsNew();
    return Ptr._wrap(ret, NativeScripts);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, NativeScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, NativeScript);
    const ret = HaskellShelley.csl_bridge_nativeScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScripts);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsFromHex(hex_str);
    return Ptr._wrap(ret, NativeScripts);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_nativeScriptsFromJson(json);
    return Ptr._wrap(ret, NativeScripts);
  }

}


export class NetworkId extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_networkIdToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_networkIdFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NetworkId);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_networkIdToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_networkIdFromHex(hex_str);
    return Ptr._wrap(ret, NetworkId);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_networkIdToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_networkIdFromJson(json);
    return Ptr._wrap(ret, NetworkId);
  }

  static async testnet() {
    const ret = await HaskellShelley.csl_bridge_networkIdTestnet();
    return Ptr._wrap(ret, NetworkId);
  }

  static async mainnet() {
    const ret = await HaskellShelley.csl_bridge_networkIdMainnet();
    return Ptr._wrap(ret, NetworkId);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_networkIdKind(this.ptr);
    return ret;
  }

}


export class NetworkInfo extends Ptr {
  static async new(network_id, protocol_magic) {
    const ret = await HaskellShelley.csl_bridge_networkInfoNew(network_id, protocol_magic);
    return Ptr._wrap(ret, NetworkInfo);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_networkInfoNetworkId(this.ptr);
    return ret;
  }

  async protocol_magic() {
    const ret = await HaskellShelley.csl_bridge_networkInfoProtocolMagic(this.ptr);
    return ret;
  }

  static async testnet_preview() {
    const ret = await HaskellShelley.csl_bridge_networkInfoTestnetPreview();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async testnet_preprod() {
    const ret = await HaskellShelley.csl_bridge_networkInfoTestnetPreprod();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async mainnet() {
    const ret = await HaskellShelley.csl_bridge_networkInfoMainnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

}


export class NewConstitutionAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionFromHex(hex_str);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionFromJson(json);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async constitution() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionConstitution(this.ptr);
    return Ptr._wrap(ret, Constitution);
  }

  static async new(constitution) {
    const constitutionPtr = Ptr._assertClass(constitution, Constitution);
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionNew(constitutionPtr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  static async new_with_action_id(gov_action_id, constitution) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const constitutionPtr = Ptr._assertClass(constitution, Constitution);
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionNewWithActionId(gov_action_idPtr, constitutionPtr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async has_script_hash() {
    const ret = await HaskellShelley.csl_bridge_newConstitutionActionHasScriptHash(this.ptr);
    return ret;
  }

}


export class NoConfidenceAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionFromHex(hex_str);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionFromJson(json);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionNew();
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  static async new_with_action_id(gov_action_id) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const ret = await HaskellShelley.csl_bridge_noConfidenceActionNewWithActionId(gov_action_idPtr);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

}


export class Nonce extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_nonceToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_nonceFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Nonce);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_nonceToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_nonceFromHex(hex_str);
    return Ptr._wrap(ret, Nonce);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_nonceToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_nonceFromJson(json);
    return Ptr._wrap(ret, Nonce);
  }

  static async new_identity() {
    const ret = await HaskellShelley.csl_bridge_nonceNewIdentity();
    return Ptr._wrap(ret, Nonce);
  }

  static async new_from_hash(hash) {
    const ret = await HaskellShelley.csl_bridge_nonceNewFromHash(b64FromUint8Array(hash));
    return Ptr._wrap(ret, Nonce);
  }

  async get_hash() {
    const ret = await HaskellShelley.csl_bridge_nonceGetHash(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class OperationalCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_operationalCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_operationalCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_operationalCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_operationalCertFromHex(hex_str);
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_operationalCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_operationalCertFromJson(json);
    return Ptr._wrap(ret, OperationalCert);
  }

  async hot_vkey() {
    const ret = await HaskellShelley.csl_bridge_operationalCertHotVkey(this.ptr);
    return Ptr._wrap(ret, KESVKey);
  }

  async sequence_number() {
    const ret = await HaskellShelley.csl_bridge_operationalCertSequenceNumber(this.ptr);
    return ret;
  }

  async kes_period() {
    const ret = await HaskellShelley.csl_bridge_operationalCertKesPeriod(this.ptr);
    return ret;
  }

  async sigma() {
    const ret = await HaskellShelley.csl_bridge_operationalCertSigma(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async new(hot_vkey, sequence_number, kes_period, sigma) {
    const hot_vkeyPtr = Ptr._assertClass(hot_vkey, KESVKey);
    const sigmaPtr = Ptr._assertClass(sigma, Ed25519Signature);
    const ret = await HaskellShelley.csl_bridge_operationalCertNew(hot_vkeyPtr, sequence_number, kes_period, sigmaPtr);
    return Ptr._wrap(ret, OperationalCert);
  }

}


export class OutputDatum extends Ptr {
  static async new_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await HaskellShelley.csl_bridge_outputDatumNewDataHash(data_hashPtr);
    return Ptr._wrap(ret, OutputDatum);
  }

  static async new_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await HaskellShelley.csl_bridge_outputDatumNewData(dataPtr);
    return Ptr._wrap(ret, OutputDatum);
  }

  async data_hash() {
    const ret = await HaskellShelley.csl_bridge_outputDatumDataHash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async data() {
    const ret = await HaskellShelley.csl_bridge_outputDatumData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

}


export class ParameterChangeAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionFromHex(hex_str);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionFromJson(json);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async protocol_param_updates() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionProtocolParamUpdates(this.ptr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async policy_hash() {
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionPolicyHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(protocol_param_updates) {
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionNew(protocol_param_updatesPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_action_id(gov_action_id, protocol_param_updates) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionNewWithActionId(gov_action_idPtr, protocol_param_updatesPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_policy_hash(protocol_param_updates, policy_hash) {
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionNewWithPolicyHash(protocol_param_updatesPtr, policy_hashPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_policy_hash_and_action_id(gov_action_id, protocol_param_updates, policy_hash) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_parameterChangeActionNewWithPolicyHashAndActionId(gov_action_idPtr, protocol_param_updatesPtr, policy_hashPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

}


export class PlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_plutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_plutusDataFromHex(hex_str);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_constr_plutus_data(constr_plutus_data) {
    const constr_plutus_dataPtr = Ptr._assertClass(constr_plutus_data, ConstrPlutusData);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewConstrPlutusData(constr_plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_empty_constr_plutus_data(alternative) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewEmptyConstrPlutusData(alternativePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_single_value_constr_plutus_data(alternative, plutus_data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewSingleValueConstrPlutusData(alternativePtr, plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, PlutusMap);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewMap(mapPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, PlutusList);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewList(listPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_integer(integer) {
    const integerPtr = Ptr._assertClass(integer, BigInt);
    const ret = await HaskellShelley.csl_bridge_plutusDataNewInteger(integerPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusDataNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_plutusDataKind(this.ptr);
    return ret;
  }

  async as_constr_plutus_data() {
    const ret = await HaskellShelley.csl_bridge_plutusDataAsConstrPlutusData(this.ptr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async as_map() {
    const ret = await HaskellShelley.csl_bridge_plutusDataAsMap(this.ptr);
    return Ptr._wrap(ret, PlutusMap);
  }

  async as_list() {
    const ret = await HaskellShelley.csl_bridge_plutusDataAsList(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  async as_integer() {
    const ret = await HaskellShelley.csl_bridge_plutusDataAsInteger(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusDataAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_json(schema) {
    const ret = await HaskellShelley.csl_bridge_plutusDataToJson(this.ptr, schema);
    return ret;
  }

  static async from_json(json, schema) {
    const ret = await HaskellShelley.csl_bridge_plutusDataFromJson(json, schema);
    return Ptr._wrap(ret, PlutusData);
  }

  static async from_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.csl_bridge_plutusDataFromAddress(addressPtr);
    return Ptr._wrap(ret, PlutusData);
  }

}


export class PlutusList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusList);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_plutusListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_plutusListFromHex(hex_str);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_plutusListNew();
    return Ptr._wrap(ret, PlutusList);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_plutusListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_plutusListGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusData);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusData);
    const ret = HaskellShelley.csl_bridge_plutusListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_plutusMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_plutusMapFromHex(hex_str);
    return Ptr._wrap(ret, PlutusMap);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_plutusMapNew();
    return Ptr._wrap(ret, PlutusMap);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_plutusMapLen(this.ptr);
    return ret;
  }

  async insert(key, values) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const valuesPtr = Ptr._assertClass(values, PlutusMapValues);
    const ret = await HaskellShelley.csl_bridge_plutusMapInsert(this.ptr, keyPtr, valuesPtr);
    return Ptr._wrap(ret, PlutusMapValues);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const ret = await HaskellShelley.csl_bridge_plutusMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, PlutusMapValues);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_plutusMapKeys(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

}


export class PlutusMapValues extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_plutusMapValuesNew();
    return Ptr._wrap(ret, PlutusMapValues);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_plutusMapValuesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_plutusMapValuesGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusData);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusData);
    const ret = HaskellShelley.csl_bridge_plutusMapValuesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptNew(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v2(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptNewV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v3(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptNewV3(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.csl_bridge_plutusScriptNewWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes_v2(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromBytesV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_v3(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromBytesV3(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromBytesWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_hex_with_version(hex_str, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.csl_bridge_plutusScriptFromHexWithVersion(hex_str, languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async hash() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async language_version() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptLanguageVersion(this.ptr);
    return Ptr._wrap(ret, Language);
  }

}


export class PlutusScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const ret = await HaskellShelley.csl_bridge_plutusScriptSourceNew(scriptPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input(script_hash, input, lang_ver, script_size) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const lang_verPtr = Ptr._assertClass(lang_ver, Language);
    const ret = await HaskellShelley.csl_bridge_plutusScriptSourceNewRefInput(script_hashPtr, inputPtr, lang_verPtr, script_size);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  set_required_signers(key_hashes) {
    const key_hashesPtr = Ptr._assertClass(key_hashes, Ed25519KeyHashes);
    const ret = HaskellShelley.csl_bridge_plutusScriptSourceSetRequiredSigners(this.ptr, key_hashesPtr);
    return ret;
  }

  async get_ref_script_size() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptSourceGetRefScriptSize(this.ptr);
    return ret;
  }

}


export class PlutusScripts extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsFromJson(json);
    return Ptr._wrap(ret, PlutusScripts);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsNew();
    return Ptr._wrap(ret, PlutusScripts);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_plutusScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusScript);
    const ret = HaskellShelley.csl_bridge_plutusScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusWitness extends Ptr {
  static async new(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.csl_bridge_plutusWitnessNew(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const datumPtr = Ptr._assertClass(datum, DatumSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.csl_bridge_plutusWitnessNewWithRef(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.csl_bridge_plutusWitnessNewWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.csl_bridge_plutusWitnessNewWithRefWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  async script() {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async datum() {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessDatum(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async redeemer() {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessRedeemer(this.ptr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class PlutusWitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessesNew();
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_plutusWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusWitness);
    const ret = HaskellShelley.csl_bridge_plutusWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Pointer extends Ptr {
  static async new(slot, tx_index, cert_index) {
    const ret = await HaskellShelley.csl_bridge_pointerNew(slot, tx_index, cert_index);
    return Ptr._wrap(ret, Pointer);
  }

  static async new_pointer(slot, tx_index, cert_index) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const tx_indexPtr = Ptr._assertClass(tx_index, BigNum);
    const cert_indexPtr = Ptr._assertClass(cert_index, BigNum);
    const ret = await HaskellShelley.csl_bridge_pointerNewPointer(slotPtr, tx_indexPtr, cert_indexPtr);
    return Ptr._wrap(ret, Pointer);
  }

  async slot() {
    const ret = await HaskellShelley.csl_bridge_pointerSlot(this.ptr);
    return ret;
  }

  async tx_index() {
    const ret = await HaskellShelley.csl_bridge_pointerTxIndex(this.ptr);
    return ret;
  }

  async cert_index() {
    const ret = await HaskellShelley.csl_bridge_pointerCertIndex(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.csl_bridge_pointerSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async tx_index_bignum() {
    const ret = await HaskellShelley.csl_bridge_pointerTxIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cert_index_bignum() {
    const ret = await HaskellShelley.csl_bridge_pointerCertIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class PointerAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const stakePtr = Ptr._assertClass(stake, Pointer);
    const ret = await HaskellShelley.csl_bridge_pointerAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, PointerAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.csl_bridge_pointerAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async stake_pointer() {
    const ret = await HaskellShelley.csl_bridge_pointerAddressStakePointer(this.ptr);
    return Ptr._wrap(ret, Pointer);
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_pointerAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_pointerAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, PointerAddress);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_pointerAddressNetworkId(this.ptr);
    return ret;
  }

}


export class PoolMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataFromHex(hex_str);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataFromJson(json);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async url() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataUrl(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async pool_metadata_hash() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataPoolMetadataHash(this.ptr);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  static async new(url, pool_metadata_hash) {
    const urlPtr = Ptr._assertClass(url, URL);
    const pool_metadata_hashPtr = Ptr._assertClass(pool_metadata_hash, PoolMetadataHash);
    const ret = await HaskellShelley.csl_bridge_poolMetadataNew(urlPtr, pool_metadata_hashPtr);
    return Ptr._wrap(ret, PoolMetadata);
  }

}


export class PoolMetadataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashFromBech32(bech_str);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_poolMetadataHashFromHex(hex);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

}


export class PoolParams extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolParamsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolParamsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolParams);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolParamsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_poolParamsFromHex(hex_str);
    return Ptr._wrap(ret, PoolParams);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_poolParamsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_poolParamsFromJson(json);
    return Ptr._wrap(ret, PoolParams);
  }

  async operator() {
    const ret = await HaskellShelley.csl_bridge_poolParamsOperator(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.csl_bridge_poolParamsVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async pledge() {
    const ret = await HaskellShelley.csl_bridge_poolParamsPledge(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cost() {
    const ret = await HaskellShelley.csl_bridge_poolParamsCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async margin() {
    const ret = await HaskellShelley.csl_bridge_poolParamsMargin(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async reward_account() {
    const ret = await HaskellShelley.csl_bridge_poolParamsRewardAccount(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async pool_owners() {
    const ret = await HaskellShelley.csl_bridge_poolParamsPoolOwners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async relays() {
    const ret = await HaskellShelley.csl_bridge_poolParamsRelays(this.ptr);
    return Ptr._wrap(ret, Relays);
  }

  async pool_metadata() {
    const ret = await HaskellShelley.csl_bridge_poolParamsPoolMetadata(this.ptr);
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
      const ret = await HaskellShelley.csl_bridge_poolParamsNew(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr);
      return Ptr._wrap(ret, PoolParams);
    }
    if(pool_metadata != null) {
      const ret = await HaskellShelley.csl_bridge_poolParamsNewWithPoolMetadata(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr, pool_metadataPtr);
      return Ptr._wrap(ret, PoolParams);
    }
  }

}


export class PoolRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationFromJson(json);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async pool_params() {
    const ret = await HaskellShelley.csl_bridge_poolRegistrationPoolParams(this.ptr);
    return Ptr._wrap(ret, PoolParams);
  }

  static async new(pool_params) {
    const pool_paramsPtr = Ptr._assertClass(pool_params, PoolParams);
    const ret = await HaskellShelley.csl_bridge_poolRegistrationNew(pool_paramsPtr);
    return Ptr._wrap(ret, PoolRegistration);
  }

}


export class PoolRetirement extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolRetirementToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolRetirementFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolRetirementToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_poolRetirementFromHex(hex_str);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_poolRetirementToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_poolRetirementFromJson(json);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.csl_bridge_poolRetirementPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async epoch() {
    const ret = await HaskellShelley.csl_bridge_poolRetirementEpoch(this.ptr);
    return ret;
  }

  static async new(pool_keyhash, epoch) {
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_poolRetirementNew(pool_keyhashPtr, epoch);
    return Ptr._wrap(ret, PoolRetirement);
  }

}


export class PoolVotingThresholds extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsFromHex(hex_str);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsFromJson(json);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  static async new(motion_no_confidence, committee_normal, committee_no_confidence, hard_fork_initiation, security_relevant_threshold) {
    const motion_no_confidencePtr = Ptr._assertClass(motion_no_confidence, UnitInterval);
    const committee_normalPtr = Ptr._assertClass(committee_normal, UnitInterval);
    const committee_no_confidencePtr = Ptr._assertClass(committee_no_confidence, UnitInterval);
    const hard_fork_initiationPtr = Ptr._assertClass(hard_fork_initiation, UnitInterval);
    const security_relevant_thresholdPtr = Ptr._assertClass(security_relevant_threshold, UnitInterval);
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsNew(motion_no_confidencePtr, committee_normalPtr, committee_no_confidencePtr, hard_fork_initiationPtr, security_relevant_thresholdPtr);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async motion_no_confidence() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsMotionNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_normal() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsCommitteeNormal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_no_confidence() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsCommitteeNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async hard_fork_initiation() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsHardForkInitiation(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async security_relevant_threshold() {
    const ret = await HaskellShelley.csl_bridge_poolVotingThresholdsSecurityRelevantThreshold(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class PrivateKey extends Ptr {
  async to_public() {
    const ret = await HaskellShelley.csl_bridge_privateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async generate_ed25519() {
    const ret = await HaskellShelley.csl_bridge_privateKeyGenerateEd25519();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async generate_ed25519extended() {
    const ret = await HaskellShelley.csl_bridge_privateKeyGenerateEd25519extended();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_privateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_privateKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_privateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_extended_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_privateKeyFromExtendedBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_normal_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_privateKeyFromNormalBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  async sign(message) {
    const ret = await HaskellShelley.csl_bridge_privateKeySign(this.ptr, b64FromUint8Array(message));
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_privateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_privateKeyFromHex(hex_str);
    return Ptr._wrap(ret, PrivateKey);
  }

}


export class ProposedProtocolParameterUpdates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesFromHex(hex_str);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesFromJson(json);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesNew();
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const valuePtr = Ptr._assertClass(value, ProtocolParamUpdate);
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_proposedProtocolParameterUpdatesKeys(this.ptr);
    return Ptr._wrap(ret, GenesisHashes);
  }

}


export class ProtocolParamUpdate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateFromJson(json);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  set_minfee_a(minfee_a) {
    const minfee_aPtr = Ptr._assertClass(minfee_a, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMinfeeA(this.ptr, minfee_aPtr);
    return ret;
  }

  async minfee_a() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMinfeeA(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_minfee_b(minfee_b) {
    const minfee_bPtr = Ptr._assertClass(minfee_b, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMinfeeB(this.ptr, minfee_bPtr);
    return ret;
  }

  async minfee_b() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMinfeeB(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_block_body_size(max_block_body_size) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxBlockBodySize(this.ptr, max_block_body_size);
    return ret;
  }

  async max_block_body_size() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxBlockBodySize(this.ptr);
    return ret;
  }

  set_max_tx_size(max_tx_size) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxTxSize(this.ptr, max_tx_size);
    return ret;
  }

  async max_tx_size() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxTxSize(this.ptr);
    return ret;
  }

  set_max_block_header_size(max_block_header_size) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxBlockHeaderSize(this.ptr, max_block_header_size);
    return ret;
  }

  async max_block_header_size() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxBlockHeaderSize(this.ptr);
    return ret;
  }

  set_key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetKeyDeposit(this.ptr, key_depositPtr);
    return ret;
  }

  async key_deposit() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateKeyDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetPoolDeposit(this.ptr, pool_depositPtr);
    return ret;
  }

  async pool_deposit() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdatePoolDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_epoch(max_epoch) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxEpoch(this.ptr, max_epoch);
    return ret;
  }

  async max_epoch() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxEpoch(this.ptr);
    return ret;
  }

  set_n_opt(n_opt) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetNOpt(this.ptr, n_opt);
    return ret;
  }

  async n_opt() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateNOpt(this.ptr);
    return ret;
  }

  set_pool_pledge_influence(pool_pledge_influence) {
    const pool_pledge_influencePtr = Ptr._assertClass(pool_pledge_influence, UnitInterval);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetPoolPledgeInfluence(this.ptr, pool_pledge_influencePtr);
    return ret;
  }

  async pool_pledge_influence() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdatePoolPledgeInfluence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_expansion_rate(expansion_rate) {
    const expansion_ratePtr = Ptr._assertClass(expansion_rate, UnitInterval);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetExpansionRate(this.ptr, expansion_ratePtr);
    return ret;
  }

  async expansion_rate() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateExpansionRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_treasury_growth_rate(treasury_growth_rate) {
    const treasury_growth_ratePtr = Ptr._assertClass(treasury_growth_rate, UnitInterval);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetTreasuryGrowthRate(this.ptr, treasury_growth_ratePtr);
    return ret;
  }

  async treasury_growth_rate() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateTreasuryGrowthRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async d() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateD(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async extra_entropy() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateExtraEntropy(this.ptr);
    return Ptr._wrap(ret, Nonce);
  }

  set_protocol_version(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetProtocolVersion(this.ptr, protocol_versionPtr);
    return ret;
  }

  async protocol_version() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateProtocolVersion(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  set_min_pool_cost(min_pool_cost) {
    const min_pool_costPtr = Ptr._assertClass(min_pool_cost, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMinPoolCost(this.ptr, min_pool_costPtr);
    return ret;
  }

  async min_pool_cost() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMinPoolCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ada_per_utxo_byte(ada_per_utxo_byte) {
    const ada_per_utxo_bytePtr = Ptr._assertClass(ada_per_utxo_byte, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetAdaPerUtxoByte(this.ptr, ada_per_utxo_bytePtr);
    return ret;
  }

  async ada_per_utxo_byte() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateAdaPerUtxoByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_cost_models(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetCostModels(this.ptr, cost_modelsPtr);
    return ret;
  }

  async cost_models() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateCostModels(this.ptr);
    return Ptr._wrap(ret, Costmdls);
  }

  set_execution_costs(execution_costs) {
    const execution_costsPtr = Ptr._assertClass(execution_costs, ExUnitPrices);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetExecutionCosts(this.ptr, execution_costsPtr);
    return ret;
  }

  async execution_costs() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateExecutionCosts(this.ptr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  set_max_tx_ex_units(max_tx_ex_units) {
    const max_tx_ex_unitsPtr = Ptr._assertClass(max_tx_ex_units, ExUnits);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxTxExUnits(this.ptr, max_tx_ex_unitsPtr);
    return ret;
  }

  async max_tx_ex_units() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxTxExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_block_ex_units(max_block_ex_units) {
    const max_block_ex_unitsPtr = Ptr._assertClass(max_block_ex_units, ExUnits);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxBlockExUnits(this.ptr, max_block_ex_unitsPtr);
    return ret;
  }

  async max_block_ex_units() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxBlockExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_value_size(max_value_size) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxValueSize(this.ptr, max_value_size);
    return ret;
  }

  async max_value_size() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxValueSize(this.ptr);
    return ret;
  }

  set_collateral_percentage(collateral_percentage) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetCollateralPercentage(this.ptr, collateral_percentage);
    return ret;
  }

  async collateral_percentage() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateCollateralPercentage(this.ptr);
    return ret;
  }

  set_max_collateral_inputs(max_collateral_inputs) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMaxCollateralInputs(this.ptr, max_collateral_inputs);
    return ret;
  }

  async max_collateral_inputs() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMaxCollateralInputs(this.ptr);
    return ret;
  }

  set_pool_voting_thresholds(pool_voting_thresholds) {
    const pool_voting_thresholdsPtr = Ptr._assertClass(pool_voting_thresholds, PoolVotingThresholds);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetPoolVotingThresholds(this.ptr, pool_voting_thresholdsPtr);
    return ret;
  }

  async pool_voting_thresholds() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdatePoolVotingThresholds(this.ptr);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  set_drep_voting_thresholds(drep_voting_thresholds) {
    const drep_voting_thresholdsPtr = Ptr._assertClass(drep_voting_thresholds, DRepVotingThresholds);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetDrepVotingThresholds(this.ptr, drep_voting_thresholdsPtr);
    return ret;
  }

  async drep_voting_thresholds() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateDrepVotingThresholds(this.ptr);
    return Ptr._wrap(ret, DRepVotingThresholds);
  }

  set_min_committee_size(min_committee_size) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetMinCommitteeSize(this.ptr, min_committee_size);
    return ret;
  }

  async min_committee_size() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateMinCommitteeSize(this.ptr);
    return ret;
  }

  set_committee_term_limit(committee_term_limit) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetCommitteeTermLimit(this.ptr, committee_term_limit);
    return ret;
  }

  async committee_term_limit() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateCommitteeTermLimit(this.ptr);
    return ret;
  }

  set_governance_action_validity_period(governance_action_validity_period) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetGovernanceActionValidityPeriod(this.ptr, governance_action_validity_period);
    return ret;
  }

  async governance_action_validity_period() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateGovernanceActionValidityPeriod(this.ptr);
    return ret;
  }

  set_governance_action_deposit(governance_action_deposit) {
    const governance_action_depositPtr = Ptr._assertClass(governance_action_deposit, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetGovernanceActionDeposit(this.ptr, governance_action_depositPtr);
    return ret;
  }

  async governance_action_deposit() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateGovernanceActionDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_drep_deposit(drep_deposit) {
    const drep_depositPtr = Ptr._assertClass(drep_deposit, BigNum);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetDrepDeposit(this.ptr, drep_depositPtr);
    return ret;
  }

  async drep_deposit() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateDrepDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_drep_inactivity_period(drep_inactivity_period) {
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetDrepInactivityPeriod(this.ptr, drep_inactivity_period);
    return ret;
  }

  async drep_inactivity_period() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateDrepInactivityPeriod(this.ptr);
    return ret;
  }

  set_ref_script_coins_per_byte(ref_script_coins_per_byte) {
    const ref_script_coins_per_bytePtr = Ptr._assertClass(ref_script_coins_per_byte, UnitInterval);
    const ret = HaskellShelley.csl_bridge_protocolParamUpdateSetRefScriptCoinsPerByte(this.ptr, ref_script_coins_per_bytePtr);
    return ret;
  }

  async ref_script_coins_per_byte() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateRefScriptCoinsPerByte(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_protocolParamUpdateNew();
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

}


export class ProtocolVersion extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_protocolVersionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_protocolVersionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_protocolVersionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_protocolVersionFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_protocolVersionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_protocolVersionFromJson(json);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async major() {
    const ret = await HaskellShelley.csl_bridge_protocolVersionMajor(this.ptr);
    return ret;
  }

  async minor() {
    const ret = await HaskellShelley.csl_bridge_protocolVersionMinor(this.ptr);
    return ret;
  }

  static async new(major, minor) {
    const ret = await HaskellShelley.csl_bridge_protocolVersionNew(major, minor);
    return Ptr._wrap(ret, ProtocolVersion);
  }

}


export class PublicKey extends Ptr {
  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.csl_bridge_publicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.csl_bridge_publicKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_publicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_publicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PublicKey);
  }

  async verify(data, signature) {
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.csl_bridge_publicKeyVerify(this.ptr, b64FromUint8Array(data), signaturePtr);
    return ret;
  }

  async hash() {
    const ret = await HaskellShelley.csl_bridge_publicKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_publicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_publicKeyFromHex(hex_str);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class PublicKeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_publicKeysNew();
    return Ptr._wrap(ret, PublicKeys);
  }

  async size() {
    const ret = await HaskellShelley.csl_bridge_publicKeysSize(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_publicKeysGet(this.ptr, index);
    return Ptr._wrap(ret, PublicKey);
  }

  add(key) {
    const keyPtr = Ptr._assertClass(key, PublicKey);
    const ret = HaskellShelley.csl_bridge_publicKeysAdd(this.ptr, keyPtr);
    return ret;
  }

}


export class Redeemer extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_redeemerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_redeemerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemer);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_redeemerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_redeemerFromHex(hex_str);
    return Ptr._wrap(ret, Redeemer);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_redeemerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_redeemerFromJson(json);
    return Ptr._wrap(ret, Redeemer);
  }

  async tag() {
    const ret = await HaskellShelley.csl_bridge_redeemerTag(this.ptr);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async index() {
    const ret = await HaskellShelley.csl_bridge_redeemerIndex(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.csl_bridge_redeemerData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async ex_units() {
    const ret = await HaskellShelley.csl_bridge_redeemerExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  static async new(tag, index, data, ex_units) {
    const tagPtr = Ptr._assertClass(tag, RedeemerTag);
    const indexPtr = Ptr._assertClass(index, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
    const ret = await HaskellShelley.csl_bridge_redeemerNew(tagPtr, indexPtr, dataPtr, ex_unitsPtr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class RedeemerTag extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_redeemerTagFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_redeemerTagFromHex(hex_str);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_redeemerTagFromJson(json);
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_spend() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewSpend();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_mint() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewMint();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_cert() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewCert();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_reward() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewReward();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_vote() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewVote();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_voting_proposal() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagNewVotingProposal();
    return Ptr._wrap(ret, RedeemerTag);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_redeemerTagKind(this.ptr);
    return ret;
  }

}


export class Redeemers extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_redeemersToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_redeemersFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemers);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_redeemersToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_redeemersFromHex(hex_str);
    return Ptr._wrap(ret, Redeemers);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_redeemersToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_redeemersFromJson(json);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_redeemersNew();
    return Ptr._wrap(ret, Redeemers);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_redeemersLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_redeemersGet(this.ptr, index);
    return Ptr._wrap(ret, Redeemer);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Redeemer);
    const ret = HaskellShelley.csl_bridge_redeemersAdd(this.ptr, elemPtr);
    return ret;
  }

  async total_ex_units() {
    const ret = await HaskellShelley.csl_bridge_redeemersTotalExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class Relay extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_relayToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_relayFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relay);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_relayToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_relayFromHex(hex_str);
    return Ptr._wrap(ret, Relay);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_relayToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_relayFromJson(json);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_addr(single_host_addr) {
    const single_host_addrPtr = Ptr._assertClass(single_host_addr, SingleHostAddr);
    const ret = await HaskellShelley.csl_bridge_relayNewSingleHostAddr(single_host_addrPtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_name(single_host_name) {
    const single_host_namePtr = Ptr._assertClass(single_host_name, SingleHostName);
    const ret = await HaskellShelley.csl_bridge_relayNewSingleHostName(single_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_multi_host_name(multi_host_name) {
    const multi_host_namePtr = Ptr._assertClass(multi_host_name, MultiHostName);
    const ret = await HaskellShelley.csl_bridge_relayNewMultiHostName(multi_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_relayKind(this.ptr);
    return ret;
  }

  async as_single_host_addr() {
    const ret = await HaskellShelley.csl_bridge_relayAsSingleHostAddr(this.ptr);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async as_single_host_name() {
    const ret = await HaskellShelley.csl_bridge_relayAsSingleHostName(this.ptr);
    return Ptr._wrap(ret, SingleHostName);
  }

  async as_multi_host_name() {
    const ret = await HaskellShelley.csl_bridge_relayAsMultiHostName(this.ptr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class Relays extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_relaysToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_relaysFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relays);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_relaysToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_relaysFromHex(hex_str);
    return Ptr._wrap(ret, Relays);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_relaysToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_relaysFromJson(json);
    return Ptr._wrap(ret, Relays);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_relaysNew();
    return Ptr._wrap(ret, Relays);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_relaysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_relaysGet(this.ptr, index);
    return Ptr._wrap(ret, Relay);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Relay);
    const ret = HaskellShelley.csl_bridge_relaysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class RewardAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const ret = await HaskellShelley.csl_bridge_rewardAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.csl_bridge_rewardAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressNetworkId(this.ptr);
    return ret;
  }

}


export class RewardAddresses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesFromHex(hex_str);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesFromJson(json);
    return Ptr._wrap(ret, RewardAddresses);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesNew();
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_rewardAddressesGet(this.ptr, index);
    return Ptr._wrap(ret, RewardAddress);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, RewardAddress);
    const ret = HaskellShelley.csl_bridge_rewardAddressesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptAll extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptAllToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptAllFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptAllToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptAllFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptAllToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptAllFromJson(json);
    return Ptr._wrap(ret, ScriptAll);
  }

  async native_scripts() {
    const ret = await HaskellShelley.csl_bridge_scriptAllNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.csl_bridge_scriptAllNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAll);
  }

}


export class ScriptAny extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptAnyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptAnyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptAnyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptAnyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptAnyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptAnyFromJson(json);
    return Ptr._wrap(ret, ScriptAny);
  }

  async native_scripts() {
    const ret = await HaskellShelley.csl_bridge_scriptAnyNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.csl_bridge_scriptAnyNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAny);
  }

}


export class ScriptDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_scriptDataHashFromHex(hex);
    return Ptr._wrap(ret, ScriptDataHash);
  }

}


export class ScriptHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_scriptHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_scriptHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_scriptHashFromHex(hex);
    return Ptr._wrap(ret, ScriptHash);
  }

}


export class ScriptHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptHashesFromHex(hex_str);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptHashesFromJson(json);
    return Ptr._wrap(ret, ScriptHashes);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_scriptHashesNew();
    return Ptr._wrap(ret, ScriptHashes);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_scriptHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_scriptHashesGet(this.ptr, index);
    return Ptr._wrap(ret, ScriptHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, ScriptHash);
    const ret = HaskellShelley.csl_bridge_scriptHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptNOfK extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKFromHex(hex_str);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKFromJson(json);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async n() {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKN(this.ptr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.csl_bridge_scriptNOfKNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(n, native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.csl_bridge_scriptNOfKNew(n, native_scriptsPtr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

}


export class ScriptPubkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyFromJson(json);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async addr_keyhash() {
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyAddrKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(addr_keyhash) {
    const addr_keyhashPtr = Ptr._assertClass(addr_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_scriptPubkeyNew(addr_keyhashPtr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

}


export class ScriptRef extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptRefToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_scriptRefFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_scriptRefToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_scriptRefFromHex(hex_str);
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_scriptRefToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_scriptRefFromJson(json);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await HaskellShelley.csl_bridge_scriptRefNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_plutus_script(plutus_script) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScript);
    const ret = await HaskellShelley.csl_bridge_scriptRefNewPlutusScript(plutus_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  async is_native_script() {
    const ret = await HaskellShelley.csl_bridge_scriptRefIsNativeScript(this.ptr);
    return ret;
  }

  async is_plutus_script() {
    const ret = await HaskellShelley.csl_bridge_scriptRefIsPlutusScript(this.ptr);
    return ret;
  }

  async native_script() {
    const ret = await HaskellShelley.csl_bridge_scriptRefNativeScript(this.ptr);
    return Ptr._wrap(ret, NativeScript);
  }

  async plutus_script() {
    const ret = await HaskellShelley.csl_bridge_scriptRefPlutusScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async to_unwrapped_bytes() {
    const ret = await HaskellShelley.csl_bridge_scriptRefToUnwrappedBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class SingleHostAddr extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrFromJson(json);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async port() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrPort(this.ptr);
    return ret;
  }

  async ipv4() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrIpv4(this.ptr);
    return Ptr._wrap(ret, Ipv4);
  }

  async ipv6() {
    const ret = await HaskellShelley.csl_bridge_singleHostAddrIpv6(this.ptr);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(port, ipv4, ipv6) {
    const ipv4Ptr = Ptr._assertOptionalClass(ipv4, Ipv4);
    const ipv6Ptr = Ptr._assertOptionalClass(ipv6, Ipv6);
    if(port == null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNew();
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithPort(port);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithIpv4(ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithPortIpv4(port, ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithIpv6(ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithPortIpv6(port, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithIpv4Ipv6(ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.csl_bridge_singleHostAddrNewWithPortIpv4Ipv6(port, ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
  }

}


export class SingleHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_singleHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_singleHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_singleHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_singleHostNameFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_singleHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_singleHostNameFromJson(json);
    return Ptr._wrap(ret, SingleHostName);
  }

  async port() {
    const ret = await HaskellShelley.csl_bridge_singleHostNamePort(this.ptr);
    return ret;
  }

  async dns_name() {
    const ret = await HaskellShelley.csl_bridge_singleHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(port, dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordAorAAAA);
    if(port == null) {
      const ret = await HaskellShelley.csl_bridge_singleHostNameNew(dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
    if(port != null) {
      const ret = await HaskellShelley.csl_bridge_singleHostNameNewWithPort(port, dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
  }

}


export class StakeAndVoteDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationFromJson(json);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async drep() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  static async new(stake_credential, pool_keyhash, drep) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationNew(stake_credentialPtr, pool_keyhashPtr, drepPtr);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeAndVoteDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationFromJson(json);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(stake_credential, pool_keyhash) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_stakeDelegationNew(stake_credentialPtr, pool_keyhashPtr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeDeregistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationFromJson(json);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  static async new_with_explicit_refund(stake_credential, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationNewWithExplicitRefund(stake_credentialPtr, coinPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeDeregistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationFromJson(json);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  static async new_with_explicit_deposit(stake_credential, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationNewWithExplicitDeposit(stake_credentialPtr, coinPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, pool_keyhash, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationNew(stake_credentialPtr, pool_keyhashPtr, coinPtr);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeVoteRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async drep() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, pool_keyhash, drep, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationNew(stake_credentialPtr, pool_keyhashPtr, drepPtr, coinPtr);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_stakeVoteRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Strings extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_stringsNew();
    return Ptr._wrap(ret, Strings);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_stringsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_stringsGet(this.ptr, index);
    return ret;
  }

  add(elem) {
    const ret = HaskellShelley.csl_bridge_stringsAdd(this.ptr, elem);
    return ret;
  }

}


export class TimelockExpiry extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryFromHex(hex_str);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryFromJson(json);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async slot() {
    const ret = await HaskellShelley.csl_bridge_timelockExpirySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.csl_bridge_timelockExpirySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.csl_bridge_timelockExpiryNew(slot);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  static async new_timelockexpiry(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.csl_bridge_timelockExpiryNewTimelockexpiry(slotPtr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

}


export class TimelockStart extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_timelockStartToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_timelockStartFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_timelockStartToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_timelockStartFromHex(hex_str);
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_timelockStartToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_timelockStartFromJson(json);
    return Ptr._wrap(ret, TimelockStart);
  }

  async slot() {
    const ret = await HaskellShelley.csl_bridge_timelockStartSlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.csl_bridge_timelockStartSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.csl_bridge_timelockStartNew(slot);
    return Ptr._wrap(ret, TimelockStart);
  }

  static async new_timelockstart(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.csl_bridge_timelockStartNewTimelockstart(slotPtr);
    return Ptr._wrap(ret, TimelockStart);
  }

}


export class Transaction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Transaction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionFromHex(hex_str);
    return Ptr._wrap(ret, Transaction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionFromJson(json);
    return Ptr._wrap(ret, Transaction);
  }

  async body() {
    const ret = await HaskellShelley.csl_bridge_transactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async witness_set() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async is_valid() {
    const ret = await HaskellShelley.csl_bridge_transactionIsValid(this.ptr);
    return ret;
  }

  async auxiliary_data() {
    const ret = await HaskellShelley.csl_bridge_transactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_is_valid(valid) {
    const ret = HaskellShelley.csl_bridge_transactionSetIsValid(this.ptr, valid);
    return ret;
  }

  static async new(body, witness_set, auxiliary_data) {
    const bodyPtr = Ptr._assertClass(body, TransactionBody);
    const witness_setPtr = Ptr._assertClass(witness_set, TransactionWitnessSet);
    const auxiliary_dataPtr = Ptr._assertOptionalClass(auxiliary_data, AuxiliaryData);
    if(auxiliary_data == null) {
      const ret = await HaskellShelley.csl_bridge_transactionNew(bodyPtr, witness_setPtr);
      return Ptr._wrap(ret, Transaction);
    }
    if(auxiliary_data != null) {
      const ret = await HaskellShelley.csl_bridge_transactionNewWithAuxiliaryData(bodyPtr, witness_setPtr, auxiliary_dataPtr);
      return Ptr._wrap(ret, Transaction);
    }
  }

}


export class TransactionBatch extends Ptr {
  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionBatchLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionBatchGet(this.ptr, index);
    return Ptr._wrap(ret, Transaction);
  }

}


export class TransactionBatchList extends Ptr {
  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionBatchListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionBatchListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBatch);
  }

}


export class TransactionBodies extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesFromJson(json);
    return Ptr._wrap(ret, TransactionBodies);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesNew();
    return Ptr._wrap(ret, TransactionBodies);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionBodiesGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBody);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionBody);
    const ret = HaskellShelley.csl_bridge_transactionBodiesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionBodyFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionBodyFromJson(json);
    return Ptr._wrap(ret, TransactionBody);
  }

  async inputs() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async outputs() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyOutputs(this.ptr);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async fee() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async ttl() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyTtl(this.ptr);
    return ret;
  }

  async ttl_bignum() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyTtlBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ttl(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBodySetTtl(this.ptr, ttlPtr);
    return ret;
  }

  remove_ttl() {
    const ret = HaskellShelley.csl_bridge_transactionBodyRemoveTtl(this.ptr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.csl_bridge_transactionBodySetCerts(this.ptr, certsPtr);
    return ret;
  }

  async certs() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyCerts(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.csl_bridge_transactionBodySetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async withdrawals() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyWithdrawals(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

  set_update(update) {
    const updatePtr = Ptr._assertClass(update, Update);
    const ret = HaskellShelley.csl_bridge_transactionBodySetUpdate(this.ptr, updatePtr);
    return ret;
  }

  async update() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyUpdate(this.ptr);
    return Ptr._wrap(ret, Update);
  }

  set_auxiliary_data_hash(auxiliary_data_hash) {
    const auxiliary_data_hashPtr = Ptr._assertClass(auxiliary_data_hash, AuxiliaryDataHash);
    const ret = HaskellShelley.csl_bridge_transactionBodySetAuxiliaryDataHash(this.ptr, auxiliary_data_hashPtr);
    return ret;
  }

  async auxiliary_data_hash() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyAuxiliaryDataHash(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.csl_bridge_transactionBodySetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBodySetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  async validity_start_interval_bignum() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyValidityStartIntervalBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async validity_start_interval() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyValidityStartInterval(this.ptr);
    return ret;
  }

  set_mint(mint) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const ret = HaskellShelley.csl_bridge_transactionBodySetMint(this.ptr, mintPtr);
    return ret;
  }

  async mint() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  set_reference_inputs(reference_inputs) {
    const reference_inputsPtr = Ptr._assertClass(reference_inputs, TransactionInputs);
    const ret = HaskellShelley.csl_bridge_transactionBodySetReferenceInputs(this.ptr, reference_inputsPtr);
    return ret;
  }

  async reference_inputs() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_script_data_hash(script_data_hash) {
    const script_data_hashPtr = Ptr._assertClass(script_data_hash, ScriptDataHash);
    const ret = HaskellShelley.csl_bridge_transactionBodySetScriptDataHash(this.ptr, script_data_hashPtr);
    return ret;
  }

  async script_data_hash() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyScriptDataHash(this.ptr);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TransactionInputs);
    const ret = HaskellShelley.csl_bridge_transactionBodySetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  async collateral() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyCollateral(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_required_signers(required_signers) {
    const required_signersPtr = Ptr._assertClass(required_signers, Ed25519KeyHashes);
    const ret = HaskellShelley.csl_bridge_transactionBodySetRequiredSigners(this.ptr, required_signersPtr);
    return ret;
  }

  async required_signers() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  set_network_id(network_id) {
    const network_idPtr = Ptr._assertClass(network_id, NetworkId);
    const ret = HaskellShelley.csl_bridge_transactionBodySetNetworkId(this.ptr, network_idPtr);
    return ret;
  }

  async network_id() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyNetworkId(this.ptr);
    return Ptr._wrap(ret, NetworkId);
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.csl_bridge_transactionBodySetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  async collateral_return() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyCollateralReturn(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBodySetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  async total_collateral() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyTotalCollateral(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_voting_procedures(voting_procedures) {
    const voting_proceduresPtr = Ptr._assertClass(voting_procedures, VotingProcedures);
    const ret = HaskellShelley.csl_bridge_transactionBodySetVotingProcedures(this.ptr, voting_proceduresPtr);
    return ret;
  }

  async voting_procedures() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyVotingProcedures(this.ptr);
    return Ptr._wrap(ret, VotingProcedures);
  }

  set_voting_proposals(voting_proposals) {
    const voting_proposalsPtr = Ptr._assertClass(voting_proposals, VotingProposals);
    const ret = HaskellShelley.csl_bridge_transactionBodySetVotingProposals(this.ptr, voting_proposalsPtr);
    return ret;
  }

  async voting_proposals() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyVotingProposals(this.ptr);
    return Ptr._wrap(ret, VotingProposals);
  }

  set_donation(donation) {
    const donationPtr = Ptr._assertClass(donation, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBodySetDonation(this.ptr, donationPtr);
    return ret;
  }

  async donation() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyDonation(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_current_treasury_value(current_treasury_value) {
    const current_treasury_valuePtr = Ptr._assertClass(current_treasury_value, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBodySetCurrentTreasuryValue(this.ptr, current_treasury_valuePtr);
    return ret;
  }

  async current_treasury_value() {
    const ret = await HaskellShelley.csl_bridge_transactionBodyCurrentTreasuryValue(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(inputs, outputs, fee, ttl) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    if(ttl == null) {
      const ret = await HaskellShelley.csl_bridge_transactionBodyNew(inputsPtr, outputsPtr, feePtr);
      return Ptr._wrap(ret, TransactionBody);
    }
    if(ttl != null) {
      const ret = await HaskellShelley.csl_bridge_transactionBodyNewWithTtl(inputsPtr, outputsPtr, feePtr, ttl);
      return Ptr._wrap(ret, TransactionBody);
    }
  }

  static async new_tx_body(inputs, outputs, fee) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = await HaskellShelley.csl_bridge_transactionBodyNewTxBody(inputsPtr, outputsPtr, feePtr);
    return Ptr._wrap(ret, TransactionBody);
  }

}


export class TransactionBuilder extends Ptr {
  add_inputs_from(inputs, strategy) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddInputsFrom(this.ptr, inputsPtr, strategy);
    return ret;
  }

  set_inputs(inputs) {
    const inputsPtr = Ptr._assertClass(inputs, TxInputsBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetInputs(this.ptr, inputsPtr);
    return ret;
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TxInputsBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  remove_collateral_return() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveCollateralReturn(this.ptr);
    return ret;
  }

  set_collateral_return_and_total(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCollateralReturnAndTotal(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  remove_total_collateral() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveTotalCollateral(this.ptr);
    return ret;
  }

  set_total_collateral_and_return(total_collateral, return_address) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const return_addressPtr = Ptr._assertClass(return_address, Address);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetTotalCollateralAndReturn(this.ptr, total_collateralPtr, return_addressPtr);
    return ret;
  }

  add_reference_input(reference_input) {
    const reference_inputPtr = Ptr._assertClass(reference_input, TransactionInput);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddReferenceInput(this.ptr, reference_inputPtr);
    return ret;
  }

  add_script_reference_input(reference_input, script_size) {
    const reference_inputPtr = Ptr._assertClass(reference_input, TransactionInput);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddScriptReferenceInput(this.ptr, reference_inputPtr, script_size);
    return ret;
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddBootstrapInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_regular_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddRegularInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async add_inputs_from_and_change(inputs, strategy, change_config) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const change_configPtr = Ptr._assertClass(change_config, ChangeConfig);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderAddInputsFromAndChange(this.ptr, inputsPtr, strategy, change_configPtr);
    return ret;
  }

  add_inputs_from_and_change_with_collateral_return(inputs, strategy, change_config, collateral_percentage) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const change_configPtr = Ptr._assertClass(change_config, ChangeConfig);
    const collateral_percentagePtr = Ptr._assertClass(collateral_percentage, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddInputsFromAndChangeWithCollateralReturn(this.ptr, inputsPtr, strategy, change_configPtr, collateral_percentagePtr);
    return ret;
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async fee_for_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderFeeForInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return Ptr._wrap(ret, BigNum);
  }

  add_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddOutput(this.ptr, outputPtr);
    return ret;
  }

  async fee_for_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderFeeForOutput(this.ptr, outputPtr);
    return Ptr._wrap(ret, BigNum);
  }

  set_fee(fee) {
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetFee(this.ptr, feePtr);
    return ret;
  }

  set_ttl(ttl) {
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetTtl(this.ptr, ttl);
    return ret;
  }

  set_ttl_bignum(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetTtlBignum(this.ptr, ttlPtr);
    return ret;
  }

  remove_ttl() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveTtl(this.ptr);
    return ret;
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  remove_validity_start_interval() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveValidityStartInterval(this.ptr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCerts(this.ptr, certsPtr);
    return ret;
  }

  remove_certs() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveCerts(this.ptr);
    return ret;
  }

  set_certs_builder(certs) {
    const certsPtr = Ptr._assertClass(certs, CertificatesBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCertsBuilder(this.ptr, certsPtr);
    return ret;
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  set_withdrawals_builder(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, WithdrawalsBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetWithdrawalsBuilder(this.ptr, withdrawalsPtr);
    return ret;
  }

  set_voting_builder(voting_builder) {
    const voting_builderPtr = Ptr._assertClass(voting_builder, VotingBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetVotingBuilder(this.ptr, voting_builderPtr);
    return ret;
  }

  set_voting_proposal_builder(voting_proposal_builder) {
    const voting_proposal_builderPtr = Ptr._assertClass(voting_proposal_builder, VotingProposalBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetVotingProposalBuilder(this.ptr, voting_proposal_builderPtr);
    return ret;
  }

  remove_withdrawals() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveWithdrawals(this.ptr);
    return ret;
  }

  async get_auxiliary_data() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_auxiliary_data(auxiliary_data) {
    const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetAuxiliaryData(this.ptr, auxiliary_dataPtr);
    return ret;
  }

  remove_auxiliary_data() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveAuxiliaryData(this.ptr);
    return ret;
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  add_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valPtr = Ptr._assertClass(val, TransactionMetadatum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddMetadatum(this.ptr, keyPtr, valPtr);
    return ret;
  }

  add_json_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddJsonMetadatum(this.ptr, keyPtr, val);
    return ret;
  }

  add_json_metadatum_with_schema(key, val, schema) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddJsonMetadatumWithSchema(this.ptr, keyPtr, val, schema);
    return ret;
  }

  set_mint_builder(mint_builder) {
    const mint_builderPtr = Ptr._assertClass(mint_builder, MintBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetMintBuilder(this.ptr, mint_builderPtr);
    return ret;
  }

  remove_mint_builder() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveMintBuilder(this.ptr);
    return ret;
  }

  async get_mint_builder() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetMintBuilder(this.ptr);
    return Ptr._wrap(ret, MintBuilder);
  }

  set_mint(mint, mint_scripts) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const mint_scriptsPtr = Ptr._assertClass(mint_scripts, NativeScripts);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetMint(this.ptr, mintPtr, mint_scriptsPtr);
    return ret;
  }

  async get_mint() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_mint_scripts() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetMintScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_mint_asset(policy_script, mint_assets) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetMintAsset(this.ptr, policy_scriptPtr, mint_assetsPtr);
    return ret;
  }

  add_mint_asset(policy_script, asset_name, amount) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddMintAsset(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr);
    return ret;
  }

  add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const output_coinPtr = Ptr._assertClass(output_coin, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddMintAssetAndOutput(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr, output_coinPtr);
    return ret;
  }

  add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddMintAssetAndOutputMinRequiredCoin(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr);
    return ret;
  }

  add_extra_witness_datum(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddExtraWitnessDatum(this.ptr, datumPtr);
    return ret;
  }

  async get_extra_witness_datums() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetExtraWitnessDatums(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_donation(donation) {
    const donationPtr = Ptr._assertClass(donation, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetDonation(this.ptr, donationPtr);
    return ret;
  }

  async get_donation() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetDonation(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_current_treasury_value(current_treasury_value) {
    const current_treasury_valuePtr = Ptr._assertClass(current_treasury_value, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetCurrentTreasuryValue(this.ptr, current_treasury_valuePtr);
    return ret;
  }

  async get_current_treasury_value() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetCurrentTreasuryValue(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(cfg) {
    const cfgPtr = Ptr._assertClass(cfg, TransactionBuilderConfig);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderNew(cfgPtr);
    return Ptr._wrap(ret, TransactionBuilder);
  }

  async get_reference_inputs() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_explicit_input() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetExplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_implicit_input() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetImplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_input() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetTotalInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_output() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetTotalOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_explicit_output() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetExplicitOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_deposit() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_fee_if_set() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderGetFeeIfSet(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async add_change_if_needed(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderAddChangeIfNeeded(this.ptr, addressPtr);
    return ret;
  }

  async add_change_if_needed_with_datum(address, plutus_data) {
    const addressPtr = Ptr._assertClass(address, Address);
    const plutus_dataPtr = Ptr._assertClass(plutus_data, OutputDatum);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderAddChangeIfNeededWithDatum(this.ptr, addressPtr, plutus_dataPtr);
    return ret;
  }

  calc_script_data_hash(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.csl_bridge_transactionBuilderCalcScriptDataHash(this.ptr, cost_modelsPtr);
    return ret;
  }

  set_script_data_hash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptDataHash);
    const ret = HaskellShelley.csl_bridge_transactionBuilderSetScriptDataHash(this.ptr, hashPtr);
    return ret;
  }

  remove_script_data_hash() {
    const ret = HaskellShelley.csl_bridge_transactionBuilderRemoveScriptDataHash(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.csl_bridge_transactionBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  async full_size() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderFullSize(this.ptr);
    return ret;
  }

  async output_sizes() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderOutputSizes(this.ptr);
    return base64ToUint32Array(ret);
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async build_tx() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderBuildTx(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async build_tx_unsafe() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderBuildTxUnsafe(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async min_fee() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderMinFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class TransactionBuilderConfig extends Ptr {
}


export class TransactionBuilderConfigBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderNew();
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async fee_algo(fee_algo) {
    const fee_algoPtr = Ptr._assertClass(fee_algo, LinearFee);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderFeeAlgo(this.ptr, fee_algoPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_byte(coins_per_utxo_byte) {
    const coins_per_utxo_bytePtr = Ptr._assertClass(coins_per_utxo_byte, BigNum);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderCoinsPerUtxoByte(this.ptr, coins_per_utxo_bytePtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async ex_unit_prices(ex_unit_prices) {
    const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderExUnitPrices(this.ptr, ex_unit_pricesPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderPoolDeposit(this.ptr, pool_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderKeyDeposit(this.ptr, key_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_value_size(max_value_size) {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderMaxValueSize(this.ptr, max_value_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_tx_size(max_tx_size) {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderMaxTxSize(this.ptr, max_tx_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async ref_script_coins_per_byte(ref_script_coins_per_byte) {
    const ref_script_coins_per_bytePtr = Ptr._assertClass(ref_script_coins_per_byte, UnitInterval);
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderRefScriptCoinsPerByte(this.ptr, ref_script_coins_per_bytePtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async prefer_pure_change(prefer_pure_change) {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderPreferPureChange(this.ptr, prefer_pure_change);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async deduplicate_explicit_ref_inputs_with_regular_inputs(deduplicate_explicit_ref_inputs_with_regular_inputs) {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderDeduplicateExplicitRefInputsWithRegularInputs(this.ptr, deduplicate_explicit_ref_inputs_with_regular_inputs);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_transactionBuilderConfigBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBuilderConfig);
  }

}


export class TransactionHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_transactionHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_transactionHashFromBech32(bech_str);
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_transactionHashFromHex(hex);
    return Ptr._wrap(ret, TransactionHash);
  }

}


export class TransactionInput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionInputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionInputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionInputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionInputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionInputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionInputFromJson(json);
    return Ptr._wrap(ret, TransactionInput);
  }

  async transaction_id() {
    const ret = await HaskellShelley.csl_bridge_transactionInputTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await HaskellShelley.csl_bridge_transactionInputIndex(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await HaskellShelley.csl_bridge_transactionInputNew(transaction_idPtr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class TransactionInputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionInputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionInputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionInputsFromJson(json);
    return Ptr._wrap(ret, TransactionInputs);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsNew();
    return Ptr._wrap(ret, TransactionInputs);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionInputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionInput);
    const ret = await HaskellShelley.csl_bridge_transactionInputsAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.csl_bridge_transactionInputsToOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class TransactionMetadatum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, MetadataMap);
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumNewMap(mapPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, MetadataList);
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumNewList(listPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_int(int_value) {
    const int_valuePtr = Ptr._assertClass(int_value, Int);
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumNewInt(int_valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_text(text) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumNewText(text);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumKind(this.ptr);
    return ret;
  }

  async as_map() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumAsMap(this.ptr);
    return Ptr._wrap(ret, MetadataMap);
  }

  async as_list() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumAsList(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

  async as_int() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  async as_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async as_text() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumAsText(this.ptr);
    return ret;
  }

}


export class TransactionMetadatumLabels extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsNew();
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionMetadatumLabelsGet(this.ptr, index);
    return Ptr._wrap(ret, BigNum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BigNum);
    const ret = HaskellShelley.csl_bridge_transactionMetadatumLabelsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputFromJson(json);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async address() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  async amount() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmount(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async data_hash() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputDataHash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async plutus_data() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async script_ref() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputScriptRef(this.ptr);
    return Ptr._wrap(ret, ScriptRef);
  }

  set_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = HaskellShelley.csl_bridge_transactionOutputSetScriptRef(this.ptr, script_refPtr);
    return ret;
  }

  set_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = HaskellShelley.csl_bridge_transactionOutputSetPlutusData(this.ptr, dataPtr);
    return ret;
  }

  set_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = HaskellShelley.csl_bridge_transactionOutputSetDataHash(this.ptr, data_hashPtr);
    return ret;
  }

  async has_plutus_data() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputHasPlutusData(this.ptr);
    return ret;
  }

  async has_data_hash() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputHasDataHash(this.ptr);
    return ret;
  }

  async has_script_ref() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputHasScriptRef(this.ptr);
    return ret;
  }

  static async new(address, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.csl_bridge_transactionOutputNew(addressPtr, amountPtr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async serialization_format() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputSerializationFormat(this.ptr);
    return ret;
  }

}


export class TransactionOutputAmountBuilder extends Ptr {
  async with_value(amount) {
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmountBuilderWithValue(this.ptr, amountPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmountBuilderWithCoin(this.ptr, coinPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin_and_asset(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmountBuilderWithCoinAndAsset(this.ptr, coinPtr, multiassetPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const data_costPtr = Ptr._assertClass(data_cost, DataCost);
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(this.ptr, multiassetPtr, data_costPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputAmountBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionOutputBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderNew();
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderWithAddress(this.ptr, addressPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderWithDataHash(this.ptr, data_hashPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderWithPlutusData(this.ptr, dataPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderWithScriptRef(this.ptr, script_refPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async next() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputBuilderNext(this.ptr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

}


export class TransactionOutputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsNew();
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionOutput);
    const ret = HaskellShelley.csl_bridge_transactionOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionUnspentOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  static async new(input, output) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputNew(inputPtr, outputPtr);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async input() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputInput(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

  async output() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputOutput(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionUnspentOutputs extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputsNew();
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionUnspentOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionUnspentOutput);
    const ret = HaskellShelley.csl_bridge_transactionUnspentOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionWitnessSet extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  set_vkeys(vkeys) {
    const vkeysPtr = Ptr._assertClass(vkeys, Vkeywitnesses);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetVkeys(this.ptr, vkeysPtr);
    return ret;
  }

  async vkeys() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetVkeys(this.ptr);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_bootstraps(bootstraps) {
    const bootstrapsPtr = Ptr._assertClass(bootstraps, BootstrapWitnesses);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetBootstraps(this.ptr, bootstrapsPtr);
    return ret;
  }

  async bootstraps() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetBootstraps(this.ptr);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_data(plutus_data) {
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusList);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetPlutusData(this.ptr, plutus_dataPtr);
    return ret;
  }

  async plutus_data() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_redeemers(redeemers) {
    const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetSetRedeemers(this.ptr, redeemersPtr);
    return ret;
  }

  async redeemers() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetRedeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetNew();
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

}


export class TransactionWitnessSets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsNew();
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_transactionWitnessSetsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionWitnessSet);
    const ret = HaskellShelley.csl_bridge_transactionWitnessSetsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TreasuryWithdrawals extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsFromJson(json);
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsNew();
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = HaskellShelley.csl_bridge_treasuryWithdrawalsInsert(this.ptr, keyPtr, valuePtr);
    return ret;
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsKeys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsLen(this.ptr);
    return ret;
  }

}


export class TreasuryWithdrawalsAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionFromHex(hex_str);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionFromJson(json);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async withdrawals() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionWithdrawals(this.ptr);
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  async policy_hash() {
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionPolicyHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, TreasuryWithdrawals);
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionNew(withdrawalsPtr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  static async new_with_policy_hash(withdrawals, policy_hash) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, TreasuryWithdrawals);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.csl_bridge_treasuryWithdrawalsActionNewWithPolicyHash(withdrawalsPtr, policy_hashPtr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

}


export class TxBuilderConstants extends Ptr {
  static async plutus_default_cost_models() {
    const ret = await HaskellShelley.csl_bridge_txBuilderConstantsPlutusDefaultCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_alonzo_cost_models() {
    const ret = await HaskellShelley.csl_bridge_txBuilderConstantsPlutusAlonzoCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_vasil_cost_models() {
    const ret = await HaskellShelley.csl_bridge_txBuilderConstantsPlutusVasilCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_conway_cost_models() {
    const ret = await HaskellShelley.csl_bridge_txBuilderConstantsPlutusConwayCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

}


export class TxInputsBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderNew();
    return Ptr._wrap(ret, TxInputsBuilder);
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScriptSource);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddBootstrapInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  add_regular_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddRegularInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderLen(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  add_required_signers(keys) {
    const keysPtr = Ptr._assertClass(keys, Ed25519KeyHashes);
    const ret = HaskellShelley.csl_bridge_txInputsBuilderAddRequiredSigners(this.ptr, keysPtr);
    return ret;
  }

  async total_value() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderTotalValue(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async inputs() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async inputs_option() {
    const ret = await HaskellShelley.csl_bridge_txInputsBuilderInputsOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class URL extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_uRLToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_uRLFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, URL);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_uRLToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_uRLFromHex(hex_str);
    return Ptr._wrap(ret, URL);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_uRLToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_uRLFromJson(json);
    return Ptr._wrap(ret, URL);
  }

  static async new(url) {
    const ret = await HaskellShelley.csl_bridge_uRLNew(url);
    return Ptr._wrap(ret, URL);
  }

  async url() {
    const ret = await HaskellShelley.csl_bridge_uRLUrl(this.ptr);
    return ret;
  }

}


export class UnitInterval extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_unitIntervalToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_unitIntervalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_unitIntervalToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_unitIntervalFromHex(hex_str);
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_unitIntervalToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_unitIntervalFromJson(json);
    return Ptr._wrap(ret, UnitInterval);
  }

  async numerator() {
    const ret = await HaskellShelley.csl_bridge_unitIntervalNumerator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async denominator() {
    const ret = await HaskellShelley.csl_bridge_unitIntervalDenominator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(numerator, denominator) {
    const numeratorPtr = Ptr._assertClass(numerator, BigNum);
    const denominatorPtr = Ptr._assertClass(denominator, BigNum);
    const ret = await HaskellShelley.csl_bridge_unitIntervalNew(numeratorPtr, denominatorPtr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class Update extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_updateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_updateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Update);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_updateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_updateFromHex(hex_str);
    return Ptr._wrap(ret, Update);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_updateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_updateFromJson(json);
    return Ptr._wrap(ret, Update);
  }

  async proposed_protocol_parameter_updates() {
    const ret = await HaskellShelley.csl_bridge_updateProposedProtocolParameterUpdates(this.ptr);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async epoch() {
    const ret = await HaskellShelley.csl_bridge_updateEpoch(this.ptr);
    return ret;
  }

  static async new(proposed_protocol_parameter_updates, epoch) {
    const proposed_protocol_parameter_updatesPtr = Ptr._assertClass(proposed_protocol_parameter_updates, ProposedProtocolParameterUpdates);
    const ret = await HaskellShelley.csl_bridge_updateNew(proposed_protocol_parameter_updatesPtr, epoch);
    return Ptr._wrap(ret, Update);
  }

}


export class UpdateCommitteeAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionFromHex(hex_str);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionFromJson(json);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async committee() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionCommittee(this.ptr);
    return Ptr._wrap(ret, Committee);
  }

  async members_to_remove() {
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionMembersToRemove(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

  static async new(committee, members_to_remove) {
    const committeePtr = Ptr._assertClass(committee, Committee);
    const members_to_removePtr = Ptr._assertClass(members_to_remove, Credentials);
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionNew(committeePtr, members_to_removePtr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  static async new_with_action_id(gov_action_id, committee, members_to_remove) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const committeePtr = Ptr._assertClass(committee, Committee);
    const members_to_removePtr = Ptr._assertClass(members_to_remove, Credentials);
    const ret = await HaskellShelley.csl_bridge_updateCommitteeActionNewWithActionId(gov_action_idPtr, committeePtr, members_to_removePtr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

}


export class VRFCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vRFCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vRFCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vRFCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_vRFCertFromHex(hex_str);
    return Ptr._wrap(ret, VRFCert);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_vRFCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_vRFCertFromJson(json);
    return Ptr._wrap(ret, VRFCert);
  }

  async output() {
    const ret = await HaskellShelley.csl_bridge_vRFCertOutput(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async proof() {
    const ret = await HaskellShelley.csl_bridge_vRFCertProof(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(output, proof) {
    const ret = await HaskellShelley.csl_bridge_vRFCertNew(b64FromUint8Array(output), b64FromUint8Array(proof));
    return Ptr._wrap(ret, VRFCert);
  }

}


export class VRFKeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_vRFKeyHashFromHex(hex);
    return Ptr._wrap(ret, VRFKeyHash);
  }

}


export class VRFVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.csl_bridge_vRFVKeyFromHex(hex);
    return Ptr._wrap(ret, VRFVKey);
  }

}


export class Value extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_valueToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_valueFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Value);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_valueToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_valueFromHex(hex_str);
    return Ptr._wrap(ret, Value);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_valueToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_valueFromJson(json);
    return Ptr._wrap(ret, Value);
  }

  static async new(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_valueNew(coinPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_from_assets(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.csl_bridge_valueNewFromAssets(multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_with_assets(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.csl_bridge_valueNewWithAssets(coinPtr, multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async zero() {
    const ret = await HaskellShelley.csl_bridge_valueZero();
    return Ptr._wrap(ret, Value);
  }

  async is_zero() {
    const ret = await HaskellShelley.csl_bridge_valueIsZero(this.ptr);
    return ret;
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_valueCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = HaskellShelley.csl_bridge_valueSetCoin(this.ptr, coinPtr);
    return ret;
  }

  async multiasset() {
    const ret = await HaskellShelley.csl_bridge_valueMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  set_multiasset(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = HaskellShelley.csl_bridge_valueSetMultiasset(this.ptr, multiassetPtr);
    return ret;
  }

  async checked_add(rhs) {
    const rhsPtr = Ptr._assertClass(rhs, Value);
    const ret = await HaskellShelley.csl_bridge_valueCheckedAdd(this.ptr, rhsPtr);
    return Ptr._wrap(ret, Value);
  }

  async checked_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.csl_bridge_valueCheckedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async clamped_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.csl_bridge_valueClampedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.csl_bridge_valueCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

}


export class VersionedBlock extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_versionedBlockToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_versionedBlockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VersionedBlock);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_versionedBlockToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_versionedBlockFromHex(hex_str);
    return Ptr._wrap(ret, VersionedBlock);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_versionedBlockToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_versionedBlockFromJson(json);
    return Ptr._wrap(ret, VersionedBlock);
  }

  static async new(block, era_code) {
    const blockPtr = Ptr._assertClass(block, Block);
    const ret = await HaskellShelley.csl_bridge_versionedBlockNew(blockPtr, era_code);
    return Ptr._wrap(ret, VersionedBlock);
  }

  async block() {
    const ret = await HaskellShelley.csl_bridge_versionedBlockBlock(this.ptr);
    return Ptr._wrap(ret, Block);
  }

  async era() {
    const ret = await HaskellShelley.csl_bridge_versionedBlockEra(this.ptr);
    return ret;
  }

}


export class Vkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_vkeyFromHex(hex_str);
    return Ptr._wrap(ret, Vkey);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_vkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_vkeyFromJson(json);
    return Ptr._wrap(ret, Vkey);
  }

  static async new(pk) {
    const pkPtr = Ptr._assertClass(pk, PublicKey);
    const ret = await HaskellShelley.csl_bridge_vkeyNew(pkPtr);
    return Ptr._wrap(ret, Vkey);
  }

  async public_key() {
    const ret = await HaskellShelley.csl_bridge_vkeyPublicKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class Vkeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_vkeysNew();
    return Ptr._wrap(ret, Vkeys);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_vkeysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_vkeysGet(this.ptr, index);
    return Ptr._wrap(ret, Vkey);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkey);
    const ret = HaskellShelley.csl_bridge_vkeysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Vkeywitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessFromJson(json);
    return Ptr._wrap(ret, Vkeywitness);
  }

  static async new(vkey, signature) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.csl_bridge_vkeywitnessNew(vkeyPtr, signaturePtr);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async vkey() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class Vkeywitnesses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesFromJson(json);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesNew();
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkeywitness);
    const ret = await HaskellShelley.csl_bridge_vkeywitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class VoteDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_voteDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VoteDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_voteDelegationFromHex(hex_str);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_voteDelegationFromJson(json);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async drep() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  static async new(stake_credential, drep) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const ret = await HaskellShelley.csl_bridge_voteDelegationNew(stake_credentialPtr, drepPtr);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_voteDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class VoteRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async drep() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  async coin() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, drep, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationNew(stake_credentialPtr, drepPtr, coinPtr);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_voteRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Voter extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_voterToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_voterFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Voter);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_voterToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_voterFromHex(hex_str);
    return Ptr._wrap(ret, Voter);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_voterToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_voterFromJson(json);
    return Ptr._wrap(ret, Voter);
  }

  static async new_constitutional_committee_hot_credential(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.csl_bridge_voterNewConstitutionalCommitteeHotCredential(credPtr);
    return Ptr._wrap(ret, Voter);
  }

  static async new_drep_credential(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.csl_bridge_voterNewDrepCredential(credPtr);
    return Ptr._wrap(ret, Voter);
  }

  static async new_stake_pool_key_hash(key_hash) {
    const key_hashPtr = Ptr._assertClass(key_hash, Ed25519KeyHash);
    const ret = await HaskellShelley.csl_bridge_voterNewStakePoolKeyHash(key_hashPtr);
    return Ptr._wrap(ret, Voter);
  }

  async kind() {
    const ret = await HaskellShelley.csl_bridge_voterKind(this.ptr);
    return ret;
  }

  async to_constitutional_committee_hot_credential() {
    const ret = await HaskellShelley.csl_bridge_voterToConstitutionalCommitteeHotCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_drep_credential() {
    const ret = await HaskellShelley.csl_bridge_voterToDrepCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_stake_pool_key_hash() {
    const ret = await HaskellShelley.csl_bridge_voterToStakePoolKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.csl_bridge_voterHasScriptCredentials(this.ptr);
    return ret;
  }

  async to_key_hash() {
    const ret = await HaskellShelley.csl_bridge_voterToKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class Voters extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.csl_bridge_votersToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_votersFromJson(json);
    return Ptr._wrap(ret, Voters);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_votersNew();
    return Ptr._wrap(ret, Voters);
  }

  add(voter) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const ret = HaskellShelley.csl_bridge_votersAdd(this.ptr, voterPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_votersGet(this.ptr, index);
    return Ptr._wrap(ret, Voter);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_votersLen(this.ptr);
    return ret;
  }

}


export class VotingBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderNew();
    return Ptr._wrap(ret, VotingBuilder);
  }

  add(voter, gov_action_id, voting_procedure) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const ret = HaskellShelley.csl_bridge_votingBuilderAdd(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr);
    return ret;
  }

  add_with_plutus_witness(voter, gov_action_id, voting_procedure, witness) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.csl_bridge_votingBuilderAddWithPlutusWitness(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr, witnessPtr);
    return ret;
  }

  add_with_native_script(voter, gov_action_id, voting_procedure, native_script_source) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.csl_bridge_votingBuilderAddWithNativeScript(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_votingBuilderBuild(this.ptr);
    return Ptr._wrap(ret, VotingProcedures);
  }

}


export class VotingProcedure extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_votingProcedureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_votingProcedureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProcedure);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_votingProcedureToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_votingProcedureFromHex(hex_str);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_votingProcedureToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_votingProcedureFromJson(json);
    return Ptr._wrap(ret, VotingProcedure);
  }

  static async new(vote) {
    const ret = await HaskellShelley.csl_bridge_votingProcedureNew(vote);
    return Ptr._wrap(ret, VotingProcedure);
  }

  static async new_with_anchor(vote, anchor) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.csl_bridge_votingProcedureNewWithAnchor(vote, anchorPtr);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async vote_kind() {
    const ret = await HaskellShelley.csl_bridge_votingProcedureVoteKind(this.ptr);
    return ret;
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_votingProcedureAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

}


export class VotingProcedures extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_votingProceduresToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_votingProceduresFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProcedures);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_votingProceduresToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_votingProceduresFromHex(hex_str);
    return Ptr._wrap(ret, VotingProcedures);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_votingProceduresToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_votingProceduresFromJson(json);
    return Ptr._wrap(ret, VotingProcedures);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_votingProceduresNew();
    return Ptr._wrap(ret, VotingProcedures);
  }

  insert(voter, governance_action_id, voting_procedure) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const ret = HaskellShelley.csl_bridge_votingProceduresInsert(this.ptr, voterPtr, governance_action_idPtr, voting_procedurePtr);
    return ret;
  }

  async get(voter, governance_action_id) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const ret = await HaskellShelley.csl_bridge_votingProceduresGet(this.ptr, voterPtr, governance_action_idPtr);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async get_voters() {
    const ret = await HaskellShelley.csl_bridge_votingProceduresGetVoters(this.ptr);
    return Ptr._wrap(ret, Voters);
  }

  async get_governance_action_ids_by_voter(voter) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const ret = await HaskellShelley.csl_bridge_votingProceduresGetGovernanceActionIdsByVoter(this.ptr, voterPtr);
    return Ptr._wrap(ret, GovernanceActionIds);
  }

}


export class VotingProposal extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_votingProposalToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_votingProposalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProposal);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_votingProposalToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_votingProposalFromHex(hex_str);
    return Ptr._wrap(ret, VotingProposal);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_votingProposalToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_votingProposalFromJson(json);
    return Ptr._wrap(ret, VotingProposal);
  }

  async governance_action() {
    const ret = await HaskellShelley.csl_bridge_votingProposalGovernanceAction(this.ptr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async anchor() {
    const ret = await HaskellShelley.csl_bridge_votingProposalAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  async reward_account() {
    const ret = await HaskellShelley.csl_bridge_votingProposalRewardAccount(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async deposit() {
    const ret = await HaskellShelley.csl_bridge_votingProposalDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(governance_action, anchor, reward_account, deposit) {
    const governance_actionPtr = Ptr._assertClass(governance_action, GovernanceAction);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const reward_accountPtr = Ptr._assertClass(reward_account, RewardAddress);
    const depositPtr = Ptr._assertClass(deposit, BigNum);
    const ret = await HaskellShelley.csl_bridge_votingProposalNew(governance_actionPtr, anchorPtr, reward_accountPtr, depositPtr);
    return Ptr._wrap(ret, VotingProposal);
  }

}


export class VotingProposalBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_votingProposalBuilderNew();
    return Ptr._wrap(ret, VotingProposalBuilder);
  }

  add(proposal) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const ret = HaskellShelley.csl_bridge_votingProposalBuilderAdd(this.ptr, proposalPtr);
    return ret;
  }

  add_with_plutus_witness(proposal, witness) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.csl_bridge_votingProposalBuilderAddWithPlutusWitness(this.ptr, proposalPtr, witnessPtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.csl_bridge_votingProposalBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_votingProposalBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_votingProposalBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_votingProposalBuilderBuild(this.ptr);
    return Ptr._wrap(ret, VotingProposals);
  }

}


export class VotingProposals extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_votingProposalsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_votingProposalsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProposals);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_votingProposalsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_votingProposalsFromHex(hex_str);
    return Ptr._wrap(ret, VotingProposals);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_votingProposalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_votingProposalsFromJson(json);
    return Ptr._wrap(ret, VotingProposals);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_votingProposalsNew();
    return Ptr._wrap(ret, VotingProposals);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_votingProposalsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.csl_bridge_votingProposalsGet(this.ptr, index);
    return Ptr._wrap(ret, VotingProposal);
  }

  async add(proposal) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const ret = await HaskellShelley.csl_bridge_votingProposalsAdd(this.ptr, proposalPtr);
    return ret;
  }

}


export class Withdrawals extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.csl_bridge_withdrawalsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_hex() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.csl_bridge_withdrawalsFromHex(hex_str);
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_json() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.csl_bridge_withdrawalsFromJson(json);
    return Ptr._wrap(ret, Withdrawals);
  }

  static async new() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsNew();
    return Ptr._wrap(ret, Withdrawals);
  }

  async len() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.csl_bridge_withdrawalsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await HaskellShelley.csl_bridge_withdrawalsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsKeys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

}


export class WithdrawalsBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderNew();
    return Ptr._wrap(ret, WithdrawalsBuilder);
  }

  add(address, coin) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = HaskellShelley.csl_bridge_withdrawalsBuilderAdd(this.ptr, addressPtr, coinPtr);
    return ret;
  }

  add_with_plutus_witness(address, coin, witness) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.csl_bridge_withdrawalsBuilderAddWithPlutusWitness(this.ptr, addressPtr, coinPtr, witnessPtr);
    return ret;
  }

  add_with_native_script(address, coin, native_script_source) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.csl_bridge_withdrawalsBuilderAddWithNativeScript(this.ptr, addressPtr, coinPtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_total_withdrawals() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderGetTotalWithdrawals(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.csl_bridge_withdrawalsBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

}


export const calculate_ex_units_ceil_cost = async (ex_units, ex_unit_prices) => {
  const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.csl_bridge_calculateExUnitsCeilCost(ex_unitsPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const create_send_all = async (address, utxos, config) => {
  const addressPtr = Ptr._assertClass(address, Address);
  const utxosPtr = Ptr._assertClass(utxos, TransactionUnspentOutputs);
  const configPtr = Ptr._assertClass(config, TransactionBuilderConfig);
  const ret = await HaskellShelley.csl_bridge_createSendAll(addressPtr, utxosPtr, configPtr);
  return Ptr._wrap(ret, TransactionBatchList);
};


export const decode_arbitrary_bytes_from_metadatum = async (metadata) => {
  const metadataPtr = Ptr._assertClass(metadata, TransactionMetadatum);
  const ret = await HaskellShelley.csl_bridge_decodeArbitraryBytesFromMetadatum(metadataPtr);
  return uint8ArrayFromB64(ret);
};


export const decode_metadatum_to_json_str = async (metadatum, schema) => {
  const metadatumPtr = Ptr._assertClass(metadatum, TransactionMetadatum);
  const ret = await HaskellShelley.csl_bridge_decodeMetadatumToJsonStr(metadatumPtr, schema);
  return ret;
};


export const decode_plutus_datum_to_json_str = async (datum, schema) => {
  const datumPtr = Ptr._assertClass(datum, PlutusData);
  const ret = await HaskellShelley.csl_bridge_decodePlutusDatumToJsonStr(datumPtr, schema);
  return ret;
};


export const decrypt_with_password = async (password, data) => {
  const ret = await HaskellShelley.csl_bridge_decryptWithPassword(password, data);
  return ret;
};


export const encode_arbitrary_bytes_as_metadatum = async (bytes) => {
  const ret = await HaskellShelley.csl_bridge_encodeArbitraryBytesAsMetadatum(b64FromUint8Array(bytes));
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_metadatum = async (json, schema) => {
  const ret = await HaskellShelley.csl_bridge_encodeJsonStrToMetadatum(json, schema);
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_native_script = async (json, self_xpub, schema) => {
  const ret = await HaskellShelley.csl_bridge_encodeJsonStrToNativeScript(json, self_xpub, schema);
  return Ptr._wrap(ret, NativeScript);
};


export const encode_json_str_to_plutus_datum = async (json, schema) => {
  const ret = await HaskellShelley.csl_bridge_encodeJsonStrToPlutusDatum(json, schema);
  return Ptr._wrap(ret, PlutusData);
};


export const encrypt_with_password = async (password, salt, nonce, data) => {
  const ret = await HaskellShelley.csl_bridge_encryptWithPassword(password, salt, nonce, data);
  return ret;
};


export const get_deposit = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.csl_bridge_getDeposit(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, BigNum);
};


export const get_implicit_input = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.csl_bridge_getImplicitInput(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, Value);
};


export const hash_auxiliary_data = async (auxiliary_data) => {
  const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
  const ret = await HaskellShelley.csl_bridge_hashAuxiliaryData(auxiliary_dataPtr);
  return Ptr._wrap(ret, AuxiliaryDataHash);
};


export const hash_plutus_data = async (plutus_data) => {
  const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
  const ret = await HaskellShelley.csl_bridge_hashPlutusData(plutus_dataPtr);
  return Ptr._wrap(ret, DataHash);
};


export const hash_script_data = async (redeemers, cost_models, datums) => {
  const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
  const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
  const datumsPtr = Ptr._assertOptionalClass(datums, PlutusList);
  if(datums == null) {
    const ret = await HaskellShelley.csl_bridge_hashScriptData(redeemersPtr, cost_modelsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
  if(datums != null) {
    const ret = await HaskellShelley.csl_bridge_hashScriptDataWithDatums(redeemersPtr, cost_modelsPtr, datumsPtr);
    return Ptr._wrap(ret, ScriptDataHash);
  }
};


export const hash_transaction = async (tx_body) => {
  const tx_bodyPtr = Ptr._assertClass(tx_body, TransactionBody);
  const ret = await HaskellShelley.csl_bridge_hashTransaction(tx_bodyPtr);
  return Ptr._wrap(ret, TransactionHash);
};


export const make_daedalus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, LegacyDaedalusPrivateKey);
  const ret = await HaskellShelley.csl_bridge_makeDaedalusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const make_icarus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await HaskellShelley.csl_bridge_makeIcarusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const make_vkey_witness = async (tx_body_hash, sk) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await HaskellShelley.csl_bridge_makeVkeyWitness(tx_body_hashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
};


export const min_ada_for_output = async (output, data_cost) => {
  const outputPtr = Ptr._assertClass(output, TransactionOutput);
  const data_costPtr = Ptr._assertClass(data_cost, DataCost);
  const ret = await HaskellShelley.csl_bridge_minAdaForOutput(outputPtr, data_costPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_fee = async (tx, linear_fee) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const linear_feePtr = Ptr._assertClass(linear_fee, LinearFee);
  const ret = await HaskellShelley.csl_bridge_minFee(txPtr, linear_feePtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_ref_script_fee = async (total_ref_scripts_size, ref_script_coins_per_byte) => {
  const ref_script_coins_per_bytePtr = Ptr._assertClass(ref_script_coins_per_byte, UnitInterval);
  const ret = await HaskellShelley.csl_bridge_minRefScriptFee(total_ref_scripts_size, ref_script_coins_per_bytePtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_script_fee = async (tx, ex_unit_prices) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.csl_bridge_minScriptFee(txPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const AddressKind = Object.freeze({
  Base: 0,
  Pointer: 1,
  Enterprise: 2,
  Reward: 3,
  Byron: 4,
  Malformed: 5,
});


export const BlockEra = Object.freeze({
  Byron: 0,
  Shelley: 1,
  Allegra: 2,
  Mary: 3,
  Alonzo: 4,
  Babbage: 5,
  Conway: 6,
  Unknown: 7,
});


export const CborContainerType = Object.freeze({
  Array: 0,
  Map: 1,
});


export const CertificateKind = Object.freeze({
  StakeRegistration: 0,
  StakeDeregistration: 1,
  StakeDelegation: 2,
  PoolRegistration: 3,
  PoolRetirement: 4,
  GenesisKeyDelegation: 5,
  MoveInstantaneousRewardsCert: 6,
  CommitteeHotAuth: 7,
  CommitteeColdResign: 8,
  DRepDeregistration: 9,
  DRepRegistration: 10,
  DRepUpdate: 11,
  StakeAndVoteDelegation: 12,
  StakeRegistrationAndDelegation: 13,
  StakeVoteRegistrationAndDelegation: 14,
  VoteDelegation: 15,
  VoteRegistrationAndDelegation: 16,
});


export const CoinSelectionStrategyCIP2 = Object.freeze({
  LargestFirst: 0,
  RandomImprove: 1,
  LargestFirstMultiAsset: 2,
  RandomImproveMultiAsset: 3,
});


export const CredKind = Object.freeze({
  Key: 0,
  Script: 1,
});


export const DRepKind = Object.freeze({
  KeyHash: 0,
  ScriptHash: 1,
  AlwaysAbstain: 2,
  AlwaysNoConfidence: 3,
});


export const GovernanceActionKind = Object.freeze({
  ParameterChangeAction: 0,
  HardForkInitiationAction: 1,
  TreasuryWithdrawalsAction: 2,
  NoConfidenceAction: 3,
  UpdateCommitteeAction: 4,
  NewConstitutionAction: 5,
  InfoAction: 6,
});


export const LanguageKind = Object.freeze({
  PlutusV1: 0,
  PlutusV2: 1,
  PlutusV3: 2,
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
  Vote: 4,
  VotingProposal: 5,
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
  PlutusScriptV3: 3,
});


export const ScriptSchema = Object.freeze({
  Wallet: 0,
  Node: 1,
});


export const TransactionMetadatumKind = Object.freeze({
  MetadataMap: 0,
  MetadataList: 1,
  Int: 2,
  Bytes: 3,
  Text: 4,
});


export const VoteKind = Object.freeze({
  No: 0,
  Yes: 1,
  Abstain: 2,
});


export const VoterKind = Object.freeze({
  ConstitutionalCommitteeHotKeyHash: 0,
  ConstitutionalCommitteeHotScriptHash: 1,
  DRepKeyHash: 2,
  DRepScriptHash: 3,
  StakingPoolKeyHash: 4,
});


