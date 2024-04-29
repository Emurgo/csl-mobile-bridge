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
    const ret = await HaskellShelley.addressFromBytes(b64FromUint8Array(data));
    return Ptr._wrap(ret, Address);
  }

  async to_json() {
    const ret = await HaskellShelley.addressToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.addressFromJson(json);
    return Ptr._wrap(ret, Address);
  }

  async is_malformed() {
    const ret = await HaskellShelley.addressIsMalformed(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await HaskellShelley.addressToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.addressFromHex(hex_str);
    return Ptr._wrap(ret, Address);
  }

  async to_bytes() {
    const ret = await HaskellShelley.addressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    if(prefix == null) {
      const ret = await HaskellShelley.addressToBech32(this.ptr);
      return ret;
    }
    if(prefix != null) {
      const ret = await HaskellShelley.addressToBech32WithPrefix(this.ptr, prefix);
      return ret;
    }
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.addressFromBech32(bech_str);
    return Ptr._wrap(ret, Address);
  }

  async network_id() {
    const ret = await HaskellShelley.addressNetworkId(this.ptr);
    return ret;
  }

}


export class Anchor extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.anchorToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.anchorFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Anchor);
  }

  async to_hex() {
    const ret = await HaskellShelley.anchorToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.anchorFromHex(hex_str);
    return Ptr._wrap(ret, Anchor);
  }

  async to_json() {
    const ret = await HaskellShelley.anchorToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.anchorFromJson(json);
    return Ptr._wrap(ret, Anchor);
  }

  async url() {
    const ret = await HaskellShelley.anchorUrl(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async anchor_data_hash() {
    const ret = await HaskellShelley.anchorAnchorDataHash(this.ptr);
    return Ptr._wrap(ret, AnchorDataHash);
  }

  static async new(anchor_url, anchor_data_hash) {
    const anchor_urlPtr = Ptr._assertClass(anchor_url, URL);
    const anchor_data_hashPtr = Ptr._assertClass(anchor_data_hash, AnchorDataHash);
    const ret = await HaskellShelley.anchorNew(anchor_urlPtr, anchor_data_hashPtr);
    return Ptr._wrap(ret, Anchor);
  }

}


export class AnchorDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.anchorDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AnchorDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.anchorDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.anchorDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.anchorDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, AnchorDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.anchorDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.anchorDataHashFromHex(hex);
    return Ptr._wrap(ret, AnchorDataHash);
  }

}


export class AssetName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.assetNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.assetNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetName);
  }

  async to_hex() {
    const ret = await HaskellShelley.assetNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.assetNameFromHex(hex_str);
    return Ptr._wrap(ret, AssetName);
  }

  async to_json() {
    const ret = await HaskellShelley.assetNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.assetNameFromJson(json);
    return Ptr._wrap(ret, AssetName);
  }

  static async new(name) {
    const ret = await HaskellShelley.assetNameNew(b64FromUint8Array(name));
    return Ptr._wrap(ret, AssetName);
  }

  async name() {
    const ret = await HaskellShelley.assetNameName(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class AssetNames extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.assetNamesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.assetNamesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AssetNames);
  }

  async to_hex() {
    const ret = await HaskellShelley.assetNamesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.assetNamesFromHex(hex_str);
    return Ptr._wrap(ret, AssetNames);
  }

  async to_json() {
    const ret = await HaskellShelley.assetNamesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.assetNamesFromJson(json);
    return Ptr._wrap(ret, AssetNames);
  }

  static async new() {
    const ret = await HaskellShelley.assetNamesNew();
    return Ptr._wrap(ret, AssetNames);
  }

  async len() {
    const ret = await HaskellShelley.assetNamesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.assetNamesGet(this.ptr, index);
    return Ptr._wrap(ret, AssetName);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, AssetName);
    const ret = HaskellShelley.assetNamesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Assets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.assetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.assetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Assets);
  }

  async to_hex() {
    const ret = await HaskellShelley.assetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.assetsFromHex(hex_str);
    return Ptr._wrap(ret, Assets);
  }

  async to_json() {
    const ret = await HaskellShelley.assetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.assetsFromJson(json);
    return Ptr._wrap(ret, Assets);
  }

  static async new() {
    const ret = await HaskellShelley.assetsNew();
    return Ptr._wrap(ret, Assets);
  }

  async len() {
    const ret = await HaskellShelley.assetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.assetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.assetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.assetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class AuxiliaryData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.auxiliaryDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.auxiliaryDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_hex() {
    const ret = await HaskellShelley.auxiliaryDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.auxiliaryDataFromHex(hex_str);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async to_json() {
    const ret = await HaskellShelley.auxiliaryDataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.auxiliaryDataFromJson(json);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  static async new() {
    const ret = await HaskellShelley.auxiliaryDataNew();
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async metadata() {
    const ret = await HaskellShelley.auxiliaryDataMetadata(this.ptr);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.auxiliaryDataSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.auxiliaryDataNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.auxiliaryDataSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.auxiliaryDataPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.auxiliaryDataSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async prefer_alonzo_format() {
    const ret = await HaskellShelley.auxiliaryDataPreferAlonzoFormat(this.ptr);
    return ret;
  }

  set_prefer_alonzo_format(prefer) {
    const ret = HaskellShelley.auxiliaryDataSetPreferAlonzoFormat(this.ptr, prefer);
    return ret;
  }

}


export class AuxiliaryDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.auxiliaryDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.auxiliaryDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.auxiliaryDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.auxiliaryDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.auxiliaryDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.auxiliaryDataHashFromHex(hex);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

}


export class AuxiliaryDataSet extends Ptr {
  static async new() {
    const ret = await HaskellShelley.auxiliaryDataSetNew();
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async len() {
    const ret = await HaskellShelley.auxiliaryDataSetLen(this.ptr);
    return ret;
  }

  async insert(tx_index, data) {
    const dataPtr = Ptr._assertClass(data, AuxiliaryData);
    const ret = await HaskellShelley.auxiliaryDataSetInsert(this.ptr, tx_index, dataPtr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async get(tx_index) {
    const ret = await HaskellShelley.auxiliaryDataSetGet(this.ptr, tx_index);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async indices() {
    const ret = await HaskellShelley.auxiliaryDataSetIndices(this.ptr);
    return base64ToUint32Array(ret);
  }

}


export class BaseAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const stakePtr = Ptr._assertClass(stake, Credential);
    const ret = await HaskellShelley.baseAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.baseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async stake_cred() {
    const ret = await HaskellShelley.baseAddressStakeCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.baseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.baseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, BaseAddress);
  }

}


export class BigInt extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.bigIntToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.bigIntFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigInt);
  }

  async to_hex() {
    const ret = await HaskellShelley.bigIntToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.bigIntFromHex(hex_str);
    return Ptr._wrap(ret, BigInt);
  }

  async to_json() {
    const ret = await HaskellShelley.bigIntToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.bigIntFromJson(json);
    return Ptr._wrap(ret, BigInt);
  }

  async is_zero() {
    const ret = await HaskellShelley.bigIntIsZero(this.ptr);
    return ret;
  }

  async as_u64() {
    const ret = await HaskellShelley.bigIntAsU64(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_int() {
    const ret = await HaskellShelley.bigIntAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  static async from_str(text) {
    const ret = await HaskellShelley.bigIntFromStr(text);
    return Ptr._wrap(ret, BigInt);
  }

  async to_str() {
    const ret = await HaskellShelley.bigIntToStr(this.ptr);
    return ret;
  }

  async add(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.bigIntAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  async mul(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.bigIntMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

  static async one() {
    const ret = await HaskellShelley.bigIntOne();
    return Ptr._wrap(ret, BigInt);
  }

  async increment() {
    const ret = await HaskellShelley.bigIntIncrement(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async div_ceil(other) {
    const otherPtr = Ptr._assertClass(other, BigInt);
    const ret = await HaskellShelley.bigIntDivCeil(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigInt);
  }

}


export class BigNum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.bigNumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.bigNumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BigNum);
  }

  async to_hex() {
    const ret = await HaskellShelley.bigNumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.bigNumFromHex(hex_str);
    return Ptr._wrap(ret, BigNum);
  }

  async to_json() {
    const ret = await HaskellShelley.bigNumToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.bigNumFromJson(json);
    return Ptr._wrap(ret, BigNum);
  }

  static async from_str(string) {
    const ret = await HaskellShelley.bigNumFromStr(string);
    return Ptr._wrap(ret, BigNum);
  }

  async to_str() {
    const ret = await HaskellShelley.bigNumToStr(this.ptr);
    return ret;
  }

  static async zero() {
    const ret = await HaskellShelley.bigNumZero();
    return Ptr._wrap(ret, BigNum);
  }

  static async one() {
    const ret = await HaskellShelley.bigNumOne();
    return Ptr._wrap(ret, BigNum);
  }

  async is_zero() {
    const ret = await HaskellShelley.bigNumIsZero(this.ptr);
    return ret;
  }

  async div_floor(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.bigNumDivFloor(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_mul(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.bigNumCheckedMul(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_add(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.bigNumCheckedAdd(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async checked_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.bigNumCheckedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async clamped_sub(other) {
    const otherPtr = Ptr._assertClass(other, BigNum);
    const ret = await HaskellShelley.bigNumClampedSub(this.ptr, otherPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.bigNumCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

  async less_than(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, BigNum);
    const ret = await HaskellShelley.bigNumLessThan(this.ptr, rhs_valuePtr);
    return ret;
  }

  static async max_value() {
    const ret = await HaskellShelley.bigNumMaxValue();
    return Ptr._wrap(ret, BigNum);
  }

  static async max(a, b) {
    const aPtr = Ptr._assertClass(a, BigNum);
    const bPtr = Ptr._assertClass(b, BigNum);
    const ret = await HaskellShelley.bigNumMax(aPtr, bPtr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class Bip32PrivateKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.bip32PrivateKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  static async from_128_xprv(bytes) {
    const ret = await HaskellShelley.bip32PrivateKeyFrom_128Xprv(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_128_xprv() {
    const ret = await HaskellShelley.bip32PrivateKeyTo_128Xprv(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async generate_ed25519_bip32() {
    const ret = await HaskellShelley.bip32PrivateKeyGenerateEd25519Bip32();
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.bip32PrivateKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_public() {
    const ret = await HaskellShelley.bip32PrivateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.bip32PrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.bip32PrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.bip32PrivateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.bip32PrivateKeyToBech32(this.ptr);
    return ret;
  }

  static async from_bip39_entropy(entropy, password) {
    const ret = await HaskellShelley.bip32PrivateKeyFromBip39Entropy(b64FromUint8Array(entropy), b64FromUint8Array(password));
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

  async chaincode() {
    const ret = await HaskellShelley.bip32PrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.bip32PrivateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.bip32PrivateKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PrivateKey);
  }

}


export class Bip32PublicKey extends Ptr {
  async derive(index) {
    const ret = await HaskellShelley.bip32PublicKeyDerive(this.ptr, index);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_raw_key() {
    const ret = await HaskellShelley.bip32PublicKeyToRawKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.bip32PublicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.bip32PublicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.bip32PublicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.bip32PublicKeyToBech32(this.ptr);
    return ret;
  }

  async chaincode() {
    const ret = await HaskellShelley.bip32PublicKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_hex() {
    const ret = await HaskellShelley.bip32PublicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.bip32PublicKeyFromHex(hex_str);
    return Ptr._wrap(ret, Bip32PublicKey);
  }

}


export class Block extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.blockToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.blockFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Block);
  }

  async to_hex() {
    const ret = await HaskellShelley.blockToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.blockFromHex(hex_str);
    return Ptr._wrap(ret, Block);
  }

  async to_json() {
    const ret = await HaskellShelley.blockToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.blockFromJson(json);
    return Ptr._wrap(ret, Block);
  }

  async header() {
    const ret = await HaskellShelley.blockHeader(this.ptr);
    return Ptr._wrap(ret, Header);
  }

  async transaction_bodies() {
    const ret = await HaskellShelley.blockTransactionBodies(this.ptr);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async transaction_witness_sets() {
    const ret = await HaskellShelley.blockTransactionWitnessSets(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async auxiliary_data_set() {
    const ret = await HaskellShelley.blockAuxiliaryDataSet(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataSet);
  }

  async invalid_transactions() {
    const ret = await HaskellShelley.blockInvalidTransactions(this.ptr);
    return base64ToUint32Array(ret);
  }

  static async new(header, transaction_bodies, transaction_witness_sets, auxiliary_data_set, invalid_transactions) {
    const headerPtr = Ptr._assertClass(header, Header);
    const transaction_bodiesPtr = Ptr._assertClass(transaction_bodies, TransactionBodies);
    const transaction_witness_setsPtr = Ptr._assertClass(transaction_witness_sets, TransactionWitnessSets);
    const auxiliary_data_setPtr = Ptr._assertClass(auxiliary_data_set, AuxiliaryDataSet);
    const ret = await HaskellShelley.blockNew(headerPtr, transaction_bodiesPtr, transaction_witness_setsPtr, auxiliary_data_setPtr, uint32ArrayToBase64(invalid_transactions));
    return Ptr._wrap(ret, Block);
  }

  static async from_wrapped_bytes(data) {
    const ret = await HaskellShelley.blockFromWrappedBytes(b64FromUint8Array(data));
    return Ptr._wrap(ret, Block);
  }

}


export class BlockHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.blockHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BlockHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.blockHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.blockHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.blockHashFromBech32(bech_str);
    return Ptr._wrap(ret, BlockHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.blockHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.blockHashFromHex(hex);
    return Ptr._wrap(ret, BlockHash);
  }

}


export class BootstrapWitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.bootstrapWitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.bootstrapWitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.bootstrapWitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.bootstrapWitnessFromHex(hex_str);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async to_json() {
    const ret = await HaskellShelley.bootstrapWitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.bootstrapWitnessFromJson(json);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  async vkey() {
    const ret = await HaskellShelley.bootstrapWitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.bootstrapWitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async chain_code() {
    const ret = await HaskellShelley.bootstrapWitnessChainCode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async attributes() {
    const ret = await HaskellShelley.bootstrapWitnessAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(vkey, signature, chain_code, attributes) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.bootstrapWitnessNew(vkeyPtr, signaturePtr, b64FromUint8Array(chain_code), b64FromUint8Array(attributes));
    return Ptr._wrap(ret, BootstrapWitness);
  }

}


export class BootstrapWitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.bootstrapWitnessesNew();
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.bootstrapWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.bootstrapWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, BootstrapWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BootstrapWitness);
    const ret = HaskellShelley.bootstrapWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ByronAddress extends Ptr {
  async to_base58() {
    const ret = await HaskellShelley.byronAddressToBase58(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.byronAddressToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.byronAddressFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ByronAddress);
  }

  async byron_protocol_magic() {
    const ret = await HaskellShelley.byronAddressByronProtocolMagic(this.ptr);
    return ret;
  }

  async attributes() {
    const ret = await HaskellShelley.byronAddressAttributes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async network_id() {
    const ret = await HaskellShelley.byronAddressNetworkId(this.ptr);
    return ret;
  }

  static async from_base58(s) {
    const ret = await HaskellShelley.byronAddressFromBase58(s);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async icarus_from_key(key, protocol_magic) {
    const keyPtr = Ptr._assertClass(key, Bip32PublicKey);
    const ret = await HaskellShelley.byronAddressIcarusFromKey(keyPtr, protocol_magic);
    return Ptr._wrap(ret, ByronAddress);
  }

  static async is_valid(s) {
    const ret = await HaskellShelley.byronAddressIsValid(s);
    return ret;
  }

  async to_address() {
    const ret = await HaskellShelley.byronAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.byronAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, ByronAddress);
  }

}


export class Certificate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.certificateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.certificateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificate);
  }

  async to_hex() {
    const ret = await HaskellShelley.certificateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.certificateFromHex(hex_str);
    return Ptr._wrap(ret, Certificate);
  }

  async to_json() {
    const ret = await HaskellShelley.certificateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.certificateFromJson(json);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration(stake_registration) {
    const stake_registrationPtr = Ptr._assertClass(stake_registration, StakeRegistration);
    const ret = await HaskellShelley.certificateNewStakeRegistration(stake_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_deregistration(stake_deregistration) {
    const stake_deregistrationPtr = Ptr._assertClass(stake_deregistration, StakeDeregistration);
    const ret = await HaskellShelley.certificateNewStakeDeregistration(stake_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_delegation(stake_delegation) {
    const stake_delegationPtr = Ptr._assertClass(stake_delegation, StakeDelegation);
    const ret = await HaskellShelley.certificateNewStakeDelegation(stake_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_registration(pool_registration) {
    const pool_registrationPtr = Ptr._assertClass(pool_registration, PoolRegistration);
    const ret = await HaskellShelley.certificateNewPoolRegistration(pool_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_pool_retirement(pool_retirement) {
    const pool_retirementPtr = Ptr._assertClass(pool_retirement, PoolRetirement);
    const ret = await HaskellShelley.certificateNewPoolRetirement(pool_retirementPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_genesis_key_delegation(genesis_key_delegation) {
    const genesis_key_delegationPtr = Ptr._assertClass(genesis_key_delegation, GenesisKeyDelegation);
    const ret = await HaskellShelley.certificateNewGenesisKeyDelegation(genesis_key_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert) {
    const move_instantaneous_rewards_certPtr = Ptr._assertClass(move_instantaneous_rewards_cert, MoveInstantaneousRewardsCert);
    const ret = await HaskellShelley.certificateNewMoveInstantaneousRewardsCert(move_instantaneous_rewards_certPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_committee_hot_auth(committee_hot_auth) {
    const committee_hot_authPtr = Ptr._assertClass(committee_hot_auth, CommitteeHotAuth);
    const ret = await HaskellShelley.certificateNewCommitteeHotAuth(committee_hot_authPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_committee_cold_resign(committee_cold_resign) {
    const committee_cold_resignPtr = Ptr._assertClass(committee_cold_resign, CommitteeColdResign);
    const ret = await HaskellShelley.certificateNewCommitteeColdResign(committee_cold_resignPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_deregistration(drep_deregistration) {
    const drep_deregistrationPtr = Ptr._assertClass(drep_deregistration, DrepDeregistration);
    const ret = await HaskellShelley.certificateNewDrepDeregistration(drep_deregistrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_registration(drep_registration) {
    const drep_registrationPtr = Ptr._assertClass(drep_registration, DrepRegistration);
    const ret = await HaskellShelley.certificateNewDrepRegistration(drep_registrationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_drep_update(drep_update) {
    const drep_updatePtr = Ptr._assertClass(drep_update, DrepUpdate);
    const ret = await HaskellShelley.certificateNewDrepUpdate(drep_updatePtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_and_vote_delegation(stake_and_vote_delegation) {
    const stake_and_vote_delegationPtr = Ptr._assertClass(stake_and_vote_delegation, StakeAndVoteDelegation);
    const ret = await HaskellShelley.certificateNewStakeAndVoteDelegation(stake_and_vote_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_registration_and_delegation(stake_registration_and_delegation) {
    const stake_registration_and_delegationPtr = Ptr._assertClass(stake_registration_and_delegation, StakeRegistrationAndDelegation);
    const ret = await HaskellShelley.certificateNewStakeRegistrationAndDelegation(stake_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_stake_vote_registration_and_delegation(stake_vote_registration_and_delegation) {
    const stake_vote_registration_and_delegationPtr = Ptr._assertClass(stake_vote_registration_and_delegation, StakeVoteRegistrationAndDelegation);
    const ret = await HaskellShelley.certificateNewStakeVoteRegistrationAndDelegation(stake_vote_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_vote_delegation(vote_delegation) {
    const vote_delegationPtr = Ptr._assertClass(vote_delegation, VoteDelegation);
    const ret = await HaskellShelley.certificateNewVoteDelegation(vote_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  static async new_vote_registration_and_delegation(vote_registration_and_delegation) {
    const vote_registration_and_delegationPtr = Ptr._assertClass(vote_registration_and_delegation, VoteRegistrationAndDelegation);
    const ret = await HaskellShelley.certificateNewVoteRegistrationAndDelegation(vote_registration_and_delegationPtr);
    return Ptr._wrap(ret, Certificate);
  }

  async kind() {
    const ret = await HaskellShelley.certificateKind(this.ptr);
    return ret;
  }

  async as_stake_registration() {
    const ret = await HaskellShelley.certificateAsStakeRegistration(this.ptr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async as_stake_deregistration() {
    const ret = await HaskellShelley.certificateAsStakeDeregistration(this.ptr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async as_stake_delegation() {
    const ret = await HaskellShelley.certificateAsStakeDelegation(this.ptr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async as_pool_registration() {
    const ret = await HaskellShelley.certificateAsPoolRegistration(this.ptr);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async as_pool_retirement() {
    const ret = await HaskellShelley.certificateAsPoolRetirement(this.ptr);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async as_genesis_key_delegation() {
    const ret = await HaskellShelley.certificateAsGenesisKeyDelegation(this.ptr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async as_move_instantaneous_rewards_cert() {
    const ret = await HaskellShelley.certificateAsMoveInstantaneousRewardsCert(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async as_committee_hot_auth() {
    const ret = await HaskellShelley.certificateAsCommitteeHotAuth(this.ptr);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async as_committee_cold_resign() {
    const ret = await HaskellShelley.certificateAsCommitteeColdResign(this.ptr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async as_drep_deregistration() {
    const ret = await HaskellShelley.certificateAsDrepDeregistration(this.ptr);
    return Ptr._wrap(ret, DrepDeregistration);
  }

  async as_drep_registration() {
    const ret = await HaskellShelley.certificateAsDrepRegistration(this.ptr);
    return Ptr._wrap(ret, DrepRegistration);
  }

  async as_drep_update() {
    const ret = await HaskellShelley.certificateAsDrepUpdate(this.ptr);
    return Ptr._wrap(ret, DrepUpdate);
  }

  async as_stake_and_vote_delegation() {
    const ret = await HaskellShelley.certificateAsStakeAndVoteDelegation(this.ptr);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async as_stake_registration_and_delegation() {
    const ret = await HaskellShelley.certificateAsStakeRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async as_stake_vote_registration_and_delegation() {
    const ret = await HaskellShelley.certificateAsStakeVoteRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async as_vote_delegation() {
    const ret = await HaskellShelley.certificateAsVoteDelegation(this.ptr);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async as_vote_registration_and_delegation() {
    const ret = await HaskellShelley.certificateAsVoteRegistrationAndDelegation(this.ptr);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async has_required_script_witness() {
    const ret = await HaskellShelley.certificateHasRequiredScriptWitness(this.ptr);
    return ret;
  }

}


export class Certificates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.certificatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.certificatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Certificates);
  }

  async to_hex() {
    const ret = await HaskellShelley.certificatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.certificatesFromHex(hex_str);
    return Ptr._wrap(ret, Certificates);
  }

  async to_json() {
    const ret = await HaskellShelley.certificatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.certificatesFromJson(json);
    return Ptr._wrap(ret, Certificates);
  }

  static async new() {
    const ret = await HaskellShelley.certificatesNew();
    return Ptr._wrap(ret, Certificates);
  }

  async len() {
    const ret = await HaskellShelley.certificatesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.certificatesGet(this.ptr, index);
    return Ptr._wrap(ret, Certificate);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Certificate);
    const ret = HaskellShelley.certificatesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class CertificatesBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.certificatesBuilderNew();
    return Ptr._wrap(ret, CertificatesBuilder);
  }

  add(cert) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const ret = HaskellShelley.certificatesBuilderAdd(this.ptr, certPtr);
    return ret;
  }

  add_with_plutus_witness(cert, witness) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.certificatesBuilderAddWithPlutusWitness(this.ptr, certPtr, witnessPtr);
    return ret;
  }

  add_with_native_script(cert, native_script_source) {
    const certPtr = Ptr._assertClass(cert, Certificate);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.certificatesBuilderAddWithNativeScript(this.ptr, certPtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.certificatesBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.certificatesBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.certificatesBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_certificates_refund(pool_deposit, key_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.certificatesBuilderGetCertificatesRefund(this.ptr, pool_depositPtr, key_depositPtr);
    return Ptr._wrap(ret, Value);
  }

  async get_certificates_deposit(pool_deposit, key_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.certificatesBuilderGetCertificatesDeposit(this.ptr, pool_depositPtr, key_depositPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.certificatesBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.certificatesBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

}


export class Committee extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.committeeToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.committeeFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Committee);
  }

  async to_hex() {
    const ret = await HaskellShelley.committeeToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.committeeFromHex(hex_str);
    return Ptr._wrap(ret, Committee);
  }

  async to_json() {
    const ret = await HaskellShelley.committeeToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.committeeFromJson(json);
    return Ptr._wrap(ret, Committee);
  }

  static async new(quorum_threshold) {
    const quorum_thresholdPtr = Ptr._assertClass(quorum_threshold, UnitInterval);
    const ret = await HaskellShelley.committeeNew(quorum_thresholdPtr);
    return Ptr._wrap(ret, Committee);
  }

  async members_keys() {
    const ret = await HaskellShelley.committeeMembersKeys(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

  async quorum_threshold() {
    const ret = await HaskellShelley.committeeQuorumThreshold(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  add_member(committee_cold_credential, epoch) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const ret = HaskellShelley.committeeAddMember(this.ptr, committee_cold_credentialPtr, epoch);
    return ret;
  }

  async get_member_epoch(committee_cold_credential) {
    const committee_cold_credentialPtr = Ptr._assertClass(committee_cold_credential, Credential);
    const ret = await HaskellShelley.committeeGetMemberEpoch(this.ptr, committee_cold_credentialPtr);
    return ret;
  }

}


export class CommitteeColdResign extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.committeeColdResignToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.committeeColdResignFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async to_hex() {
    const ret = await HaskellShelley.committeeColdResignToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.committeeColdResignFromHex(hex_str);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async to_json() {
    const ret = await HaskellShelley.committeeColdResignToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.committeeColdResignFromJson(json);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async committee_cold_key() {
    const ret = await HaskellShelley.committeeColdResignCommitteeColdKey(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async anchor() {
    const ret = await HaskellShelley.committeeColdResignAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(committee_cold_key) {
    const committee_cold_keyPtr = Ptr._assertClass(committee_cold_key, Credential);
    const ret = await HaskellShelley.committeeColdResignNew(committee_cold_keyPtr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  static async new_with_anchor(committee_cold_key, anchor) {
    const committee_cold_keyPtr = Ptr._assertClass(committee_cold_key, Credential);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.committeeColdResignNewWithAnchor(committee_cold_keyPtr, anchorPtr);
    return Ptr._wrap(ret, CommitteeColdResign);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.committeeColdResignHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class CommitteeHotAuth extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.committeeHotAuthToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.committeeHotAuthFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async to_hex() {
    const ret = await HaskellShelley.committeeHotAuthToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.committeeHotAuthFromHex(hex_str);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async to_json() {
    const ret = await HaskellShelley.committeeHotAuthToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.committeeHotAuthFromJson(json);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async committee_cold_key() {
    const ret = await HaskellShelley.committeeHotAuthCommitteeColdKey(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async committee_hot_key() {
    const ret = await HaskellShelley.committeeHotAuthCommitteeHotKey(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  static async new(committee_cold_key, committee_hot_key) {
    const committee_cold_keyPtr = Ptr._assertClass(committee_cold_key, Credential);
    const committee_hot_keyPtr = Ptr._assertClass(committee_hot_key, Credential);
    const ret = await HaskellShelley.committeeHotAuthNew(committee_cold_keyPtr, committee_hot_keyPtr);
    return Ptr._wrap(ret, CommitteeHotAuth);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.committeeHotAuthHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Constitution extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.constitutionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.constitutionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Constitution);
  }

  async to_hex() {
    const ret = await HaskellShelley.constitutionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.constitutionFromHex(hex_str);
    return Ptr._wrap(ret, Constitution);
  }

  async to_json() {
    const ret = await HaskellShelley.constitutionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.constitutionFromJson(json);
    return Ptr._wrap(ret, Constitution);
  }

  async anchor() {
    const ret = await HaskellShelley.constitutionAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  async script_hash() {
    const ret = await HaskellShelley.constitutionScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(anchor) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.constitutionNew(anchorPtr);
    return Ptr._wrap(ret, Constitution);
  }

  static async new_with_script_hash(anchor, script_hash) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const ret = await HaskellShelley.constitutionNewWithScriptHash(anchorPtr, script_hashPtr);
    return Ptr._wrap(ret, Constitution);
  }

}


export class ConstrPlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.constrPlutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.constrPlutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.constrPlutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.constrPlutusDataFromHex(hex_str);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async alternative() {
    const ret = await HaskellShelley.constrPlutusDataAlternative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.constrPlutusDataData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new(alternative, data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusList);
    const ret = await HaskellShelley.constrPlutusDataNew(alternativePtr, dataPtr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

}


export class CostModel extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.costModelToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.costModelFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, CostModel);
  }

  async to_hex() {
    const ret = await HaskellShelley.costModelToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.costModelFromHex(hex_str);
    return Ptr._wrap(ret, CostModel);
  }

  async to_json() {
    const ret = await HaskellShelley.costModelToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.costModelFromJson(json);
    return Ptr._wrap(ret, CostModel);
  }

  static async new() {
    const ret = await HaskellShelley.costModelNew();
    return Ptr._wrap(ret, CostModel);
  }

  async set(operation, cost) {
    const costPtr = Ptr._assertClass(cost, Int);
    const ret = await HaskellShelley.costModelSet(this.ptr, operation, costPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(operation) {
    const ret = await HaskellShelley.costModelGet(this.ptr, operation);
    return Ptr._wrap(ret, Int);
  }

  async len() {
    const ret = await HaskellShelley.costModelLen(this.ptr);
    return ret;
  }

}


export class Costmdls extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.costmdlsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.costmdlsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Costmdls);
  }

  async to_hex() {
    const ret = await HaskellShelley.costmdlsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.costmdlsFromHex(hex_str);
    return Ptr._wrap(ret, Costmdls);
  }

  async to_json() {
    const ret = await HaskellShelley.costmdlsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.costmdlsFromJson(json);
    return Ptr._wrap(ret, Costmdls);
  }

  static async new() {
    const ret = await HaskellShelley.costmdlsNew();
    return Ptr._wrap(ret, Costmdls);
  }

  async len() {
    const ret = await HaskellShelley.costmdlsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, Language);
    const valuePtr = Ptr._assertClass(value, CostModel);
    const ret = await HaskellShelley.costmdlsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, CostModel);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, Language);
    const ret = await HaskellShelley.costmdlsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, CostModel);
  }

  async keys() {
    const ret = await HaskellShelley.costmdlsKeys(this.ptr);
    return Ptr._wrap(ret, Languages);
  }

  async retain_language_versions(languages) {
    const languagesPtr = Ptr._assertClass(languages, Languages);
    const ret = await HaskellShelley.costmdlsRetainLanguageVersions(this.ptr, languagesPtr);
    return Ptr._wrap(ret, Costmdls);
  }

}


export class Credential extends Ptr {
  static async from_keyhash(hash) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const ret = await HaskellShelley.credentialFromKeyhash(hashPtr);
    return Ptr._wrap(ret, Credential);
  }

  static async from_scripthash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptHash);
    const ret = await HaskellShelley.credentialFromScripthash(hashPtr);
    return Ptr._wrap(ret, Credential);
  }

  async to_keyhash() {
    const ret = await HaskellShelley.credentialToKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_scripthash() {
    const ret = await HaskellShelley.credentialToScripthash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async kind() {
    const ret = await HaskellShelley.credentialKind(this.ptr);
    return ret;
  }

  async has_script_hash() {
    const ret = await HaskellShelley.credentialHasScriptHash(this.ptr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.credentialToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.credentialFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Credential);
  }

  async to_hex() {
    const ret = await HaskellShelley.credentialToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.credentialFromHex(hex_str);
    return Ptr._wrap(ret, Credential);
  }

  async to_json() {
    const ret = await HaskellShelley.credentialToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.credentialFromJson(json);
    return Ptr._wrap(ret, Credential);
  }

}


export class Credentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.credentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.credentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Credentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.credentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.credentialsFromHex(hex_str);
    return Ptr._wrap(ret, Credentials);
  }

  async to_json() {
    const ret = await HaskellShelley.credentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.credentialsFromJson(json);
    return Ptr._wrap(ret, Credentials);
  }

  static async new() {
    const ret = await HaskellShelley.credentialsNew();
    return Ptr._wrap(ret, Credentials);
  }

  async len() {
    const ret = await HaskellShelley.credentialsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.credentialsGet(this.ptr, index);
    return Ptr._wrap(ret, Credential);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Credential);
    const ret = HaskellShelley.credentialsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class DNSRecordAorAAAA extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.dNSRecordAorAAAAToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.dNSRecordAorAAAAFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_hex() {
    const ret = await HaskellShelley.dNSRecordAorAAAAToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.dNSRecordAorAAAAFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async to_json() {
    const ret = await HaskellShelley.dNSRecordAorAAAAToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.dNSRecordAorAAAAFromJson(json);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.dNSRecordAorAAAANew(dns_name);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  async record() {
    const ret = await HaskellShelley.dNSRecordAorAAAARecord(this.ptr);
    return ret;
  }

}


export class DNSRecordSRV extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.dNSRecordSRVToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.dNSRecordSRVFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_hex() {
    const ret = await HaskellShelley.dNSRecordSRVToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.dNSRecordSRVFromHex(hex_str);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async to_json() {
    const ret = await HaskellShelley.dNSRecordSRVToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.dNSRecordSRVFromJson(json);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const ret = await HaskellShelley.dNSRecordSRVNew(dns_name);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  async record() {
    const ret = await HaskellShelley.dNSRecordSRVRecord(this.ptr);
    return ret;
  }

}


export class DRep extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.dRepToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.dRepFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DRep);
  }

  async to_hex() {
    const ret = await HaskellShelley.dRepToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.dRepFromHex(hex_str);
    return Ptr._wrap(ret, DRep);
  }

  async to_json() {
    const ret = await HaskellShelley.dRepToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.dRepFromJson(json);
    return Ptr._wrap(ret, DRep);
  }

  static async new_key_hash(key_hash) {
    const key_hashPtr = Ptr._assertClass(key_hash, Ed25519KeyHash);
    const ret = await HaskellShelley.dRepNewKeyHash(key_hashPtr);
    return Ptr._wrap(ret, DRep);
  }

  static async new_script_hash(script_hash) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const ret = await HaskellShelley.dRepNewScriptHash(script_hashPtr);
    return Ptr._wrap(ret, DRep);
  }

  static async new_always_abstain() {
    const ret = await HaskellShelley.dRepNewAlwaysAbstain();
    return Ptr._wrap(ret, DRep);
  }

  static async new_always_no_confidence() {
    const ret = await HaskellShelley.dRepNewAlwaysNoConfidence();
    return Ptr._wrap(ret, DRep);
  }

  async kind() {
    const ret = await HaskellShelley.dRepKind(this.ptr);
    return ret;
  }

  async to_key_hash() {
    const ret = await HaskellShelley.dRepToKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_script_hash() {
    const ret = await HaskellShelley.dRepToScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

}


export class DataCost extends Ptr {
  static async new_coins_per_byte(coins_per_byte) {
    const coins_per_bytePtr = Ptr._assertClass(coins_per_byte, BigNum);
    const ret = await HaskellShelley.dataCostNewCoinsPerByte(coins_per_bytePtr);
    return Ptr._wrap(ret, DataCost);
  }

  async coins_per_byte() {
    const ret = await HaskellShelley.dataCostCoinsPerByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class DataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.dataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.dataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.dataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.dataHashFromBech32(bech_str);
    return Ptr._wrap(ret, DataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.dataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.dataHashFromHex(hex);
    return Ptr._wrap(ret, DataHash);
  }

}


export class DatumSource extends Ptr {
  static async new(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = await HaskellShelley.datumSourceNew(datumPtr);
    return Ptr._wrap(ret, DatumSource);
  }

  static async new_ref_input(input) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const ret = await HaskellShelley.datumSourceNewRefInput(inputPtr);
    return Ptr._wrap(ret, DatumSource);
  }

}


export class DrepDeregistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.drepDeregistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.drepDeregistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DrepDeregistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.drepDeregistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.drepDeregistrationFromHex(hex_str);
    return Ptr._wrap(ret, DrepDeregistration);
  }

  async to_json() {
    const ret = await HaskellShelley.drepDeregistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.drepDeregistrationFromJson(json);
    return Ptr._wrap(ret, DrepDeregistration);
  }

  async voting_credential() {
    const ret = await HaskellShelley.drepDeregistrationVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.drepDeregistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(voting_credential, coin) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.drepDeregistrationNew(voting_credentialPtr, coinPtr);
    return Ptr._wrap(ret, DrepDeregistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.drepDeregistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DrepRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.drepRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.drepRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DrepRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.drepRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.drepRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, DrepRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.drepRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.drepRegistrationFromJson(json);
    return Ptr._wrap(ret, DrepRegistration);
  }

  async voting_credential() {
    const ret = await HaskellShelley.drepRegistrationVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.drepRegistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async anchor() {
    const ret = await HaskellShelley.drepRegistrationAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(voting_credential, coin) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.drepRegistrationNew(voting_credentialPtr, coinPtr);
    return Ptr._wrap(ret, DrepRegistration);
  }

  static async new_with_anchor(voting_credential, coin, anchor) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.drepRegistrationNewWithAnchor(voting_credentialPtr, coinPtr, anchorPtr);
    return Ptr._wrap(ret, DrepRegistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.drepRegistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DrepUpdate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.drepUpdateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.drepUpdateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DrepUpdate);
  }

  async to_hex() {
    const ret = await HaskellShelley.drepUpdateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.drepUpdateFromHex(hex_str);
    return Ptr._wrap(ret, DrepUpdate);
  }

  async to_json() {
    const ret = await HaskellShelley.drepUpdateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.drepUpdateFromJson(json);
    return Ptr._wrap(ret, DrepUpdate);
  }

  async voting_credential() {
    const ret = await HaskellShelley.drepUpdateVotingCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async anchor() {
    const ret = await HaskellShelley.drepUpdateAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  static async new(voting_credential) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const ret = await HaskellShelley.drepUpdateNew(voting_credentialPtr);
    return Ptr._wrap(ret, DrepUpdate);
  }

  static async new_with_anchor(voting_credential, anchor) {
    const voting_credentialPtr = Ptr._assertClass(voting_credential, Credential);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.drepUpdateNewWithAnchor(voting_credentialPtr, anchorPtr);
    return Ptr._wrap(ret, DrepUpdate);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.drepUpdateHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class DrepVotingThresholds extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.drepVotingThresholdsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.drepVotingThresholdsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, DrepVotingThresholds);
  }

  async to_hex() {
    const ret = await HaskellShelley.drepVotingThresholdsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.drepVotingThresholdsFromHex(hex_str);
    return Ptr._wrap(ret, DrepVotingThresholds);
  }

  async to_json() {
    const ret = await HaskellShelley.drepVotingThresholdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.drepVotingThresholdsFromJson(json);
    return Ptr._wrap(ret, DrepVotingThresholds);
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
    const ret = await HaskellShelley.drepVotingThresholdsNew(motion_no_confidencePtr, committee_normalPtr, committee_no_confidencePtr, update_constitutionPtr, hard_fork_initiationPtr, pp_network_groupPtr, pp_economic_groupPtr, pp_technical_groupPtr, pp_governance_groupPtr, treasury_withdrawalPtr);
    return Ptr._wrap(ret, DrepVotingThresholds);
  }

  static async new_default() {
    const ret = await HaskellShelley.drepVotingThresholdsNewDefault();
    return Ptr._wrap(ret, DrepVotingThresholds);
  }

  set_motion_no_confidence(motion_no_confidence) {
    const motion_no_confidencePtr = Ptr._assertClass(motion_no_confidence, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetMotionNoConfidence(this.ptr, motion_no_confidencePtr);
    return ret;
  }

  set_committee_normal(committee_normal) {
    const committee_normalPtr = Ptr._assertClass(committee_normal, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetCommitteeNormal(this.ptr, committee_normalPtr);
    return ret;
  }

  set_committee_no_confidence(committee_no_confidence) {
    const committee_no_confidencePtr = Ptr._assertClass(committee_no_confidence, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetCommitteeNoConfidence(this.ptr, committee_no_confidencePtr);
    return ret;
  }

  set_update_constitution(update_constitution) {
    const update_constitutionPtr = Ptr._assertClass(update_constitution, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetUpdateConstitution(this.ptr, update_constitutionPtr);
    return ret;
  }

  set_hard_fork_initiation(hard_fork_initiation) {
    const hard_fork_initiationPtr = Ptr._assertClass(hard_fork_initiation, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetHardForkInitiation(this.ptr, hard_fork_initiationPtr);
    return ret;
  }

  set_pp_network_group(pp_network_group) {
    const pp_network_groupPtr = Ptr._assertClass(pp_network_group, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetPpNetworkGroup(this.ptr, pp_network_groupPtr);
    return ret;
  }

  set_pp_economic_group(pp_economic_group) {
    const pp_economic_groupPtr = Ptr._assertClass(pp_economic_group, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetPpEconomicGroup(this.ptr, pp_economic_groupPtr);
    return ret;
  }

  set_pp_technical_group(pp_technical_group) {
    const pp_technical_groupPtr = Ptr._assertClass(pp_technical_group, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetPpTechnicalGroup(this.ptr, pp_technical_groupPtr);
    return ret;
  }

  set_pp_governance_group(pp_governance_group) {
    const pp_governance_groupPtr = Ptr._assertClass(pp_governance_group, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetPpGovernanceGroup(this.ptr, pp_governance_groupPtr);
    return ret;
  }

  set_treasury_withdrawal(treasury_withdrawal) {
    const treasury_withdrawalPtr = Ptr._assertClass(treasury_withdrawal, UnitInterval);
    const ret = HaskellShelley.drepVotingThresholdsSetTreasuryWithdrawal(this.ptr, treasury_withdrawalPtr);
    return ret;
  }

  async motion_no_confidence() {
    const ret = await HaskellShelley.drepVotingThresholdsMotionNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_normal() {
    const ret = await HaskellShelley.drepVotingThresholdsCommitteeNormal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_no_confidence() {
    const ret = await HaskellShelley.drepVotingThresholdsCommitteeNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async update_constitution() {
    const ret = await HaskellShelley.drepVotingThresholdsUpdateConstitution(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async hard_fork_initiation() {
    const ret = await HaskellShelley.drepVotingThresholdsHardForkInitiation(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_network_group() {
    const ret = await HaskellShelley.drepVotingThresholdsPpNetworkGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_economic_group() {
    const ret = await HaskellShelley.drepVotingThresholdsPpEconomicGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_technical_group() {
    const ret = await HaskellShelley.drepVotingThresholdsPpTechnicalGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async pp_governance_group() {
    const ret = await HaskellShelley.drepVotingThresholdsPpGovernanceGroup(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async treasury_withdrawal() {
    const ret = await HaskellShelley.drepVotingThresholdsTreasuryWithdrawal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class Ed25519KeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ed25519KeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.ed25519KeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.ed25519KeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.ed25519KeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.ed25519KeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.ed25519KeyHashFromHex(hex);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class Ed25519KeyHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.ed25519KeyHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ed25519KeyHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.ed25519KeyHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.ed25519KeyHashesFromHex(hex_str);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.ed25519KeyHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.ed25519KeyHashesFromJson(json);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  static async new() {
    const ret = await HaskellShelley.ed25519KeyHashesNew();
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async len() {
    const ret = await HaskellShelley.ed25519KeyHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.ed25519KeyHashesGet(this.ptr, index);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = HaskellShelley.ed25519KeyHashesAdd(this.ptr, elemPtr);
    return ret;
  }

  async contains(elem) {
    const elemPtr = Ptr._assertClass(elem, Ed25519KeyHash);
    const ret = await HaskellShelley.ed25519KeyHashesContains(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.ed25519KeyHashesToOption(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class Ed25519Signature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.ed25519SignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32() {
    const ret = await HaskellShelley.ed25519SignatureToBech32(this.ptr);
    return ret;
  }

  async to_hex() {
    const ret = await HaskellShelley.ed25519SignatureToHex(this.ptr);
    return ret;
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.ed25519SignatureFromBech32(bech32_str);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_hex(input) {
    const ret = await HaskellShelley.ed25519SignatureFromHex(input);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ed25519SignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class EnterpriseAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const ret = await HaskellShelley.enterpriseAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.enterpriseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.enterpriseAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.enterpriseAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, EnterpriseAddress);
  }

}


export class ExUnitPrices extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.exUnitPricesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.exUnitPricesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_hex() {
    const ret = await HaskellShelley.exUnitPricesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.exUnitPricesFromHex(hex_str);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async to_json() {
    const ret = await HaskellShelley.exUnitPricesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.exUnitPricesFromJson(json);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  async mem_price() {
    const ret = await HaskellShelley.exUnitPricesMemPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async step_price() {
    const ret = await HaskellShelley.exUnitPricesStepPrice(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  static async new(mem_price, step_price) {
    const mem_pricePtr = Ptr._assertClass(mem_price, UnitInterval);
    const step_pricePtr = Ptr._assertClass(step_price, UnitInterval);
    const ret = await HaskellShelley.exUnitPricesNew(mem_pricePtr, step_pricePtr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

}


export class ExUnits extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.exUnitsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.exUnitsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ExUnits);
  }

  async to_hex() {
    const ret = await HaskellShelley.exUnitsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.exUnitsFromHex(hex_str);
    return Ptr._wrap(ret, ExUnits);
  }

  async to_json() {
    const ret = await HaskellShelley.exUnitsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.exUnitsFromJson(json);
    return Ptr._wrap(ret, ExUnits);
  }

  async mem() {
    const ret = await HaskellShelley.exUnitsMem(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async steps() {
    const ret = await HaskellShelley.exUnitsSteps(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(mem, steps) {
    const memPtr = Ptr._assertClass(mem, BigNum);
    const stepsPtr = Ptr._assertClass(steps, BigNum);
    const ret = await HaskellShelley.exUnitsNew(memPtr, stepsPtr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class FixedTransaction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.fixedTransactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.fixedTransactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, FixedTransaction);
  }

  async to_hex() {
    const ret = await HaskellShelley.fixedTransactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.fixedTransactionFromHex(hex_str);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new(raw_body, raw_witness_set, is_valid) {
    const ret = await HaskellShelley.fixedTransactionNew(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  static async new_with_auxiliary(raw_body, raw_witness_set, raw_auxiliary_data, is_valid) {
    const ret = await HaskellShelley.fixedTransactionNewWithAuxiliary(b64FromUint8Array(raw_body), b64FromUint8Array(raw_witness_set), b64FromUint8Array(raw_auxiliary_data), is_valid);
    return Ptr._wrap(ret, FixedTransaction);
  }

  async body() {
    const ret = await HaskellShelley.fixedTransactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async raw_body() {
    const ret = await HaskellShelley.fixedTransactionRawBody(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_body(raw_body) {
    const ret = HaskellShelley.fixedTransactionSetBody(this.ptr, b64FromUint8Array(raw_body));
    return ret;
  }

  set_witness_set(raw_witness_set) {
    const ret = HaskellShelley.fixedTransactionSetWitnessSet(this.ptr, b64FromUint8Array(raw_witness_set));
    return ret;
  }

  async witness_set() {
    const ret = await HaskellShelley.fixedTransactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async raw_witness_set() {
    const ret = await HaskellShelley.fixedTransactionRawWitnessSet(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  set_is_valid(valid) {
    const ret = HaskellShelley.fixedTransactionSetIsValid(this.ptr, valid);
    return ret;
  }

  async is_valid() {
    const ret = await HaskellShelley.fixedTransactionIsValid(this.ptr);
    return ret;
  }

  set_auxiliary_data(raw_auxiliary_data) {
    const ret = HaskellShelley.fixedTransactionSetAuxiliaryData(this.ptr, b64FromUint8Array(raw_auxiliary_data));
    return ret;
  }

  async auxiliary_data() {
    const ret = await HaskellShelley.fixedTransactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  async raw_auxiliary_data() {
    const ret = await HaskellShelley.fixedTransactionRawAuxiliaryData(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class GeneralTransactionMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.generalTransactionMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.generalTransactionMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.generalTransactionMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.generalTransactionMetadataFromHex(hex_str);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.generalTransactionMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.generalTransactionMetadataFromJson(json);
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  static async new() {
    const ret = await HaskellShelley.generalTransactionMetadataNew();
    return Ptr._wrap(ret, GeneralTransactionMetadata);
  }

  async len() {
    const ret = await HaskellShelley.generalTransactionMetadataLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.generalTransactionMetadataInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = await HaskellShelley.generalTransactionMetadataGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async keys() {
    const ret = await HaskellShelley.generalTransactionMetadataKeys(this.ptr);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

}


export class GenesisDelegateHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.genesisDelegateHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.genesisDelegateHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.genesisDelegateHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.genesisDelegateHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.genesisDelegateHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.genesisDelegateHashFromHex(hex);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

}


export class GenesisHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.genesisHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.genesisHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.genesisHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.genesisHashFromBech32(bech_str);
    return Ptr._wrap(ret, GenesisHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.genesisHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.genesisHashFromHex(hex);
    return Ptr._wrap(ret, GenesisHash);
  }

}


export class GenesisHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.genesisHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.genesisHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.genesisHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.genesisHashesFromHex(hex_str);
    return Ptr._wrap(ret, GenesisHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.genesisHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.genesisHashesFromJson(json);
    return Ptr._wrap(ret, GenesisHashes);
  }

  static async new() {
    const ret = await HaskellShelley.genesisHashesNew();
    return Ptr._wrap(ret, GenesisHashes);
  }

  async len() {
    const ret = await HaskellShelley.genesisHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.genesisHashesGet(this.ptr, index);
    return Ptr._wrap(ret, GenesisHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, GenesisHash);
    const ret = HaskellShelley.genesisHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class GenesisKeyDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.genesisKeyDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.genesisKeyDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.genesisKeyDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.genesisKeyDelegationFromHex(hex_str);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.genesisKeyDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.genesisKeyDelegationFromJson(json);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

  async genesishash() {
    const ret = await HaskellShelley.genesisKeyDelegationGenesishash(this.ptr);
    return Ptr._wrap(ret, GenesisHash);
  }

  async genesis_delegate_hash() {
    const ret = await HaskellShelley.genesisKeyDelegationGenesisDelegateHash(this.ptr);
    return Ptr._wrap(ret, GenesisDelegateHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.genesisKeyDelegationVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  static async new(genesishash, genesis_delegate_hash, vrf_keyhash) {
    const genesishashPtr = Ptr._assertClass(genesishash, GenesisHash);
    const genesis_delegate_hashPtr = Ptr._assertClass(genesis_delegate_hash, GenesisDelegateHash);
    const vrf_keyhashPtr = Ptr._assertClass(vrf_keyhash, VRFKeyHash);
    const ret = await HaskellShelley.genesisKeyDelegationNew(genesishashPtr, genesis_delegate_hashPtr, vrf_keyhashPtr);
    return Ptr._wrap(ret, GenesisKeyDelegation);
  }

}


export class GovernanceAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.governanceActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.governanceActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GovernanceAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.governanceActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.governanceActionFromHex(hex_str);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async to_json() {
    const ret = await HaskellShelley.governanceActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.governanceActionFromJson(json);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_parameter_change_action(parameter_change_action) {
    const parameter_change_actionPtr = Ptr._assertClass(parameter_change_action, ParameterChangeAction);
    const ret = await HaskellShelley.governanceActionNewParameterChangeAction(parameter_change_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_hard_fork_initiation_action(hard_fork_initiation_action) {
    const hard_fork_initiation_actionPtr = Ptr._assertClass(hard_fork_initiation_action, HardForkInitiationAction);
    const ret = await HaskellShelley.governanceActionNewHardForkInitiationAction(hard_fork_initiation_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_treasury_withdrawals_action(treasury_withdrawals_action) {
    const treasury_withdrawals_actionPtr = Ptr._assertClass(treasury_withdrawals_action, TreasuryWithdrawalsAction);
    const ret = await HaskellShelley.governanceActionNewTreasuryWithdrawalsAction(treasury_withdrawals_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_no_confidence_action(no_confidence_action) {
    const no_confidence_actionPtr = Ptr._assertClass(no_confidence_action, NoConfidenceAction);
    const ret = await HaskellShelley.governanceActionNewNoConfidenceAction(no_confidence_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_new_committee_action(new_committee_action) {
    const new_committee_actionPtr = Ptr._assertClass(new_committee_action, UpdateCommitteeAction);
    const ret = await HaskellShelley.governanceActionNewNewCommitteeAction(new_committee_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_new_constitution_action(new_constitution_action) {
    const new_constitution_actionPtr = Ptr._assertClass(new_constitution_action, NewConstitutionAction);
    const ret = await HaskellShelley.governanceActionNewNewConstitutionAction(new_constitution_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  static async new_info_action(info_action) {
    const info_actionPtr = Ptr._assertClass(info_action, InfoAction);
    const ret = await HaskellShelley.governanceActionNewInfoAction(info_actionPtr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async kind() {
    const ret = await HaskellShelley.governanceActionKind(this.ptr);
    return ret;
  }

  async as_parameter_change_action() {
    const ret = await HaskellShelley.governanceActionAsParameterChangeAction(this.ptr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async as_hard_fork_initiation_action() {
    const ret = await HaskellShelley.governanceActionAsHardForkInitiationAction(this.ptr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async as_treasury_withdrawals_action() {
    const ret = await HaskellShelley.governanceActionAsTreasuryWithdrawalsAction(this.ptr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async as_no_confidence_action() {
    const ret = await HaskellShelley.governanceActionAsNoConfidenceAction(this.ptr);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async as_new_committee_action() {
    const ret = await HaskellShelley.governanceActionAsNewCommitteeAction(this.ptr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async as_new_constitution_action() {
    const ret = await HaskellShelley.governanceActionAsNewConstitutionAction(this.ptr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async as_info_action() {
    const ret = await HaskellShelley.governanceActionAsInfoAction(this.ptr);
    return Ptr._wrap(ret, InfoAction);
  }

}


export class GovernanceActionId extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.governanceActionIdToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.governanceActionIdFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async to_hex() {
    const ret = await HaskellShelley.governanceActionIdToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.governanceActionIdFromHex(hex_str);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async to_json() {
    const ret = await HaskellShelley.governanceActionIdToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.governanceActionIdFromJson(json);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async transaction_id() {
    const ret = await HaskellShelley.governanceActionIdTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await HaskellShelley.governanceActionIdIndex(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await HaskellShelley.governanceActionIdNew(transaction_idPtr, index);
    return Ptr._wrap(ret, GovernanceActionId);
  }

}


export class GovernanceActionIds extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.governanceActionIdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.governanceActionIdsFromJson(json);
    return Ptr._wrap(ret, GovernanceActionIds);
  }

  static async new() {
    const ret = await HaskellShelley.governanceActionIdsNew();
    return Ptr._wrap(ret, GovernanceActionIds);
  }

  add(governance_action_id) {
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const ret = HaskellShelley.governanceActionIdsAdd(this.ptr, governance_action_idPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.governanceActionIdsGet(this.ptr, index);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async len() {
    const ret = await HaskellShelley.governanceActionIdsLen(this.ptr);
    return ret;
  }

}


export class HardForkInitiationAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.hardForkInitiationActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.hardForkInitiationActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.hardForkInitiationActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.hardForkInitiationActionFromHex(hex_str);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async to_json() {
    const ret = await HaskellShelley.hardForkInitiationActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.hardForkInitiationActionFromJson(json);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.hardForkInitiationActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async protocol_version() {
    const ret = await HaskellShelley.hardForkInitiationActionProtocolVersion(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  static async new(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = await HaskellShelley.hardForkInitiationActionNew(protocol_versionPtr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

  static async new_with_action_id(gov_action_id, protocol_version) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = await HaskellShelley.hardForkInitiationActionNewWithActionId(gov_action_idPtr, protocol_versionPtr);
    return Ptr._wrap(ret, HardForkInitiationAction);
  }

}


export class Header extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.headerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.headerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Header);
  }

  async to_hex() {
    const ret = await HaskellShelley.headerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.headerFromHex(hex_str);
    return Ptr._wrap(ret, Header);
  }

  async to_json() {
    const ret = await HaskellShelley.headerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.headerFromJson(json);
    return Ptr._wrap(ret, Header);
  }

  async header_body() {
    const ret = await HaskellShelley.headerHeaderBody(this.ptr);
    return Ptr._wrap(ret, HeaderBody);
  }

  async body_signature() {
    const ret = await HaskellShelley.headerBodySignature(this.ptr);
    return Ptr._wrap(ret, KESSignature);
  }

  static async new(header_body, body_signature) {
    const header_bodyPtr = Ptr._assertClass(header_body, HeaderBody);
    const body_signaturePtr = Ptr._assertClass(body_signature, KESSignature);
    const ret = await HaskellShelley.headerNew(header_bodyPtr, body_signaturePtr);
    return Ptr._wrap(ret, Header);
  }

}


export class HeaderBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.headerBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.headerBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.headerBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.headerBodyFromHex(hex_str);
    return Ptr._wrap(ret, HeaderBody);
  }

  async to_json() {
    const ret = await HaskellShelley.headerBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.headerBodyFromJson(json);
    return Ptr._wrap(ret, HeaderBody);
  }

  async block_number() {
    const ret = await HaskellShelley.headerBodyBlockNumber(this.ptr);
    return ret;
  }

  async slot() {
    const ret = await HaskellShelley.headerBodySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.headerBodySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async prev_hash() {
    const ret = await HaskellShelley.headerBodyPrevHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async issuer_vkey() {
    const ret = await HaskellShelley.headerBodyIssuerVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async vrf_vkey() {
    const ret = await HaskellShelley.headerBodyVrfVkey(this.ptr);
    return Ptr._wrap(ret, VRFVKey);
  }

  async has_nonce_and_leader_vrf() {
    const ret = await HaskellShelley.headerBodyHasNonceAndLeaderVrf(this.ptr);
    return ret;
  }

  async nonce_vrf_or_nothing() {
    const ret = await HaskellShelley.headerBodyNonceVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async leader_vrf_or_nothing() {
    const ret = await HaskellShelley.headerBodyLeaderVrfOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async has_vrf_result() {
    const ret = await HaskellShelley.headerBodyHasVrfResult(this.ptr);
    return ret;
  }

  async vrf_result_or_nothing() {
    const ret = await HaskellShelley.headerBodyVrfResultOrNothing(this.ptr);
    return Ptr._wrap(ret, VRFCert);
  }

  async block_body_size() {
    const ret = await HaskellShelley.headerBodyBlockBodySize(this.ptr);
    return ret;
  }

  async block_body_hash() {
    const ret = await HaskellShelley.headerBodyBlockBodyHash(this.ptr);
    return Ptr._wrap(ret, BlockHash);
  }

  async operational_cert() {
    const ret = await HaskellShelley.headerBodyOperationalCert(this.ptr);
    return Ptr._wrap(ret, OperationalCert);
  }

  async protocol_version() {
    const ret = await HaskellShelley.headerBodyProtocolVersion(this.ptr);
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
      const ret = await HaskellShelley.headerBodyNew(block_number, slot, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.headerBodyNewWithPrevHash(block_number, slot, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
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
      const ret = await HaskellShelley.headerBodyNewHeaderbody(block_number, slotPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
    if(prev_hash != null) {
      const ret = await HaskellShelley.headerBodyNewHeaderbodyWithPrevHash(block_number, slotPtr, prev_hashPtr, issuer_vkeyPtr, vrf_vkeyPtr, vrf_resultPtr, block_body_size, block_body_hashPtr, operational_certPtr, protocol_versionPtr);
      return Ptr._wrap(ret, HeaderBody);
    }
  }

}


export class InfoAction extends Ptr {
  static async new() {
    const ret = await HaskellShelley.infoActionNew();
    return Ptr._wrap(ret, InfoAction);
  }

}


export class Int extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.intToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.intFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Int);
  }

  async to_hex() {
    const ret = await HaskellShelley.intToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.intFromHex(hex_str);
    return Ptr._wrap(ret, Int);
  }

  async to_json() {
    const ret = await HaskellShelley.intToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.intFromJson(json);
    return Ptr._wrap(ret, Int);
  }

  static async new(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.intNew(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_negative(x) {
    const xPtr = Ptr._assertClass(x, BigNum);
    const ret = await HaskellShelley.intNewNegative(xPtr);
    return Ptr._wrap(ret, Int);
  }

  static async new_i32(x) {
    const ret = await HaskellShelley.intNewI32(x);
    return Ptr._wrap(ret, Int);
  }

  async is_positive() {
    const ret = await HaskellShelley.intIsPositive(this.ptr);
    return ret;
  }

  async as_positive() {
    const ret = await HaskellShelley.intAsPositive(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_negative() {
    const ret = await HaskellShelley.intAsNegative(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_i32() {
    const ret = await HaskellShelley.intAsI32(this.ptr);
    return ret;
  }

  async as_i32_or_nothing() {
    const ret = await HaskellShelley.intAsI32OrNothing(this.ptr);
    return ret;
  }

  async as_i32_or_fail() {
    const ret = await HaskellShelley.intAsI32OrFail(this.ptr);
    return ret;
  }

  async to_str() {
    const ret = await HaskellShelley.intToStr(this.ptr);
    return ret;
  }

  static async from_str(string) {
    const ret = await HaskellShelley.intFromStr(string);
    return Ptr._wrap(ret, Int);
  }

}


export class Ipv4 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.ipv4ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ipv4FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv4);
  }

  async to_hex() {
    const ret = await HaskellShelley.ipv4ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.ipv4FromHex(hex_str);
    return Ptr._wrap(ret, Ipv4);
  }

  async to_json() {
    const ret = await HaskellShelley.ipv4ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.ipv4FromJson(json);
    return Ptr._wrap(ret, Ipv4);
  }

  static async new(data) {
    const ret = await HaskellShelley.ipv4New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv4);
  }

  async ip() {
    const ret = await HaskellShelley.ipv4Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class Ipv6 extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.ipv6ToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ipv6FromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ipv6);
  }

  async to_hex() {
    const ret = await HaskellShelley.ipv6ToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.ipv6FromHex(hex_str);
    return Ptr._wrap(ret, Ipv6);
  }

  async to_json() {
    const ret = await HaskellShelley.ipv6ToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.ipv6FromJson(json);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(data) {
    const ret = await HaskellShelley.ipv6New(b64FromUint8Array(data));
    return Ptr._wrap(ret, Ipv6);
  }

  async ip() {
    const ret = await HaskellShelley.ipv6Ip(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class KESSignature extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.kESSignatureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.kESSignatureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESSignature);
  }

}


export class KESVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.kESVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, KESVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.kESVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.kESVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.kESVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, KESVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.kESVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.kESVKeyFromHex(hex);
    return Ptr._wrap(ret, KESVKey);
  }

}


export class Language extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.languageToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.languageFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Language);
  }

  async to_hex() {
    const ret = await HaskellShelley.languageToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.languageFromHex(hex_str);
    return Ptr._wrap(ret, Language);
  }

  async to_json() {
    const ret = await HaskellShelley.languageToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.languageFromJson(json);
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v1() {
    const ret = await HaskellShelley.languageNewPlutusV1();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v2() {
    const ret = await HaskellShelley.languageNewPlutusV2();
    return Ptr._wrap(ret, Language);
  }

  static async new_plutus_v3() {
    const ret = await HaskellShelley.languageNewPlutusV3();
    return Ptr._wrap(ret, Language);
  }

  async kind() {
    const ret = await HaskellShelley.languageKind(this.ptr);
    return ret;
  }

}


export class Languages extends Ptr {
  static async new() {
    const ret = await HaskellShelley.languagesNew();
    return Ptr._wrap(ret, Languages);
  }

  async len() {
    const ret = await HaskellShelley.languagesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.languagesGet(this.ptr, index);
    return Ptr._wrap(ret, Language);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Language);
    const ret = HaskellShelley.languagesAdd(this.ptr, elemPtr);
    return ret;
  }

  static async list() {
    const ret = await HaskellShelley.languagesList();
    return Ptr._wrap(ret, Languages);
  }

}


export class LegacyDaedalusPrivateKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.legacyDaedalusPrivateKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, LegacyDaedalusPrivateKey);
  }

  async as_bytes() {
    const ret = await HaskellShelley.legacyDaedalusPrivateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async chaincode() {
    const ret = await HaskellShelley.legacyDaedalusPrivateKeyChaincode(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class LinearFee extends Ptr {
  async constant() {
    const ret = await HaskellShelley.linearFeeConstant(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async coefficient() {
    const ret = await HaskellShelley.linearFeeCoefficient(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(coefficient, constant) {
    const coefficientPtr = Ptr._assertClass(coefficient, BigNum);
    const constantPtr = Ptr._assertClass(constant, BigNum);
    const ret = await HaskellShelley.linearFeeNew(coefficientPtr, constantPtr);
    return Ptr._wrap(ret, LinearFee);
  }

}


export class MIRToStakeCredentials extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.mIRToStakeCredentialsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.mIRToStakeCredentialsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_hex() {
    const ret = await HaskellShelley.mIRToStakeCredentialsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.mIRToStakeCredentialsFromHex(hex_str);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async to_json() {
    const ret = await HaskellShelley.mIRToStakeCredentialsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.mIRToStakeCredentialsFromJson(json);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  static async new() {
    const ret = await HaskellShelley.mIRToStakeCredentialsNew();
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

  async len() {
    const ret = await HaskellShelley.mIRToStakeCredentialsLen(this.ptr);
    return ret;
  }

  async insert(cred, delta) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const deltaPtr = Ptr._assertClass(delta, Int);
    const ret = await HaskellShelley.mIRToStakeCredentialsInsert(this.ptr, credPtr, deltaPtr);
    return Ptr._wrap(ret, Int);
  }

  async get(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.mIRToStakeCredentialsGet(this.ptr, credPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.mIRToStakeCredentialsKeys(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

}


export class MalformedAddress extends Ptr {
  async original_bytes() {
    const ret = await HaskellShelley.malformedAddressOriginalBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_address() {
    const ret = await HaskellShelley.malformedAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.malformedAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, MalformedAddress);
  }

}


export class MetadataList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.metadataListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.metadataListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataList);
  }

  async to_hex() {
    const ret = await HaskellShelley.metadataListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.metadataListFromHex(hex_str);
    return Ptr._wrap(ret, MetadataList);
  }

  static async new() {
    const ret = await HaskellShelley.metadataListNew();
    return Ptr._wrap(ret, MetadataList);
  }

  async len() {
    const ret = await HaskellShelley.metadataListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.metadataListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionMetadatum);
    const ret = HaskellShelley.metadataListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class MetadataMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.metadataMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.metadataMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MetadataMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.metadataMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.metadataMapFromHex(hex_str);
    return Ptr._wrap(ret, MetadataMap);
  }

  static async new() {
    const ret = await HaskellShelley.metadataMapNew();
    return Ptr._wrap(ret, MetadataMap);
  }

  async len() {
    const ret = await HaskellShelley.metadataMapLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.metadataMapInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_str(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.metadataMapInsertStr(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async insert_i32(key, value) {
    const valuePtr = Ptr._assertClass(value, TransactionMetadatum);
    const ret = await HaskellShelley.metadataMapInsertI32(this.ptr, key, valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.metadataMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_str(key) {
    const ret = await HaskellShelley.metadataMapGetStr(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async get_i32(key) {
    const ret = await HaskellShelley.metadataMapGetI32(this.ptr, key);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async has(key) {
    const keyPtr = Ptr._assertClass(key, TransactionMetadatum);
    const ret = await HaskellShelley.metadataMapHas(this.ptr, keyPtr);
    return ret;
  }

  async keys() {
    const ret = await HaskellShelley.metadataMapKeys(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

}


export class Mint extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.mintToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.mintFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Mint);
  }

  async to_hex() {
    const ret = await HaskellShelley.mintToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.mintFromHex(hex_str);
    return Ptr._wrap(ret, Mint);
  }

  async to_json() {
    const ret = await HaskellShelley.mintToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.mintFromJson(json);
    return Ptr._wrap(ret, Mint);
  }

  static async new() {
    const ret = await HaskellShelley.mintNew();
    return Ptr._wrap(ret, Mint);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.mintNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, Mint);
  }

  async len() {
    const ret = await HaskellShelley.mintLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const valuePtr = Ptr._assertClass(value, MintAssets);
    const ret = await HaskellShelley.mintInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, ScriptHash);
    const ret = await HaskellShelley.mintGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, MintsAssets);
  }

  async keys() {
    const ret = await HaskellShelley.mintKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async as_positive_multiasset() {
    const ret = await HaskellShelley.mintAsPositiveMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  async as_negative_multiasset() {
    const ret = await HaskellShelley.mintAsNegativeMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MintAssets extends Ptr {
  static async new() {
    const ret = await HaskellShelley.mintAssetsNew();
    return Ptr._wrap(ret, MintAssets);
  }

  static async new_from_entry(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.mintAssetsNewFromEntry(keyPtr, valuePtr);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await HaskellShelley.mintAssetsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const valuePtr = Ptr._assertClass(value, Int);
    const ret = await HaskellShelley.mintAssetsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, Int);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, AssetName);
    const ret = await HaskellShelley.mintAssetsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, Int);
  }

  async keys() {
    const ret = await HaskellShelley.mintAssetsKeys(this.ptr);
    return Ptr._wrap(ret, AssetNames);
  }

}


export class MintBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.mintBuilderNew();
    return Ptr._wrap(ret, MintBuilder);
  }

  add_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.mintBuilderAddAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  set_asset(mint, asset_name, amount) {
    const mintPtr = Ptr._assertClass(mint, MintWitness);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.mintBuilderSetAsset(this.ptr, mintPtr, asset_namePtr, amountPtr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.mintBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.mintBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.mintBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.mintBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_redeemers() {
    const ret = await HaskellShelley.mintBuilderGetRedeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.mintBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async has_native_scripts() {
    const ret = await HaskellShelley.mintBuilderHasNativeScripts(this.ptr);
    return ret;
  }

}


export class MintWitness extends Ptr {
  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await HaskellShelley.mintWitnessNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, MintWitness);
  }

  static async new_plutus_script(plutus_script, redeemer) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.mintWitnessNewPlutusScript(plutus_scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, MintWitness);
  }

}


export class MintsAssets extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.mintsAssetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.mintsAssetsFromJson(json);
    return Ptr._wrap(ret, MintsAssets);
  }

  static async new() {
    const ret = await HaskellShelley.mintsAssetsNew();
    return Ptr._wrap(ret, MintsAssets);
  }

  add(mint_assets) {
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = HaskellShelley.mintsAssetsAdd(this.ptr, mint_assetsPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.mintsAssetsGet(this.ptr, index);
    return Ptr._wrap(ret, MintAssets);
  }

  async len() {
    const ret = await HaskellShelley.mintsAssetsLen(this.ptr);
    return ret;
  }

}


export class MoveInstantaneousReward extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.moveInstantaneousRewardToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.moveInstantaneousRewardFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_hex() {
    const ret = await HaskellShelley.moveInstantaneousRewardToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.moveInstantaneousRewardFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async to_json() {
    const ret = await HaskellShelley.moveInstantaneousRewardToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.moveInstantaneousRewardFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_other_pot(pot, amount) {
    const amountPtr = Ptr._assertClass(amount, BigNum);
    const ret = await HaskellShelley.moveInstantaneousRewardNewToOtherPot(pot, amountPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new_to_stake_creds(pot, amounts) {
    const amountsPtr = Ptr._assertClass(amounts, MIRToStakeCredentials);
    const ret = await HaskellShelley.moveInstantaneousRewardNewToStakeCreds(pot, amountsPtr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  async pot() {
    const ret = await HaskellShelley.moveInstantaneousRewardPot(this.ptr);
    return ret;
  }

  async kind() {
    const ret = await HaskellShelley.moveInstantaneousRewardKind(this.ptr);
    return ret;
  }

  async as_to_other_pot() {
    const ret = await HaskellShelley.moveInstantaneousRewardAsToOtherPot(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async as_to_stake_creds() {
    const ret = await HaskellShelley.moveInstantaneousRewardAsToStakeCreds(this.ptr);
    return Ptr._wrap(ret, MIRToStakeCredentials);
  }

}


export class MoveInstantaneousRewardsCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertFromHex(hex_str);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async to_json() {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertFromJson(json);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

  async move_instantaneous_reward() {
    const ret = await HaskellShelley.moveInstantaneousRewardsCertMoveInstantaneousReward(this.ptr);
    return Ptr._wrap(ret, MoveInstantaneousReward);
  }

  static async new(move_instantaneous_reward) {
    const move_instantaneous_rewardPtr = Ptr._assertClass(move_instantaneous_reward, MoveInstantaneousReward);
    const ret = await HaskellShelley.moveInstantaneousRewardsCertNew(move_instantaneous_rewardPtr);
    return Ptr._wrap(ret, MoveInstantaneousRewardsCert);
  }

}


export class MultiAsset extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.multiAssetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.multiAssetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_hex() {
    const ret = await HaskellShelley.multiAssetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.multiAssetFromHex(hex_str);
    return Ptr._wrap(ret, MultiAsset);
  }

  async to_json() {
    const ret = await HaskellShelley.multiAssetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.multiAssetFromJson(json);
    return Ptr._wrap(ret, MultiAsset);
  }

  static async new() {
    const ret = await HaskellShelley.multiAssetNew();
    return Ptr._wrap(ret, MultiAsset);
  }

  async len() {
    const ret = await HaskellShelley.multiAssetLen(this.ptr);
    return ret;
  }

  async insert(policy_id, assets) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const assetsPtr = Ptr._assertClass(assets, Assets);
    const ret = await HaskellShelley.multiAssetInsert(this.ptr, policy_idPtr, assetsPtr);
    return Ptr._wrap(ret, Assets);
  }

  async get(policy_id) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const ret = await HaskellShelley.multiAssetGet(this.ptr, policy_idPtr);
    return Ptr._wrap(ret, Assets);
  }

  async set_asset(policy_id, asset_name, value) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.multiAssetSetAsset(this.ptr, policy_idPtr, asset_namePtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_asset(policy_id, asset_name) {
    const policy_idPtr = Ptr._assertClass(policy_id, ScriptHash);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const ret = await HaskellShelley.multiAssetGetAsset(this.ptr, policy_idPtr, asset_namePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.multiAssetKeys(this.ptr);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async sub(rhs_ma) {
    const rhs_maPtr = Ptr._assertClass(rhs_ma, MultiAsset);
    const ret = await HaskellShelley.multiAssetSub(this.ptr, rhs_maPtr);
    return Ptr._wrap(ret, MultiAsset);
  }

}


export class MultiHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.multiHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.multiHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.multiHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.multiHostNameFromHex(hex_str);
    return Ptr._wrap(ret, MultiHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.multiHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.multiHostNameFromJson(json);
    return Ptr._wrap(ret, MultiHostName);
  }

  async dns_name() {
    const ret = await HaskellShelley.multiHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordSRV);
  }

  static async new(dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordSRV);
    const ret = await HaskellShelley.multiHostNameNew(dns_namePtr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class NativeScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.nativeScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.nativeScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.nativeScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.nativeScriptFromHex(hex_str);
    return Ptr._wrap(ret, NativeScript);
  }

  async to_json() {
    const ret = await HaskellShelley.nativeScriptToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.nativeScriptFromJson(json);
    return Ptr._wrap(ret, NativeScript);
  }

  async hash() {
    const ret = await HaskellShelley.nativeScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new_script_pubkey(script_pubkey) {
    const script_pubkeyPtr = Ptr._assertClass(script_pubkey, ScriptPubkey);
    const ret = await HaskellShelley.nativeScriptNewScriptPubkey(script_pubkeyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_all(script_all) {
    const script_allPtr = Ptr._assertClass(script_all, ScriptAll);
    const ret = await HaskellShelley.nativeScriptNewScriptAll(script_allPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_any(script_any) {
    const script_anyPtr = Ptr._assertClass(script_any, ScriptAny);
    const ret = await HaskellShelley.nativeScriptNewScriptAny(script_anyPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_script_n_of_k(script_n_of_k) {
    const script_n_of_kPtr = Ptr._assertClass(script_n_of_k, ScriptNOfK);
    const ret = await HaskellShelley.nativeScriptNewScriptNOfK(script_n_of_kPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_start(timelock_start) {
    const timelock_startPtr = Ptr._assertClass(timelock_start, TimelockStart);
    const ret = await HaskellShelley.nativeScriptNewTimelockStart(timelock_startPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  static async new_timelock_expiry(timelock_expiry) {
    const timelock_expiryPtr = Ptr._assertClass(timelock_expiry, TimelockExpiry);
    const ret = await HaskellShelley.nativeScriptNewTimelockExpiry(timelock_expiryPtr);
    return Ptr._wrap(ret, NativeScript);
  }

  async kind() {
    const ret = await HaskellShelley.nativeScriptKind(this.ptr);
    return ret;
  }

  async as_script_pubkey() {
    const ret = await HaskellShelley.nativeScriptAsScriptPubkey(this.ptr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async as_script_all() {
    const ret = await HaskellShelley.nativeScriptAsScriptAll(this.ptr);
    return Ptr._wrap(ret, ScriptAll);
  }

  async as_script_any() {
    const ret = await HaskellShelley.nativeScriptAsScriptAny(this.ptr);
    return Ptr._wrap(ret, ScriptAny);
  }

  async as_script_n_of_k() {
    const ret = await HaskellShelley.nativeScriptAsScriptNOfK(this.ptr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async as_timelock_start() {
    const ret = await HaskellShelley.nativeScriptAsTimelockStart(this.ptr);
    return Ptr._wrap(ret, TimelockStart);
  }

  async as_timelock_expiry() {
    const ret = await HaskellShelley.nativeScriptAsTimelockExpiry(this.ptr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async get_required_signers() {
    const ret = await HaskellShelley.nativeScriptGetRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

}


export class NativeScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const ret = await HaskellShelley.nativeScriptSourceNew(scriptPtr);
    return Ptr._wrap(ret, NativeScriptSource);
  }

  static async new_ref_input(script_hash, input, required_signers) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const required_signersPtr = Ptr._assertClass(required_signers, Ed25519KeyHashes);
    const ret = await HaskellShelley.nativeScriptSourceNewRefInput(script_hashPtr, inputPtr, required_signersPtr);
    return Ptr._wrap(ret, NativeScriptSource);
  }

}


export class NativeScripts extends Ptr {
  static async new() {
    const ret = await HaskellShelley.nativeScriptsNew();
    return Ptr._wrap(ret, NativeScripts);
  }

  async len() {
    const ret = await HaskellShelley.nativeScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.nativeScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, NativeScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, NativeScript);
    const ret = HaskellShelley.nativeScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_bytes() {
    const ret = await HaskellShelley.nativeScriptsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.nativeScriptsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NativeScripts);
  }

  async to_hex() {
    const ret = await HaskellShelley.nativeScriptsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.nativeScriptsFromHex(hex_str);
    return Ptr._wrap(ret, NativeScripts);
  }

  async to_json() {
    const ret = await HaskellShelley.nativeScriptsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.nativeScriptsFromJson(json);
    return Ptr._wrap(ret, NativeScripts);
  }

}


export class NetworkId extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.networkIdToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.networkIdFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NetworkId);
  }

  async to_hex() {
    const ret = await HaskellShelley.networkIdToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.networkIdFromHex(hex_str);
    return Ptr._wrap(ret, NetworkId);
  }

  async to_json() {
    const ret = await HaskellShelley.networkIdToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.networkIdFromJson(json);
    return Ptr._wrap(ret, NetworkId);
  }

  static async testnet() {
    const ret = await HaskellShelley.networkIdTestnet();
    return Ptr._wrap(ret, NetworkId);
  }

  static async mainnet() {
    const ret = await HaskellShelley.networkIdMainnet();
    return Ptr._wrap(ret, NetworkId);
  }

  async kind() {
    const ret = await HaskellShelley.networkIdKind(this.ptr);
    return ret;
  }

}


export class NetworkInfo extends Ptr {
  static async new(network_id, protocol_magic) {
    const ret = await HaskellShelley.networkInfoNew(network_id, protocol_magic);
    return Ptr._wrap(ret, NetworkInfo);
  }

  async network_id() {
    const ret = await HaskellShelley.networkInfoNetworkId(this.ptr);
    return ret;
  }

  async protocol_magic() {
    const ret = await HaskellShelley.networkInfoProtocolMagic(this.ptr);
    return ret;
  }

  static async testnet_preview() {
    const ret = await HaskellShelley.networkInfoTestnetPreview();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async testnet_preprod() {
    const ret = await HaskellShelley.networkInfoTestnetPreprod();
    return Ptr._wrap(ret, NetworkInfo);
  }

  static async mainnet() {
    const ret = await HaskellShelley.networkInfoMainnet();
    return Ptr._wrap(ret, NetworkInfo);
  }

}


export class NewConstitutionAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.newConstitutionActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.newConstitutionActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.newConstitutionActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.newConstitutionActionFromHex(hex_str);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async to_json() {
    const ret = await HaskellShelley.newConstitutionActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.newConstitutionActionFromJson(json);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.newConstitutionActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async constitution() {
    const ret = await HaskellShelley.newConstitutionActionConstitution(this.ptr);
    return Ptr._wrap(ret, Constitution);
  }

  static async new(constitution) {
    const constitutionPtr = Ptr._assertClass(constitution, Constitution);
    const ret = await HaskellShelley.newConstitutionActionNew(constitutionPtr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  static async new_with_action_id(gov_action_id, constitution) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const constitutionPtr = Ptr._assertClass(constitution, Constitution);
    const ret = await HaskellShelley.newConstitutionActionNewWithActionId(gov_action_idPtr, constitutionPtr);
    return Ptr._wrap(ret, NewConstitutionAction);
  }

  async has_script_hash() {
    const ret = await HaskellShelley.newConstitutionActionHasScriptHash(this.ptr);
    return ret;
  }

}


export class NoConfidenceAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.noConfidenceActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.noConfidenceActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.noConfidenceActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.noConfidenceActionFromHex(hex_str);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async to_json() {
    const ret = await HaskellShelley.noConfidenceActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.noConfidenceActionFromJson(json);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.noConfidenceActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  static async new() {
    const ret = await HaskellShelley.noConfidenceActionNew();
    return Ptr._wrap(ret, NoConfidenceAction);
  }

  static async new_with_action_id(gov_action_id) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const ret = await HaskellShelley.noConfidenceActionNewWithActionId(gov_action_idPtr);
    return Ptr._wrap(ret, NoConfidenceAction);
  }

}


export class Nonce extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.nonceToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.nonceFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Nonce);
  }

  async to_hex() {
    const ret = await HaskellShelley.nonceToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.nonceFromHex(hex_str);
    return Ptr._wrap(ret, Nonce);
  }

  async to_json() {
    const ret = await HaskellShelley.nonceToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.nonceFromJson(json);
    return Ptr._wrap(ret, Nonce);
  }

  static async new_identity() {
    const ret = await HaskellShelley.nonceNewIdentity();
    return Ptr._wrap(ret, Nonce);
  }

  static async new_from_hash(hash) {
    const ret = await HaskellShelley.nonceNewFromHash(b64FromUint8Array(hash));
    return Ptr._wrap(ret, Nonce);
  }

  async get_hash() {
    const ret = await HaskellShelley.nonceGetHash(this.ptr);
    return uint8ArrayFromB64(ret);
  }

}


export class OperationalCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.operationalCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.operationalCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.operationalCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.operationalCertFromHex(hex_str);
    return Ptr._wrap(ret, OperationalCert);
  }

  async to_json() {
    const ret = await HaskellShelley.operationalCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.operationalCertFromJson(json);
    return Ptr._wrap(ret, OperationalCert);
  }

  async hot_vkey() {
    const ret = await HaskellShelley.operationalCertHotVkey(this.ptr);
    return Ptr._wrap(ret, KESVKey);
  }

  async sequence_number() {
    const ret = await HaskellShelley.operationalCertSequenceNumber(this.ptr);
    return ret;
  }

  async kes_period() {
    const ret = await HaskellShelley.operationalCertKesPeriod(this.ptr);
    return ret;
  }

  async sigma() {
    const ret = await HaskellShelley.operationalCertSigma(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

  static async new(hot_vkey, sequence_number, kes_period, sigma) {
    const hot_vkeyPtr = Ptr._assertClass(hot_vkey, KESVKey);
    const sigmaPtr = Ptr._assertClass(sigma, Ed25519Signature);
    const ret = await HaskellShelley.operationalCertNew(hot_vkeyPtr, sequence_number, kes_period, sigmaPtr);
    return Ptr._wrap(ret, OperationalCert);
  }

}


export class OutputDatum extends Ptr {
  static async new_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await HaskellShelley.outputDatumNewDataHash(data_hashPtr);
    return Ptr._wrap(ret, OutputDatum);
  }

  static async new_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await HaskellShelley.outputDatumNewData(dataPtr);
    return Ptr._wrap(ret, OutputDatum);
  }

  async data_hash() {
    const ret = await HaskellShelley.outputDatumDataHash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async data() {
    const ret = await HaskellShelley.outputDatumData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

}


export class ParameterChangeAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.parameterChangeActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.parameterChangeActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.parameterChangeActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.parameterChangeActionFromHex(hex_str);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async to_json() {
    const ret = await HaskellShelley.parameterChangeActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.parameterChangeActionFromJson(json);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.parameterChangeActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async protocol_param_updates() {
    const ret = await HaskellShelley.parameterChangeActionProtocolParamUpdates(this.ptr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async policy_hash() {
    const ret = await HaskellShelley.parameterChangeActionPolicyHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(protocol_param_updates) {
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const ret = await HaskellShelley.parameterChangeActionNew(protocol_param_updatesPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_action_id(gov_action_id, protocol_param_updates) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const ret = await HaskellShelley.parameterChangeActionNewWithActionId(gov_action_idPtr, protocol_param_updatesPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_policy_hash(protocol_param_updates, policy_hash) {
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.parameterChangeActionNewWithPolicyHash(protocol_param_updatesPtr, policy_hashPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

  static async new_with_policy_hash_and_action_id(gov_action_id, protocol_param_updates, policy_hash) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const protocol_param_updatesPtr = Ptr._assertClass(protocol_param_updates, ProtocolParamUpdate);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.parameterChangeActionNewWithPolicyHashAndActionId(gov_action_idPtr, protocol_param_updatesPtr, policy_hashPtr);
    return Ptr._wrap(ret, ParameterChangeAction);
  }

}


export class PlutusData extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.plutusDataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.plutusDataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async to_hex() {
    const ret = await HaskellShelley.plutusDataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.plutusDataFromHex(hex_str);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_constr_plutus_data(constr_plutus_data) {
    const constr_plutus_dataPtr = Ptr._assertClass(constr_plutus_data, ConstrPlutusData);
    const ret = await HaskellShelley.plutusDataNewConstrPlutusData(constr_plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_empty_constr_plutus_data(alternative) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const ret = await HaskellShelley.plutusDataNewEmptyConstrPlutusData(alternativePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_single_value_constr_plutus_data(alternative, plutus_data) {
    const alternativePtr = Ptr._assertClass(alternative, BigNum);
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
    const ret = await HaskellShelley.plutusDataNewSingleValueConstrPlutusData(alternativePtr, plutus_dataPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, PlutusMap);
    const ret = await HaskellShelley.plutusDataNewMap(mapPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, PlutusList);
    const ret = await HaskellShelley.plutusDataNewList(listPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_integer(integer) {
    const integerPtr = Ptr._assertClass(integer, BigInt);
    const ret = await HaskellShelley.plutusDataNewInteger(integerPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.plutusDataNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusData);
  }

  async kind() {
    const ret = await HaskellShelley.plutusDataKind(this.ptr);
    return ret;
  }

  async as_constr_plutus_data() {
    const ret = await HaskellShelley.plutusDataAsConstrPlutusData(this.ptr);
    return Ptr._wrap(ret, ConstrPlutusData);
  }

  async as_map() {
    const ret = await HaskellShelley.plutusDataAsMap(this.ptr);
    return Ptr._wrap(ret, PlutusMap);
  }

  async as_list() {
    const ret = await HaskellShelley.plutusDataAsList(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  async as_integer() {
    const ret = await HaskellShelley.plutusDataAsInteger(this.ptr);
    return Ptr._wrap(ret, BigInt);
  }

  async as_bytes() {
    const ret = await HaskellShelley.plutusDataAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_json(schema) {
    const ret = await HaskellShelley.plutusDataToJson(this.ptr, schema);
    return ret;
  }

  static async from_json(json, schema) {
    const ret = await HaskellShelley.plutusDataFromJson(json, schema);
    return Ptr._wrap(ret, PlutusData);
  }

  static async from_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.plutusDataFromAddress(addressPtr);
    return Ptr._wrap(ret, PlutusData);
  }

}


export class PlutusList extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.plutusListToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.plutusListFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusList);
  }

  async to_hex() {
    const ret = await HaskellShelley.plutusListToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.plutusListFromHex(hex_str);
    return Ptr._wrap(ret, PlutusList);
  }

  static async new() {
    const ret = await HaskellShelley.plutusListNew();
    return Ptr._wrap(ret, PlutusList);
  }

  async len() {
    const ret = await HaskellShelley.plutusListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.plutusListGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusData);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusData);
    const ret = HaskellShelley.plutusListAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusMap extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.plutusMapToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.plutusMapFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusMap);
  }

  async to_hex() {
    const ret = await HaskellShelley.plutusMapToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.plutusMapFromHex(hex_str);
    return Ptr._wrap(ret, PlutusMap);
  }

  static async new() {
    const ret = await HaskellShelley.plutusMapNew();
    return Ptr._wrap(ret, PlutusMap);
  }

  async len() {
    const ret = await HaskellShelley.plutusMapLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const valuePtr = Ptr._assertClass(value, PlutusData);
    const ret = await HaskellShelley.plutusMapInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, PlutusData);
    const ret = await HaskellShelley.plutusMapGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, PlutusData);
  }

  async keys() {
    const ret = await HaskellShelley.plutusMapKeys(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

}


export class PlutusScript extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.plutusScriptToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.plutusScriptFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  async to_hex() {
    const ret = await HaskellShelley.plutusScriptToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.plutusScriptFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new(bytes) {
    const ret = await HaskellShelley.plutusScriptNew(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v2(bytes) {
    const ret = await HaskellShelley.plutusScriptNewV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_v3(bytes) {
    const ret = await HaskellShelley.plutusScriptNewV3(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async new_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.plutusScriptNewWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async bytes() {
    const ret = await HaskellShelley.plutusScriptBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes_v2(bytes) {
    const ret = await HaskellShelley.plutusScriptFromBytesV2(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_v3(bytes) {
    const ret = await HaskellShelley.plutusScriptFromBytesV3(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_bytes_with_version(bytes, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.plutusScriptFromBytesWithVersion(b64FromUint8Array(bytes), languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  static async from_hex_with_version(hex_str, language) {
    const languagePtr = Ptr._assertClass(language, Language);
    const ret = await HaskellShelley.plutusScriptFromHexWithVersion(hex_str, languagePtr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async hash() {
    const ret = await HaskellShelley.plutusScriptHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  async language_version() {
    const ret = await HaskellShelley.plutusScriptLanguageVersion(this.ptr);
    return Ptr._wrap(ret, Language);
  }

}


export class PlutusScriptSource extends Ptr {
  static async new(script) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const ret = await HaskellShelley.plutusScriptSourceNew(scriptPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

  static async new_ref_input(script_hash, input, lang_ver) {
    const script_hashPtr = Ptr._assertClass(script_hash, ScriptHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const lang_verPtr = Ptr._assertClass(lang_ver, Language);
    const ret = await HaskellShelley.plutusScriptSourceNewRefInput(script_hashPtr, inputPtr, lang_verPtr);
    return Ptr._wrap(ret, PlutusScriptSource);
  }

}


export class PlutusScripts extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.plutusScriptsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.plutusScriptsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_hex() {
    const ret = await HaskellShelley.plutusScriptsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.plutusScriptsFromHex(hex_str);
    return Ptr._wrap(ret, PlutusScripts);
  }

  async to_json() {
    const ret = await HaskellShelley.plutusScriptsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.plutusScriptsFromJson(json);
    return Ptr._wrap(ret, PlutusScripts);
  }

  static async new() {
    const ret = await HaskellShelley.plutusScriptsNew();
    return Ptr._wrap(ret, PlutusScripts);
  }

  async len() {
    const ret = await HaskellShelley.plutusScriptsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.plutusScriptsGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusScript);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusScript);
    const ret = HaskellShelley.plutusScriptsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class PlutusWitness extends Ptr {
  static async new(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.plutusWitnessNew(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref(script, datum, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const datumPtr = Ptr._assertClass(datum, DatumSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.plutusWitnessNewWithRef(scriptPtr, datumPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScript);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.plutusWitnessNewWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  static async new_with_ref_without_datum(script, redeemer) {
    const scriptPtr = Ptr._assertClass(script, PlutusScriptSource);
    const redeemerPtr = Ptr._assertClass(redeemer, Redeemer);
    const ret = await HaskellShelley.plutusWitnessNewWithRefWithoutDatum(scriptPtr, redeemerPtr);
    return Ptr._wrap(ret, PlutusWitness);
  }

  async script() {
    const ret = await HaskellShelley.plutusWitnessScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

  async datum() {
    const ret = await HaskellShelley.plutusWitnessDatum(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async redeemer() {
    const ret = await HaskellShelley.plutusWitnessRedeemer(this.ptr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class PlutusWitnesses extends Ptr {
  static async new() {
    const ret = await HaskellShelley.plutusWitnessesNew();
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.plutusWitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.plutusWitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, PlutusWitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, PlutusWitness);
    const ret = HaskellShelley.plutusWitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Pointer extends Ptr {
  static async new(slot, tx_index, cert_index) {
    const ret = await HaskellShelley.pointerNew(slot, tx_index, cert_index);
    return Ptr._wrap(ret, Pointer);
  }

  static async new_pointer(slot, tx_index, cert_index) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const tx_indexPtr = Ptr._assertClass(tx_index, BigNum);
    const cert_indexPtr = Ptr._assertClass(cert_index, BigNum);
    const ret = await HaskellShelley.pointerNewPointer(slotPtr, tx_indexPtr, cert_indexPtr);
    return Ptr._wrap(ret, Pointer);
  }

  async slot() {
    const ret = await HaskellShelley.pointerSlot(this.ptr);
    return ret;
  }

  async tx_index() {
    const ret = await HaskellShelley.pointerTxIndex(this.ptr);
    return ret;
  }

  async cert_index() {
    const ret = await HaskellShelley.pointerCertIndex(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.pointerSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async tx_index_bignum() {
    const ret = await HaskellShelley.pointerTxIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cert_index_bignum() {
    const ret = await HaskellShelley.pointerCertIndexBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class PointerAddress extends Ptr {
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const stakePtr = Ptr._assertClass(stake, Pointer);
    const ret = await HaskellShelley.pointerAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, PointerAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.pointerAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async stake_pointer() {
    const ret = await HaskellShelley.pointerAddressStakePointer(this.ptr);
    return Ptr._wrap(ret, Pointer);
  }

  async to_address() {
    const ret = await HaskellShelley.pointerAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.pointerAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, PointerAddress);
  }

}


export class PoolMetadata extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.poolMetadataToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolMetadataFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolMetadataToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.poolMetadataFromHex(hex_str);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async to_json() {
    const ret = await HaskellShelley.poolMetadataToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.poolMetadataFromJson(json);
    return Ptr._wrap(ret, PoolMetadata);
  }

  async url() {
    const ret = await HaskellShelley.poolMetadataUrl(this.ptr);
    return Ptr._wrap(ret, URL);
  }

  async pool_metadata_hash() {
    const ret = await HaskellShelley.poolMetadataPoolMetadataHash(this.ptr);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  static async new(url, pool_metadata_hash) {
    const urlPtr = Ptr._assertClass(url, URL);
    const pool_metadata_hashPtr = Ptr._assertClass(pool_metadata_hash, PoolMetadataHash);
    const ret = await HaskellShelley.poolMetadataNew(urlPtr, pool_metadata_hashPtr);
    return Ptr._wrap(ret, PoolMetadata);
  }

}


export class PoolMetadataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolMetadataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.poolMetadataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.poolMetadataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.poolMetadataHashFromBech32(bech_str);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolMetadataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.poolMetadataHashFromHex(hex);
    return Ptr._wrap(ret, PoolMetadataHash);
  }

}


export class PoolParams extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.poolParamsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolParamsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolParams);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolParamsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.poolParamsFromHex(hex_str);
    return Ptr._wrap(ret, PoolParams);
  }

  async to_json() {
    const ret = await HaskellShelley.poolParamsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.poolParamsFromJson(json);
    return Ptr._wrap(ret, PoolParams);
  }

  async operator() {
    const ret = await HaskellShelley.poolParamsOperator(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async vrf_keyhash() {
    const ret = await HaskellShelley.poolParamsVrfKeyhash(this.ptr);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async pledge() {
    const ret = await HaskellShelley.poolParamsPledge(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async cost() {
    const ret = await HaskellShelley.poolParamsCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async margin() {
    const ret = await HaskellShelley.poolParamsMargin(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async reward_account() {
    const ret = await HaskellShelley.poolParamsRewardAccount(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async pool_owners() {
    const ret = await HaskellShelley.poolParamsPoolOwners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  async relays() {
    const ret = await HaskellShelley.poolParamsRelays(this.ptr);
    return Ptr._wrap(ret, Relays);
  }

  async pool_metadata() {
    const ret = await HaskellShelley.poolParamsPoolMetadata(this.ptr);
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
      const ret = await HaskellShelley.poolParamsNew(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr);
      return Ptr._wrap(ret, PoolParams);
    }
    if(pool_metadata != null) {
      const ret = await HaskellShelley.poolParamsNewWithPoolMetadata(operatorPtr, vrf_keyhashPtr, pledgePtr, costPtr, marginPtr, reward_accountPtr, pool_ownersPtr, relaysPtr, pool_metadataPtr);
      return Ptr._wrap(ret, PoolParams);
    }
  }

}


export class PoolRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.poolRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.poolRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.poolRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.poolRegistrationFromJson(json);
    return Ptr._wrap(ret, PoolRegistration);
  }

  async pool_params() {
    const ret = await HaskellShelley.poolRegistrationPoolParams(this.ptr);
    return Ptr._wrap(ret, PoolParams);
  }

  static async new(pool_params) {
    const pool_paramsPtr = Ptr._assertClass(pool_params, PoolParams);
    const ret = await HaskellShelley.poolRegistrationNew(pool_paramsPtr);
    return Ptr._wrap(ret, PoolRegistration);
  }

}


export class PoolRetirement extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.poolRetirementToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolRetirementFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolRetirementToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.poolRetirementFromHex(hex_str);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async to_json() {
    const ret = await HaskellShelley.poolRetirementToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.poolRetirementFromJson(json);
    return Ptr._wrap(ret, PoolRetirement);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.poolRetirementPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async epoch() {
    const ret = await HaskellShelley.poolRetirementEpoch(this.ptr);
    return ret;
  }

  static async new(pool_keyhash, epoch) {
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.poolRetirementNew(pool_keyhashPtr, epoch);
    return Ptr._wrap(ret, PoolRetirement);
  }

}


export class PoolVotingThresholds extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.poolVotingThresholdsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.poolVotingThresholdsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async to_hex() {
    const ret = await HaskellShelley.poolVotingThresholdsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.poolVotingThresholdsFromHex(hex_str);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async to_json() {
    const ret = await HaskellShelley.poolVotingThresholdsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.poolVotingThresholdsFromJson(json);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  static async new(motion_no_confidence, committee_normal, committee_no_confidence, hard_fork_initiation, security_relevant_threshold) {
    const motion_no_confidencePtr = Ptr._assertClass(motion_no_confidence, UnitInterval);
    const committee_normalPtr = Ptr._assertClass(committee_normal, UnitInterval);
    const committee_no_confidencePtr = Ptr._assertClass(committee_no_confidence, UnitInterval);
    const hard_fork_initiationPtr = Ptr._assertClass(hard_fork_initiation, UnitInterval);
    const security_relevant_thresholdPtr = Ptr._assertClass(security_relevant_threshold, UnitInterval);
    const ret = await HaskellShelley.poolVotingThresholdsNew(motion_no_confidencePtr, committee_normalPtr, committee_no_confidencePtr, hard_fork_initiationPtr, security_relevant_thresholdPtr);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  async motion_no_confidence() {
    const ret = await HaskellShelley.poolVotingThresholdsMotionNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_normal() {
    const ret = await HaskellShelley.poolVotingThresholdsCommitteeNormal(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async committee_no_confidence() {
    const ret = await HaskellShelley.poolVotingThresholdsCommitteeNoConfidence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async hard_fork_initiation() {
    const ret = await HaskellShelley.poolVotingThresholdsHardForkInitiation(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class PrivateKey extends Ptr {
  async to_public() {
    const ret = await HaskellShelley.privateKeyToPublic(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

  static async generate_ed25519() {
    const ret = await HaskellShelley.privateKeyGenerateEd25519();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async generate_ed25519extended() {
    const ret = await HaskellShelley.privateKeyGenerateEd25519extended();
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.privateKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PrivateKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.privateKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.privateKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_extended_bytes(bytes) {
    const ret = await HaskellShelley.privateKeyFromExtendedBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  static async from_normal_bytes(bytes) {
    const ret = await HaskellShelley.privateKeyFromNormalBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PrivateKey);
  }

  async sign(message) {
    const ret = await HaskellShelley.privateKeySign(this.ptr, b64FromUint8Array(message));
    return Ptr._wrap(ret, Ed25519Signature);
  }

  async to_hex() {
    const ret = await HaskellShelley.privateKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.privateKeyFromHex(hex_str);
    return Ptr._wrap(ret, PrivateKey);
  }

}


export class ProposedProtocolParameterUpdates extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_hex() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesFromHex(hex_str);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async to_json() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesFromJson(json);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  static async new() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesNew();
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async len() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const valuePtr = Ptr._assertClass(value, ProtocolParamUpdate);
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, GenesisHash);
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async keys() {
    const ret = await HaskellShelley.proposedProtocolParameterUpdatesKeys(this.ptr);
    return Ptr._wrap(ret, GenesisHashes);
  }

}


export class ProtocolParamUpdate extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.protocolParamUpdateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.protocolParamUpdateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_hex() {
    const ret = await HaskellShelley.protocolParamUpdateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.protocolParamUpdateFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  async to_json() {
    const ret = await HaskellShelley.protocolParamUpdateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.protocolParamUpdateFromJson(json);
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

  set_minfee_a(minfee_a) {
    const minfee_aPtr = Ptr._assertClass(minfee_a, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetMinfeeA(this.ptr, minfee_aPtr);
    return ret;
  }

  async minfee_a() {
    const ret = await HaskellShelley.protocolParamUpdateMinfeeA(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_minfee_b(minfee_b) {
    const minfee_bPtr = Ptr._assertClass(minfee_b, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetMinfeeB(this.ptr, minfee_bPtr);
    return ret;
  }

  async minfee_b() {
    const ret = await HaskellShelley.protocolParamUpdateMinfeeB(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_block_body_size(max_block_body_size) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxBlockBodySize(this.ptr, max_block_body_size);
    return ret;
  }

  async max_block_body_size() {
    const ret = await HaskellShelley.protocolParamUpdateMaxBlockBodySize(this.ptr);
    return ret;
  }

  set_max_tx_size(max_tx_size) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxTxSize(this.ptr, max_tx_size);
    return ret;
  }

  async max_tx_size() {
    const ret = await HaskellShelley.protocolParamUpdateMaxTxSize(this.ptr);
    return ret;
  }

  set_max_block_header_size(max_block_header_size) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxBlockHeaderSize(this.ptr, max_block_header_size);
    return ret;
  }

  async max_block_header_size() {
    const ret = await HaskellShelley.protocolParamUpdateMaxBlockHeaderSize(this.ptr);
    return ret;
  }

  set_key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetKeyDeposit(this.ptr, key_depositPtr);
    return ret;
  }

  async key_deposit() {
    const ret = await HaskellShelley.protocolParamUpdateKeyDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetPoolDeposit(this.ptr, pool_depositPtr);
    return ret;
  }

  async pool_deposit() {
    const ret = await HaskellShelley.protocolParamUpdatePoolDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_max_epoch(max_epoch) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxEpoch(this.ptr, max_epoch);
    return ret;
  }

  async max_epoch() {
    const ret = await HaskellShelley.protocolParamUpdateMaxEpoch(this.ptr);
    return ret;
  }

  set_n_opt(n_opt) {
    const ret = HaskellShelley.protocolParamUpdateSetNOpt(this.ptr, n_opt);
    return ret;
  }

  async n_opt() {
    const ret = await HaskellShelley.protocolParamUpdateNOpt(this.ptr);
    return ret;
  }

  set_pool_pledge_influence(pool_pledge_influence) {
    const pool_pledge_influencePtr = Ptr._assertClass(pool_pledge_influence, UnitInterval);
    const ret = HaskellShelley.protocolParamUpdateSetPoolPledgeInfluence(this.ptr, pool_pledge_influencePtr);
    return ret;
  }

  async pool_pledge_influence() {
    const ret = await HaskellShelley.protocolParamUpdatePoolPledgeInfluence(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_expansion_rate(expansion_rate) {
    const expansion_ratePtr = Ptr._assertClass(expansion_rate, UnitInterval);
    const ret = HaskellShelley.protocolParamUpdateSetExpansionRate(this.ptr, expansion_ratePtr);
    return ret;
  }

  async expansion_rate() {
    const ret = await HaskellShelley.protocolParamUpdateExpansionRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  set_treasury_growth_rate(treasury_growth_rate) {
    const treasury_growth_ratePtr = Ptr._assertClass(treasury_growth_rate, UnitInterval);
    const ret = HaskellShelley.protocolParamUpdateSetTreasuryGrowthRate(this.ptr, treasury_growth_ratePtr);
    return ret;
  }

  async treasury_growth_rate() {
    const ret = await HaskellShelley.protocolParamUpdateTreasuryGrowthRate(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async d() {
    const ret = await HaskellShelley.protocolParamUpdateD(this.ptr);
    return Ptr._wrap(ret, UnitInterval);
  }

  async extra_entropy() {
    const ret = await HaskellShelley.protocolParamUpdateExtraEntropy(this.ptr);
    return Ptr._wrap(ret, Nonce);
  }

  set_protocol_version(protocol_version) {
    const protocol_versionPtr = Ptr._assertClass(protocol_version, ProtocolVersion);
    const ret = HaskellShelley.protocolParamUpdateSetProtocolVersion(this.ptr, protocol_versionPtr);
    return ret;
  }

  async protocol_version() {
    const ret = await HaskellShelley.protocolParamUpdateProtocolVersion(this.ptr);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  set_min_pool_cost(min_pool_cost) {
    const min_pool_costPtr = Ptr._assertClass(min_pool_cost, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetMinPoolCost(this.ptr, min_pool_costPtr);
    return ret;
  }

  async min_pool_cost() {
    const ret = await HaskellShelley.protocolParamUpdateMinPoolCost(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ada_per_utxo_byte(ada_per_utxo_byte) {
    const ada_per_utxo_bytePtr = Ptr._assertClass(ada_per_utxo_byte, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetAdaPerUtxoByte(this.ptr, ada_per_utxo_bytePtr);
    return ret;
  }

  async ada_per_utxo_byte() {
    const ret = await HaskellShelley.protocolParamUpdateAdaPerUtxoByte(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_cost_models(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.protocolParamUpdateSetCostModels(this.ptr, cost_modelsPtr);
    return ret;
  }

  async cost_models() {
    const ret = await HaskellShelley.protocolParamUpdateCostModels(this.ptr);
    return Ptr._wrap(ret, Costmdls);
  }

  set_execution_costs(execution_costs) {
    const execution_costsPtr = Ptr._assertClass(execution_costs, ExUnitPrices);
    const ret = HaskellShelley.protocolParamUpdateSetExecutionCosts(this.ptr, execution_costsPtr);
    return ret;
  }

  async execution_costs() {
    const ret = await HaskellShelley.protocolParamUpdateExecutionCosts(this.ptr);
    return Ptr._wrap(ret, ExUnitPrices);
  }

  set_max_tx_ex_units(max_tx_ex_units) {
    const max_tx_ex_unitsPtr = Ptr._assertClass(max_tx_ex_units, ExUnits);
    const ret = HaskellShelley.protocolParamUpdateSetMaxTxExUnits(this.ptr, max_tx_ex_unitsPtr);
    return ret;
  }

  async max_tx_ex_units() {
    const ret = await HaskellShelley.protocolParamUpdateMaxTxExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_block_ex_units(max_block_ex_units) {
    const max_block_ex_unitsPtr = Ptr._assertClass(max_block_ex_units, ExUnits);
    const ret = HaskellShelley.protocolParamUpdateSetMaxBlockExUnits(this.ptr, max_block_ex_unitsPtr);
    return ret;
  }

  async max_block_ex_units() {
    const ret = await HaskellShelley.protocolParamUpdateMaxBlockExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  set_max_value_size(max_value_size) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxValueSize(this.ptr, max_value_size);
    return ret;
  }

  async max_value_size() {
    const ret = await HaskellShelley.protocolParamUpdateMaxValueSize(this.ptr);
    return ret;
  }

  set_collateral_percentage(collateral_percentage) {
    const ret = HaskellShelley.protocolParamUpdateSetCollateralPercentage(this.ptr, collateral_percentage);
    return ret;
  }

  async collateral_percentage() {
    const ret = await HaskellShelley.protocolParamUpdateCollateralPercentage(this.ptr);
    return ret;
  }

  set_max_collateral_inputs(max_collateral_inputs) {
    const ret = HaskellShelley.protocolParamUpdateSetMaxCollateralInputs(this.ptr, max_collateral_inputs);
    return ret;
  }

  async max_collateral_inputs() {
    const ret = await HaskellShelley.protocolParamUpdateMaxCollateralInputs(this.ptr);
    return ret;
  }

  set_pool_voting_thresholds(pool_voting_thresholds) {
    const pool_voting_thresholdsPtr = Ptr._assertClass(pool_voting_thresholds, PoolVotingThresholds);
    const ret = HaskellShelley.protocolParamUpdateSetPoolVotingThresholds(this.ptr, pool_voting_thresholdsPtr);
    return ret;
  }

  async pool_voting_thresholds() {
    const ret = await HaskellShelley.protocolParamUpdatePoolVotingThresholds(this.ptr);
    return Ptr._wrap(ret, PoolVotingThresholds);
  }

  set_drep_voting_thresholds(drep_voting_thresholds) {
    const drep_voting_thresholdsPtr = Ptr._assertClass(drep_voting_thresholds, DrepVotingThresholds);
    const ret = HaskellShelley.protocolParamUpdateSetDrepVotingThresholds(this.ptr, drep_voting_thresholdsPtr);
    return ret;
  }

  async drep_voting_thresholds() {
    const ret = await HaskellShelley.protocolParamUpdateDrepVotingThresholds(this.ptr);
    return Ptr._wrap(ret, DrepVotingThresholds);
  }

  set_min_committee_size(min_committee_size) {
    const ret = HaskellShelley.protocolParamUpdateSetMinCommitteeSize(this.ptr, min_committee_size);
    return ret;
  }

  async min_committee_size() {
    const ret = await HaskellShelley.protocolParamUpdateMinCommitteeSize(this.ptr);
    return ret;
  }

  set_committee_term_limit(committee_term_limit) {
    const ret = HaskellShelley.protocolParamUpdateSetCommitteeTermLimit(this.ptr, committee_term_limit);
    return ret;
  }

  async committee_term_limit() {
    const ret = await HaskellShelley.protocolParamUpdateCommitteeTermLimit(this.ptr);
    return ret;
  }

  set_governance_action_validity_period(governance_action_validity_period) {
    const ret = HaskellShelley.protocolParamUpdateSetGovernanceActionValidityPeriod(this.ptr, governance_action_validity_period);
    return ret;
  }

  async governance_action_validity_period() {
    const ret = await HaskellShelley.protocolParamUpdateGovernanceActionValidityPeriod(this.ptr);
    return ret;
  }

  set_governance_action_deposit(governance_action_deposit) {
    const governance_action_depositPtr = Ptr._assertClass(governance_action_deposit, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetGovernanceActionDeposit(this.ptr, governance_action_depositPtr);
    return ret;
  }

  async governance_action_deposit() {
    const ret = await HaskellShelley.protocolParamUpdateGovernanceActionDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_drep_deposit(drep_deposit) {
    const drep_depositPtr = Ptr._assertClass(drep_deposit, BigNum);
    const ret = HaskellShelley.protocolParamUpdateSetDrepDeposit(this.ptr, drep_depositPtr);
    return ret;
  }

  async drep_deposit() {
    const ret = await HaskellShelley.protocolParamUpdateDrepDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_drep_inactivity_period(drep_inactivity_period) {
    const ret = HaskellShelley.protocolParamUpdateSetDrepInactivityPeriod(this.ptr, drep_inactivity_period);
    return ret;
  }

  async drep_inactivity_period() {
    const ret = await HaskellShelley.protocolParamUpdateDrepInactivityPeriod(this.ptr);
    return ret;
  }

  static async new() {
    const ret = await HaskellShelley.protocolParamUpdateNew();
    return Ptr._wrap(ret, ProtocolParamUpdate);
  }

}


export class ProtocolVersion extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.protocolVersionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.protocolVersionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_hex() {
    const ret = await HaskellShelley.protocolVersionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.protocolVersionFromHex(hex_str);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async to_json() {
    const ret = await HaskellShelley.protocolVersionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.protocolVersionFromJson(json);
    return Ptr._wrap(ret, ProtocolVersion);
  }

  async major() {
    const ret = await HaskellShelley.protocolVersionMajor(this.ptr);
    return ret;
  }

  async minor() {
    const ret = await HaskellShelley.protocolVersionMinor(this.ptr);
    return ret;
  }

  static async new(major, minor) {
    const ret = await HaskellShelley.protocolVersionNew(major, minor);
    return Ptr._wrap(ret, ProtocolVersion);
  }

}


export class PublicKey extends Ptr {
  static async from_bech32(bech32_str) {
    const ret = await HaskellShelley.publicKeyFromBech32(bech32_str);
    return Ptr._wrap(ret, PublicKey);
  }

  async to_bech32() {
    const ret = await HaskellShelley.publicKeyToBech32(this.ptr);
    return ret;
  }

  async as_bytes() {
    const ret = await HaskellShelley.publicKeyAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.publicKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, PublicKey);
  }

  async verify(data, signature) {
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.publicKeyVerify(this.ptr, b64FromUint8Array(data), signaturePtr);
    return ret;
  }

  async hash() {
    const ret = await HaskellShelley.publicKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.publicKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.publicKeyFromHex(hex_str);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class PublicKeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.publicKeysNew();
    return Ptr._wrap(ret, PublicKeys);
  }

  async size() {
    const ret = await HaskellShelley.publicKeysSize(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.publicKeysGet(this.ptr, index);
    return Ptr._wrap(ret, PublicKey);
  }

  add(key) {
    const keyPtr = Ptr._assertClass(key, PublicKey);
    const ret = HaskellShelley.publicKeysAdd(this.ptr, keyPtr);
    return ret;
  }

}


export class Redeemer extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.redeemerToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.redeemerFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemer);
  }

  async to_hex() {
    const ret = await HaskellShelley.redeemerToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.redeemerFromHex(hex_str);
    return Ptr._wrap(ret, Redeemer);
  }

  async to_json() {
    const ret = await HaskellShelley.redeemerToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.redeemerFromJson(json);
    return Ptr._wrap(ret, Redeemer);
  }

  async tag() {
    const ret = await HaskellShelley.redeemerTag(this.ptr);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async index() {
    const ret = await HaskellShelley.redeemerIndex(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async data() {
    const ret = await HaskellShelley.redeemerData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async ex_units() {
    const ret = await HaskellShelley.redeemerExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

  static async new(tag, index, data, ex_units) {
    const tagPtr = Ptr._assertClass(tag, RedeemerTag);
    const indexPtr = Ptr._assertClass(index, BigNum);
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
    const ret = await HaskellShelley.redeemerNew(tagPtr, indexPtr, dataPtr, ex_unitsPtr);
    return Ptr._wrap(ret, Redeemer);
  }

}


export class RedeemerTag extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.redeemerTagToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.redeemerTagFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_hex() {
    const ret = await HaskellShelley.redeemerTagToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.redeemerTagFromHex(hex_str);
    return Ptr._wrap(ret, RedeemerTag);
  }

  async to_json() {
    const ret = await HaskellShelley.redeemerTagToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.redeemerTagFromJson(json);
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_spend() {
    const ret = await HaskellShelley.redeemerTagNewSpend();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_mint() {
    const ret = await HaskellShelley.redeemerTagNewMint();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_cert() {
    const ret = await HaskellShelley.redeemerTagNewCert();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_reward() {
    const ret = await HaskellShelley.redeemerTagNewReward();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_vote() {
    const ret = await HaskellShelley.redeemerTagNewVote();
    return Ptr._wrap(ret, RedeemerTag);
  }

  static async new_voting_proposal() {
    const ret = await HaskellShelley.redeemerTagNewVotingProposal();
    return Ptr._wrap(ret, RedeemerTag);
  }

  async kind() {
    const ret = await HaskellShelley.redeemerTagKind(this.ptr);
    return ret;
  }

}


export class Redeemers extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.redeemersToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.redeemersFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Redeemers);
  }

  async to_hex() {
    const ret = await HaskellShelley.redeemersToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.redeemersFromHex(hex_str);
    return Ptr._wrap(ret, Redeemers);
  }

  async to_json() {
    const ret = await HaskellShelley.redeemersToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.redeemersFromJson(json);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.redeemersNew();
    return Ptr._wrap(ret, Redeemers);
  }

  static async new_with_serialization_format(redeemers, serialization_format) {
    throw new Error('The function is broken. It will be removed in the next version.');
  }

  async len() {
    const ret = await HaskellShelley.redeemersLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.redeemersGet(this.ptr, index);
    return Ptr._wrap(ret, Redeemer);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Redeemer);
    const ret = HaskellShelley.redeemersAdd(this.ptr, elemPtr);
    return ret;
  }

  async total_ex_units() {
    const ret = await HaskellShelley.redeemersTotalExUnits(this.ptr);
    return Ptr._wrap(ret, ExUnits);
  }

}


export class Relay extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.relayToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.relayFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relay);
  }

  async to_hex() {
    const ret = await HaskellShelley.relayToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.relayFromHex(hex_str);
    return Ptr._wrap(ret, Relay);
  }

  async to_json() {
    const ret = await HaskellShelley.relayToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.relayFromJson(json);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_addr(single_host_addr) {
    const single_host_addrPtr = Ptr._assertClass(single_host_addr, SingleHostAddr);
    const ret = await HaskellShelley.relayNewSingleHostAddr(single_host_addrPtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_single_host_name(single_host_name) {
    const single_host_namePtr = Ptr._assertClass(single_host_name, SingleHostName);
    const ret = await HaskellShelley.relayNewSingleHostName(single_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  static async new_multi_host_name(multi_host_name) {
    const multi_host_namePtr = Ptr._assertClass(multi_host_name, MultiHostName);
    const ret = await HaskellShelley.relayNewMultiHostName(multi_host_namePtr);
    return Ptr._wrap(ret, Relay);
  }

  async kind() {
    const ret = await HaskellShelley.relayKind(this.ptr);
    return ret;
  }

  async as_single_host_addr() {
    const ret = await HaskellShelley.relayAsSingleHostAddr(this.ptr);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async as_single_host_name() {
    const ret = await HaskellShelley.relayAsSingleHostName(this.ptr);
    return Ptr._wrap(ret, SingleHostName);
  }

  async as_multi_host_name() {
    const ret = await HaskellShelley.relayAsMultiHostName(this.ptr);
    return Ptr._wrap(ret, MultiHostName);
  }

}


export class Relays extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.relaysToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.relaysFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Relays);
  }

  async to_hex() {
    const ret = await HaskellShelley.relaysToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.relaysFromHex(hex_str);
    return Ptr._wrap(ret, Relays);
  }

  async to_json() {
    const ret = await HaskellShelley.relaysToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.relaysFromJson(json);
    return Ptr._wrap(ret, Relays);
  }

  static async new() {
    const ret = await HaskellShelley.relaysNew();
    return Ptr._wrap(ret, Relays);
  }

  async len() {
    const ret = await HaskellShelley.relaysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.relaysGet(this.ptr, index);
    return Ptr._wrap(ret, Relay);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Relay);
    const ret = HaskellShelley.relaysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class RewardAddress extends Ptr {
  static async new(network, payment) {
    const paymentPtr = Ptr._assertClass(payment, Credential);
    const ret = await HaskellShelley.rewardAddressNew(network, paymentPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async payment_cred() {
    const ret = await HaskellShelley.rewardAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_address() {
    const ret = await HaskellShelley.rewardAddressToAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  static async from_address(addr) {
    const addrPtr = Ptr._assertClass(addr, Address);
    const ret = await HaskellShelley.rewardAddressFromAddress(addrPtr);
    return Ptr._wrap(ret, RewardAddress);
  }

}


export class RewardAddresses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.rewardAddressesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.rewardAddressesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_hex() {
    const ret = await HaskellShelley.rewardAddressesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.rewardAddressesFromHex(hex_str);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async to_json() {
    const ret = await HaskellShelley.rewardAddressesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.rewardAddressesFromJson(json);
    return Ptr._wrap(ret, RewardAddresses);
  }

  static async new() {
    const ret = await HaskellShelley.rewardAddressesNew();
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await HaskellShelley.rewardAddressesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.rewardAddressesGet(this.ptr, index);
    return Ptr._wrap(ret, RewardAddress);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, RewardAddress);
    const ret = HaskellShelley.rewardAddressesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptAll extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptAllToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptAllFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptAllToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptAllFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAll);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptAllToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptAllFromJson(json);
    return Ptr._wrap(ret, ScriptAll);
  }

  async native_scripts() {
    const ret = await HaskellShelley.scriptAllNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.scriptAllNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAll);
  }

}


export class ScriptAny extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptAnyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptAnyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptAnyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptAnyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptAny);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptAnyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptAnyFromJson(json);
    return Ptr._wrap(ret, ScriptAny);
  }

  async native_scripts() {
    const ret = await HaskellShelley.scriptAnyNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.scriptAnyNew(native_scriptsPtr);
    return Ptr._wrap(ret, ScriptAny);
  }

}


export class ScriptDataHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptDataHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.scriptDataHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.scriptDataHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.scriptDataHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptDataHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.scriptDataHashFromHex(hex);
    return Ptr._wrap(ret, ScriptDataHash);
  }

}


export class ScriptHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.scriptHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.scriptHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.scriptHashFromBech32(bech_str);
    return Ptr._wrap(ret, ScriptHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.scriptHashFromHex(hex);
    return Ptr._wrap(ret, ScriptHash);
  }

}


export class ScriptHashes extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptHashesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptHashesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptHashesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptHashesFromHex(hex_str);
    return Ptr._wrap(ret, ScriptHashes);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptHashesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptHashesFromJson(json);
    return Ptr._wrap(ret, ScriptHashes);
  }

  static async new() {
    const ret = await HaskellShelley.scriptHashesNew();
    return Ptr._wrap(ret, ScriptHashes);
  }

  async len() {
    const ret = await HaskellShelley.scriptHashesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.scriptHashesGet(this.ptr, index);
    return Ptr._wrap(ret, ScriptHash);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, ScriptHash);
    const ret = HaskellShelley.scriptHashesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class ScriptNOfK extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptNOfKToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptNOfKFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptNOfKToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptNOfKFromHex(hex_str);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptNOfKToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptNOfKFromJson(json);
    return Ptr._wrap(ret, ScriptNOfK);
  }

  async n() {
    const ret = await HaskellShelley.scriptNOfKN(this.ptr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.scriptNOfKNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  static async new(n, native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = await HaskellShelley.scriptNOfKNew(n, native_scriptsPtr);
    return Ptr._wrap(ret, ScriptNOfK);
  }

}


export class ScriptPubkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptPubkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptPubkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptPubkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptPubkeyFromHex(hex_str);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptPubkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptPubkeyFromJson(json);
    return Ptr._wrap(ret, ScriptPubkey);
  }

  async addr_keyhash() {
    const ret = await HaskellShelley.scriptPubkeyAddrKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(addr_keyhash) {
    const addr_keyhashPtr = Ptr._assertClass(addr_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.scriptPubkeyNew(addr_keyhashPtr);
    return Ptr._wrap(ret, ScriptPubkey);
  }

}


export class ScriptRef extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.scriptRefToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.scriptRefFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_hex() {
    const ret = await HaskellShelley.scriptRefToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.scriptRefFromHex(hex_str);
    return Ptr._wrap(ret, ScriptRef);
  }

  async to_json() {
    const ret = await HaskellShelley.scriptRefToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.scriptRefFromJson(json);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_native_script(native_script) {
    const native_scriptPtr = Ptr._assertClass(native_script, NativeScript);
    const ret = await HaskellShelley.scriptRefNewNativeScript(native_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  static async new_plutus_script(plutus_script) {
    const plutus_scriptPtr = Ptr._assertClass(plutus_script, PlutusScript);
    const ret = await HaskellShelley.scriptRefNewPlutusScript(plutus_scriptPtr);
    return Ptr._wrap(ret, ScriptRef);
  }

  async is_native_script() {
    const ret = await HaskellShelley.scriptRefIsNativeScript(this.ptr);
    return ret;
  }

  async is_plutus_script() {
    const ret = await HaskellShelley.scriptRefIsPlutusScript(this.ptr);
    return ret;
  }

  async native_script() {
    const ret = await HaskellShelley.scriptRefNativeScript(this.ptr);
    return Ptr._wrap(ret, NativeScript);
  }

  async plutus_script() {
    const ret = await HaskellShelley.scriptRefPlutusScript(this.ptr);
    return Ptr._wrap(ret, PlutusScript);
  }

}


export class SingleHostAddr extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.singleHostAddrToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.singleHostAddrFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_hex() {
    const ret = await HaskellShelley.singleHostAddrToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.singleHostAddrFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async to_json() {
    const ret = await HaskellShelley.singleHostAddrToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.singleHostAddrFromJson(json);
    return Ptr._wrap(ret, SingleHostAddr);
  }

  async port() {
    const ret = await HaskellShelley.singleHostAddrPort(this.ptr);
    return ret;
  }

  async ipv4() {
    const ret = await HaskellShelley.singleHostAddrIpv4(this.ptr);
    return Ptr._wrap(ret, Ipv4);
  }

  async ipv6() {
    const ret = await HaskellShelley.singleHostAddrIpv6(this.ptr);
    return Ptr._wrap(ret, Ipv6);
  }

  static async new(port, ipv4, ipv6) {
    const ipv4Ptr = Ptr._assertOptionalClass(ipv4, Ipv4);
    const ipv6Ptr = Ptr._assertOptionalClass(ipv6, Ipv6);
    if(port == null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.singleHostAddrNew();
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 == null) {
      const ret = await HaskellShelley.singleHostAddrNewWithPort(port);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.singleHostAddrNewWithIpv4(ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 == null) {
      const ret = await HaskellShelley.singleHostAddrNewWithPortIpv4(port, ipv4Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.singleHostAddrNewWithIpv6(ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 == null && ipv6 != null) {
      const ret = await HaskellShelley.singleHostAddrNewWithPortIpv6(port, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port == null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.singleHostAddrNewWithIpv4Ipv6(ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
    if(port != null && ipv4 != null && ipv6 != null) {
      const ret = await HaskellShelley.singleHostAddrNewWithPortIpv4Ipv6(port, ipv4Ptr, ipv6Ptr);
      return Ptr._wrap(ret, SingleHostAddr);
    }
  }

}


export class SingleHostName extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.singleHostNameToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.singleHostNameFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_hex() {
    const ret = await HaskellShelley.singleHostNameToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.singleHostNameFromHex(hex_str);
    return Ptr._wrap(ret, SingleHostName);
  }

  async to_json() {
    const ret = await HaskellShelley.singleHostNameToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.singleHostNameFromJson(json);
    return Ptr._wrap(ret, SingleHostName);
  }

  async port() {
    const ret = await HaskellShelley.singleHostNamePort(this.ptr);
    return ret;
  }

  async dns_name() {
    const ret = await HaskellShelley.singleHostNameDnsName(this.ptr);
    return Ptr._wrap(ret, DNSRecordAorAAAA);
  }

  static async new(port, dns_name) {
    const dns_namePtr = Ptr._assertClass(dns_name, DNSRecordAorAAAA);
    if(port == null) {
      const ret = await HaskellShelley.singleHostNameNew(dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
    if(port != null) {
      const ret = await HaskellShelley.singleHostNameNewWithPort(port, dns_namePtr);
      return Ptr._wrap(ret, SingleHostName);
    }
  }

}


export class StakeAndVoteDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeAndVoteDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeAndVoteDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeAndVoteDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeAndVoteDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeAndVoteDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeAndVoteDelegationFromJson(json);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeAndVoteDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.stakeAndVoteDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async drep() {
    const ret = await HaskellShelley.stakeAndVoteDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  static async new(stake_credential, pool_keyhash, drep) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const ret = await HaskellShelley.stakeAndVoteDelegationNew(stake_credentialPtr, pool_keyhashPtr, drepPtr);
    return Ptr._wrap(ret, StakeAndVoteDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeAndVoteDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeDelegationFromJson(json);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.stakeDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  static async new(stake_credential, pool_keyhash) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const ret = await HaskellShelley.stakeDelegationNew(stake_credentialPtr, pool_keyhashPtr);
    return Ptr._wrap(ret, StakeDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeDeregistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeDeregistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeDeregistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeDeregistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeDeregistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeDeregistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeDeregistrationFromJson(json);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeDeregistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.stakeDeregistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const ret = await HaskellShelley.stakeDeregistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  static async new_with_coin(stake_credential, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.stakeDeregistrationNewWithCoin(stake_credentialPtr, coinPtr);
    return Ptr._wrap(ret, StakeDeregistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeDeregistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeRegistration extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeRegistrationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeRegistrationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeRegistrationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeRegistrationFromHex(hex_str);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeRegistrationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeRegistrationFromJson(json);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeRegistrationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async coin() {
    const ret = await HaskellShelley.stakeRegistrationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const ret = await HaskellShelley.stakeRegistrationNew(stake_credentialPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  static async new_with_coin(stake_credential, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.stakeRegistrationNewWithCoin(stake_credentialPtr, coinPtr);
    return Ptr._wrap(ret, StakeRegistration);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeRegistrationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async coin() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, pool_keyhash, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.stakeRegistrationAndDelegationNew(stake_credentialPtr, pool_keyhashPtr, coinPtr);
    return Ptr._wrap(ret, StakeRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class StakeVoteRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async pool_keyhash() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationPoolKeyhash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async drep() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  async coin() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, pool_keyhash, drep, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const pool_keyhashPtr = Ptr._assertClass(pool_keyhash, Ed25519KeyHash);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationNew(stake_credentialPtr, pool_keyhashPtr, drepPtr, coinPtr);
    return Ptr._wrap(ret, StakeVoteRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.stakeVoteRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Strings extends Ptr {
  static async new() {
    const ret = await HaskellShelley.stringsNew();
    return Ptr._wrap(ret, Strings);
  }

  async len() {
    const ret = await HaskellShelley.stringsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.stringsGet(this.ptr, index);
    return ret;
  }

  add(elem) {
    const ret = HaskellShelley.stringsAdd(this.ptr, elem);
    return ret;
  }

}


export class TimelockExpiry extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.timelockExpiryToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.timelockExpiryFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_hex() {
    const ret = await HaskellShelley.timelockExpiryToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.timelockExpiryFromHex(hex_str);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async to_json() {
    const ret = await HaskellShelley.timelockExpiryToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.timelockExpiryFromJson(json);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  async slot() {
    const ret = await HaskellShelley.timelockExpirySlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.timelockExpirySlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.timelockExpiryNew(slot);
    return Ptr._wrap(ret, TimelockExpiry);
  }

  static async new_timelockexpiry(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.timelockExpiryNewTimelockexpiry(slotPtr);
    return Ptr._wrap(ret, TimelockExpiry);
  }

}


export class TimelockStart extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.timelockStartToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.timelockStartFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_hex() {
    const ret = await HaskellShelley.timelockStartToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.timelockStartFromHex(hex_str);
    return Ptr._wrap(ret, TimelockStart);
  }

  async to_json() {
    const ret = await HaskellShelley.timelockStartToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.timelockStartFromJson(json);
    return Ptr._wrap(ret, TimelockStart);
  }

  async slot() {
    const ret = await HaskellShelley.timelockStartSlot(this.ptr);
    return ret;
  }

  async slot_bignum() {
    const ret = await HaskellShelley.timelockStartSlotBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(slot) {
    const ret = await HaskellShelley.timelockStartNew(slot);
    return Ptr._wrap(ret, TimelockStart);
  }

  static async new_timelockstart(slot) {
    const slotPtr = Ptr._assertClass(slot, BigNum);
    const ret = await HaskellShelley.timelockStartNewTimelockstart(slotPtr);
    return Ptr._wrap(ret, TimelockStart);
  }

}


export class Transaction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Transaction);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionFromHex(hex_str);
    return Ptr._wrap(ret, Transaction);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionFromJson(json);
    return Ptr._wrap(ret, Transaction);
  }

  async body() {
    const ret = await HaskellShelley.transactionBody(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async witness_set() {
    const ret = await HaskellShelley.transactionWitnessSet(this.ptr);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async is_valid() {
    const ret = await HaskellShelley.transactionIsValid(this.ptr);
    return ret;
  }

  async auxiliary_data() {
    const ret = await HaskellShelley.transactionAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_is_valid(valid) {
    const ret = HaskellShelley.transactionSetIsValid(this.ptr, valid);
    return ret;
  }

  static async new(body, witness_set, auxiliary_data) {
    const bodyPtr = Ptr._assertClass(body, TransactionBody);
    const witness_setPtr = Ptr._assertClass(witness_set, TransactionWitnessSet);
    const auxiliary_dataPtr = Ptr._assertOptionalClass(auxiliary_data, AuxiliaryData);
    if(auxiliary_data == null) {
      const ret = await HaskellShelley.transactionNew(bodyPtr, witness_setPtr);
      return Ptr._wrap(ret, Transaction);
    }
    if(auxiliary_data != null) {
      const ret = await HaskellShelley.transactionNewWithAuxiliaryData(bodyPtr, witness_setPtr, auxiliary_dataPtr);
      return Ptr._wrap(ret, Transaction);
    }
  }

}


export class TransactionBatch extends Ptr {
  async len() {
    const ret = await HaskellShelley.transactionBatchLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionBatchGet(this.ptr, index);
    return Ptr._wrap(ret, Transaction);
  }

}


export class TransactionBatchList extends Ptr {
  async len() {
    const ret = await HaskellShelley.transactionBatchListLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionBatchListGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBatch);
  }

}


export class TransactionBodies extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionBodiesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionBodiesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionBodiesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionBodiesFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBodies);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionBodiesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionBodiesFromJson(json);
    return Ptr._wrap(ret, TransactionBodies);
  }

  static async new() {
    const ret = await HaskellShelley.transactionBodiesNew();
    return Ptr._wrap(ret, TransactionBodies);
  }

  async len() {
    const ret = await HaskellShelley.transactionBodiesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionBodiesGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionBody);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionBody);
    const ret = HaskellShelley.transactionBodiesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionBody extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionBodyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionBodyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionBodyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionBodyFromHex(hex_str);
    return Ptr._wrap(ret, TransactionBody);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionBodyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionBodyFromJson(json);
    return Ptr._wrap(ret, TransactionBody);
  }

  async inputs() {
    const ret = await HaskellShelley.transactionBodyInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async outputs() {
    const ret = await HaskellShelley.transactionBodyOutputs(this.ptr);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async fee() {
    const ret = await HaskellShelley.transactionBodyFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async ttl() {
    const ret = await HaskellShelley.transactionBodyTtl(this.ptr);
    return ret;
  }

  async ttl_bignum() {
    const ret = await HaskellShelley.transactionBodyTtlBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_ttl(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.transactionBodySetTtl(this.ptr, ttlPtr);
    return ret;
  }

  remove_ttl() {
    const ret = HaskellShelley.transactionBodyRemoveTtl(this.ptr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.transactionBodySetCerts(this.ptr, certsPtr);
    return ret;
  }

  async certs() {
    const ret = await HaskellShelley.transactionBodyCerts(this.ptr);
    return Ptr._wrap(ret, Certificates);
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.transactionBodySetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  async withdrawals() {
    const ret = await HaskellShelley.transactionBodyWithdrawals(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

  set_update(update) {
    const updatePtr = Ptr._assertClass(update, Update);
    const ret = HaskellShelley.transactionBodySetUpdate(this.ptr, updatePtr);
    return ret;
  }

  async update() {
    const ret = await HaskellShelley.transactionBodyUpdate(this.ptr);
    return Ptr._wrap(ret, Update);
  }

  set_auxiliary_data_hash(auxiliary_data_hash) {
    const auxiliary_data_hashPtr = Ptr._assertClass(auxiliary_data_hash, AuxiliaryDataHash);
    const ret = HaskellShelley.transactionBodySetAuxiliaryDataHash(this.ptr, auxiliary_data_hashPtr);
    return ret;
  }

  async auxiliary_data_hash() {
    const ret = await HaskellShelley.transactionBodyAuxiliaryDataHash(this.ptr);
    return Ptr._wrap(ret, AuxiliaryDataHash);
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.transactionBodySetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.transactionBodySetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  async validity_start_interval_bignum() {
    const ret = await HaskellShelley.transactionBodyValidityStartIntervalBignum(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async validity_start_interval() {
    const ret = await HaskellShelley.transactionBodyValidityStartInterval(this.ptr);
    return ret;
  }

  set_mint(mint) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const ret = HaskellShelley.transactionBodySetMint(this.ptr, mintPtr);
    return ret;
  }

  async mint() {
    const ret = await HaskellShelley.transactionBodyMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  set_reference_inputs(reference_inputs) {
    const reference_inputsPtr = Ptr._assertClass(reference_inputs, TransactionInputs);
    const ret = HaskellShelley.transactionBodySetReferenceInputs(this.ptr, reference_inputsPtr);
    return ret;
  }

  async reference_inputs() {
    const ret = await HaskellShelley.transactionBodyReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_script_data_hash(script_data_hash) {
    const script_data_hashPtr = Ptr._assertClass(script_data_hash, ScriptDataHash);
    const ret = HaskellShelley.transactionBodySetScriptDataHash(this.ptr, script_data_hashPtr);
    return ret;
  }

  async script_data_hash() {
    const ret = await HaskellShelley.transactionBodyScriptDataHash(this.ptr);
    return Ptr._wrap(ret, ScriptDataHash);
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TransactionInputs);
    const ret = HaskellShelley.transactionBodySetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  async collateral() {
    const ret = await HaskellShelley.transactionBodyCollateral(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  set_required_signers(required_signers) {
    const required_signersPtr = Ptr._assertClass(required_signers, Ed25519KeyHashes);
    const ret = HaskellShelley.transactionBodySetRequiredSigners(this.ptr, required_signersPtr);
    return ret;
  }

  async required_signers() {
    const ret = await HaskellShelley.transactionBodyRequiredSigners(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHashes);
  }

  set_network_id(network_id) {
    const network_idPtr = Ptr._assertClass(network_id, NetworkId);
    const ret = HaskellShelley.transactionBodySetNetworkId(this.ptr, network_idPtr);
    return ret;
  }

  async network_id() {
    const ret = await HaskellShelley.transactionBodyNetworkId(this.ptr);
    return Ptr._wrap(ret, NetworkId);
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.transactionBodySetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  async collateral_return() {
    const ret = await HaskellShelley.transactionBodyCollateralReturn(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.transactionBodySetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  async total_collateral() {
    const ret = await HaskellShelley.transactionBodyTotalCollateral(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_voting_procedures(voting_procedures) {
    const voting_proceduresPtr = Ptr._assertClass(voting_procedures, VotingProcedures);
    const ret = HaskellShelley.transactionBodySetVotingProcedures(this.ptr, voting_proceduresPtr);
    return ret;
  }

  async voting_procedures() {
    const ret = await HaskellShelley.transactionBodyVotingProcedures(this.ptr);
    return Ptr._wrap(ret, VotingProcedures);
  }

  set_voting_proposals(voting_proposals) {
    const voting_proposalsPtr = Ptr._assertClass(voting_proposals, VotingProposals);
    const ret = HaskellShelley.transactionBodySetVotingProposals(this.ptr, voting_proposalsPtr);
    return ret;
  }

  async voting_proposals() {
    const ret = await HaskellShelley.transactionBodyVotingProposals(this.ptr);
    return Ptr._wrap(ret, VotingProposals);
  }

  set_donation(donation) {
    const donationPtr = Ptr._assertClass(donation, BigNum);
    const ret = HaskellShelley.transactionBodySetDonation(this.ptr, donationPtr);
    return ret;
  }

  async donation() {
    const ret = await HaskellShelley.transactionBodyDonation(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_current_treasury_value(current_treasury_value) {
    const current_treasury_valuePtr = Ptr._assertClass(current_treasury_value, BigNum);
    const ret = HaskellShelley.transactionBodySetCurrentTreasuryValue(this.ptr, current_treasury_valuePtr);
    return ret;
  }

  async current_treasury_value() {
    const ret = await HaskellShelley.transactionBodyCurrentTreasuryValue(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(inputs, outputs, fee, ttl) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    if(ttl == null) {
      const ret = await HaskellShelley.transactionBodyNew(inputsPtr, outputsPtr, feePtr);
      return Ptr._wrap(ret, TransactionBody);
    }
    if(ttl != null) {
      const ret = await HaskellShelley.transactionBodyNewWithTtl(inputsPtr, outputsPtr, feePtr, ttl);
      return Ptr._wrap(ret, TransactionBody);
    }
  }

  static async new_tx_body(inputs, outputs, fee) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionInputs);
    const outputsPtr = Ptr._assertClass(outputs, TransactionOutputs);
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = await HaskellShelley.transactionBodyNewTxBody(inputsPtr, outputsPtr, feePtr);
    return Ptr._wrap(ret, TransactionBody);
  }

}


export class TransactionBuilder extends Ptr {
  add_inputs_from(inputs, strategy) {
    const inputsPtr = Ptr._assertClass(inputs, TransactionUnspentOutputs);
    const ret = HaskellShelley.transactionBuilderAddInputsFrom(this.ptr, inputsPtr, strategy);
    return ret;
  }

  set_inputs(inputs) {
    const inputsPtr = Ptr._assertClass(inputs, TxInputsBuilder);
    const ret = HaskellShelley.transactionBuilderSetInputs(this.ptr, inputsPtr);
    return ret;
  }

  set_collateral(collateral) {
    const collateralPtr = Ptr._assertClass(collateral, TxInputsBuilder);
    const ret = HaskellShelley.transactionBuilderSetCollateral(this.ptr, collateralPtr);
    return ret;
  }

  set_collateral_return(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.transactionBuilderSetCollateralReturn(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_collateral_return_and_total(collateral_return) {
    const collateral_returnPtr = Ptr._assertClass(collateral_return, TransactionOutput);
    const ret = HaskellShelley.transactionBuilderSetCollateralReturnAndTotal(this.ptr, collateral_returnPtr);
    return ret;
  }

  set_total_collateral(total_collateral) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const ret = HaskellShelley.transactionBuilderSetTotalCollateral(this.ptr, total_collateralPtr);
    return ret;
  }

  set_total_collateral_and_return(total_collateral, return_address) {
    const total_collateralPtr = Ptr._assertClass(total_collateral, BigNum);
    const return_addressPtr = Ptr._assertClass(return_address, Address);
    const ret = HaskellShelley.transactionBuilderSetTotalCollateralAndReturn(this.ptr, total_collateralPtr, return_addressPtr);
    return ret;
  }

  add_reference_input(reference_input) {
    const reference_inputPtr = Ptr._assertClass(reference_input, TransactionInput);
    const ret = HaskellShelley.transactionBuilderAddReferenceInput(this.ptr, reference_inputPtr);
    return ret;
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.transactionBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.transactionBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.transactionBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.transactionBuilderAddBootstrapInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_regular_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.transactionBuilderAddRegularInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.transactionBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.transactionBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async fee_for_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.transactionBuilderFeeForInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return Ptr._wrap(ret, BigNum);
  }

  add_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = HaskellShelley.transactionBuilderAddOutput(this.ptr, outputPtr);
    return ret;
  }

  async fee_for_output(output) {
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.transactionBuilderFeeForOutput(this.ptr, outputPtr);
    return Ptr._wrap(ret, BigNum);
  }

  set_fee(fee) {
    const feePtr = Ptr._assertClass(fee, BigNum);
    const ret = HaskellShelley.transactionBuilderSetFee(this.ptr, feePtr);
    return ret;
  }

  set_ttl(ttl) {
    const ret = HaskellShelley.transactionBuilderSetTtl(this.ptr, ttl);
    return ret;
  }

  set_ttl_bignum(ttl) {
    const ttlPtr = Ptr._assertClass(ttl, BigNum);
    const ret = HaskellShelley.transactionBuilderSetTtlBignum(this.ptr, ttlPtr);
    return ret;
  }

  set_validity_start_interval(validity_start_interval) {
    const ret = HaskellShelley.transactionBuilderSetValidityStartInterval(this.ptr, validity_start_interval);
    return ret;
  }

  set_validity_start_interval_bignum(validity_start_interval) {
    const validity_start_intervalPtr = Ptr._assertClass(validity_start_interval, BigNum);
    const ret = HaskellShelley.transactionBuilderSetValidityStartIntervalBignum(this.ptr, validity_start_intervalPtr);
    return ret;
  }

  set_certs(certs) {
    const certsPtr = Ptr._assertClass(certs, Certificates);
    const ret = HaskellShelley.transactionBuilderSetCerts(this.ptr, certsPtr);
    return ret;
  }

  set_certs_builder(certs) {
    const certsPtr = Ptr._assertClass(certs, CertificatesBuilder);
    const ret = HaskellShelley.transactionBuilderSetCertsBuilder(this.ptr, certsPtr);
    return ret;
  }

  set_withdrawals(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, Withdrawals);
    const ret = HaskellShelley.transactionBuilderSetWithdrawals(this.ptr, withdrawalsPtr);
    return ret;
  }

  set_withdrawals_builder(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, WithdrawalsBuilder);
    const ret = HaskellShelley.transactionBuilderSetWithdrawalsBuilder(this.ptr, withdrawalsPtr);
    return ret;
  }

  set_voting_builder(voting_builder) {
    const voting_builderPtr = Ptr._assertClass(voting_builder, VotingBuilder);
    const ret = HaskellShelley.transactionBuilderSetVotingBuilder(this.ptr, voting_builderPtr);
    return ret;
  }

  set_voting_proposal_builder(voting_proposal_builder) {
    const voting_proposal_builderPtr = Ptr._assertClass(voting_proposal_builder, VotingProposalBuilder);
    const ret = HaskellShelley.transactionBuilderSetVotingProposalBuilder(this.ptr, voting_proposal_builderPtr);
    return ret;
  }

  async get_auxiliary_data() {
    const ret = await HaskellShelley.transactionBuilderGetAuxiliaryData(this.ptr);
    return Ptr._wrap(ret, AuxiliaryData);
  }

  set_auxiliary_data(auxiliary_data) {
    const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
    const ret = HaskellShelley.transactionBuilderSetAuxiliaryData(this.ptr, auxiliary_dataPtr);
    return ret;
  }

  set_metadata(metadata) {
    const metadataPtr = Ptr._assertClass(metadata, GeneralTransactionMetadata);
    const ret = HaskellShelley.transactionBuilderSetMetadata(this.ptr, metadataPtr);
    return ret;
  }

  add_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const valPtr = Ptr._assertClass(val, TransactionMetadatum);
    const ret = HaskellShelley.transactionBuilderAddMetadatum(this.ptr, keyPtr, valPtr);
    return ret;
  }

  add_json_metadatum(key, val) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.transactionBuilderAddJsonMetadatum(this.ptr, keyPtr, val);
    return ret;
  }

  add_json_metadatum_with_schema(key, val, schema) {
    const keyPtr = Ptr._assertClass(key, BigNum);
    const ret = HaskellShelley.transactionBuilderAddJsonMetadatumWithSchema(this.ptr, keyPtr, val, schema);
    return ret;
  }

  set_mint_builder(mint_builder) {
    const mint_builderPtr = Ptr._assertClass(mint_builder, MintBuilder);
    const ret = HaskellShelley.transactionBuilderSetMintBuilder(this.ptr, mint_builderPtr);
    return ret;
  }

  async get_mint_builder() {
    const ret = await HaskellShelley.transactionBuilderGetMintBuilder(this.ptr);
    return Ptr._wrap(ret, MintBuilder);
  }

  set_mint(mint, mint_scripts) {
    const mintPtr = Ptr._assertClass(mint, Mint);
    const mint_scriptsPtr = Ptr._assertClass(mint_scripts, NativeScripts);
    const ret = HaskellShelley.transactionBuilderSetMint(this.ptr, mintPtr, mint_scriptsPtr);
    return ret;
  }

  async get_mint() {
    const ret = await HaskellShelley.transactionBuilderGetMint(this.ptr);
    return Ptr._wrap(ret, Mint);
  }

  async get_mint_scripts() {
    const ret = await HaskellShelley.transactionBuilderGetMintScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_mint_asset(policy_script, mint_assets) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const mint_assetsPtr = Ptr._assertClass(mint_assets, MintAssets);
    const ret = HaskellShelley.transactionBuilderSetMintAsset(this.ptr, policy_scriptPtr, mint_assetsPtr);
    return ret;
  }

  add_mint_asset(policy_script, asset_name, amount) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const ret = HaskellShelley.transactionBuilderAddMintAsset(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr);
    return ret;
  }

  add_mint_asset_and_output(policy_script, asset_name, amount, output_builder, output_coin) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const output_coinPtr = Ptr._assertClass(output_coin, BigNum);
    const ret = HaskellShelley.transactionBuilderAddMintAssetAndOutput(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr, output_coinPtr);
    return ret;
  }

  add_mint_asset_and_output_min_required_coin(policy_script, asset_name, amount, output_builder) {
    const policy_scriptPtr = Ptr._assertClass(policy_script, NativeScript);
    const asset_namePtr = Ptr._assertClass(asset_name, AssetName);
    const amountPtr = Ptr._assertClass(amount, Int);
    const output_builderPtr = Ptr._assertClass(output_builder, TransactionOutputAmountBuilder);
    const ret = HaskellShelley.transactionBuilderAddMintAssetAndOutputMinRequiredCoin(this.ptr, policy_scriptPtr, asset_namePtr, amountPtr, output_builderPtr);
    return ret;
  }

  add_extra_witness_datum(datum) {
    const datumPtr = Ptr._assertClass(datum, PlutusData);
    const ret = HaskellShelley.transactionBuilderAddExtraWitnessDatum(this.ptr, datumPtr);
    return ret;
  }

  async get_extra_witness_datums() {
    const ret = await HaskellShelley.transactionBuilderGetExtraWitnessDatums(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_donation(donation) {
    const donationPtr = Ptr._assertClass(donation, BigNum);
    const ret = HaskellShelley.transactionBuilderSetDonation(this.ptr, donationPtr);
    return ret;
  }

  async get_donation() {
    const ret = await HaskellShelley.transactionBuilderGetDonation(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_current_treasury_value(current_treasury_value) {
    const current_treasury_valuePtr = Ptr._assertClass(current_treasury_value, BigNum);
    const ret = HaskellShelley.transactionBuilderSetCurrentTreasuryValue(this.ptr, current_treasury_valuePtr);
    return ret;
  }

  async get_current_treasury_value() {
    const ret = await HaskellShelley.transactionBuilderGetCurrentTreasuryValue(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(cfg) {
    const cfgPtr = Ptr._assertClass(cfg, TransactionBuilderConfig);
    const ret = await HaskellShelley.transactionBuilderNew(cfgPtr);
    return Ptr._wrap(ret, TransactionBuilder);
  }

  async get_reference_inputs() {
    const ret = await HaskellShelley.transactionBuilderGetReferenceInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_explicit_input() {
    const ret = await HaskellShelley.transactionBuilderGetExplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_implicit_input() {
    const ret = await HaskellShelley.transactionBuilderGetImplicitInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_input() {
    const ret = await HaskellShelley.transactionBuilderGetTotalInput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_total_output() {
    const ret = await HaskellShelley.transactionBuilderGetTotalOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_explicit_output() {
    const ret = await HaskellShelley.transactionBuilderGetExplicitOutput(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async get_deposit() {
    const ret = await HaskellShelley.transactionBuilderGetDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async get_fee_if_set() {
    const ret = await HaskellShelley.transactionBuilderGetFeeIfSet(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async add_change_if_needed(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.transactionBuilderAddChangeIfNeeded(this.ptr, addressPtr);
    return ret;
  }

  async add_change_if_needed_with_datum(address, plutus_data) {
    const addressPtr = Ptr._assertClass(address, Address);
    const plutus_dataPtr = Ptr._assertClass(plutus_data, OutputDatum);
    const ret = await HaskellShelley.transactionBuilderAddChangeIfNeededWithDatum(this.ptr, addressPtr, plutus_dataPtr);
    return ret;
  }

  calc_script_data_hash(cost_models) {
    const cost_modelsPtr = Ptr._assertClass(cost_models, Costmdls);
    const ret = HaskellShelley.transactionBuilderCalcScriptDataHash(this.ptr, cost_modelsPtr);
    return ret;
  }

  set_script_data_hash(hash) {
    const hashPtr = Ptr._assertClass(hash, ScriptDataHash);
    const ret = HaskellShelley.transactionBuilderSetScriptDataHash(this.ptr, hashPtr);
    return ret;
  }

  remove_script_data_hash() {
    const ret = HaskellShelley.transactionBuilderRemoveScriptDataHash(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.transactionBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  async full_size() {
    const ret = await HaskellShelley.transactionBuilderFullSize(this.ptr);
    return ret;
  }

  async output_sizes() {
    const ret = await HaskellShelley.transactionBuilderOutputSizes(this.ptr);
    return base64ToUint32Array(ret);
  }

  async build() {
    const ret = await HaskellShelley.transactionBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBody);
  }

  async build_tx() {
    const ret = await HaskellShelley.transactionBuilderBuildTx(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async build_tx_unsafe() {
    const ret = await HaskellShelley.transactionBuilderBuildTxUnsafe(this.ptr);
    return Ptr._wrap(ret, Transaction);
  }

  async min_fee() {
    const ret = await HaskellShelley.transactionBuilderMinFee(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

}


export class TransactionBuilderConfig extends Ptr {
}


export class TransactionBuilderConfigBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.transactionBuilderConfigBuilderNew();
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async fee_algo(fee_algo) {
    const fee_algoPtr = Ptr._assertClass(fee_algo, LinearFee);
    const ret = await HaskellShelley.transactionBuilderConfigBuilderFeeAlgo(this.ptr, fee_algoPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async coins_per_utxo_byte(coins_per_utxo_byte) {
    const coins_per_utxo_bytePtr = Ptr._assertClass(coins_per_utxo_byte, BigNum);
    const ret = await HaskellShelley.transactionBuilderConfigBuilderCoinsPerUtxoByte(this.ptr, coins_per_utxo_bytePtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async ex_unit_prices(ex_unit_prices) {
    const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
    const ret = await HaskellShelley.transactionBuilderConfigBuilderExUnitPrices(this.ptr, ex_unit_pricesPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async pool_deposit(pool_deposit) {
    const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
    const ret = await HaskellShelley.transactionBuilderConfigBuilderPoolDeposit(this.ptr, pool_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async key_deposit(key_deposit) {
    const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
    const ret = await HaskellShelley.transactionBuilderConfigBuilderKeyDeposit(this.ptr, key_depositPtr);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_value_size(max_value_size) {
    const ret = await HaskellShelley.transactionBuilderConfigBuilderMaxValueSize(this.ptr, max_value_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async max_tx_size(max_tx_size) {
    const ret = await HaskellShelley.transactionBuilderConfigBuilderMaxTxSize(this.ptr, max_tx_size);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async prefer_pure_change(prefer_pure_change) {
    const ret = await HaskellShelley.transactionBuilderConfigBuilderPreferPureChange(this.ptr, prefer_pure_change);
    return Ptr._wrap(ret, TransactionBuilderConfigBuilder);
  }

  async build() {
    const ret = await HaskellShelley.transactionBuilderConfigBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionBuilderConfig);
  }

}


export class TransactionHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.transactionHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.transactionHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.transactionHashFromBech32(bech_str);
    return Ptr._wrap(ret, TransactionHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.transactionHashFromHex(hex);
    return Ptr._wrap(ret, TransactionHash);
  }

}


export class TransactionInput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionInputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionInputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionInputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionInputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInput);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionInputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionInputFromJson(json);
    return Ptr._wrap(ret, TransactionInput);
  }

  async transaction_id() {
    const ret = await HaskellShelley.transactionInputTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  async index() {
    const ret = await HaskellShelley.transactionInputIndex(this.ptr);
    return ret;
  }

  static async new(transaction_id, index) {
    const transaction_idPtr = Ptr._assertClass(transaction_id, TransactionHash);
    const ret = await HaskellShelley.transactionInputNew(transaction_idPtr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

}


export class TransactionInputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionInputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionInputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionInputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionInputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionInputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionInputsFromJson(json);
    return Ptr._wrap(ret, TransactionInputs);
  }

  static async new() {
    const ret = await HaskellShelley.transactionInputsNew();
    return Ptr._wrap(ret, TransactionInputs);
  }

  async len() {
    const ret = await HaskellShelley.transactionInputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionInputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionInput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionInput);
    const ret = HaskellShelley.transactionInputsAdd(this.ptr, elemPtr);
    return ret;
  }

  async to_option() {
    const ret = await HaskellShelley.transactionInputsToOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class TransactionMetadatum extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionMetadatumToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionMetadatumFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionMetadatumToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionMetadatumFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_map(map) {
    const mapPtr = Ptr._assertClass(map, MetadataMap);
    const ret = await HaskellShelley.transactionMetadatumNewMap(mapPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_list(list) {
    const listPtr = Ptr._assertClass(list, MetadataList);
    const ret = await HaskellShelley.transactionMetadatumNewList(listPtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_int(int_value) {
    const int_valuePtr = Ptr._assertClass(int_value, Int);
    const ret = await HaskellShelley.transactionMetadatumNewInt(int_valuePtr);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_bytes(bytes) {
    const ret = await HaskellShelley.transactionMetadatumNewBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  static async new_text(text) {
    const ret = await HaskellShelley.transactionMetadatumNewText(text);
    return Ptr._wrap(ret, TransactionMetadatum);
  }

  async kind() {
    const ret = await HaskellShelley.transactionMetadatumKind(this.ptr);
    return ret;
  }

  async as_map() {
    const ret = await HaskellShelley.transactionMetadatumAsMap(this.ptr);
    return Ptr._wrap(ret, MetadataMap);
  }

  async as_list() {
    const ret = await HaskellShelley.transactionMetadatumAsList(this.ptr);
    return Ptr._wrap(ret, MetadataList);
  }

  async as_int() {
    const ret = await HaskellShelley.transactionMetadatumAsInt(this.ptr);
    return Ptr._wrap(ret, Int);
  }

  async as_bytes() {
    const ret = await HaskellShelley.transactionMetadatumAsBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async as_text() {
    const ret = await HaskellShelley.transactionMetadatumAsText(this.ptr);
    return ret;
  }

}


export class TransactionMetadatumLabels extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionMetadatumLabelsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionMetadatumLabelsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionMetadatumLabelsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionMetadatumLabelsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  static async new() {
    const ret = await HaskellShelley.transactionMetadatumLabelsNew();
    return Ptr._wrap(ret, TransactionMetadatumLabels);
  }

  async len() {
    const ret = await HaskellShelley.transactionMetadatumLabelsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionMetadatumLabelsGet(this.ptr, index);
    return Ptr._wrap(ret, BigNum);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, BigNum);
    const ret = HaskellShelley.transactionMetadatumLabelsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionOutputFromJson(json);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async address() {
    const ret = await HaskellShelley.transactionOutputAddress(this.ptr);
    return Ptr._wrap(ret, Address);
  }

  async amount() {
    const ret = await HaskellShelley.transactionOutputAmount(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async data_hash() {
    const ret = await HaskellShelley.transactionOutputDataHash(this.ptr);
    return Ptr._wrap(ret, DataHash);
  }

  async plutus_data() {
    const ret = await HaskellShelley.transactionOutputPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusData);
  }

  async script_ref() {
    const ret = await HaskellShelley.transactionOutputScriptRef(this.ptr);
    return Ptr._wrap(ret, ScriptRef);
  }

  set_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = HaskellShelley.transactionOutputSetScriptRef(this.ptr, script_refPtr);
    return ret;
  }

  set_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = HaskellShelley.transactionOutputSetPlutusData(this.ptr, dataPtr);
    return ret;
  }

  set_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = HaskellShelley.transactionOutputSetDataHash(this.ptr, data_hashPtr);
    return ret;
  }

  async has_plutus_data() {
    const ret = await HaskellShelley.transactionOutputHasPlutusData(this.ptr);
    return ret;
  }

  async has_data_hash() {
    const ret = await HaskellShelley.transactionOutputHasDataHash(this.ptr);
    return ret;
  }

  async has_script_ref() {
    const ret = await HaskellShelley.transactionOutputHasScriptRef(this.ptr);
    return ret;
  }

  static async new(address, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.transactionOutputNew(addressPtr, amountPtr);
    return Ptr._wrap(ret, TransactionOutput);
  }

  async serialization_format() {
    const ret = await HaskellShelley.transactionOutputSerializationFormat(this.ptr);
    return ret;
  }

}


export class TransactionOutputAmountBuilder extends Ptr {
  async with_value(amount) {
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = await HaskellShelley.transactionOutputAmountBuilderWithValue(this.ptr, amountPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.transactionOutputAmountBuilderWithCoin(this.ptr, coinPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_coin_and_asset(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.transactionOutputAmountBuilderWithCoinAndAsset(this.ptr, coinPtr, multiassetPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async with_asset_and_min_required_coin_by_utxo_cost(multiasset, data_cost) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const data_costPtr = Ptr._assertClass(data_cost, DataCost);
    const ret = await HaskellShelley.transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(this.ptr, multiassetPtr, data_costPtr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

  async build() {
    const ret = await HaskellShelley.transactionOutputAmountBuilderBuild(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionOutputBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.transactionOutputBuilderNew();
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_address(address) {
    const addressPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.transactionOutputBuilderWithAddress(this.ptr, addressPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_data_hash(data_hash) {
    const data_hashPtr = Ptr._assertClass(data_hash, DataHash);
    const ret = await HaskellShelley.transactionOutputBuilderWithDataHash(this.ptr, data_hashPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_plutus_data(data) {
    const dataPtr = Ptr._assertClass(data, PlutusData);
    const ret = await HaskellShelley.transactionOutputBuilderWithPlutusData(this.ptr, dataPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async with_script_ref(script_ref) {
    const script_refPtr = Ptr._assertClass(script_ref, ScriptRef);
    const ret = await HaskellShelley.transactionOutputBuilderWithScriptRef(this.ptr, script_refPtr);
    return Ptr._wrap(ret, TransactionOutputBuilder);
  }

  async next() {
    const ret = await HaskellShelley.transactionOutputBuilderNext(this.ptr);
    return Ptr._wrap(ret, TransactionOutputAmountBuilder);
  }

}


export class TransactionOutputs extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionOutputsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionOutputsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionOutputsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionOutputsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.transactionOutputsNew();
    return Ptr._wrap(ret, TransactionOutputs);
  }

  async len() {
    const ret = await HaskellShelley.transactionOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionOutput);
    const ret = HaskellShelley.transactionOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionUnspentOutput extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionUnspentOutputToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionUnspentOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionUnspentOutputToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionUnspentOutputFromHex(hex_str);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionUnspentOutputToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionUnspentOutputFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  static async new(input, output) {
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const outputPtr = Ptr._assertClass(output, TransactionOutput);
    const ret = await HaskellShelley.transactionUnspentOutputNew(inputPtr, outputPtr);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  async input() {
    const ret = await HaskellShelley.transactionUnspentOutputInput(this.ptr);
    return Ptr._wrap(ret, TransactionInput);
  }

  async output() {
    const ret = await HaskellShelley.transactionUnspentOutputOutput(this.ptr);
    return Ptr._wrap(ret, TransactionOutput);
  }

}


export class TransactionUnspentOutputs extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.transactionUnspentOutputsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionUnspentOutputsFromJson(json);
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  static async new() {
    const ret = await HaskellShelley.transactionUnspentOutputsNew();
    return Ptr._wrap(ret, TransactionUnspentOutputs);
  }

  async len() {
    const ret = await HaskellShelley.transactionUnspentOutputsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionUnspentOutputsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionUnspentOutput);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionUnspentOutput);
    const ret = HaskellShelley.transactionUnspentOutputsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TransactionWitnessSet extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionWitnessSetToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionWitnessSetFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionWitnessSetToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionWitnessSetFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionWitnessSetToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionWitnessSetFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  set_vkeys(vkeys) {
    const vkeysPtr = Ptr._assertClass(vkeys, Vkeywitnesses);
    const ret = HaskellShelley.transactionWitnessSetSetVkeys(this.ptr, vkeysPtr);
    return ret;
  }

  async vkeys() {
    const ret = await HaskellShelley.transactionWitnessSetVkeys(this.ptr);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  set_native_scripts(native_scripts) {
    const native_scriptsPtr = Ptr._assertClass(native_scripts, NativeScripts);
    const ret = HaskellShelley.transactionWitnessSetSetNativeScripts(this.ptr, native_scriptsPtr);
    return ret;
  }

  async native_scripts() {
    const ret = await HaskellShelley.transactionWitnessSetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  set_bootstraps(bootstraps) {
    const bootstrapsPtr = Ptr._assertClass(bootstraps, BootstrapWitnesses);
    const ret = HaskellShelley.transactionWitnessSetSetBootstraps(this.ptr, bootstrapsPtr);
    return ret;
  }

  async bootstraps() {
    const ret = await HaskellShelley.transactionWitnessSetBootstraps(this.ptr);
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  set_plutus_scripts(plutus_scripts) {
    const plutus_scriptsPtr = Ptr._assertClass(plutus_scripts, PlutusScripts);
    const ret = HaskellShelley.transactionWitnessSetSetPlutusScripts(this.ptr, plutus_scriptsPtr);
    return ret;
  }

  async plutus_scripts() {
    const ret = await HaskellShelley.transactionWitnessSetPlutusScripts(this.ptr);
    return Ptr._wrap(ret, PlutusScripts);
  }

  set_plutus_data(plutus_data) {
    const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusList);
    const ret = HaskellShelley.transactionWitnessSetSetPlutusData(this.ptr, plutus_dataPtr);
    return ret;
  }

  async plutus_data() {
    const ret = await HaskellShelley.transactionWitnessSetPlutusData(this.ptr);
    return Ptr._wrap(ret, PlutusList);
  }

  set_redeemers(redeemers) {
    const redeemersPtr = Ptr._assertClass(redeemers, Redeemers);
    const ret = HaskellShelley.transactionWitnessSetSetRedeemers(this.ptr, redeemersPtr);
    return ret;
  }

  async redeemers() {
    const ret = await HaskellShelley.transactionWitnessSetRedeemers(this.ptr);
    return Ptr._wrap(ret, Redeemers);
  }

  static async new() {
    const ret = await HaskellShelley.transactionWitnessSetNew();
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

}


export class TransactionWitnessSets extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.transactionWitnessSetsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionWitnessSetsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_hex() {
    const ret = await HaskellShelley.transactionWitnessSetsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.transactionWitnessSetsFromHex(hex_str);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async to_json() {
    const ret = await HaskellShelley.transactionWitnessSetsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.transactionWitnessSetsFromJson(json);
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  static async new() {
    const ret = await HaskellShelley.transactionWitnessSetsNew();
    return Ptr._wrap(ret, TransactionWitnessSets);
  }

  async len() {
    const ret = await HaskellShelley.transactionWitnessSetsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.transactionWitnessSetsGet(this.ptr, index);
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, TransactionWitnessSet);
    const ret = HaskellShelley.transactionWitnessSetsAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class TreasuryWithdrawals extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.treasuryWithdrawalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.treasuryWithdrawalsFromJson(json);
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  static async new() {
    const ret = await HaskellShelley.treasuryWithdrawalsNew();
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await HaskellShelley.treasuryWithdrawalsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = HaskellShelley.treasuryWithdrawalsInsert(this.ptr, keyPtr, valuePtr);
    return ret;
  }

  async keys() {
    const ret = await HaskellShelley.treasuryWithdrawalsKeys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

  async len() {
    const ret = await HaskellShelley.treasuryWithdrawalsLen(this.ptr);
    return ret;
  }

}


export class TreasuryWithdrawalsAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.treasuryWithdrawalsActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.treasuryWithdrawalsActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.treasuryWithdrawalsActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.treasuryWithdrawalsActionFromHex(hex_str);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async to_json() {
    const ret = await HaskellShelley.treasuryWithdrawalsActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.treasuryWithdrawalsActionFromJson(json);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  async withdrawals() {
    const ret = await HaskellShelley.treasuryWithdrawalsActionWithdrawals(this.ptr);
    return Ptr._wrap(ret, TreasuryWithdrawals);
  }

  async policy_hash() {
    const ret = await HaskellShelley.treasuryWithdrawalsActionPolicyHash(this.ptr);
    return Ptr._wrap(ret, ScriptHash);
  }

  static async new(withdrawals) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, TreasuryWithdrawals);
    const ret = await HaskellShelley.treasuryWithdrawalsActionNew(withdrawalsPtr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

  static async new_with_policy_hash(withdrawals, policy_hash) {
    const withdrawalsPtr = Ptr._assertClass(withdrawals, TreasuryWithdrawals);
    const policy_hashPtr = Ptr._assertClass(policy_hash, ScriptHash);
    const ret = await HaskellShelley.treasuryWithdrawalsActionNewWithPolicyHash(withdrawalsPtr, policy_hashPtr);
    return Ptr._wrap(ret, TreasuryWithdrawalsAction);
  }

}


export class TxBuilderConstants extends Ptr {
  static async plutus_default_cost_models() {
    const ret = await HaskellShelley.txBuilderConstantsPlutusDefaultCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_alonzo_cost_models() {
    const ret = await HaskellShelley.txBuilderConstantsPlutusAlonzoCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

  static async plutus_vasil_cost_models() {
    const ret = await HaskellShelley.txBuilderConstantsPlutusVasilCostModels();
    return Ptr._wrap(ret, Costmdls);
  }

}


export class TxInputsBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.txInputsBuilderNew();
    return Ptr._wrap(ret, TxInputsBuilder);
  }

  add_key_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.txInputsBuilderAddKeyInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_native_script_input(script, input, amount) {
    const scriptPtr = Ptr._assertClass(script, NativeScript);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.txInputsBuilderAddNativeScriptInput(this.ptr, scriptPtr, inputPtr, amountPtr);
    return ret;
  }

  add_plutus_script_input(witness, input, amount) {
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.txInputsBuilderAddPlutusScriptInput(this.ptr, witnessPtr, inputPtr, amountPtr);
    return ret;
  }

  add_bootstrap_input(hash, input, amount) {
    const hashPtr = Ptr._assertClass(hash, ByronAddress);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.txInputsBuilderAddBootstrapInput(this.ptr, hashPtr, inputPtr, amountPtr);
    return ret;
  }

  add_regular_input(address, input, amount) {
    const addressPtr = Ptr._assertClass(address, Address);
    const inputPtr = Ptr._assertClass(input, TransactionInput);
    const amountPtr = Ptr._assertClass(amount, Value);
    const ret = HaskellShelley.txInputsBuilderAddRegularInput(this.ptr, addressPtr, inputPtr, amountPtr);
    return ret;
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.txInputsBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_input_scripts() {
    const ret = await HaskellShelley.txInputsBuilderGetNativeInputScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_plutus_input_scripts() {
    const ret = await HaskellShelley.txInputsBuilderGetPlutusInputScripts(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async len() {
    const ret = await HaskellShelley.txInputsBuilderLen(this.ptr);
    return ret;
  }

  add_required_signer(key) {
    const keyPtr = Ptr._assertClass(key, Ed25519KeyHash);
    const ret = HaskellShelley.txInputsBuilderAddRequiredSigner(this.ptr, keyPtr);
    return ret;
  }

  add_required_signers(keys) {
    const keysPtr = Ptr._assertClass(keys, Ed25519KeyHashes);
    const ret = HaskellShelley.txInputsBuilderAddRequiredSigners(this.ptr, keysPtr);
    return ret;
  }

  async total_value() {
    const ret = await HaskellShelley.txInputsBuilderTotalValue(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async inputs() {
    const ret = await HaskellShelley.txInputsBuilderInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async inputs_option() {
    const ret = await HaskellShelley.txInputsBuilderInputsOption(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

}


export class URL extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.uRLToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.uRLFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, URL);
  }

  async to_hex() {
    const ret = await HaskellShelley.uRLToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.uRLFromHex(hex_str);
    return Ptr._wrap(ret, URL);
  }

  async to_json() {
    const ret = await HaskellShelley.uRLToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.uRLFromJson(json);
    return Ptr._wrap(ret, URL);
  }

  static async new(url) {
    const ret = await HaskellShelley.uRLNew(url);
    return Ptr._wrap(ret, URL);
  }

  async url() {
    const ret = await HaskellShelley.uRLUrl(this.ptr);
    return ret;
  }

}


export class UnitInterval extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.unitIntervalToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.unitIntervalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_hex() {
    const ret = await HaskellShelley.unitIntervalToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.unitIntervalFromHex(hex_str);
    return Ptr._wrap(ret, UnitInterval);
  }

  async to_json() {
    const ret = await HaskellShelley.unitIntervalToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.unitIntervalFromJson(json);
    return Ptr._wrap(ret, UnitInterval);
  }

  async numerator() {
    const ret = await HaskellShelley.unitIntervalNumerator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  async denominator() {
    const ret = await HaskellShelley.unitIntervalDenominator(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(numerator, denominator) {
    const numeratorPtr = Ptr._assertClass(numerator, BigNum);
    const denominatorPtr = Ptr._assertClass(denominator, BigNum);
    const ret = await HaskellShelley.unitIntervalNew(numeratorPtr, denominatorPtr);
    return Ptr._wrap(ret, UnitInterval);
  }

}


export class Update extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.updateToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.updateFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Update);
  }

  async to_hex() {
    const ret = await HaskellShelley.updateToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.updateFromHex(hex_str);
    return Ptr._wrap(ret, Update);
  }

  async to_json() {
    const ret = await HaskellShelley.updateToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.updateFromJson(json);
    return Ptr._wrap(ret, Update);
  }

  async proposed_protocol_parameter_updates() {
    const ret = await HaskellShelley.updateProposedProtocolParameterUpdates(this.ptr);
    return Ptr._wrap(ret, ProposedProtocolParameterUpdates);
  }

  async epoch() {
    const ret = await HaskellShelley.updateEpoch(this.ptr);
    return ret;
  }

  static async new(proposed_protocol_parameter_updates, epoch) {
    const proposed_protocol_parameter_updatesPtr = Ptr._assertClass(proposed_protocol_parameter_updates, ProposedProtocolParameterUpdates);
    const ret = await HaskellShelley.updateNew(proposed_protocol_parameter_updatesPtr, epoch);
    return Ptr._wrap(ret, Update);
  }

}


export class UpdateCommitteeAction extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.updateCommitteeActionToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.updateCommitteeActionFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async to_hex() {
    const ret = await HaskellShelley.updateCommitteeActionToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.updateCommitteeActionFromHex(hex_str);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async to_json() {
    const ret = await HaskellShelley.updateCommitteeActionToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.updateCommitteeActionFromJson(json);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  async gov_action_id() {
    const ret = await HaskellShelley.updateCommitteeActionGovActionId(this.ptr);
    return Ptr._wrap(ret, GovernanceActionId);
  }

  async committee() {
    const ret = await HaskellShelley.updateCommitteeActionCommittee(this.ptr);
    return Ptr._wrap(ret, Committee);
  }

  async members_to_remove() {
    const ret = await HaskellShelley.updateCommitteeActionMembersToRemove(this.ptr);
    return Ptr._wrap(ret, Credentials);
  }

  static async new(committee, members_to_remove) {
    const committeePtr = Ptr._assertClass(committee, Committee);
    const members_to_removePtr = Ptr._assertClass(members_to_remove, Credentials);
    const ret = await HaskellShelley.updateCommitteeActionNew(committeePtr, members_to_removePtr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

  static async new_with_action_id(gov_action_id, committee, members_to_remove) {
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const committeePtr = Ptr._assertClass(committee, Committee);
    const members_to_removePtr = Ptr._assertClass(members_to_remove, Credentials);
    const ret = await HaskellShelley.updateCommitteeActionNewWithActionId(gov_action_idPtr, committeePtr, members_to_removePtr);
    return Ptr._wrap(ret, UpdateCommitteeAction);
  }

}


export class VRFCert extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.vRFCertToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vRFCertFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFCert);
  }

  async to_hex() {
    const ret = await HaskellShelley.vRFCertToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.vRFCertFromHex(hex_str);
    return Ptr._wrap(ret, VRFCert);
  }

  async to_json() {
    const ret = await HaskellShelley.vRFCertToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.vRFCertFromJson(json);
    return Ptr._wrap(ret, VRFCert);
  }

  async output() {
    const ret = await HaskellShelley.vRFCertOutput(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async proof() {
    const ret = await HaskellShelley.vRFCertProof(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async new(output, proof) {
    const ret = await HaskellShelley.vRFCertNew(b64FromUint8Array(output), b64FromUint8Array(proof));
    return Ptr._wrap(ret, VRFCert);
  }

}


export class VRFKeyHash extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vRFKeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_bytes() {
    const ret = await HaskellShelley.vRFKeyHashToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.vRFKeyHashToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.vRFKeyHashFromBech32(bech_str);
    return Ptr._wrap(ret, VRFKeyHash);
  }

  async to_hex() {
    const ret = await HaskellShelley.vRFKeyHashToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.vRFKeyHashFromHex(hex);
    return Ptr._wrap(ret, VRFKeyHash);
  }

}


export class VRFVKey extends Ptr {
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vRFVKeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_bytes() {
    const ret = await HaskellShelley.vRFVKeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  async to_bech32(prefix) {
    const ret = await HaskellShelley.vRFVKeyToBech32(this.ptr, prefix);
    return ret;
  }

  static async from_bech32(bech_str) {
    const ret = await HaskellShelley.vRFVKeyFromBech32(bech_str);
    return Ptr._wrap(ret, VRFVKey);
  }

  async to_hex() {
    const ret = await HaskellShelley.vRFVKeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex) {
    const ret = await HaskellShelley.vRFVKeyFromHex(hex);
    return Ptr._wrap(ret, VRFVKey);
  }

}


export class Value extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.valueToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.valueFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Value);
  }

  async to_hex() {
    const ret = await HaskellShelley.valueToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.valueFromHex(hex_str);
    return Ptr._wrap(ret, Value);
  }

  async to_json() {
    const ret = await HaskellShelley.valueToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.valueFromJson(json);
    return Ptr._wrap(ret, Value);
  }

  static async new(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.valueNew(coinPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_from_assets(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.valueNewFromAssets(multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async new_with_assets(coin, multiasset) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = await HaskellShelley.valueNewWithAssets(coinPtr, multiassetPtr);
    return Ptr._wrap(ret, Value);
  }

  static async zero() {
    const ret = await HaskellShelley.valueZero();
    return Ptr._wrap(ret, Value);
  }

  async is_zero() {
    const ret = await HaskellShelley.valueIsZero(this.ptr);
    return ret;
  }

  async coin() {
    const ret = await HaskellShelley.valueCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  set_coin(coin) {
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = HaskellShelley.valueSetCoin(this.ptr, coinPtr);
    return ret;
  }

  async multiasset() {
    const ret = await HaskellShelley.valueMultiasset(this.ptr);
    return Ptr._wrap(ret, MultiAsset);
  }

  set_multiasset(multiasset) {
    const multiassetPtr = Ptr._assertClass(multiasset, MultiAsset);
    const ret = HaskellShelley.valueSetMultiasset(this.ptr, multiassetPtr);
    return ret;
  }

  async checked_add(rhs) {
    const rhsPtr = Ptr._assertClass(rhs, Value);
    const ret = await HaskellShelley.valueCheckedAdd(this.ptr, rhsPtr);
    return Ptr._wrap(ret, Value);
  }

  async checked_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.valueCheckedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async clamped_sub(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.valueClampedSub(this.ptr, rhs_valuePtr);
    return Ptr._wrap(ret, Value);
  }

  async compare(rhs_value) {
    const rhs_valuePtr = Ptr._assertClass(rhs_value, Value);
    const ret = await HaskellShelley.valueCompare(this.ptr, rhs_valuePtr);
    return ret;
  }

}


export class Vkey extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.vkeyToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vkeyFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkey);
  }

  async to_hex() {
    const ret = await HaskellShelley.vkeyToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.vkeyFromHex(hex_str);
    return Ptr._wrap(ret, Vkey);
  }

  async to_json() {
    const ret = await HaskellShelley.vkeyToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.vkeyFromJson(json);
    return Ptr._wrap(ret, Vkey);
  }

  static async new(pk) {
    const pkPtr = Ptr._assertClass(pk, PublicKey);
    const ret = await HaskellShelley.vkeyNew(pkPtr);
    return Ptr._wrap(ret, Vkey);
  }

  async public_key() {
    const ret = await HaskellShelley.vkeyPublicKey(this.ptr);
    return Ptr._wrap(ret, PublicKey);
  }

}


export class Vkeys extends Ptr {
  static async new() {
    const ret = await HaskellShelley.vkeysNew();
    return Ptr._wrap(ret, Vkeys);
  }

  async len() {
    const ret = await HaskellShelley.vkeysLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.vkeysGet(this.ptr, index);
    return Ptr._wrap(ret, Vkey);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkey);
    const ret = HaskellShelley.vkeysAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class Vkeywitness extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.vkeywitnessToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vkeywitnessFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_hex() {
    const ret = await HaskellShelley.vkeywitnessToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.vkeywitnessFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async to_json() {
    const ret = await HaskellShelley.vkeywitnessToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.vkeywitnessFromJson(json);
    return Ptr._wrap(ret, Vkeywitness);
  }

  static async new(vkey, signature) {
    const vkeyPtr = Ptr._assertClass(vkey, Vkey);
    const signaturePtr = Ptr._assertClass(signature, Ed25519Signature);
    const ret = await HaskellShelley.vkeywitnessNew(vkeyPtr, signaturePtr);
    return Ptr._wrap(ret, Vkeywitness);
  }

  async vkey() {
    const ret = await HaskellShelley.vkeywitnessVkey(this.ptr);
    return Ptr._wrap(ret, Vkey);
  }

  async signature() {
    const ret = await HaskellShelley.vkeywitnessSignature(this.ptr);
    return Ptr._wrap(ret, Ed25519Signature);
  }

}


export class Vkeywitnesses extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.vkeywitnessesToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.vkeywitnessesFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_hex() {
    const ret = await HaskellShelley.vkeywitnessesToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.vkeywitnessesFromHex(hex_str);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async to_json() {
    const ret = await HaskellShelley.vkeywitnessesToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.vkeywitnessesFromJson(json);
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  static async new() {
    const ret = await HaskellShelley.vkeywitnessesNew();
    return Ptr._wrap(ret, Vkeywitnesses);
  }

  async len() {
    const ret = await HaskellShelley.vkeywitnessesLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.vkeywitnessesGet(this.ptr, index);
    return Ptr._wrap(ret, Vkeywitness);
  }

  add(elem) {
    const elemPtr = Ptr._assertClass(elem, Vkeywitness);
    const ret = HaskellShelley.vkeywitnessesAdd(this.ptr, elemPtr);
    return ret;
  }

}


export class VoteDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.voteDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.voteDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VoteDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.voteDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.voteDelegationFromHex(hex_str);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.voteDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.voteDelegationFromJson(json);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.voteDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async drep() {
    const ret = await HaskellShelley.voteDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  static async new(stake_credential, drep) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const ret = await HaskellShelley.voteDelegationNew(stake_credentialPtr, drepPtr);
    return Ptr._wrap(ret, VoteDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.voteDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class VoteRegistrationAndDelegation extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.voteRegistrationAndDelegationFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async to_hex() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.voteRegistrationAndDelegationFromHex(hex_str);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async to_json() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.voteRegistrationAndDelegationFromJson(json);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async stake_credential() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationStakeCredential(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async drep() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationDrep(this.ptr);
    return Ptr._wrap(ret, DRep);
  }

  async coin() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationCoin(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(stake_credential, drep, coin) {
    const stake_credentialPtr = Ptr._assertClass(stake_credential, Credential);
    const drepPtr = Ptr._assertClass(drep, DRep);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = await HaskellShelley.voteRegistrationAndDelegationNew(stake_credentialPtr, drepPtr, coinPtr);
    return Ptr._wrap(ret, VoteRegistrationAndDelegation);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.voteRegistrationAndDelegationHasScriptCredentials(this.ptr);
    return ret;
  }

}


export class Voter extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.voterToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.voterFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Voter);
  }

  async to_hex() {
    const ret = await HaskellShelley.voterToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.voterFromHex(hex_str);
    return Ptr._wrap(ret, Voter);
  }

  async to_json() {
    const ret = await HaskellShelley.voterToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.voterFromJson(json);
    return Ptr._wrap(ret, Voter);
  }

  static async new_constitutional_committee_hot_key(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.voterNewConstitutionalCommitteeHotKey(credPtr);
    return Ptr._wrap(ret, Voter);
  }

  static async new_drep(cred) {
    const credPtr = Ptr._assertClass(cred, Credential);
    const ret = await HaskellShelley.voterNewDrep(credPtr);
    return Ptr._wrap(ret, Voter);
  }

  static async new_staking_pool(key_hash) {
    const key_hashPtr = Ptr._assertClass(key_hash, Ed25519KeyHash);
    const ret = await HaskellShelley.voterNewStakingPool(key_hashPtr);
    return Ptr._wrap(ret, Voter);
  }

  async kind() {
    const ret = await HaskellShelley.voterKind(this.ptr);
    return ret;
  }

  async to_constitutional_committee_hot_cred() {
    const ret = await HaskellShelley.voterToConstitutionalCommitteeHotCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_drep_cred() {
    const ret = await HaskellShelley.voterToDrepCred(this.ptr);
    return Ptr._wrap(ret, Credential);
  }

  async to_staking_pool_key_hash() {
    const ret = await HaskellShelley.voterToStakingPoolKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  async has_script_credentials() {
    const ret = await HaskellShelley.voterHasScriptCredentials(this.ptr);
    return ret;
  }

  async to_key_hash() {
    const ret = await HaskellShelley.voterToKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

}


export class Voters extends Ptr {
  async to_json() {
    const ret = await HaskellShelley.votersToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.votersFromJson(json);
    return Ptr._wrap(ret, Voters);
  }

  static async new() {
    const ret = await HaskellShelley.votersNew();
    return Ptr._wrap(ret, Voters);
  }

  add(voter) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const ret = HaskellShelley.votersAdd(this.ptr, voterPtr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.votersGet(this.ptr, index);
    return Ptr._wrap(ret, Voter);
  }

  async len() {
    const ret = await HaskellShelley.votersLen(this.ptr);
    return ret;
  }

}


export class VotingBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.votingBuilderNew();
    return Ptr._wrap(ret, VotingBuilder);
  }

  add(voter, gov_action_id, voting_procedure) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const ret = HaskellShelley.votingBuilderAdd(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr);
    return ret;
  }

  add_with_plutus_witness(voter, gov_action_id, voting_procedure, witness) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.votingBuilderAddWithPlutusWitness(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr, witnessPtr);
    return ret;
  }

  add_with_native_script(voter, gov_action_id, voting_procedure, native_script_source) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const gov_action_idPtr = Ptr._assertClass(gov_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.votingBuilderAddWithNativeScript(this.ptr, voterPtr, gov_action_idPtr, voting_procedurePtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.votingBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.votingBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.votingBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.votingBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.votingBuilderBuild(this.ptr);
    return Ptr._wrap(ret, VotingProcedures);
  }

}


export class VotingProcedure extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.votingProcedureToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.votingProcedureFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProcedure);
  }

  async to_hex() {
    const ret = await HaskellShelley.votingProcedureToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.votingProcedureFromHex(hex_str);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async to_json() {
    const ret = await HaskellShelley.votingProcedureToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.votingProcedureFromJson(json);
    return Ptr._wrap(ret, VotingProcedure);
  }

  static async new(vote) {
    const ret = await HaskellShelley.votingProcedureNew(vote);
    return Ptr._wrap(ret, VotingProcedure);
  }

  static async new_with_anchor(vote, anchor) {
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const ret = await HaskellShelley.votingProcedureNewWithAnchor(vote, anchorPtr);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async vote_kind() {
    const ret = await HaskellShelley.votingProcedureVoteKind(this.ptr);
    return ret;
  }

  async anchor() {
    const ret = await HaskellShelley.votingProcedureAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

}


export class VotingProcedures extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.votingProceduresToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.votingProceduresFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProcedures);
  }

  async to_hex() {
    const ret = await HaskellShelley.votingProceduresToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.votingProceduresFromHex(hex_str);
    return Ptr._wrap(ret, VotingProcedures);
  }

  async to_json() {
    const ret = await HaskellShelley.votingProceduresToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.votingProceduresFromJson(json);
    return Ptr._wrap(ret, VotingProcedures);
  }

  static async new() {
    const ret = await HaskellShelley.votingProceduresNew();
    return Ptr._wrap(ret, VotingProcedures);
  }

  insert(voter, governance_action_id, voting_procedure) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const voting_procedurePtr = Ptr._assertClass(voting_procedure, VotingProcedure);
    const ret = HaskellShelley.votingProceduresInsert(this.ptr, voterPtr, governance_action_idPtr, voting_procedurePtr);
    return ret;
  }

  async get(voter, governance_action_id) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const governance_action_idPtr = Ptr._assertClass(governance_action_id, GovernanceActionId);
    const ret = await HaskellShelley.votingProceduresGet(this.ptr, voterPtr, governance_action_idPtr);
    return Ptr._wrap(ret, VotingProcedure);
  }

  async get_voters() {
    const ret = await HaskellShelley.votingProceduresGetVoters(this.ptr);
    return Ptr._wrap(ret, Voters);
  }

  async get_governance_action_ids_by_voter(voter) {
    const voterPtr = Ptr._assertClass(voter, Voter);
    const ret = await HaskellShelley.votingProceduresGetGovernanceActionIdsByVoter(this.ptr, voterPtr);
    return Ptr._wrap(ret, GovernanceActionIds);
  }

}


export class VotingProposal extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.votingProposalToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.votingProposalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProposal);
  }

  async to_hex() {
    const ret = await HaskellShelley.votingProposalToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.votingProposalFromHex(hex_str);
    return Ptr._wrap(ret, VotingProposal);
  }

  async to_json() {
    const ret = await HaskellShelley.votingProposalToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.votingProposalFromJson(json);
    return Ptr._wrap(ret, VotingProposal);
  }

  async governance_action() {
    const ret = await HaskellShelley.votingProposalGovernanceAction(this.ptr);
    return Ptr._wrap(ret, GovernanceAction);
  }

  async anchor() {
    const ret = await HaskellShelley.votingProposalAnchor(this.ptr);
    return Ptr._wrap(ret, Anchor);
  }

  async reward_account() {
    const ret = await HaskellShelley.votingProposalRewardAccount(this.ptr);
    return Ptr._wrap(ret, RewardAddress);
  }

  async deposit() {
    const ret = await HaskellShelley.votingProposalDeposit(this.ptr);
    return Ptr._wrap(ret, BigNum);
  }

  static async new(governance_action, anchor, reward_account, deposit) {
    const governance_actionPtr = Ptr._assertClass(governance_action, GovernanceAction);
    const anchorPtr = Ptr._assertClass(anchor, Anchor);
    const reward_accountPtr = Ptr._assertClass(reward_account, RewardAddress);
    const depositPtr = Ptr._assertClass(deposit, BigNum);
    const ret = await HaskellShelley.votingProposalNew(governance_actionPtr, anchorPtr, reward_accountPtr, depositPtr);
    return Ptr._wrap(ret, VotingProposal);
  }

}


export class VotingProposalBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.votingProposalBuilderNew();
    return Ptr._wrap(ret, VotingProposalBuilder);
  }

  add(proposal) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const ret = HaskellShelley.votingProposalBuilderAdd(this.ptr, proposalPtr);
    return ret;
  }

  add_with_plutus_witness(proposal, witness) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.votingProposalBuilderAddWithPlutusWitness(this.ptr, proposalPtr, witnessPtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.votingProposalBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.votingProposalBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.votingProposalBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.votingProposalBuilderBuild(this.ptr);
    return Ptr._wrap(ret, VotingProposals);
  }

}


export class VotingProposals extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.votingProposalsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.votingProposalsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, VotingProposals);
  }

  async to_hex() {
    const ret = await HaskellShelley.votingProposalsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.votingProposalsFromHex(hex_str);
    return Ptr._wrap(ret, VotingProposals);
  }

  async to_json() {
    const ret = await HaskellShelley.votingProposalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.votingProposalsFromJson(json);
    return Ptr._wrap(ret, VotingProposals);
  }

  static async new() {
    const ret = await HaskellShelley.votingProposalsNew();
    return Ptr._wrap(ret, VotingProposals);
  }

  async len() {
    const ret = await HaskellShelley.votingProposalsLen(this.ptr);
    return ret;
  }

  async get(index) {
    const ret = await HaskellShelley.votingProposalsGet(this.ptr, index);
    return Ptr._wrap(ret, VotingProposal);
  }

  add(proposal) {
    const proposalPtr = Ptr._assertClass(proposal, VotingProposal);
    const ret = HaskellShelley.votingProposalsAdd(this.ptr, proposalPtr);
    return ret;
  }

}


export class Withdrawals extends Ptr {
  async to_bytes() {
    const ret = await HaskellShelley.withdrawalsToBytes(this.ptr);
    return uint8ArrayFromB64(ret);
  }

  static async from_bytes(bytes) {
    const ret = await HaskellShelley.withdrawalsFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_hex() {
    const ret = await HaskellShelley.withdrawalsToHex(this.ptr);
    return ret;
  }

  static async from_hex(hex_str) {
    const ret = await HaskellShelley.withdrawalsFromHex(hex_str);
    return Ptr._wrap(ret, Withdrawals);
  }

  async to_json() {
    const ret = await HaskellShelley.withdrawalsToJson(this.ptr);
    return ret;
  }

  static async from_json(json) {
    const ret = await HaskellShelley.withdrawalsFromJson(json);
    return Ptr._wrap(ret, Withdrawals);
  }

  static async new() {
    const ret = await HaskellShelley.withdrawalsNew();
    return Ptr._wrap(ret, Withdrawals);
  }

  async len() {
    const ret = await HaskellShelley.withdrawalsLen(this.ptr);
    return ret;
  }

  async insert(key, value) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const valuePtr = Ptr._assertClass(value, BigNum);
    const ret = await HaskellShelley.withdrawalsInsert(this.ptr, keyPtr, valuePtr);
    return Ptr._wrap(ret, BigNum);
  }

  async get(key) {
    const keyPtr = Ptr._assertClass(key, RewardAddress);
    const ret = await HaskellShelley.withdrawalsGet(this.ptr, keyPtr);
    return Ptr._wrap(ret, BigNum);
  }

  async keys() {
    const ret = await HaskellShelley.withdrawalsKeys(this.ptr);
    return Ptr._wrap(ret, RewardAddresses);
  }

}


export class WithdrawalsBuilder extends Ptr {
  static async new() {
    const ret = await HaskellShelley.withdrawalsBuilderNew();
    return Ptr._wrap(ret, WithdrawalsBuilder);
  }

  add(address, coin) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const ret = HaskellShelley.withdrawalsBuilderAdd(this.ptr, addressPtr, coinPtr);
    return ret;
  }

  add_with_plutus_witness(address, coin, witness) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const witnessPtr = Ptr._assertClass(witness, PlutusWitness);
    const ret = HaskellShelley.withdrawalsBuilderAddWithPlutusWitness(this.ptr, addressPtr, coinPtr, witnessPtr);
    return ret;
  }

  add_with_native_script(address, coin, native_script_source) {
    const addressPtr = Ptr._assertClass(address, RewardAddress);
    const coinPtr = Ptr._assertClass(coin, BigNum);
    const native_script_sourcePtr = Ptr._assertClass(native_script_source, NativeScriptSource);
    const ret = HaskellShelley.withdrawalsBuilderAddWithNativeScript(this.ptr, addressPtr, coinPtr, native_script_sourcePtr);
    return ret;
  }

  async get_plutus_witnesses() {
    const ret = await HaskellShelley.withdrawalsBuilderGetPlutusWitnesses(this.ptr);
    return Ptr._wrap(ret, PlutusWitnesses);
  }

  async get_ref_inputs() {
    const ret = await HaskellShelley.withdrawalsBuilderGetRefInputs(this.ptr);
    return Ptr._wrap(ret, TransactionInputs);
  }

  async get_native_scripts() {
    const ret = await HaskellShelley.withdrawalsBuilderGetNativeScripts(this.ptr);
    return Ptr._wrap(ret, NativeScripts);
  }

  async get_total_withdrawals() {
    const ret = await HaskellShelley.withdrawalsBuilderGetTotalWithdrawals(this.ptr);
    return Ptr._wrap(ret, Value);
  }

  async has_plutus_scripts() {
    const ret = await HaskellShelley.withdrawalsBuilderHasPlutusScripts(this.ptr);
    return ret;
  }

  async build() {
    const ret = await HaskellShelley.withdrawalsBuilderBuild(this.ptr);
    return Ptr._wrap(ret, Withdrawals);
  }

}


export const calculate_ex_units_ceil_cost = async (ex_units, ex_unit_prices) => {
  const ex_unitsPtr = Ptr._assertClass(ex_units, ExUnits);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.calculateExUnitsCeilCost(ex_unitsPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


export const create_send_all = async (address, utxos, config) => {
  const addressPtr = Ptr._assertClass(address, Address);
  const utxosPtr = Ptr._assertClass(utxos, TransactionUnspentOutputs);
  const configPtr = Ptr._assertClass(config, TransactionBuilderConfig);
  const ret = await HaskellShelley.createSendAll(addressPtr, utxosPtr, configPtr);
  return Ptr._wrap(ret, TransactionBatchList);
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


export const decode_plutus_datum_to_json_str = async (datum, schema) => {
  const datumPtr = Ptr._assertClass(datum, PlutusData);
  const ret = await HaskellShelley.decodePlutusDatumToJsonStr(datumPtr, schema);
  return ret;
};


export const decrypt_with_password = async (password, data) => {
  const ret = await HaskellShelley.decryptWithPassword(password, data);
  return ret;
};


export const encode_arbitrary_bytes_as_metadatum = async (bytes) => {
  const ret = await HaskellShelley.encodeArbitraryBytesAsMetadatum(b64FromUint8Array(bytes));
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_metadatum = async (json, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToMetadatum(json, schema);
  return Ptr._wrap(ret, TransactionMetadatum);
};


export const encode_json_str_to_native_script = async (json, self_xpub, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToNativeScript(json, self_xpub, schema);
  return Ptr._wrap(ret, NativeScript);
};


export const encode_json_str_to_plutus_datum = async (json, schema) => {
  const ret = await HaskellShelley.encodeJsonStrToPlutusDatum(json, schema);
  return Ptr._wrap(ret, PlutusData);
};


export const encrypt_with_password = async (password, salt, nonce, data) => {
  const ret = await HaskellShelley.encryptWithPassword(password, salt, nonce, data);
  return ret;
};


export const get_deposit = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.getDeposit(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, BigNum);
};


export const get_implicit_input = async (txbody, pool_deposit, key_deposit) => {
  const txbodyPtr = Ptr._assertClass(txbody, TransactionBody);
  const pool_depositPtr = Ptr._assertClass(pool_deposit, BigNum);
  const key_depositPtr = Ptr._assertClass(key_deposit, BigNum);
  const ret = await HaskellShelley.getImplicitInput(txbodyPtr, pool_depositPtr, key_depositPtr);
  return Ptr._wrap(ret, Value);
};


export const hash_auxiliary_data = async (auxiliary_data) => {
  const auxiliary_dataPtr = Ptr._assertClass(auxiliary_data, AuxiliaryData);
  const ret = await HaskellShelley.hashAuxiliaryData(auxiliary_dataPtr);
  return Ptr._wrap(ret, AuxiliaryDataHash);
};


export const hash_plutus_data = async (plutus_data) => {
  const plutus_dataPtr = Ptr._assertClass(plutus_data, PlutusData);
  const ret = await HaskellShelley.hashPlutusData(plutus_dataPtr);
  return Ptr._wrap(ret, DataHash);
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


export const make_icarus_bootstrap_witness = async (tx_body_hash, addr, key) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await HaskellShelley.makeIcarusBootstrapWitness(tx_body_hashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
};


export const make_vkey_witness = async (tx_body_hash, sk) => {
  const tx_body_hashPtr = Ptr._assertClass(tx_body_hash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await HaskellShelley.makeVkeyWitness(tx_body_hashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
};


export const min_ada_for_output = async (output, data_cost) => {
  const outputPtr = Ptr._assertClass(output, TransactionOutput);
  const data_costPtr = Ptr._assertClass(data_cost, DataCost);
  const ret = await HaskellShelley.minAdaForOutput(outputPtr, data_costPtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_fee = async (tx, linear_fee) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const linear_feePtr = Ptr._assertClass(linear_fee, LinearFee);
  const ret = await HaskellShelley.minFee(txPtr, linear_feePtr);
  return Ptr._wrap(ret, BigNum);
};


export const min_script_fee = async (tx, ex_unit_prices) => {
  const txPtr = Ptr._assertClass(tx, Transaction);
  const ex_unit_pricesPtr = Ptr._assertClass(ex_unit_prices, ExUnitPrices);
  const ret = await HaskellShelley.minScriptFee(txPtr, ex_unit_pricesPtr);
  return Ptr._wrap(ret, BigNum);
};


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
  DrepDeregistration: 9,
  DrepRegistration: 10,
  DrepUpdate: 11,
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


