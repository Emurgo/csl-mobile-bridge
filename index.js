import { NativeModules } from 'react-native';
import { decode as base64_decode, encode as base64_encode } from 'base-64';

const { HaskellShelley } = NativeModules;

// export default HaskellShelley;

function Uint8ArrayFromB64(base64_string) {
  return Uint8Array.from(base64_decode(base64_string), c => c.charCodeAt(0));
}

function b64FromUint8Array(uint8Array) {
  return base64_encode(String.fromCharCode.apply(null, uint8Array));
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

export class BigNum extends Ptr {

  /**
  * @param {string} string
  * @returns {Promise<BigNum>}
  */
  static async from_str(string) {
    const ret = await HaskellShelley.bigNumFromStr(string);
    return Ptr._wrap(ret, BigNum);
  }

  /**
  * String representation of the BigNum value for use from environments
  * that don't support BigInt
  * @returns {Promise<string>}
  */
  async to_str() {
    return await HaskellShelley.bigNumToStr(this.ptr);
  }
}

// use same underlying functions written for BigNum
export class Coin extends Ptr {

  /**
  * @param {string} string
  * @returns {Promise<Coin>}
  */
  static async from_str(string) {
    const ret = await HaskellShelley.bigNumFromStr(string);
    return Ptr._wrap(ret, Coin);
  }

  /**
  * @returns {Promise<string>}
  */
  async to_str() {
    return await HaskellShelley.bigNumToStr(this.ptr);
  }
}

export class ByronAddress extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  async to_base58() {
    return HaskellShelley.byronAddressToBase58(this.ptr);
  }

  /**
  * @param {string} string
  * @returns {Promise<ByronAddress>}
  */
  static async from_base58(string) {
    const ret = await HaskellShelley.byronAddressFromBase58(string);
    return Ptr._wrap(ret, ByronAddress);
  }

}

export class Address extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
    const b64 = await HaskellShelley.addressToBytes(this.ptr);
    return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Address>}
  */
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.addressFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Address);
  }

}

export class Ed25519KeyHash extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
    const b64 = await HaskellShelley.ed25519KeyHashToBytes(this.ptr);
    return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ed25519KeyHash>}
  */
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.ed25519KeyHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, Ed25519KeyHash);
  }
}

export class TransactionHash extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
    const b64 = await HaskellShelley.transactionHashToBytes(this.ptr);
    return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionHash>}
  */
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionHashFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionHash);
  }
}

export class StakeCredential extends Ptr {

  /**
  * @param {Ed25519KeyHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static async from_keyhash(hash) {
    const keyHashPtr = Ptr._assertClass(hash, Ed25519KeyHash);
    const ret = await HaskellShelley.stakeCredentialFromKeyHash(keyHashPtr);
    return Ptr._wrap(ret, StakeCredential);
  }

  // TODO
  // static async from_scripthash(hash)

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  async to_keyhash() {
    const ret = await HaskellShelley.stakeCredentialToKeyHash(this.ptr);
    return Ptr._wrap(ret, Ed25519KeyHash);
  }

  // TODO
  // static async to_scripthash(hash)

  /**
  * @returns {Promise<number>}
  */
  async kind() {
    return await HaskellShelley.stakeCredentialKind(this.ptr);
  }
}

export class BaseAddress extends Ptr {

  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @param {StakeCredential} stake
  * @returns {Promise<BaseAddress>}
  */
  static async new(network, payment, stake) {
    const paymentPtr = Ptr._assertClass(payment, StakeCredential);
    const stakePtr = Ptr._assertClass(stake, StakeCredential);
    const ret = await HaskellShelley.baseAddressNew(network, paymentPtr, stakePtr);
    return Ptr._wrap(ret, BaseAddress);
  }

  /**
  * @returns {Promise<StakeCredential>}
  */
  async payment_cred() {
    const ret = await HaskellShelley.baseAddressPaymentCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }

  /**
  * @returns {Promise<StakeCredential>}
  */
  async stake_cred() {
    const ret = await HaskellShelley.baseAddressStakeCred(this.ptr);
    return Ptr._wrap(ret, StakeCredential);
  }
}

export class UnitInterval extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
    const b64 = await HaskellShelley.unitIntervalToBytes(this.ptr);
    return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<UnitInterval>}
  */
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.unitIntervalFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, UnitInterval);
  }

  /**
  * @param {BigNum} numerator
  * @param {BigNum} denominator
  * @returns {Promise<UnitInterval>}
  */
  static async new(numerator, denominator) {
    const numeratorPtr = Ptr._assertClass(numerator, BigNum);
    const denominatorPtr = Ptr._assertClass(denominator, BigNum);
    const ret = await HaskellShelley.unitIntervalNew(numeratorPtr, denominatorPtr);
    return Ptr._wrap(ret, UnitInterval);
  }
}


export class TransactionInput extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
    const b64 = await HaskellShelley.transactionInputToBytes(this.ptr);
    return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionInput>}
  */
  static async from_bytes(bytes) {
    const ret = await HaskellShelley.transactionInputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionInput);
  }

  /**
  * @param {TransactionHash} transactionId
  * @param {TransactionIndex} index
  * @returns {Promise<TransactionInput>}
  */
  static async new(transactionId, index) {
    const transactionIdPtr = Ptr._assertClass(transactionId, TransactionHash);
    const indexPtr = Ptr._assertClass(index, TransactionIndex);
    const ret = await HaskellShelley.transactionInputNew(transactionIdPtr, indexPtr);
    return Ptr._wrap(ret, TransactionInput);
  }

}

export class TransactionOutput extends Ptr {

  /**
  * @returns {Promise<Uint8Array>}
  */
  async to_bytes() {
      const b64 = await HaskellShelley.transactionOutputToBytes(this.ptr);
      return Uint8ArrayFromB64(b64);
  }

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionOutput>}
  */
  static async from_bytes(bytes: Uint8Array) {
    const ret = await HaskellShelley.transactionOutputFromBytes(b64FromUint8Array(bytes));
    return Ptr._wrap(ret, TransactionOutput);
  }

  /**
  * @param {Address} address
  * @param {Coin} amount
  * @returns {Promise<TransactionOutput>}
  */
  static async new(address: Address, amount: Coin) {
    const addrPtr = Ptr._assertClass(address, Address);
    const ret = await HaskellShelley.transactionOutputNew(addrPtr, amount);
    return Ptr._wrap(ret, TransactionOutput);
  }

}
