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

/**
* @param {TransactionHash} txBodyHash
* @param {ByronAddress} addr
* @param {Bip32PrivateKey} key
* @returns {Promise<BootstrapWitness>}
*/
export const make_icarus_bootstrap_witness = async (txBodyHash, addr, key) => {
  const txBodyHashPtr = Ptr._assertClass(txBodyHash, TransactionHash);
  const addrPtr = Ptr._assertClass(addr, ByronAddress);
  const keyPtr = Ptr._assertClass(key, Bip32PrivateKey);
  const ret = await HaskellShelley.makeIcarusBootstrapWitness(txBodyHashPtr, addrPtr, keyPtr);
  return Ptr._wrap(ret, BootstrapWitness);
}

/**
* @param {TransactionHash} txBodyHash
* @param {PrivateKey} sk
* @returns {Promise<Vkeywitness>}
*/
export const make_vkey_witness = async (txBodyHash, sk) => {
  const txBodyHashPtr = Ptr._assertClass(txBodyHash, TransactionHash);
  const skPtr = Ptr._assertClass(sk, PrivateKey);
  const ret = await HaskellShelley.makeVkeyWitness(txBodyHashPtr, skPtr);
  return Ptr._wrap(ret, Vkeywitness);
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

// TODO
export class PrivateKey extends Ptr {}

/**
*/
export class Bip32PrivateKey extends Ptr {
    /**
    * derive this private key with the given index.
    *
    * # Security considerations
    *
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    * @param {number} index
    * @returns {Promise<Bip32PrivateKey>}
    */
    async derive(index) {
        const ret = await HaskellShelley.bip32PrivateKeyDerive(this.ptr, index);
        return Ptr._wrap(ret, Bip32PrivateKey);
    }

    /**
    * @returns {Promise<Bip32PrivateKey>}
    */
    static async generate_ed25519_bip32() {
        const ret = await HaskellShelley.bip32PrivateKeyGenerateEd25519Bip32();
        return Ptr._wrap(ret, Bip32PrivateKey);
    }

    /**
    * @returns {Promise<PrivateKey>}
    */
    async to_raw_key() {
        const ret = await HaskellShelley.bip32PrivateKeyToRawKey(this.ptr);
        return Ptr._wrap(ret, PrivateKey);
    }

    /**
    * @returns {Promise<Bip32PublicKey>}
    */
    async to_public() {
        const ret = await HaskellShelley.bip32PrivateKeyToPublic(this.ptr);
        return Ptr._wrap(ret, Bip32PublicKey);
    }

    /**
    * @param {Uint8Array} bytes
    * @returns {Promise<Bip32PrivateKey>}
    */
    static async from_bytes(bytes) {
        const ret = await HaskellShelley.bip32PrivateKeyFromBytes(b64FromUint8Array(bytes));
        return Ptr._wrap(ret, Bip32PrivateKey);
    }

    /**
    * @returns {Promise<Uint8Array>}
    */
    async as_bytes() {
        const b64 = await HaskellShelley.bip32PrivateKeyAsBytes(this.ptr);
        return Uint8ArrayFromB64(b64);
    }

    /**
    * @param {string} bech32Str
    * @returns {Promise<Bip32PrivateKey>}
    */
    static async from_bech32(bech32Str) {
        const ret = await HaskellShelley.bip32PrivateKeyFromBech32(bech32Str);
        return Ptr._wrap(ret, Bip32PrivateKey);
    }

    /**
    * @returns {Promise<string>}
    */
    to_bech32() {
        return HaskellShelley.bip32PrivateKeyToBech32(this.ptr);
    }

    /**
    * @param {Uint8Array} entropy
    * @param {Uint8Array} password
    * @returns {Promise<Bip32PrivateKey>}
    */
    static async from_bip39_entropy(entropy, password) {
        const ret = await HaskellShelley.bip32PrivateKeyFromBip39Entropy(b64FromUint8Array(entropy), b64FromUint8Array(password));
        return Ptr._wrap(ret, Bip32PrivateKey);
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
  * @returns {Promise<TransactionHash>}
  */
  async transaction_id() {
    const ret = await HaskellShelley.transactionInputTransactionId(this.ptr);
    return Ptr._wrap(ret, TransactionHash);
  }

  /**
  * @returns {Promise<number>}
  */
  async index() {
    return await HaskellShelley.transactionInputIndex(this.ptr);
  }

  /**
  * @param {TransactionHash} transactionId
  * @param {TransactionIndex} index
  * @returns {Promise<TransactionInput>}
  */
  static async new(transactionId, index) {
    const transactionIdPtr = Ptr._assertClass(transactionId, TransactionHash);
    const ret = await HaskellShelley.transactionInputNew(transactionIdPtr, index);
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
    const amountPtr = Ptr._assertClass(amount, Coin);
    const ret = await HaskellShelley.transactionOutputNew(addrPtr, amountPtr);
    return Ptr._wrap(ret, TransactionOutput);
  }
}

export class LinearFee extends Ptr {
  /**
  * @returns {Promise<Coin>}
  */
  async constant() {
    const ret = await HaskellShelley.linearFeeConstant(this.ptr);
    return Ptr._wrap(ret, Coin);
  }

  /**
  * @returns {Promise<Coin>}
  */
  async coefficient() {
    const ret = await HaskellShelley.linearFeeCoefficient(this.ptr);
    return Ptr._wrap(ret, Coin);
  }

  /**
  * @param {Coin} coefficient
  * @param {Coin} constant
  * @returns {Promise<LinearFee>}
  */
  static async new(coefficient: Coin, constant: Coin) {
    const coeffPtr = Ptr._assertClass(coefficient, Coin);
    const constPtr = Ptr._assertClass(constant, Coin);
    const ret = await HaskellShelley.linearFeeNew(coeffPtr, constPtr);
    return Ptr._wrap(ret, LinearFee);
  }
}

// TODO
export class Vkeywitness extends Ptr {}

export class Vkeywitnesses extends Ptr {
    /**
    * @returns {Promise<Vkeywitnesses>}
    */
    static async new() {
        const ret = await HaskellShelley.vkeywitnessesNew();
        return Ptr._wrap(ret, Vkeywitnesses);
    }

    /**
    * @returns {Promise<number>}
    */
    async len() {
      return HaskellShelley.vkeywitnessesLen(this.ptr);
    }

    /**
    * @param {Vkwitness} item
    * @returns {Promise<void>}
    */
    async add(item) {
      const itemPtr = Ptr._assertClass(item, Vkwitness);
      item.ptr = null;
      return HaskellShelley.vkeywitnessesAdd(this.ptr, itemPtr);
    }
}

// TODO
export class BootstrapWitness extends Ptr {}

export class BootstrapWitnesses extends Ptr {
  /**
  * @returns {Promise<BootstrapWitnesses>}
  */
  static async new() {
    const ret = await HaskellShelley.bootstrapWitnessesNew();
    return Ptr._wrap(ret, BootstrapWitnesses);
  }

  /**
  * @returns {Promise<number>}
  */
  async len() {
    return HaskellShelley.bootstrapWitnessesLen(this.ptr);
  }

  /**
  * @param {BootstrapWitness} item
  * @returns {Promise<void>}
  */
  async add(item) {
    const itemPtr = Ptr._assertClass(item, BootstrapWitness);
    item.ptr = null;
    return HaskellShelley.bootstrapWitnessAdd(this.ptr, itemPtr);
  }
}

export class TransactionWitnessSet extends Ptr {
  /**
  * @returns {Promise<TransactionWitnessSet>}
  */
  static async new() {
    const ret = await HaskellShelley.transactionWitnessSetNew();
    return Ptr._wrap(ret, TransactionWitnessSet);
  }

  /**
  * @param {BootstrapWitnesses} bootstraps
  * @returns {Promise<void>}
  */
  async set_bootstraps(bootstraps) {
    const bootstrapsPtr = Ptr._assertClass(bootstraps, BootstrapWitnesses);
    bootstraps.ptr = null;
    return HaskellShelley.transactionWitnessSetSetBootstraps(this.ptr, bootstrapsPtr);
  }

  /**
  * @param {Vkeywitnesses} vkeys
  * @returns {Promise<void>}
  */
  async set_vkeys(vkeys) {
    const vkeysPtr = Ptr._assertClass(vkeys, Vkeywitnesses);
    vkeys.ptr = null;
    return HaskellShelley.transactionWitnessSetSetVkeys(this.ptr, vkeysPtr);
  }
}
