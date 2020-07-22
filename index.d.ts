export type Optional<T> = T | undefined;

export class Ptr {
  /**
    * Frees the pointer
    * @returns {Promise<void>}
    */
  free(): Promise<void>;
}

/**
* Generic u64 wrapper for platforms that don't support u64 or BigInt/etc
* This is an unsigned type - no negative numbers.
* Can be converted to/from plain rust
*/
export class BigNum extends Ptr {
  /**
  * @param {string} string
  * @returns {Promise<Value>}
  */
  static from_str(string: string): Promise<BigNum>;

  /**
  * String representation of the BigNum value for use from environments that
  * don't support BigInt
  * @returns {Promise<string>}
  */
  to_str(): Promise<string>;

}

export class Coin extends Ptr {
  /**
  * @param {string} string
  * @returns {Promise<Value>}
  */
  static from_str(string: string): Promise<Coin>;

  /**
  * @returns {Promise<string>}
  */
  to_str(): Promise<string>;

}

export class ByronAddress extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  to_base58(): Promise<string>

  /**
  * @param {string} string
  * @returns {Promise<ByronAddress>}
  */
  static from_base58(string: string): Promise<ByronAddress>

}

export class Address extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Address>}
  */
  static from_bytes(bytes: Uint8Array): Promise<Address>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

}

export class Ed25519KeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ed25519KeyHash>}
  */
  static from_bytes(bytes: Uint8Array): Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

}

export class TransactionHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionHash>}
  */
  static from_bytes(bytes: Uint8Array): Promise<TransactionHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

}

export class StakeCredential extends Ptr {

  /**
  * @param {Ed25519KeyHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static from_keyhash(hash: Ed25519KeyHash): Promise<StakeCredential>

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  to_keyhash(): Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<number>}
  */
  kind(): Promise<number>
}

export class BaseAddress extends Ptr {

  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @param {StakeCredential} stake
  * @returns {Promise<BaseAddress>}
  */
  static new(network, payment, stake): Promise<BaseAddress>

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred(): Promise<StakeCredential>

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_cred(): Promise<StakeCredential>
}

export class UnitInterval extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<UnitInterval>}
  */
  static from_bytes(bytes: Uint8Array): Promise<UnitInterval>;

  /**
  * @param {BigNum} numerator
  * @param {BigNum} denominator
  * @returns {Promise<UnitInterval>}
  */
  static new(numerator, denominator): Promise<UnitInterval>
}

export class TransactionInput extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionInput>}
  */
  static from_bytes(bytes: Uint8Array): Promise<TransactionInput>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @param {TransactionHash} transactionId
  * @param {TransactionIndex} index
  * @returns {Promise<TransactionInput>}
  */
  static new(transactionId: TransactionHash, index: TransactionIndex): Promise<TransactionInput>;
}

export class TransactionOutput extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionOutput>}
  */
  static from_bytes(bytes: Uint8Array): Promise<TransactionOutput>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @param {Address} address
  * @param {Coin} amount
  * @returns {Promise<TransactionInput>}
  */
  static new(address: Address, amount: Coin): Promise<TransactionOutput>;
}

export class LinearFee extends Ptr {
  /**
  * @returns {Promise<Coin>}
  */
  constant(): Promise<Coin>;

  /**
  * @returns {Promise<Coin>}
  */
  coefficient(): Promise<Coin>;

  /**
  * @param {Coin} coefficient
  * @param {Coin} constant
  * @returns {Promise<LinearFee>}
  */
  static new(coefficient: Coin, constant: Coin): Promise<LinearFee>;
}
