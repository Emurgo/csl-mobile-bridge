export type Optional<T> = T | undefined;

export type TransactionIndex = number;

export type Coin = number;

export class Ptr {
  /**
    * Frees the pointer
    * @returns {Promise<void>}
    */
  free(): Promise<void>;
}

// NOT SUPPORTED
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

export class AddrKeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<AddrKeyHash>}
  */
  static from_bytes(bytes: Uint8Array): Promise<AddrKeyHash>;

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
  * @param {AddrKeyHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static from_keyhash(hash: AddrKeyHash): Promise<StakeCredential>

  /**
  * @returns {Promise<AddrKeyHash>}
  */
  to_keyhash(): Promise<AddrKeyHash>;

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
  * @param {number} index0
  * @param {number} index1
  * @returns {Promise<UnitInterval>}
  */
  static new(index0, index1): Promise<UnitInterval>
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
