export type Optional<T> = T | undefined;

export class Ptr {
  /**
    * Frees the pointer
    * @returns {Promise<void>}
    */
  free(): Promise<void>;
}

export type TransactionIndex = number

export const make_icarus_bootstrap_witness: (
  txBodyHash: TransactionHash,
  addr: ByronAddress,
  key: Bip32PrivateKey,
) => Promise<BootstrapWitness>

export const make_vkey_witness: (
  txBodyHash: TransactionHash,
  sk: PrivateKey,
) => Promise<Vkeywitness>

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
  derive(index: number): Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<Bip32PrivateKey>}
  */
  static generate_ed25519_bip32(): Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<PrivateKey>}
  */
  to_raw_key(): Promise<PrivateKey>;

  /**
  * @returns {Promise<Bip32PublicKey>}
  */
  to_public(): Promise<Bip32PublicKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bytes(bytes: Uint8Array): Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes(): Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bech32(bech32_str: string): Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32(): Promise<string>;

  /**
  * @param {Uint8Array} entropy
  * @param {Uint8Array} password
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bip39_entropy(entropy: Uint8Array, password: Uint8Array): Promise<Bip32PrivateKey>;
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
  * @returns {Promise<TransactionHash>}
  */
  transaction_id(): Promise<TransactionHash>

  /**
  * @returns {Promise<number>}
  */
  async index(): Promise<number>

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
  * @returns {Promise<TransactionOutput>}
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

// TODO
export class Vkeywitness extends Ptr {}

export class Vkeywitnesses extends Ptr {
    /**
    * @returns {Promise<Vkeywitnesses>}
    */
    static new(): Promise<Vkeywitnesses>

    /**
    * @returns {Promise<number>}
    */
    len(): Promise<number>

    /**
    * @param {Vkwitness} item
    * @returns {Promise<void>}
    */
    add(item: Vkwitness): Promise<void>
}

// TODO
export class BootstrapWitness extends Ptr {}

export class BootstrapWitnesses extends Ptr {
    /**
    * @returns {Promise<BootstrapWitnesses>}
    */
    static new(): Promise<BootstrapWitnesses>

    /**
    * @returns {Promise<number>}
    */
    len(): Promise<number>

    /**
    * @param {BootstrapWitness} item
    * @returns {Promise<void>}
    */
    add(item: BootstrapWitness): Promise<void>
}

export class TransactionWitnessSet extends Ptr {
  /**
  * @returns {Promise<TransactionWitnessSet>}
  */
  static new(): Promise<TransactionWitnessSet>

  /**
  * @param {BootstrapWitnesses} bootstraps
  * @returns {Promise<void>}
  */
  async set_bootstraps(bootstraps): Promise<void>

  /**
  * @param {Vkeywitnesses} bootstraps
  * @returns {Promise<void>}
  */
  async set_vkeys(bootstraps): Promise<void>
}
