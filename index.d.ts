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

export const hash_transaction: (
  txBody: TransactionBody,
) => Promise<TransactionHash>

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

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  checked_add(other): Promise<BigNum>;

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  checked_sub(other): Promise<BigNum>;

}

/**
* ED25519 key used as public key
*/
export class PublicKey extends Ptr {
  /**
  * Get private key from its bech32 representation
  * Example:
  * ```javascript
  * const pkey = PublicKey.from_bech32(&#39;ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2&#39;);
  * ```
  * @param {string} bech32_str
  * @returns {Promise<PublicKey>}
  */
  static from_bech32(bech32_str: string): Promise<PublicKey>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32(): Promise<string>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PublicKey>}
  */
  static from_bytes(bytes): Promise<PublicKey>

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes(): Promise<Uint8Array>;

  // TODO: cannot implement yet since Ed25519Signature is missing
  // /**
  // * @param {Uint8Array} data
  // * @param {Ed25519Signature} signature
  // * @returns {Promise<boolean>}
  // */
  // static verify(data, signature): Promise<boolean>

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  hash(): Promise<Ed25519KeyHash>
}

export class PrivateKey extends Ptr {
  /**
  * @returns {Promise<PublicKey>}
  */
  to_public(): Promise<PublicKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes(): Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PrivateKey>}
  */
  static from_extended_bytes(bytes): Promise<PublicKey>;
}

/**
*/
export class Bip32PublicKey extends Ptr {
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
  * @returns {Promise<Bip32PublicKey>}
  */
  derive(index: number): Promise<Bip32PublicKey>;

  /**
  * @returns {Promise<PublicKey>}
  */
  to_raw_key(): Promise<PublicKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Bip32PublicKey>}
  */
  static from_bytes(bytes: Uint8Array): Promise<Bip32PublicKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes(): Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Bip32PublicKey>}
  */
  static from_bech32(bech32_str: string): Promise<Bip32PublicKey>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32(): Promise<string>;
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

  /**
  * @param {string} string
  * @returns {Promise<boolean>}
  */
  static is_valid(string): Promise<boolean>

  /**
  * @returns {Promise<Address>}
  */
  to_address(): Promise<Address>

  /**
  * @param {Address} addr
  * @returns {Promise<ByronAddress | undefined>}
  */
  static from_address(addr): Promise<ByronAddress | undefined>
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

  /**
  * @param {string | void} prefix
  * @returns {Promise<string>}
  */
  to_bech32(prefix?: string): Promise<string>;

  /**
  * @param {string} string
  * @returns {Promise<Address>}
  */
  static from_bech32(string) : Promise<Address>
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
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeCredential>}
  */
  static from_bytes(bytes: Uint8Array): Promise<StakeCredential>;

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

export class StakeRegistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeRegistration>}
  */
  static from_bytes(bytes: Uint8Array): Promise<StakeRegistration>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential(): Promise<StakeCredential>

  /**
  * @param {StakeCredential} stakeCredential
  * @returns {Promise<StakeRegistration>}
  */
  static new(stakeCredential): Promise<StakeRegistration>
}

export class StakeDeregistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeDeregistration>}
  */
  static from_bytes(bytes: Uint8Array): Promise<StakeDeregistration>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential(): Promise<StakeCredential>

  /**
  * @param {StakeCredential} stakeCredential
  * @returns {Promise<StakeDeregistration>}
  */
  static new(stakeCredential): Promise<StakeDeregistration>
}

export class StakeDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeDelegation>}
  */
  static from_bytes(bytes): Promise<StakeDelegation>

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential(): Promise<StakeCredential>

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash(): Promise<Ed25519KeyHash>

  /**
  * @param {StakeCredential} stakeCredential
  * @param {Ed25519KeyHash} poolKeyHash
  * @returns {Promise<StakeDelegation>}
  */
  static new(stakeCredential, poolKeyHash): Promise<StakeDelegation>
}

export class Certificate extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Certificate>}
  */
  static from_bytes(bytes): Promise<Certificate>

  /**
  * @param {StakeRegistration} stakeRegistration
  * @returns {Promise<Certificate>}
  */
  static new_stake_registration(stakeRegistration): Promise<Certificate>

  /**
  * @param {StakeDeregistration} stakeDeregistration
  * @returns {Promise<Certificate>}
  */
  static new_stake_deregistration(stakeDeregistration): Promise<Certificate>

  /**
  * @param {StakeDelegation} stakeDelegation
  * @returns {Promise<Certificate>}
  */
  static new_stake_delegation(stakeDelegation): Promise<Certificate>
}

export class Certificates extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Certificates>}
  */
  static from_bytes(bytes): Promise<Certificates>

  /**
  * @returns {Promise<Certificates>}
  */
  static new(): Promise<Certificates>

  /**
  * @returns {Promise<number>}
  */
  len(): Promise<number>

  /**
  * @param {Certificate} item
  * @returns {Promise<void>}
  */
  add(item: Certificate): Promise<void>
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

  /**
  * @returns {Promise<Address>}
  */
  to_address(): Promise<Address>

  /**
  * @param {Address} addr
  * @returns {Promise<BaseAddress | undefined>}
  */
  static from_address(addr): Promise<BaseAddress | undefined>
}

export class RewardAddress extends Ptr {
  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @returns {Promise<RewardAddress>}
  */
  static new(network: number, payment: StakeCredential): Promise<RewardAddress>

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred(): Promise<StakeCredential>

  /**
  * @returns {Promise<Address>}
  */
  to_address(): Promise<Address>

  /**
  * @param {Address} addr
  * @returns {Promise<RewardAddress | undefined>}
  */
  static from_address(addr: Address): Promise<RewardAddress | undefined>
}

/* TODO */
export class RewardAddresses extends Ptr {}

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
  transaction_id(): Promise<TransactionHash>;

  /**
  * @returns {Promise<number>}
  */
  index(): Promise<number>;

  /**
  * @param {TransactionHash} transactionId
  * @param {TransactionIndex} index
  * @returns {Promise<TransactionInput>}
  */
  static new(transactionId: TransactionHash, index: TransactionIndex): Promise<TransactionInput>;
}

export class TransactionInputs extends Ptr {
  /**
  * @returns {Promise<number>}
  */
  len(): Promise<number>
  /**
  * @param {number} index
  * @returns {Promise<TransactionInput>}
  */
  get(index: number): Promise<TransactionInput>
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
  * @param {BigNum} amount
  * @returns {Promise<TransactionOutput>}
  */
  static new(address: Address, amount: BigNum): Promise<TransactionOutput>;

  /**
  * @returns {Promise<Address>}
  */
  address(): Promise<Address>

  /**
  * @returns {Promise<BigNum>}
  */
  amount(): Promise<BigNum>
}

export class TransactionOutputs extends Ptr {
  /**
  * @returns {Promise<number>}
  */
  len(): Promise<number>
  /**
  * @param {number} index
  * @returns {Promise<TransactionOutput>}
  */
  get(index: number): Promise<TransactionOutput>
}

export class LinearFee extends Ptr {
  /**
  * @returns {Promise<BigNum>}
  */
  constant(): Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  coefficient(): Promise<BigNum>;

  /**
  * @param {BigNum} coefficient
  * @param {BigNum} constant
  * @returns {Promise<LinearFee>}
  */
  static new(coefficient: BigNum, constant: BigNum): Promise<LinearFee>;
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
    * @param {Vkeywitness} item
    * @returns {Promise<void>}
    */
    add(item: Vkeywitness): Promise<void>
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
  set_bootstraps(bootstraps: BootstrapWitnesses): Promise<void>

  /**
  * @param {Vkeywitnesses} bootstraps
  * @returns {Promise<void>}
  */
  set_vkeys(vkeywitnesses: Vkeywitnesses): Promise<void>
}

export class TransactionMetadata extends Ptr {}

export class TransactionBody extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionBody>}
  */
  static from_bytes(bytes: Uint8Array): Promise<TransactionBody>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes(): Promise<Uint8Array>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  inputs(): Promise<TransactionInputs>

  /**
  * @returns {Promise<TransactionOutputs>}
  */
  outputs(): Promise<TransactionOutputs>

  /**
  * @returns {Promise<number>}
  */
  fee(): Promise<number>

  /**
  * @returns {Promise<number>}
  */
  ttl(): Promise<number>

  /**
  * @returns {Promise<Certificates>}
  */
  certs(): Promise<Certificates>

  /**
  * @returns {Promise<Withdrawals>}
  */
  withdrawals(): Promise<Withdrawals>
}

export class Transaction extends Ptr {
  /**
  * @returns {Promise<TransactionBody>}
  */
  body(): Promise<TransactionBody>
  /**
  * @param {TransactionBody} body
  * @param {TransactionWitnessSet} witnessSet
  * @param {TransactionMetadata | void} metadata
  * @returns {Promise<Transaction>}
  */
  static new(
    body: TransactionBody,
    witnessSet: TransactionWitnessSet,
    metadata?: TransactionMetadata,
  ): Promise<Transaction>
}

export class TransactionBuilder extends Ptr {
  /**
  * @param {Ed25519KeyHash} hash
  * @param {TransactionInput} input
  * @param {BigNum} amount
  * @returns {Promise<void>}
  */
  add_key_input(
    hash: Ed25519KeyHash,
    input: TransactionInput,
    amount: BigNum,
  ): Promise<void>

  /**
  * @param {ByronAddress} hash
  * @param {TransactionInput} input
  * @param {BigNum} amount
  * @returns {Promise<void>}
  */
  add_key_input(
    hash: ByronAddress,
    input: TransactionInput,
    amount: BigNum,
  ): Promise<void>

  /**
  * @param {TransactionOutput} output
  * @returns {Promise<void>}
  */
  add_output(
    output: TransactionOutput,
  ): Promise<void>

  /**
  * @param {BigNum} fee
  * @returns {Promise<void>}
  */
  set_fee(fee: BigNum): Promise<void>

  /**
  * @param {number} ttl
  * @returns {Promise<void>}
  */
  set_ttl(ttl: number): Promise<void>

  /**
  * @param {Certificates} certs
  * @returns {Promise<void>}
  */
  set_certs(certs: Certificates): Promise<void>

  /**
  * @param {Withdrawals} certs
  * @returns {Promise<void>}
  */
  set_withdrawals(withdrawals: Withdrawals): Promise<void>

  /**
  * @param {LinearFee} linearFee
  * @param {BigNum} minimumUtxoVal
  * @param {BigNum} poolDeposit
  * @param {BigNum} keyDeposit
  * @returns {Promise<TransactionBuilder>}
  */
  static new(
    linearFee: LinearFee,
    minimumUtxoVal: BigNum,
    poolDeposit: BigNum,
    keyDeposit: BigNum,
  ): Promise<TransactionBuilder>

  /**
  * @returns {Promise<BigNum>}
  */
  get_explicit_input(): Promise<BigNum>

  /**
  * @returns {Promise<BigNum>}
  */
  get_implicit_input(): Promise<BigNum>

  /**
  * @returns {Promise<BigNum>}
  */
  get_explicit_output(): Promise<BigNum>

  /**
  * @returns {Promise<BigNum>}
  */
  get_deposit(): Promise<BigNum>

  /**
  * @returns {Promise<BigNum>}
  */
  get_fee_if_set(): Promise<BigNum>

  /**
  * @param {Address} address
  * @returns {Promise<boolean>}
  */
  add_change_if_needed(address: Address)

  /**
  * @returns {Promise<TransactionBody>}
  */
  build(): Promise<TransactionBody>

  /**
  * @returns {Promise<BigNum>}
  */
  min_fee(): Promise<BigNum>
}

export class Withdrawals extends Ptr {
  /**
  * @returns {Promise<Withdrawals>}
  */
  static new(): Promise<Withdrawals>;

  /**
  * @returns {Promise<number>}
  */
  len(): Promise<number>

  /**
  * @param {RewardAddress} key
  * @param {BigNum} value
  * @returns {Promise<BigNum>}
  */
  insert(key, value): Promise<BigNum>;

  /**
  * @param {RewardAddress} key
  * @returns {Promise<BigNum | undefined>}
  */
  get(key: RewardAddress): Promise<BigNum | undefined>;

  /**
  * @returns {Promise<RewardAddress>}
  */
  keys(): Promise<RewardAddress>;
}
