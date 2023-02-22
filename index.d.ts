export type Optional<T> = T | undefined;

export class Ptr {
  /**
    * Frees the pointer
    * @returns {Promise<void>}
    */
  free(): Promise<void>;
}

export class Address extends Ptr {
  /**
  * @param {Uint8Array} data
  * @returns {Promise<Optional<Address>>}
  */
  static from_bytes: (data: Uint8Array) => Promise<Optional<Address>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Address>>}
  */
  static from_json: (json: string) => Promise<Optional<Address>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Address>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Address>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Optional<string>} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: Optional<string>) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<Address>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<Address>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  network_id: () => Promise<Optional<number>>;

}


export class AssetName extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<AssetName>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<AssetName>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<AssetName>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<AssetName>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<AssetName>>}
  */
  static from_json: (json: string) => Promise<Optional<AssetName>>;

  /**
  * @param {Uint8Array} name
  * @returns {Promise<Optional<AssetName>>}
  */
  static new: (name: Uint8Array) => Promise<Optional<AssetName>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  name: () => Promise<Uint8Array>;

}


export class AssetNames extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<AssetNames>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<AssetNames>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<AssetNames>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<AssetNames>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<AssetNames>>}
  */
  static from_json: (json: string) => Promise<Optional<AssetNames>>;

  /**
  * @returns {Promise<AssetNames>}
  */
  static new: () => Promise<AssetNames>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<AssetName>}
  */
  get: (index: number) => Promise<AssetName>;

  /**
  * @param {AssetName} elem
  */
  add: (elem: AssetName) => Promise<void>;

}


export class Assets extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Assets>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Assets>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Assets>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Assets>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Assets>>}
  */
  static from_json: (json: string) => Promise<Optional<Assets>>;

  /**
  * @returns {Promise<Assets>}
  */
  static new: () => Promise<Assets>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {AssetName} key
  * @param {BigNum} value
  * @returns {Promise<Optional<BigNum>>}
  */
  insert: (key: AssetName, value: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {AssetName} key
  * @returns {Promise<Optional<BigNum>>}
  */
  get: (key: AssetName) => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<AssetNames>}
  */
  keys: () => Promise<AssetNames>;

}


export class AuxiliaryData extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<AuxiliaryData>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<AuxiliaryData>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  static from_json: (json: string) => Promise<Optional<AuxiliaryData>>;

  /**
  * @returns {Promise<AuxiliaryData>}
  */
  static new: () => Promise<AuxiliaryData>;

  /**
  * @returns {Promise<Optional<GeneralTransactionMetadata>>}
  */
  metadata: () => Promise<Optional<GeneralTransactionMetadata>>;

  /**
  * @param {GeneralTransactionMetadata} metadata
  */
  set_metadata: (metadata: GeneralTransactionMetadata) => Promise<void>;

  /**
  * @returns {Promise<Optional<NativeScripts>>}
  */
  native_scripts: () => Promise<Optional<NativeScripts>>;

  /**
  * @param {NativeScripts} native_scripts
  */
  set_native_scripts: (native_scripts: NativeScripts) => Promise<void>;

  /**
  * @returns {Promise<Optional<PlutusScripts>>}
  */
  plutus_scripts: () => Promise<Optional<PlutusScripts>>;

  /**
  * @param {PlutusScripts} plutus_scripts
  */
  set_plutus_scripts: (plutus_scripts: PlutusScripts) => Promise<void>;

  /**
  * @returns {Promise<boolean>}
  */
  prefer_alonzo_format: () => Promise<boolean>;

  /**
  * @param {boolean} prefer
  */
  set_prefer_alonzo_format: (prefer: boolean) => Promise<void>;

}


export class AuxiliaryDataHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<AuxiliaryDataHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<AuxiliaryDataHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<AuxiliaryDataHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<AuxiliaryDataHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<AuxiliaryDataHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<AuxiliaryDataHash>>;

}


export class AuxiliaryDataSet extends Ptr {
  /**
  * @returns {Promise<AuxiliaryDataSet>}
  */
  static new: () => Promise<AuxiliaryDataSet>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} tx_index
  * @param {AuxiliaryData} data
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  insert: (tx_index: number, data: AuxiliaryData) => Promise<Optional<AuxiliaryData>>;

  /**
  * @param {number} tx_index
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  get: (tx_index: number) => Promise<Optional<AuxiliaryData>>;

  /**
  * @returns {Promise<Uint32Array>}
  */
  indices: () => Promise<Uint32Array>;

}


export class BaseAddress extends Ptr {
  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @param {StakeCredential} stake
  * @returns {Promise<BaseAddress>}
  */
  static new: (network: number, payment: StakeCredential, stake: StakeCredential) => Promise<BaseAddress>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_cred: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<BaseAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<BaseAddress>>;

}


export class BigInt extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<BigInt>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<BigInt>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<BigInt>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<BigInt>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<BigInt>>}
  */
  static from_json: (json: string) => Promise<Optional<BigInt>>;

  /**
  * @returns {Promise<boolean>}
  */
  is_zero: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  as_u64: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<Int>>}
  */
  as_int: () => Promise<Optional<Int>>;

  /**
  * @param {string} text
  * @returns {Promise<Optional<BigInt>>}
  */
  static from_str: (text: string) => Promise<Optional<BigInt>>;

  /**
  * @returns {Promise<string>}
  */
  to_str: () => Promise<string>;

  /**
  * @param {BigInt} other
  * @returns {Promise<BigInt>}
  */
  add: (other: BigInt) => Promise<BigInt>;

  /**
  * @param {BigInt} other
  * @returns {Promise<BigInt>}
  */
  mul: (other: BigInt) => Promise<BigInt>;

  /**
  * @returns {Promise<BigInt>}
  */
  static one: () => Promise<BigInt>;

  /**
  * @returns {Promise<BigInt>}
  */
  increment: () => Promise<BigInt>;

  /**
  * @param {BigInt} other
  * @returns {Promise<BigInt>}
  */
  div_ceil: (other: BigInt) => Promise<BigInt>;

}


export class BigNum extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<BigNum>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<BigNum>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<BigNum>>}
  */
  static from_json: (json: string) => Promise<Optional<BigNum>>;

  /**
  * @param {string} string
  * @returns {Promise<Optional<BigNum>>}
  */
  static from_str: (string: string) => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<string>}
  */
  to_str: () => Promise<string>;

  /**
  * @returns {Promise<BigNum>}
  */
  static zero: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  static one: () => Promise<BigNum>;

  /**
  * @returns {Promise<boolean>}
  */
  is_zero: () => Promise<boolean>;

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  div_floor: (other: BigNum) => Promise<BigNum>;

  /**
  * @param {BigNum} other
  * @returns {Promise<Optional<BigNum>>}
  */
  checked_mul: (other: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} other
  * @returns {Promise<Optional<BigNum>>}
  */
  checked_add: (other: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} other
  * @returns {Promise<Optional<BigNum>>}
  */
  checked_sub: (other: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  clamped_sub: (other: BigNum) => Promise<BigNum>;

  /**
  * @param {BigNum} rhs_value
  * @returns {Promise<number>}
  */
  compare: (rhs_value: BigNum) => Promise<number>;

  /**
  * @param {BigNum} rhs_value
  * @returns {Promise<boolean>}
  */
  less_than: (rhs_value: BigNum) => Promise<boolean>;

  /**
  * @returns {Promise<BigNum>}
  */
  static max_value: () => Promise<BigNum>;

  /**
  * @param {BigNum} a
  * @param {BigNum} b
  * @returns {Promise<BigNum>}
  */
  static max: (a: BigNum, b: BigNum) => Promise<BigNum>;

}


export class Bip32PrivateKey extends Ptr {
  /**
  * @param {number} index
  * @returns {Promise<Bip32PrivateKey>}
  */
  derive: (index: number) => Promise<Bip32PrivateKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Bip32PrivateKey>>}
  */
  static from_128_xprv: (bytes: Uint8Array) => Promise<Optional<Bip32PrivateKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_128_xprv: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Optional<Bip32PrivateKey>>}
  */
  static generate_ed25519_bip32: () => Promise<Optional<Bip32PrivateKey>>;

  /**
  * @returns {Promise<PrivateKey>}
  */
  to_raw_key: () => Promise<PrivateKey>;

  /**
  * @returns {Promise<Bip32PublicKey>}
  */
  to_public: () => Promise<Bip32PublicKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Bip32PrivateKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Bip32PrivateKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Optional<Bip32PrivateKey>>}
  */
  static from_bech32: (bech32_str: string) => Promise<Optional<Bip32PrivateKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32: () => Promise<string>;

  /**
  * @param {Uint8Array} entropy
  * @param {Uint8Array} password
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bip39_entropy: (entropy: Uint8Array, password: Uint8Array) => Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  chaincode: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Bip32PrivateKey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Bip32PrivateKey>>;

}


export class Bip32PublicKey extends Ptr {
  /**
  * @param {number} index
  * @returns {Promise<Optional<Bip32PublicKey>>}
  */
  derive: (index: number) => Promise<Optional<Bip32PublicKey>>;

  /**
  * @returns {Promise<PublicKey>}
  */
  to_raw_key: () => Promise<PublicKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Bip32PublicKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Bip32PublicKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Optional<Bip32PublicKey>>}
  */
  static from_bech32: (bech32_str: string) => Promise<Optional<Bip32PublicKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32: () => Promise<string>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  chaincode: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Bip32PublicKey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Bip32PublicKey>>;

}


export class Block extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Block>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Block>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Block>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Block>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Block>>}
  */
  static from_json: (json: string) => Promise<Optional<Block>>;

  /**
  * @returns {Promise<Header>}
  */
  header: () => Promise<Header>;

  /**
  * @returns {Promise<TransactionBodies>}
  */
  transaction_bodies: () => Promise<TransactionBodies>;

  /**
  * @returns {Promise<TransactionWitnessSets>}
  */
  transaction_witness_sets: () => Promise<TransactionWitnessSets>;

  /**
  * @returns {Promise<AuxiliaryDataSet>}
  */
  auxiliary_data_set: () => Promise<AuxiliaryDataSet>;

  /**
  * @returns {Promise<Uint32Array>}
  */
  invalid_transactions: () => Promise<Uint32Array>;

  /**
  * @param {Header} header
  * @param {TransactionBodies} transaction_bodies
  * @param {TransactionWitnessSets} transaction_witness_sets
  * @param {AuxiliaryDataSet} auxiliary_data_set
  * @param {Uint32Array} invalid_transactions
  * @returns {Promise<Block>}
  */
  static new: (header: Header, transaction_bodies: TransactionBodies, transaction_witness_sets: TransactionWitnessSets, auxiliary_data_set: AuxiliaryDataSet, invalid_transactions: Uint32Array) => Promise<Block>;

}


export class BlockHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<BlockHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<BlockHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<BlockHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<BlockHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<BlockHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<BlockHash>>;

}


export class BootstrapWitness extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<BootstrapWitness>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<BootstrapWitness>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<BootstrapWitness>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<BootstrapWitness>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<BootstrapWitness>>}
  */
  static from_json: (json: string) => Promise<Optional<BootstrapWitness>>;

  /**
  * @returns {Promise<Vkey>}
  */
  vkey: () => Promise<Vkey>;

  /**
  * @returns {Promise<Ed25519Signature>}
  */
  signature: () => Promise<Ed25519Signature>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  chain_code: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  attributes: () => Promise<Uint8Array>;

  /**
  * @param {Vkey} vkey
  * @param {Ed25519Signature} signature
  * @param {Uint8Array} chain_code
  * @param {Uint8Array} attributes
  * @returns {Promise<BootstrapWitness>}
  */
  static new: (vkey: Vkey, signature: Ed25519Signature, chain_code: Uint8Array, attributes: Uint8Array) => Promise<BootstrapWitness>;

}


export class BootstrapWitnesses extends Ptr {
  /**
  * @returns {Promise<BootstrapWitnesses>}
  */
  static new: () => Promise<BootstrapWitnesses>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<BootstrapWitness>}
  */
  get: (index: number) => Promise<BootstrapWitness>;

  /**
  * @param {BootstrapWitness} elem
  */
  add: (elem: BootstrapWitness) => Promise<void>;

}


export class ByronAddress extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  to_base58: () => Promise<string>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ByronAddress>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ByronAddress>>;

  /**
  * @returns {Promise<number>}
  */
  byron_protocol_magic: () => Promise<number>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  attributes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  network_id: () => Promise<Optional<number>>;

  /**
  * @param {string} s
  * @returns {Promise<Optional<ByronAddress>>}
  */
  static from_base58: (s: string) => Promise<Optional<ByronAddress>>;

  /**
  * @param {Bip32PublicKey} key
  * @param {number} protocol_magic
  * @returns {Promise<ByronAddress>}
  */
  static icarus_from_key: (key: Bip32PublicKey, protocol_magic: number) => Promise<ByronAddress>;

  /**
  * @param {string} s
  * @returns {Promise<boolean>}
  */
  static is_valid: (s: string) => Promise<boolean>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<ByronAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<ByronAddress>>;

}


export class Certificate extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Certificate>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Certificate>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Certificate>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Certificate>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Certificate>>}
  */
  static from_json: (json: string) => Promise<Optional<Certificate>>;

  /**
  * @param {StakeRegistration} stake_registration
  * @returns {Promise<Certificate>}
  */
  static new_stake_registration: (stake_registration: StakeRegistration) => Promise<Certificate>;

  /**
  * @param {StakeDeregistration} stake_deregistration
  * @returns {Promise<Certificate>}
  */
  static new_stake_deregistration: (stake_deregistration: StakeDeregistration) => Promise<Certificate>;

  /**
  * @param {StakeDelegation} stake_delegation
  * @returns {Promise<Certificate>}
  */
  static new_stake_delegation: (stake_delegation: StakeDelegation) => Promise<Certificate>;

  /**
  * @param {PoolRegistration} pool_registration
  * @returns {Promise<Certificate>}
  */
  static new_pool_registration: (pool_registration: PoolRegistration) => Promise<Certificate>;

  /**
  * @param {PoolRetirement} pool_retirement
  * @returns {Promise<Certificate>}
  */
  static new_pool_retirement: (pool_retirement: PoolRetirement) => Promise<Certificate>;

  /**
  * @param {GenesisKeyDelegation} genesis_key_delegation
  * @returns {Promise<Certificate>}
  */
  static new_genesis_key_delegation: (genesis_key_delegation: GenesisKeyDelegation) => Promise<Certificate>;

  /**
  * @param {MoveInstantaneousRewardsCert} move_instantaneous_rewards_cert
  * @returns {Promise<Certificate>}
  */
  static new_move_instantaneous_rewards_cert: (move_instantaneous_rewards_cert: MoveInstantaneousRewardsCert) => Promise<Certificate>;

  /**
  * @returns {Promise<CertificateKind>}
  */
  kind: () => Promise<CertificateKind>;

  /**
  * @returns {Promise<Optional<StakeRegistration>>}
  */
  as_stake_registration: () => Promise<Optional<StakeRegistration>>;

  /**
  * @returns {Promise<Optional<StakeDeregistration>>}
  */
  as_stake_deregistration: () => Promise<Optional<StakeDeregistration>>;

  /**
  * @returns {Promise<Optional<StakeDelegation>>}
  */
  as_stake_delegation: () => Promise<Optional<StakeDelegation>>;

  /**
  * @returns {Promise<Optional<PoolRegistration>>}
  */
  as_pool_registration: () => Promise<Optional<PoolRegistration>>;

  /**
  * @returns {Promise<Optional<PoolRetirement>>}
  */
  as_pool_retirement: () => Promise<Optional<PoolRetirement>>;

  /**
  * @returns {Promise<Optional<GenesisKeyDelegation>>}
  */
  as_genesis_key_delegation: () => Promise<Optional<GenesisKeyDelegation>>;

  /**
  * @returns {Promise<Optional<MoveInstantaneousRewardsCert>>}
  */
  as_move_instantaneous_rewards_cert: () => Promise<Optional<MoveInstantaneousRewardsCert>>;

}


export class Certificates extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Certificates>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Certificates>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Certificates>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Certificates>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Certificates>>}
  */
  static from_json: (json: string) => Promise<Optional<Certificates>>;

  /**
  * @returns {Promise<Certificates>}
  */
  static new: () => Promise<Certificates>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Certificate>}
  */
  get: (index: number) => Promise<Certificate>;

  /**
  * @param {Certificate} elem
  */
  add: (elem: Certificate) => Promise<void>;

}


export class ConstrPlutusData extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ConstrPlutusData>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ConstrPlutusData>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ConstrPlutusData>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ConstrPlutusData>>;

  /**
  * @returns {Promise<BigNum>}
  */
  alternative: () => Promise<BigNum>;

  /**
  * @returns {Promise<PlutusList>}
  */
  data: () => Promise<PlutusList>;

  /**
  * @param {BigNum} alternative
  * @param {PlutusList} data
  * @returns {Promise<ConstrPlutusData>}
  */
  static new: (alternative: BigNum, data: PlutusList) => Promise<ConstrPlutusData>;

}


export class CostModel extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<CostModel>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<CostModel>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<CostModel>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<CostModel>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<CostModel>>}
  */
  static from_json: (json: string) => Promise<Optional<CostModel>>;

  /**
  * @returns {Promise<CostModel>}
  */
  static new: () => Promise<CostModel>;

  /**
  * @param {number} operation
  * @param {Int} cost
  * @returns {Promise<Optional<Int>>}
  */
  set: (operation: number, cost: Int) => Promise<Optional<Int>>;

  /**
  * @param {number} operation
  * @returns {Promise<Optional<Int>>}
  */
  get: (operation: number) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class Costmdls extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Costmdls>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Costmdls>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Costmdls>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Costmdls>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Costmdls>>}
  */
  static from_json: (json: string) => Promise<Optional<Costmdls>>;

  /**
  * @returns {Promise<Costmdls>}
  */
  static new: () => Promise<Costmdls>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {Language} key
  * @param {CostModel} value
  * @returns {Promise<Optional<CostModel>>}
  */
  insert: (key: Language, value: CostModel) => Promise<Optional<CostModel>>;

  /**
  * @param {Language} key
  * @returns {Promise<Optional<CostModel>>}
  */
  get: (key: Language) => Promise<Optional<CostModel>>;

  /**
  * @returns {Promise<Languages>}
  */
  keys: () => Promise<Languages>;

  /**
  * @param {Languages} languages
  * @returns {Promise<Costmdls>}
  */
  retain_language_versions: (languages: Languages) => Promise<Costmdls>;

}


export class DNSRecordAorAAAA extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<DNSRecordAorAAAA>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<DNSRecordAorAAAA>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<DNSRecordAorAAAA>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<DNSRecordAorAAAA>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<DNSRecordAorAAAA>>}
  */
  static from_json: (json: string) => Promise<Optional<DNSRecordAorAAAA>>;

  /**
  * @param {string} dns_name
  * @returns {Promise<Optional<DNSRecordAorAAAA>>}
  */
  static new: (dns_name: string) => Promise<Optional<DNSRecordAorAAAA>>;

  /**
  * @returns {Promise<string>}
  */
  record: () => Promise<string>;

}


export class DNSRecordSRV extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<DNSRecordSRV>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<DNSRecordSRV>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<DNSRecordSRV>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<DNSRecordSRV>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<DNSRecordSRV>>}
  */
  static from_json: (json: string) => Promise<Optional<DNSRecordSRV>>;

  /**
  * @param {string} dns_name
  * @returns {Promise<Optional<DNSRecordSRV>>}
  */
  static new: (dns_name: string) => Promise<Optional<DNSRecordSRV>>;

  /**
  * @returns {Promise<string>}
  */
  record: () => Promise<string>;

}


export class DataCost extends Ptr {
  /**
  * @param {BigNum} coins_per_word
  * @returns {Promise<DataCost>}
  */
  static new_coins_per_word: (coins_per_word: BigNum) => Promise<DataCost>;

  /**
  * @param {BigNum} coins_per_byte
  * @returns {Promise<DataCost>}
  */
  static new_coins_per_byte: (coins_per_byte: BigNum) => Promise<DataCost>;

  /**
  * @returns {Promise<BigNum>}
  */
  coins_per_byte: () => Promise<BigNum>;

}


export class DataHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<DataHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<DataHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<DataHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<DataHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<DataHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<DataHash>>;

}


export class DatumSource extends Ptr {
  /**
  * @param {PlutusData} datum
  * @returns {Promise<DatumSource>}
  */
  static new: (datum: PlutusData) => Promise<DatumSource>;

  /**
  * @param {TransactionInput} input
  * @returns {Promise<DatumSource>}
  */
  static new_ref_input: (input: TransactionInput) => Promise<DatumSource>;

}


export class Ed25519KeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<Ed25519KeyHash>>;

}


export class Ed25519KeyHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Ed25519KeyHashes>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Ed25519KeyHashes>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Ed25519KeyHashes>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Ed25519KeyHashes>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Ed25519KeyHashes>>}
  */
  static from_json: (json: string) => Promise<Optional<Ed25519KeyHashes>>;

  /**
  * @returns {Promise<Ed25519KeyHashes>}
  */
  static new: () => Promise<Ed25519KeyHashes>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Ed25519KeyHash>}
  */
  get: (index: number) => Promise<Ed25519KeyHash>;

  /**
  * @param {Ed25519KeyHash} elem
  */
  add: (elem: Ed25519KeyHash) => Promise<void>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHashes>>}
  */
  to_option: () => Promise<Optional<Ed25519KeyHashes>>;

}


export class Ed25519Signature extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32: () => Promise<string>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Optional<Ed25519Signature>>}
  */
  static from_bech32: (bech32_str: string) => Promise<Optional<Ed25519Signature>>;

  /**
  * @param {string} input
  * @returns {Promise<Optional<Ed25519Signature>>}
  */
  static from_hex: (input: string) => Promise<Optional<Ed25519Signature>>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Ed25519Signature>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Ed25519Signature>>;

}


export class EnterpriseAddress extends Ptr {
  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @returns {Promise<EnterpriseAddress>}
  */
  static new: (network: number, payment: StakeCredential) => Promise<EnterpriseAddress>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<EnterpriseAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<EnterpriseAddress>>;

}


export class ExUnitPrices extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ExUnitPrices>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ExUnitPrices>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ExUnitPrices>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ExUnitPrices>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ExUnitPrices>>}
  */
  static from_json: (json: string) => Promise<Optional<ExUnitPrices>>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  mem_price: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  step_price: () => Promise<UnitInterval>;

  /**
  * @param {UnitInterval} mem_price
  * @param {UnitInterval} step_price
  * @returns {Promise<ExUnitPrices>}
  */
  static new: (mem_price: UnitInterval, step_price: UnitInterval) => Promise<ExUnitPrices>;

}


export class ExUnits extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ExUnits>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ExUnits>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ExUnits>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ExUnits>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ExUnits>>}
  */
  static from_json: (json: string) => Promise<Optional<ExUnits>>;

  /**
  * @returns {Promise<BigNum>}
  */
  mem: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  steps: () => Promise<BigNum>;

  /**
  * @param {BigNum} mem
  * @param {BigNum} steps
  * @returns {Promise<ExUnits>}
  */
  static new: (mem: BigNum, steps: BigNum) => Promise<ExUnits>;

}


export class FixedTransaction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<FixedTransaction>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<FixedTransaction>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<FixedTransaction>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<FixedTransaction>>;

  /**
  * @param {Uint8Array} raw_body
  * @param {Uint8Array} raw_witness_set
  * @param {boolean} is_valid
  * @returns {Promise<Optional<FixedTransaction>>}
  */
  static new: (raw_body: Uint8Array, raw_witness_set: Uint8Array, is_valid: boolean) => Promise<Optional<FixedTransaction>>;

  /**
  * @param {Uint8Array} raw_body
  * @param {Uint8Array} raw_witness_set
  * @param {Uint8Array} raw_auxiliary_data
  * @param {boolean} is_valid
  * @returns {Promise<Optional<FixedTransaction>>}
  */
  static new_with_auxiliary: (raw_body: Uint8Array, raw_witness_set: Uint8Array, raw_auxiliary_data: Uint8Array, is_valid: boolean) => Promise<Optional<FixedTransaction>>;

  /**
  * @returns {Promise<TransactionBody>}
  */
  body: () => Promise<TransactionBody>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  raw_body: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} raw_body
  * @returns {Promise<void>}
  */
  set_body: (raw_body: Uint8Array) => Promise<void>;

  /**
  * @param {Uint8Array} raw_witness_set
  * @returns {Promise<void>}
  */
  set_witness_set: (raw_witness_set: Uint8Array) => Promise<void>;

  /**
  * @returns {Promise<TransactionWitnessSet>}
  */
  witness_set: () => Promise<TransactionWitnessSet>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  raw_witness_set: () => Promise<Uint8Array>;

  /**
  * @param {boolean} valid
  */
  set_is_valid: (valid: boolean) => Promise<void>;

  /**
  * @returns {Promise<boolean>}
  */
  is_valid: () => Promise<boolean>;

  /**
  * @param {Uint8Array} raw_auxiliary_data
  * @returns {Promise<void>}
  */
  set_auxiliary_data: (raw_auxiliary_data: Uint8Array) => Promise<void>;

  /**
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  auxiliary_data: () => Promise<Optional<AuxiliaryData>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  raw_auxiliary_data: () => Promise<Uint8Array>;

}


export class GeneralTransactionMetadata extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<GeneralTransactionMetadata>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<GeneralTransactionMetadata>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<GeneralTransactionMetadata>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<GeneralTransactionMetadata>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<GeneralTransactionMetadata>>}
  */
  static from_json: (json: string) => Promise<Optional<GeneralTransactionMetadata>>;

  /**
  * @returns {Promise<GeneralTransactionMetadata>}
  */
  static new: () => Promise<GeneralTransactionMetadata>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {BigNum} key
  * @param {TransactionMetadatum} value
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  insert: (key: BigNum, value: TransactionMetadatum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {BigNum} key
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  get: (key: BigNum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @returns {Promise<TransactionMetadatumLabels>}
  */
  keys: () => Promise<TransactionMetadatumLabels>;

}


export class GenesisDelegateHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<GenesisDelegateHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<GenesisDelegateHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<GenesisDelegateHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<GenesisDelegateHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<GenesisDelegateHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<GenesisDelegateHash>>;

}


export class GenesisHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<GenesisHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<GenesisHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<GenesisHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<GenesisHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<GenesisHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<GenesisHash>>;

}


export class GenesisHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<GenesisHashes>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<GenesisHashes>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<GenesisHashes>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<GenesisHashes>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<GenesisHashes>>}
  */
  static from_json: (json: string) => Promise<Optional<GenesisHashes>>;

  /**
  * @returns {Promise<GenesisHashes>}
  */
  static new: () => Promise<GenesisHashes>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<GenesisHash>}
  */
  get: (index: number) => Promise<GenesisHash>;

  /**
  * @param {GenesisHash} elem
  */
  add: (elem: GenesisHash) => Promise<void>;

}


export class GenesisKeyDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<GenesisKeyDelegation>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<GenesisKeyDelegation>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<GenesisKeyDelegation>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<GenesisKeyDelegation>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<GenesisKeyDelegation>>}
  */
  static from_json: (json: string) => Promise<Optional<GenesisKeyDelegation>>;

  /**
  * @returns {Promise<GenesisHash>}
  */
  genesishash: () => Promise<GenesisHash>;

  /**
  * @returns {Promise<GenesisDelegateHash>}
  */
  genesis_delegate_hash: () => Promise<GenesisDelegateHash>;

  /**
  * @returns {Promise<VRFKeyHash>}
  */
  vrf_keyhash: () => Promise<VRFKeyHash>;

  /**
  * @param {GenesisHash} genesishash
  * @param {GenesisDelegateHash} genesis_delegate_hash
  * @param {VRFKeyHash} vrf_keyhash
  * @returns {Promise<GenesisKeyDelegation>}
  */
  static new: (genesishash: GenesisHash, genesis_delegate_hash: GenesisDelegateHash, vrf_keyhash: VRFKeyHash) => Promise<GenesisKeyDelegation>;

}


export class Header extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Header>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Header>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Header>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Header>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Header>>}
  */
  static from_json: (json: string) => Promise<Optional<Header>>;

  /**
  * @returns {Promise<HeaderBody>}
  */
  header_body: () => Promise<HeaderBody>;

  /**
  * @returns {Promise<KESSignature>}
  */
  body_signature: () => Promise<KESSignature>;

  /**
  * @param {HeaderBody} header_body
  * @param {KESSignature} body_signature
  * @returns {Promise<Header>}
  */
  static new: (header_body: HeaderBody, body_signature: KESSignature) => Promise<Header>;

}


export class HeaderBody extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<HeaderBody>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<HeaderBody>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<HeaderBody>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<HeaderBody>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<HeaderBody>>}
  */
  static from_json: (json: string) => Promise<Optional<HeaderBody>>;

  /**
  * @returns {Promise<number>}
  */
  block_number: () => Promise<number>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  slot: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<BigNum>}
  */
  slot_bignum: () => Promise<BigNum>;

  /**
  * @returns {Promise<Optional<BlockHash>>}
  */
  prev_hash: () => Promise<Optional<BlockHash>>;

  /**
  * @returns {Promise<Vkey>}
  */
  issuer_vkey: () => Promise<Vkey>;

  /**
  * @returns {Promise<VRFVKey>}
  */
  vrf_vkey: () => Promise<VRFVKey>;

  /**
  * @returns {Promise<boolean>}
  */
  has_nonce_and_leader_vrf: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<VRFCert>>}
  */
  nonce_vrf_or_nothing: () => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<Optional<VRFCert>>}
  */
  leader_vrf_or_nothing: () => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<boolean>}
  */
  has_vrf_result: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<VRFCert>>}
  */
  vrf_result_or_nothing: () => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<number>}
  */
  block_body_size: () => Promise<number>;

  /**
  * @returns {Promise<BlockHash>}
  */
  block_body_hash: () => Promise<BlockHash>;

  /**
  * @returns {Promise<OperationalCert>}
  */
  operational_cert: () => Promise<OperationalCert>;

  /**
  * @returns {Promise<ProtocolVersion>}
  */
  protocol_version: () => Promise<ProtocolVersion>;

  /**
  * @param {number} block_number
  * @param {number} slot
  * @param {Optional<BlockHash>} prev_hash
  * @param {Vkey} issuer_vkey
  * @param {VRFVKey} vrf_vkey
  * @param {VRFCert} vrf_result
  * @param {number} block_body_size
  * @param {BlockHash} block_body_hash
  * @param {OperationalCert} operational_cert
  * @param {ProtocolVersion} protocol_version
  * @returns {Promise<HeaderBody>}
  */
  static new: (block_number: number, slot: number, prev_hash: Optional<BlockHash>, issuer_vkey: Vkey, vrf_vkey: VRFVKey, vrf_result: VRFCert, block_body_size: number, block_body_hash: BlockHash, operational_cert: OperationalCert, protocol_version: ProtocolVersion) => Promise<HeaderBody>;

  /**
  * @param {number} block_number
  * @param {BigNum} slot
  * @param {Optional<BlockHash>} prev_hash
  * @param {Vkey} issuer_vkey
  * @param {VRFVKey} vrf_vkey
  * @param {VRFCert} vrf_result
  * @param {number} block_body_size
  * @param {BlockHash} block_body_hash
  * @param {OperationalCert} operational_cert
  * @param {ProtocolVersion} protocol_version
  * @returns {Promise<HeaderBody>}
  */
  static new_headerbody: (block_number: number, slot: BigNum, prev_hash: Optional<BlockHash>, issuer_vkey: Vkey, vrf_vkey: VRFVKey, vrf_result: VRFCert, block_body_size: number, block_body_hash: BlockHash, operational_cert: OperationalCert, protocol_version: ProtocolVersion) => Promise<HeaderBody>;

}


export class InputWithScriptWitness extends Ptr {
  /**
  * @param {TransactionInput} input
  * @param {NativeScript} witness
  * @returns {Promise<InputWithScriptWitness>}
  */
  static new_with_native_script_witness: (input: TransactionInput, witness: NativeScript) => Promise<InputWithScriptWitness>;

  /**
  * @param {TransactionInput} input
  * @param {PlutusWitness} witness
  * @returns {Promise<InputWithScriptWitness>}
  */
  static new_with_plutus_witness: (input: TransactionInput, witness: PlutusWitness) => Promise<InputWithScriptWitness>;

  /**
  * @returns {Promise<TransactionInput>}
  */
  input: () => Promise<TransactionInput>;

}


export class InputsWithScriptWitness extends Ptr {
  /**
  * @returns {Promise<InputsWithScriptWitness>}
  */
  static new: () => Promise<InputsWithScriptWitness>;

  /**
  * @param {InputWithScriptWitness} input
  */
  add: (input: InputWithScriptWitness) => Promise<void>;

  /**
  * @param {number} index
  * @returns {Promise<InputWithScriptWitness>}
  */
  get: (index: number) => Promise<InputWithScriptWitness>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class Int extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Int>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Int>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Int>>}
  */
  static from_json: (json: string) => Promise<Optional<Int>>;

  /**
  * @param {BigNum} x
  * @returns {Promise<Int>}
  */
  static new: (x: BigNum) => Promise<Int>;

  /**
  * @param {BigNum} x
  * @returns {Promise<Int>}
  */
  static new_negative: (x: BigNum) => Promise<Int>;

  /**
  * @param {number} x
  * @returns {Promise<Int>}
  */
  static new_i32: (x: number) => Promise<Int>;

  /**
  * @returns {Promise<boolean>}
  */
  is_positive: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  as_positive: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  as_negative: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  as_i32: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  as_i32_or_nothing: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  as_i32_or_fail: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<string>}
  */
  to_str: () => Promise<string>;

  /**
  * @param {string} string
  * @returns {Promise<Optional<Int>>}
  */
  static from_str: (string: string) => Promise<Optional<Int>>;

}


export class Ipv4 extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Ipv4>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Ipv4>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Ipv4>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Ipv4>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Ipv4>>}
  */
  static from_json: (json: string) => Promise<Optional<Ipv4>>;

  /**
  * @param {Uint8Array} data
  * @returns {Promise<Optional<Ipv4>>}
  */
  static new: (data: Uint8Array) => Promise<Optional<Ipv4>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  ip: () => Promise<Uint8Array>;

}


export class Ipv6 extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Ipv6>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Ipv6>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Ipv6>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Ipv6>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Ipv6>>}
  */
  static from_json: (json: string) => Promise<Optional<Ipv6>>;

  /**
  * @param {Uint8Array} data
  * @returns {Promise<Optional<Ipv6>>}
  */
  static new: (data: Uint8Array) => Promise<Optional<Ipv6>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  ip: () => Promise<Uint8Array>;

}


export class KESSignature extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<KESSignature>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<KESSignature>>;

}


export class KESVKey extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<KESVKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<KESVKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<KESVKey>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<KESVKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<KESVKey>>}
  */
  static from_hex: (hex: string) => Promise<Optional<KESVKey>>;

}


export class Language extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Language>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Language>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Language>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Language>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Language>>}
  */
  static from_json: (json: string) => Promise<Optional<Language>>;

  /**
  * @returns {Promise<Language>}
  */
  static new_plutus_v1: () => Promise<Language>;

  /**
  * @returns {Promise<Language>}
  */
  static new_plutus_v2: () => Promise<Language>;

  /**
  * @returns {Promise<LanguageKind>}
  */
  kind: () => Promise<LanguageKind>;

}


export class Languages extends Ptr {
  /**
  * @returns {Promise<Languages>}
  */
  static new: () => Promise<Languages>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Language>}
  */
  get: (index: number) => Promise<Language>;

  /**
  * @param {Language} elem
  */
  add: (elem: Language) => Promise<void>;

  /**
  * @returns {Promise<Languages>}
  */
  static list: () => Promise<Languages>;

}


export class LegacyDaedalusPrivateKey extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<LegacyDaedalusPrivateKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<LegacyDaedalusPrivateKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  chaincode: () => Promise<Uint8Array>;

}


export class LinearFee extends Ptr {
  /**
  * @returns {Promise<BigNum>}
  */
  constant: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  coefficient: () => Promise<BigNum>;

  /**
  * @param {BigNum} coefficient
  * @param {BigNum} constant
  * @returns {Promise<LinearFee>}
  */
  static new: (coefficient: BigNum, constant: BigNum) => Promise<LinearFee>;

}


export class MIRToStakeCredentials extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MIRToStakeCredentials>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MIRToStakeCredentials>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MIRToStakeCredentials>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MIRToStakeCredentials>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<MIRToStakeCredentials>>}
  */
  static from_json: (json: string) => Promise<Optional<MIRToStakeCredentials>>;

  /**
  * @returns {Promise<MIRToStakeCredentials>}
  */
  static new: () => Promise<MIRToStakeCredentials>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {StakeCredential} cred
  * @param {Int} delta
  * @returns {Promise<Optional<Int>>}
  */
  insert: (cred: StakeCredential, delta: Int) => Promise<Optional<Int>>;

  /**
  * @param {StakeCredential} cred
  * @returns {Promise<Optional<Int>>}
  */
  get: (cred: StakeCredential) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<StakeCredentials>}
  */
  keys: () => Promise<StakeCredentials>;

}


export class MetadataList extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MetadataList>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MetadataList>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MetadataList>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MetadataList>>;

  /**
  * @returns {Promise<MetadataList>}
  */
  static new: () => Promise<MetadataList>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionMetadatum>}
  */
  get: (index: number) => Promise<TransactionMetadatum>;

  /**
  * @param {TransactionMetadatum} elem
  */
  add: (elem: TransactionMetadatum) => Promise<void>;

}


export class MetadataMap extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MetadataMap>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MetadataMap>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MetadataMap>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MetadataMap>>;

  /**
  * @returns {Promise<MetadataMap>}
  */
  static new: () => Promise<MetadataMap>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {TransactionMetadatum} key
  * @param {TransactionMetadatum} value
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  insert: (key: TransactionMetadatum, value: TransactionMetadatum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {string} key
  * @param {TransactionMetadatum} value
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  insert_str: (key: string, value: TransactionMetadatum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {number} key
  * @param {TransactionMetadatum} value
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  insert_i32: (key: number, value: TransactionMetadatum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {TransactionMetadatum} key
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  get: (key: TransactionMetadatum) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {string} key
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  get_str: (key: string) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {number} key
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  get_i32: (key: number) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {TransactionMetadatum} key
  * @returns {Promise<boolean>}
  */
  has: (key: TransactionMetadatum) => Promise<boolean>;

  /**
  * @returns {Promise<MetadataList>}
  */
  keys: () => Promise<MetadataList>;

}


export class Mint extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Mint>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Mint>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Mint>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Mint>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Mint>>}
  */
  static from_json: (json: string) => Promise<Optional<Mint>>;

  /**
  * @returns {Promise<Mint>}
  */
  static new: () => Promise<Mint>;

  /**
  * @param {ScriptHash} key
  * @param {MintAssets} value
  * @returns {Promise<Mint>}
  */
  static new_from_entry: (key: ScriptHash, value: MintAssets) => Promise<Mint>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {ScriptHash} key
  * @param {MintAssets} value
  * @returns {Promise<Optional<MintAssets>>}
  */
  insert: (key: ScriptHash, value: MintAssets) => Promise<Optional<MintAssets>>;

  /**
  * @param {ScriptHash} key
  * @returns {Promise<Optional<MintAssets>>}
  */
  get: (key: ScriptHash) => Promise<Optional<MintAssets>>;

  /**
  * @param {ScriptHash} key
  * @returns {Promise<Optional<MintsAssets>>}
  */
  get_all: (key: ScriptHash) => Promise<Optional<MintsAssets>>;

  /**
  * @returns {Promise<ScriptHashes>}
  */
  keys: () => Promise<ScriptHashes>;

  /**
  * @returns {Promise<MultiAsset>}
  */
  as_positive_multiasset: () => Promise<MultiAsset>;

  /**
  * @returns {Promise<MultiAsset>}
  */
  as_negative_multiasset: () => Promise<MultiAsset>;

}


export class MintAssets extends Ptr {
  /**
  * @returns {Promise<MintAssets>}
  */
  static new: () => Promise<MintAssets>;

  /**
  * @param {AssetName} key
  * @param {Int} value
  * @returns {Promise<MintAssets>}
  */
  static new_from_entry: (key: AssetName, value: Int) => Promise<MintAssets>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {AssetName} key
  * @param {Int} value
  * @returns {Promise<Optional<Int>>}
  */
  insert: (key: AssetName, value: Int) => Promise<Optional<Int>>;

  /**
  * @param {AssetName} key
  * @returns {Promise<Optional<Int>>}
  */
  get: (key: AssetName) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<AssetNames>}
  */
  keys: () => Promise<AssetNames>;

}


export class MintBuilder extends Ptr {
  /**
  * @returns {Promise<MintBuilder>}
  */
  static new: () => Promise<MintBuilder>;

  /**
  * @param {MintWitness} mint
  * @param {AssetName} asset_name
  * @param {Int} amount
  */
  add_asset: (mint: MintWitness, asset_name: AssetName, amount: Int) => Promise<void>;

  /**
  * @param {MintWitness} mint
  * @param {AssetName} asset_name
  * @param {Int} amount
  */
  set_asset: (mint: MintWitness, asset_name: AssetName, amount: Int) => Promise<void>;

  /**
  * @returns {Promise<Mint>}
  */
  build: () => Promise<Mint>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  get_native_scripts: () => Promise<NativeScripts>;

  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  get_plutus_witnesses: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<Optional<Redeemers>>}
  */
  get_redeeemers: () => Promise<Optional<Redeemers>>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_scripts: () => Promise<boolean>;

  /**
  * @returns {Promise<boolean>}
  */
  has_native_scripts: () => Promise<boolean>;

}


export class MintWitness extends Ptr {
  /**
  * @param {NativeScript} native_script
  * @returns {Promise<MintWitness>}
  */
  static new_native_script: (native_script: NativeScript) => Promise<MintWitness>;

  /**
  * @param {PlutusScriptSource} plutus_script
  * @param {Redeemer} redeemer
  * @returns {Promise<MintWitness>}
  */
  static new_plutus_script: (plutus_script: PlutusScriptSource, redeemer: Redeemer) => Promise<MintWitness>;

}


export class MintsAssets extends Ptr {
}


export class MoveInstantaneousReward extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MoveInstantaneousReward>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MoveInstantaneousReward>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MoveInstantaneousReward>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MoveInstantaneousReward>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<MoveInstantaneousReward>>}
  */
  static from_json: (json: string) => Promise<Optional<MoveInstantaneousReward>>;

  /**
  * @param {MIRPot} pot
  * @param {BigNum} amount
  * @returns {Promise<MoveInstantaneousReward>}
  */
  static new_to_other_pot: (pot: MIRPot, amount: BigNum) => Promise<MoveInstantaneousReward>;

  /**
  * @param {MIRPot} pot
  * @param {MIRToStakeCredentials} amounts
  * @returns {Promise<MoveInstantaneousReward>}
  */
  static new_to_stake_creds: (pot: MIRPot, amounts: MIRToStakeCredentials) => Promise<MoveInstantaneousReward>;

  /**
  * @returns {Promise<MIRPot>}
  */
  pot: () => Promise<MIRPot>;

  /**
  * @returns {Promise<MIRKind>}
  */
  kind: () => Promise<MIRKind>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  as_to_other_pot: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<MIRToStakeCredentials>>}
  */
  as_to_stake_creds: () => Promise<Optional<MIRToStakeCredentials>>;

}


export class MoveInstantaneousRewardsCert extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MoveInstantaneousRewardsCert>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MoveInstantaneousRewardsCert>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MoveInstantaneousRewardsCert>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MoveInstantaneousRewardsCert>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<MoveInstantaneousRewardsCert>>}
  */
  static from_json: (json: string) => Promise<Optional<MoveInstantaneousRewardsCert>>;

  /**
  * @returns {Promise<MoveInstantaneousReward>}
  */
  move_instantaneous_reward: () => Promise<MoveInstantaneousReward>;

  /**
  * @param {MoveInstantaneousReward} move_instantaneous_reward
  * @returns {Promise<MoveInstantaneousRewardsCert>}
  */
  static new: (move_instantaneous_reward: MoveInstantaneousReward) => Promise<MoveInstantaneousRewardsCert>;

}


export class MultiAsset extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MultiAsset>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MultiAsset>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MultiAsset>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MultiAsset>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<MultiAsset>>}
  */
  static from_json: (json: string) => Promise<Optional<MultiAsset>>;

  /**
  * @returns {Promise<MultiAsset>}
  */
  static new: () => Promise<MultiAsset>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {ScriptHash} policy_id
  * @param {Assets} assets
  * @returns {Promise<Optional<Assets>>}
  */
  insert: (policy_id: ScriptHash, assets: Assets) => Promise<Optional<Assets>>;

  /**
  * @param {ScriptHash} policy_id
  * @returns {Promise<Optional<Assets>>}
  */
  get: (policy_id: ScriptHash) => Promise<Optional<Assets>>;

  /**
  * @param {ScriptHash} policy_id
  * @param {AssetName} asset_name
  * @param {BigNum} value
  * @returns {Promise<Optional<BigNum>>}
  */
  set_asset: (policy_id: ScriptHash, asset_name: AssetName, value: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {ScriptHash} policy_id
  * @param {AssetName} asset_name
  * @returns {Promise<BigNum>}
  */
  get_asset: (policy_id: ScriptHash, asset_name: AssetName) => Promise<BigNum>;

  /**
  * @returns {Promise<ScriptHashes>}
  */
  keys: () => Promise<ScriptHashes>;

  /**
  * @param {MultiAsset} rhs_ma
  * @returns {Promise<MultiAsset>}
  */
  sub: (rhs_ma: MultiAsset) => Promise<MultiAsset>;

}


export class MultiHostName extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<MultiHostName>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<MultiHostName>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<MultiHostName>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<MultiHostName>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<MultiHostName>>}
  */
  static from_json: (json: string) => Promise<Optional<MultiHostName>>;

  /**
  * @returns {Promise<DNSRecordSRV>}
  */
  dns_name: () => Promise<DNSRecordSRV>;

  /**
  * @param {DNSRecordSRV} dns_name
  * @returns {Promise<MultiHostName>}
  */
  static new: (dns_name: DNSRecordSRV) => Promise<MultiHostName>;

}


export class NativeScript extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<NativeScript>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<NativeScript>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<NativeScript>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<NativeScript>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<NativeScript>>}
  */
  static from_json: (json: string) => Promise<Optional<NativeScript>>;

  /**
  * @returns {Promise<ScriptHash>}
  */
  hash: () => Promise<ScriptHash>;

  /**
  * @param {ScriptPubkey} script_pubkey
  * @returns {Promise<NativeScript>}
  */
  static new_script_pubkey: (script_pubkey: ScriptPubkey) => Promise<NativeScript>;

  /**
  * @param {ScriptAll} script_all
  * @returns {Promise<NativeScript>}
  */
  static new_script_all: (script_all: ScriptAll) => Promise<NativeScript>;

  /**
  * @param {ScriptAny} script_any
  * @returns {Promise<NativeScript>}
  */
  static new_script_any: (script_any: ScriptAny) => Promise<NativeScript>;

  /**
  * @param {ScriptNOfK} script_n_of_k
  * @returns {Promise<NativeScript>}
  */
  static new_script_n_of_k: (script_n_of_k: ScriptNOfK) => Promise<NativeScript>;

  /**
  * @param {TimelockStart} timelock_start
  * @returns {Promise<NativeScript>}
  */
  static new_timelock_start: (timelock_start: TimelockStart) => Promise<NativeScript>;

  /**
  * @param {TimelockExpiry} timelock_expiry
  * @returns {Promise<NativeScript>}
  */
  static new_timelock_expiry: (timelock_expiry: TimelockExpiry) => Promise<NativeScript>;

  /**
  * @returns {Promise<NativeScriptKind>}
  */
  kind: () => Promise<NativeScriptKind>;

  /**
  * @returns {Promise<Optional<ScriptPubkey>>}
  */
  as_script_pubkey: () => Promise<Optional<ScriptPubkey>>;

  /**
  * @returns {Promise<Optional<ScriptAll>>}
  */
  as_script_all: () => Promise<Optional<ScriptAll>>;

  /**
  * @returns {Promise<Optional<ScriptAny>>}
  */
  as_script_any: () => Promise<Optional<ScriptAny>>;

  /**
  * @returns {Promise<Optional<ScriptNOfK>>}
  */
  as_script_n_of_k: () => Promise<Optional<ScriptNOfK>>;

  /**
  * @returns {Promise<Optional<TimelockStart>>}
  */
  as_timelock_start: () => Promise<Optional<TimelockStart>>;

  /**
  * @returns {Promise<Optional<TimelockExpiry>>}
  */
  as_timelock_expiry: () => Promise<Optional<TimelockExpiry>>;

  /**
  * @returns {Promise<Ed25519KeyHashes>}
  */
  get_required_signers: () => Promise<Ed25519KeyHashes>;

}


export class NativeScripts extends Ptr {
  /**
  * @returns {Promise<NativeScripts>}
  */
  static new: () => Promise<NativeScripts>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<NativeScript>}
  */
  get: (index: number) => Promise<NativeScript>;

  /**
  * @param {NativeScript} elem
  */
  add: (elem: NativeScript) => Promise<void>;

}


export class NetworkId extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<NetworkId>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<NetworkId>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<NetworkId>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<NetworkId>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<NetworkId>>}
  */
  static from_json: (json: string) => Promise<Optional<NetworkId>>;

  /**
  * @returns {Promise<NetworkId>}
  */
  static testnet: () => Promise<NetworkId>;

  /**
  * @returns {Promise<NetworkId>}
  */
  static mainnet: () => Promise<NetworkId>;

  /**
  * @returns {Promise<NetworkIdKind>}
  */
  kind: () => Promise<NetworkIdKind>;

}


export class NetworkInfo extends Ptr {
  /**
  * @param {number} network_id
  * @param {number} protocol_magic
  * @returns {Promise<NetworkInfo>}
  */
  static new: (network_id: number, protocol_magic: number) => Promise<NetworkInfo>;

  /**
  * @returns {Promise<number>}
  */
  network_id: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  protocol_magic: () => Promise<number>;

  /**
  * @returns {Promise<NetworkInfo>}
  */
  static testnet_preview: () => Promise<NetworkInfo>;

  /**
  * @returns {Promise<NetworkInfo>}
  */
  static testnet_preprod: () => Promise<NetworkInfo>;

  /**
  * @returns {Promise<NetworkInfo>}
  */
  static testnet: () => Promise<NetworkInfo>;

  /**
  * @returns {Promise<NetworkInfo>}
  */
  static mainnet: () => Promise<NetworkInfo>;

}


export class Nonce extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Nonce>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Nonce>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Nonce>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Nonce>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Nonce>>}
  */
  static from_json: (json: string) => Promise<Optional<Nonce>>;

  /**
  * @returns {Promise<Nonce>}
  */
  static new_identity: () => Promise<Nonce>;

  /**
  * @param {Uint8Array} hash
  * @returns {Promise<Optional<Nonce>>}
  */
  static new_from_hash: (hash: Uint8Array) => Promise<Optional<Nonce>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  get_hash: () => Promise<Uint8Array>;

}


export class OperationalCert extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<OperationalCert>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<OperationalCert>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<OperationalCert>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<OperationalCert>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<OperationalCert>>}
  */
  static from_json: (json: string) => Promise<Optional<OperationalCert>>;

  /**
  * @returns {Promise<KESVKey>}
  */
  hot_vkey: () => Promise<KESVKey>;

  /**
  * @returns {Promise<number>}
  */
  sequence_number: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  kes_period: () => Promise<number>;

  /**
  * @returns {Promise<Ed25519Signature>}
  */
  sigma: () => Promise<Ed25519Signature>;

  /**
  * @param {KESVKey} hot_vkey
  * @param {number} sequence_number
  * @param {number} kes_period
  * @param {Ed25519Signature} sigma
  * @returns {Promise<OperationalCert>}
  */
  static new: (hot_vkey: KESVKey, sequence_number: number, kes_period: number, sigma: Ed25519Signature) => Promise<OperationalCert>;

}


export class PlutusData extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusData>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PlutusData>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PlutusData>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PlutusData>>;

  /**
  * @param {ConstrPlutusData} constr_plutus_data
  * @returns {Promise<PlutusData>}
  */
  static new_constr_plutus_data: (constr_plutus_data: ConstrPlutusData) => Promise<PlutusData>;

  /**
  * @param {BigNum} alternative
  * @returns {Promise<PlutusData>}
  */
  static new_empty_constr_plutus_data: (alternative: BigNum) => Promise<PlutusData>;

  /**
  * @param {PlutusMap} map
  * @returns {Promise<PlutusData>}
  */
  static new_map: (map: PlutusMap) => Promise<PlutusData>;

  /**
  * @param {PlutusList} list
  * @returns {Promise<PlutusData>}
  */
  static new_list: (list: PlutusList) => Promise<PlutusData>;

  /**
  * @param {BigInt} integer
  * @returns {Promise<PlutusData>}
  */
  static new_integer: (integer: BigInt) => Promise<PlutusData>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusData>}
  */
  static new_bytes: (bytes: Uint8Array) => Promise<PlutusData>;

  /**
  * @returns {Promise<PlutusDataKind>}
  */
  kind: () => Promise<PlutusDataKind>;

  /**
  * @returns {Promise<Optional<ConstrPlutusData>>}
  */
  as_constr_plutus_data: () => Promise<Optional<ConstrPlutusData>>;

  /**
  * @returns {Promise<Optional<PlutusMap>>}
  */
  as_map: () => Promise<Optional<PlutusMap>>;

  /**
  * @returns {Promise<Optional<PlutusList>>}
  */
  as_list: () => Promise<Optional<PlutusList>>;

  /**
  * @returns {Promise<Optional<BigInt>>}
  */
  as_integer: () => Promise<Optional<BigInt>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {PlutusDatumSchema} schema
  * @returns {Promise<Optional<string>>}
  */
  to_json: (schema: PlutusDatumSchema) => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @param {PlutusDatumSchema} schema
  * @returns {Promise<Optional<PlutusData>>}
  */
  static from_json: (json: string, schema: PlutusDatumSchema) => Promise<Optional<PlutusData>>;

}


export class PlutusList extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusList>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PlutusList>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PlutusList>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PlutusList>>;

  /**
  * @returns {Promise<PlutusList>}
  */
  static new: () => Promise<PlutusList>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<PlutusData>}
  */
  get: (index: number) => Promise<PlutusData>;

  /**
  * @param {PlutusData} elem
  */
  add: (elem: PlutusData) => Promise<void>;

}


export class PlutusMap extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusMap>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PlutusMap>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PlutusMap>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PlutusMap>>;

  /**
  * @returns {Promise<PlutusMap>}
  */
  static new: () => Promise<PlutusMap>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {PlutusData} key
  * @param {PlutusData} value
  * @returns {Promise<Optional<PlutusData>>}
  */
  insert: (key: PlutusData, value: PlutusData) => Promise<Optional<PlutusData>>;

  /**
  * @param {PlutusData} key
  * @returns {Promise<Optional<PlutusData>>}
  */
  get: (key: PlutusData) => Promise<Optional<PlutusData>>;

  /**
  * @returns {Promise<PlutusList>}
  */
  keys: () => Promise<PlutusList>;

}


export class PlutusScript extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusScript>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PlutusScript>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PlutusScript>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PlutusScript>>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusScript>}
  */
  static new: (bytes: Uint8Array) => Promise<PlutusScript>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusScript>}
  */
  static new_v2: (bytes: Uint8Array) => Promise<PlutusScript>;

  /**
  * @param {Uint8Array} bytes
  * @param {Language} language
  * @returns {Promise<PlutusScript>}
  */
  static new_with_version: (bytes: Uint8Array, language: Language) => Promise<PlutusScript>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusScript>>}
  */
  static from_bytes_v2: (bytes: Uint8Array) => Promise<Optional<PlutusScript>>;

  /**
  * @param {Uint8Array} bytes
  * @param {Language} language
  * @returns {Promise<Optional<PlutusScript>>}
  */
  static from_bytes_with_version: (bytes: Uint8Array, language: Language) => Promise<Optional<PlutusScript>>;

  /**
  * @param {string} hex_str
  * @param {Language} language
  * @returns {Promise<Optional<PlutusScript>>}
  */
  static from_hex_with_version: (hex_str: string, language: Language) => Promise<Optional<PlutusScript>>;

  /**
  * @returns {Promise<ScriptHash>}
  */
  hash: () => Promise<ScriptHash>;

  /**
  * @returns {Promise<Language>}
  */
  language_version: () => Promise<Language>;

}


export class PlutusScriptSource extends Ptr {
  /**
  * @param {PlutusScript} script
  * @returns {Promise<PlutusScriptSource>}
  */
  static new: (script: PlutusScript) => Promise<PlutusScriptSource>;

  /**
  * @param {ScriptHash} script_hash
  * @param {TransactionInput} input
  * @returns {Promise<PlutusScriptSource>}
  */
  static new_ref_input: (script_hash: ScriptHash, input: TransactionInput) => Promise<PlutusScriptSource>;

  /**
  * @param {ScriptHash} script_hash
  * @param {TransactionInput} input
  * @param {Language} lang_ver
  * @returns {Promise<PlutusScriptSource>}
  */
  static new_ref_input_with_lang_ver: (script_hash: ScriptHash, input: TransactionInput, lang_ver: Language) => Promise<PlutusScriptSource>;

}


export class PlutusScripts extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PlutusScripts>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PlutusScripts>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PlutusScripts>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PlutusScripts>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<PlutusScripts>>}
  */
  static from_json: (json: string) => Promise<Optional<PlutusScripts>>;

  /**
  * @returns {Promise<PlutusScripts>}
  */
  static new: () => Promise<PlutusScripts>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<PlutusScript>}
  */
  get: (index: number) => Promise<PlutusScript>;

  /**
  * @param {PlutusScript} elem
  */
  add: (elem: PlutusScript) => Promise<void>;

}


export class PlutusWitness extends Ptr {
  /**
  * @param {PlutusScript} script
  * @param {PlutusData} datum
  * @param {Redeemer} redeemer
  * @returns {Promise<PlutusWitness>}
  */
  static new: (script: PlutusScript, datum: PlutusData, redeemer: Redeemer) => Promise<PlutusWitness>;

  /**
  * @param {PlutusScriptSource} script
  * @param {DatumSource} datum
  * @param {Redeemer} redeemer
  * @returns {Promise<PlutusWitness>}
  */
  static new_with_ref: (script: PlutusScriptSource, datum: DatumSource, redeemer: Redeemer) => Promise<PlutusWitness>;

  /**
  * @param {PlutusScript} script
  * @param {Redeemer} redeemer
  * @returns {Promise<PlutusWitness>}
  */
  static new_without_datum: (script: PlutusScript, redeemer: Redeemer) => Promise<PlutusWitness>;

  /**
  * @param {PlutusScriptSource} script
  * @param {Redeemer} redeemer
  * @returns {Promise<PlutusWitness>}
  */
  static new_with_ref_without_datum: (script: PlutusScriptSource, redeemer: Redeemer) => Promise<PlutusWitness>;

  /**
  * @returns {Promise<Optional<PlutusScript>>}
  */
  script: () => Promise<Optional<PlutusScript>>;

  /**
  * @returns {Promise<Optional<PlutusData>>}
  */
  datum: () => Promise<Optional<PlutusData>>;

  /**
  * @returns {Promise<Redeemer>}
  */
  redeemer: () => Promise<Redeemer>;

}


export class PlutusWitnesses extends Ptr {
  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  static new: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<PlutusWitness>}
  */
  get: (index: number) => Promise<PlutusWitness>;

  /**
  * @param {PlutusWitness} elem
  */
  add: (elem: PlutusWitness) => Promise<void>;

}


export class Pointer extends Ptr {
  /**
  * @param {number} slot
  * @param {number} tx_index
  * @param {number} cert_index
  * @returns {Promise<Pointer>}
  */
  static new: (slot: number, tx_index: number, cert_index: number) => Promise<Pointer>;

  /**
  * @param {BigNum} slot
  * @param {BigNum} tx_index
  * @param {BigNum} cert_index
  * @returns {Promise<Pointer>}
  */
  static new_pointer: (slot: BigNum, tx_index: BigNum, cert_index: BigNum) => Promise<Pointer>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  slot: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  tx_index: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  cert_index: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<BigNum>}
  */
  slot_bignum: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  tx_index_bignum: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  cert_index_bignum: () => Promise<BigNum>;

}


export class PointerAddress extends Ptr {
  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @param {Pointer} stake
  * @returns {Promise<PointerAddress>}
  */
  static new: (network: number, payment: StakeCredential, stake: Pointer) => Promise<PointerAddress>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<Pointer>}
  */
  stake_pointer: () => Promise<Pointer>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<PointerAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<PointerAddress>>;

}


export class PoolMetadata extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PoolMetadata>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PoolMetadata>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PoolMetadata>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PoolMetadata>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<PoolMetadata>>}
  */
  static from_json: (json: string) => Promise<Optional<PoolMetadata>>;

  /**
  * @returns {Promise<URL>}
  */
  url: () => Promise<URL>;

  /**
  * @returns {Promise<PoolMetadataHash>}
  */
  pool_metadata_hash: () => Promise<PoolMetadataHash>;

  /**
  * @param {URL} url
  * @param {PoolMetadataHash} pool_metadata_hash
  * @returns {Promise<PoolMetadata>}
  */
  static new: (url: URL, pool_metadata_hash: PoolMetadataHash) => Promise<PoolMetadata>;

}


export class PoolMetadataHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PoolMetadataHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PoolMetadataHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<PoolMetadataHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<PoolMetadataHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<PoolMetadataHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<PoolMetadataHash>>;

}


export class PoolParams extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PoolParams>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PoolParams>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PoolParams>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PoolParams>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<PoolParams>>}
  */
  static from_json: (json: string) => Promise<Optional<PoolParams>>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  operator: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<VRFKeyHash>}
  */
  vrf_keyhash: () => Promise<VRFKeyHash>;

  /**
  * @returns {Promise<BigNum>}
  */
  pledge: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  cost: () => Promise<BigNum>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  margin: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<RewardAddress>}
  */
  reward_account: () => Promise<RewardAddress>;

  /**
  * @returns {Promise<Ed25519KeyHashes>}
  */
  pool_owners: () => Promise<Ed25519KeyHashes>;

  /**
  * @returns {Promise<Relays>}
  */
  relays: () => Promise<Relays>;

  /**
  * @returns {Promise<Optional<PoolMetadata>>}
  */
  pool_metadata: () => Promise<Optional<PoolMetadata>>;

  /**
  * @param {Ed25519KeyHash} operator
  * @param {VRFKeyHash} vrf_keyhash
  * @param {BigNum} pledge
  * @param {BigNum} cost
  * @param {UnitInterval} margin
  * @param {RewardAddress} reward_account
  * @param {Ed25519KeyHashes} pool_owners
  * @param {Relays} relays
  * @param {Optional<PoolMetadata>} pool_metadata
  * @returns {Promise<PoolParams>}
  */
  static new: (operator: Ed25519KeyHash, vrf_keyhash: VRFKeyHash, pledge: BigNum, cost: BigNum, margin: UnitInterval, reward_account: RewardAddress, pool_owners: Ed25519KeyHashes, relays: Relays, pool_metadata: Optional<PoolMetadata>) => Promise<PoolParams>;

}


export class PoolRegistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PoolRegistration>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PoolRegistration>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PoolRegistration>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PoolRegistration>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<PoolRegistration>>}
  */
  static from_json: (json: string) => Promise<Optional<PoolRegistration>>;

  /**
  * @returns {Promise<PoolParams>}
  */
  pool_params: () => Promise<PoolParams>;

  /**
  * @param {PoolParams} pool_params
  * @returns {Promise<PoolRegistration>}
  */
  static new: (pool_params: PoolParams) => Promise<PoolRegistration>;

}


export class PoolRetirement extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PoolRetirement>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PoolRetirement>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PoolRetirement>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PoolRetirement>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<PoolRetirement>>}
  */
  static from_json: (json: string) => Promise<Optional<PoolRetirement>>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<number>}
  */
  epoch: () => Promise<number>;

  /**
  * @param {Ed25519KeyHash} pool_keyhash
  * @param {number} epoch
  * @returns {Promise<PoolRetirement>}
  */
  static new: (pool_keyhash: Ed25519KeyHash, epoch: number) => Promise<PoolRetirement>;

}


export class PrivateKey extends Ptr {
  /**
  * @returns {Promise<PublicKey>}
  */
  to_public: () => Promise<PublicKey>;

  /**
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static generate_ed25519: () => Promise<Optional<PrivateKey>>;

  /**
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static generate_ed25519extended: () => Promise<Optional<PrivateKey>>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static from_bech32: (bech32_str: string) => Promise<Optional<PrivateKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32: () => Promise<string>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static from_extended_bytes: (bytes: Uint8Array) => Promise<Optional<PrivateKey>>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static from_normal_bytes: (bytes: Uint8Array) => Promise<Optional<PrivateKey>>;

  /**
  * @param {Uint8Array} message
  * @returns {Promise<Ed25519Signature>}
  */
  sign: (message: Uint8Array) => Promise<Ed25519Signature>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PrivateKey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PrivateKey>>;

}


export class ProposedProtocolParameterUpdates extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ProposedProtocolParameterUpdates>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ProposedProtocolParameterUpdates>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ProposedProtocolParameterUpdates>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ProposedProtocolParameterUpdates>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ProposedProtocolParameterUpdates>>}
  */
  static from_json: (json: string) => Promise<Optional<ProposedProtocolParameterUpdates>>;

  /**
  * @returns {Promise<ProposedProtocolParameterUpdates>}
  */
  static new: () => Promise<ProposedProtocolParameterUpdates>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {GenesisHash} key
  * @param {ProtocolParamUpdate} value
  * @returns {Promise<Optional<ProtocolParamUpdate>>}
  */
  insert: (key: GenesisHash, value: ProtocolParamUpdate) => Promise<Optional<ProtocolParamUpdate>>;

  /**
  * @param {GenesisHash} key
  * @returns {Promise<Optional<ProtocolParamUpdate>>}
  */
  get: (key: GenesisHash) => Promise<Optional<ProtocolParamUpdate>>;

  /**
  * @returns {Promise<GenesisHashes>}
  */
  keys: () => Promise<GenesisHashes>;

}


export class ProtocolParamUpdate extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ProtocolParamUpdate>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ProtocolParamUpdate>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ProtocolParamUpdate>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ProtocolParamUpdate>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ProtocolParamUpdate>>}
  */
  static from_json: (json: string) => Promise<Optional<ProtocolParamUpdate>>;

  /**
  * @param {BigNum} minfee_a
  */
  set_minfee_a: (minfee_a: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  minfee_a: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} minfee_b
  */
  set_minfee_b: (minfee_b: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  minfee_b: () => Promise<Optional<BigNum>>;

  /**
  * @param {number} max_block_body_size
  */
  set_max_block_body_size: (max_block_body_size: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_block_body_size: () => Promise<Optional<number>>;

  /**
  * @param {number} max_tx_size
  */
  set_max_tx_size: (max_tx_size: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_tx_size: () => Promise<Optional<number>>;

  /**
  * @param {number} max_block_header_size
  */
  set_max_block_header_size: (max_block_header_size: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_block_header_size: () => Promise<Optional<number>>;

  /**
  * @param {BigNum} key_deposit
  */
  set_key_deposit: (key_deposit: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  key_deposit: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} pool_deposit
  */
  set_pool_deposit: (pool_deposit: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  pool_deposit: () => Promise<Optional<BigNum>>;

  /**
  * @param {number} max_epoch
  */
  set_max_epoch: (max_epoch: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_epoch: () => Promise<Optional<number>>;

  /**
  * @param {number} n_opt
  */
  set_n_opt: (n_opt: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  n_opt: () => Promise<Optional<number>>;

  /**
  * @param {UnitInterval} pool_pledge_influence
  */
  set_pool_pledge_influence: (pool_pledge_influence: UnitInterval) => Promise<void>;

  /**
  * @returns {Promise<Optional<UnitInterval>>}
  */
  pool_pledge_influence: () => Promise<Optional<UnitInterval>>;

  /**
  * @param {UnitInterval} expansion_rate
  */
  set_expansion_rate: (expansion_rate: UnitInterval) => Promise<void>;

  /**
  * @returns {Promise<Optional<UnitInterval>>}
  */
  expansion_rate: () => Promise<Optional<UnitInterval>>;

  /**
  * @param {UnitInterval} treasury_growth_rate
  */
  set_treasury_growth_rate: (treasury_growth_rate: UnitInterval) => Promise<void>;

  /**
  * @returns {Promise<Optional<UnitInterval>>}
  */
  treasury_growth_rate: () => Promise<Optional<UnitInterval>>;

  /**
  * @returns {Promise<Optional<UnitInterval>>}
  */
  d: () => Promise<Optional<UnitInterval>>;

  /**
  * @returns {Promise<Optional<Nonce>>}
  */
  extra_entropy: () => Promise<Optional<Nonce>>;

  /**
  * @param {ProtocolVersion} protocol_version
  */
  set_protocol_version: (protocol_version: ProtocolVersion) => Promise<void>;

  /**
  * @returns {Promise<Optional<ProtocolVersion>>}
  */
  protocol_version: () => Promise<Optional<ProtocolVersion>>;

  /**
  * @param {BigNum} min_pool_cost
  */
  set_min_pool_cost: (min_pool_cost: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  min_pool_cost: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} ada_per_utxo_byte
  */
  set_ada_per_utxo_byte: (ada_per_utxo_byte: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  ada_per_utxo_byte: () => Promise<Optional<BigNum>>;

  /**
  * @param {Costmdls} cost_models
  */
  set_cost_models: (cost_models: Costmdls) => Promise<void>;

  /**
  * @returns {Promise<Optional<Costmdls>>}
  */
  cost_models: () => Promise<Optional<Costmdls>>;

  /**
  * @param {ExUnitPrices} execution_costs
  */
  set_execution_costs: (execution_costs: ExUnitPrices) => Promise<void>;

  /**
  * @returns {Promise<Optional<ExUnitPrices>>}
  */
  execution_costs: () => Promise<Optional<ExUnitPrices>>;

  /**
  * @param {ExUnits} max_tx_ex_units
  */
  set_max_tx_ex_units: (max_tx_ex_units: ExUnits) => Promise<void>;

  /**
  * @returns {Promise<Optional<ExUnits>>}
  */
  max_tx_ex_units: () => Promise<Optional<ExUnits>>;

  /**
  * @param {ExUnits} max_block_ex_units
  */
  set_max_block_ex_units: (max_block_ex_units: ExUnits) => Promise<void>;

  /**
  * @returns {Promise<Optional<ExUnits>>}
  */
  max_block_ex_units: () => Promise<Optional<ExUnits>>;

  /**
  * @param {number} max_value_size
  */
  set_max_value_size: (max_value_size: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_value_size: () => Promise<Optional<number>>;

  /**
  * @param {number} collateral_percentage
  */
  set_collateral_percentage: (collateral_percentage: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  collateral_percentage: () => Promise<Optional<number>>;

  /**
  * @param {number} max_collateral_inputs
  */
  set_max_collateral_inputs: (max_collateral_inputs: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  max_collateral_inputs: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<ProtocolParamUpdate>}
  */
  static new: () => Promise<ProtocolParamUpdate>;

}


export class ProtocolVersion extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ProtocolVersion>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ProtocolVersion>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ProtocolVersion>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ProtocolVersion>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ProtocolVersion>>}
  */
  static from_json: (json: string) => Promise<Optional<ProtocolVersion>>;

  /**
  * @returns {Promise<number>}
  */
  major: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  minor: () => Promise<number>;

  /**
  * @param {number} major
  * @param {number} minor
  * @returns {Promise<ProtocolVersion>}
  */
  static new: (major: number, minor: number) => Promise<ProtocolVersion>;

}


export class PublicKey extends Ptr {
  /**
  * @param {string} bech32_str
  * @returns {Promise<Optional<PublicKey>>}
  */
  static from_bech32: (bech32_str: string) => Promise<Optional<PublicKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_bech32: () => Promise<string>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<PublicKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<PublicKey>>;

  /**
  * @param {Uint8Array} data
  * @param {Ed25519Signature} signature
  * @returns {Promise<boolean>}
  */
  verify: (data: Uint8Array, signature: Ed25519Signature) => Promise<boolean>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  hash: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<PublicKey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<PublicKey>>;

}


export class PublicKeys extends Ptr {
  /**
  * @returns {Promise<PublicKeys>}
  */
  static new: () => Promise<PublicKeys>;

  /**
  * @returns {Promise<number>}
  */
  size: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<PublicKey>}
  */
  get: (index: number) => Promise<PublicKey>;

  /**
  * @param {PublicKey} key
  */
  add: (key: PublicKey) => Promise<void>;

}


export class Redeemer extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Redeemer>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Redeemer>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Redeemer>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Redeemer>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Redeemer>>}
  */
  static from_json: (json: string) => Promise<Optional<Redeemer>>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  tag: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<BigNum>}
  */
  index: () => Promise<BigNum>;

  /**
  * @returns {Promise<PlutusData>}
  */
  data: () => Promise<PlutusData>;

  /**
  * @returns {Promise<ExUnits>}
  */
  ex_units: () => Promise<ExUnits>;

  /**
  * @param {RedeemerTag} tag
  * @param {BigNum} index
  * @param {PlutusData} data
  * @param {ExUnits} ex_units
  * @returns {Promise<Redeemer>}
  */
  static new: (tag: RedeemerTag, index: BigNum, data: PlutusData, ex_units: ExUnits) => Promise<Redeemer>;

}


export class RedeemerTag extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<RedeemerTag>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<RedeemerTag>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<RedeemerTag>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<RedeemerTag>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<RedeemerTag>>}
  */
  static from_json: (json: string) => Promise<Optional<RedeemerTag>>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  static new_spend: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  static new_mint: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  static new_cert: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  static new_reward: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<RedeemerTagKind>}
  */
  kind: () => Promise<RedeemerTagKind>;

}


export class Redeemers extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Redeemers>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Redeemers>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Redeemers>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Redeemers>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Redeemers>>}
  */
  static from_json: (json: string) => Promise<Optional<Redeemers>>;

  /**
  * @returns {Promise<Redeemers>}
  */
  static new: () => Promise<Redeemers>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Redeemer>}
  */
  get: (index: number) => Promise<Redeemer>;

  /**
  * @param {Redeemer} elem
  */
  add: (elem: Redeemer) => Promise<void>;

  /**
  * @returns {Promise<Optional<ExUnits>>}
  */
  total_ex_units: () => Promise<Optional<ExUnits>>;

}


export class Relay extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Relay>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Relay>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Relay>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Relay>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Relay>>}
  */
  static from_json: (json: string) => Promise<Optional<Relay>>;

  /**
  * @param {SingleHostAddr} single_host_addr
  * @returns {Promise<Relay>}
  */
  static new_single_host_addr: (single_host_addr: SingleHostAddr) => Promise<Relay>;

  /**
  * @param {SingleHostName} single_host_name
  * @returns {Promise<Relay>}
  */
  static new_single_host_name: (single_host_name: SingleHostName) => Promise<Relay>;

  /**
  * @param {MultiHostName} multi_host_name
  * @returns {Promise<Relay>}
  */
  static new_multi_host_name: (multi_host_name: MultiHostName) => Promise<Relay>;

  /**
  * @returns {Promise<RelayKind>}
  */
  kind: () => Promise<RelayKind>;

  /**
  * @returns {Promise<Optional<SingleHostAddr>>}
  */
  as_single_host_addr: () => Promise<Optional<SingleHostAddr>>;

  /**
  * @returns {Promise<Optional<SingleHostName>>}
  */
  as_single_host_name: () => Promise<Optional<SingleHostName>>;

  /**
  * @returns {Promise<Optional<MultiHostName>>}
  */
  as_multi_host_name: () => Promise<Optional<MultiHostName>>;

}


export class Relays extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Relays>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Relays>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Relays>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Relays>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Relays>>}
  */
  static from_json: (json: string) => Promise<Optional<Relays>>;

  /**
  * @returns {Promise<Relays>}
  */
  static new: () => Promise<Relays>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Relay>}
  */
  get: (index: number) => Promise<Relay>;

  /**
  * @param {Relay} elem
  */
  add: (elem: Relay) => Promise<void>;

}


export class RewardAddress extends Ptr {
  /**
  * @param {number} network
  * @param {StakeCredential} payment
  * @returns {Promise<RewardAddress>}
  */
  static new: (network: number, payment: StakeCredential) => Promise<RewardAddress>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  payment_cred: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<RewardAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<RewardAddress>>;

}


export class RewardAddresses extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<RewardAddresses>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<RewardAddresses>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<RewardAddresses>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<RewardAddresses>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<RewardAddresses>>}
  */
  static from_json: (json: string) => Promise<Optional<RewardAddresses>>;

  /**
  * @returns {Promise<RewardAddresses>}
  */
  static new: () => Promise<RewardAddresses>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<RewardAddress>}
  */
  get: (index: number) => Promise<RewardAddress>;

  /**
  * @param {RewardAddress} elem
  */
  add: (elem: RewardAddress) => Promise<void>;

}


export class ScriptAll extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptAll>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptAll>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptAll>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptAll>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptAll>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptAll>>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  native_scripts: () => Promise<NativeScripts>;

  /**
  * @param {NativeScripts} native_scripts
  * @returns {Promise<ScriptAll>}
  */
  static new: (native_scripts: NativeScripts) => Promise<ScriptAll>;

}


export class ScriptAny extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptAny>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptAny>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptAny>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptAny>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptAny>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptAny>>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  native_scripts: () => Promise<NativeScripts>;

  /**
  * @param {NativeScripts} native_scripts
  * @returns {Promise<ScriptAny>}
  */
  static new: (native_scripts: NativeScripts) => Promise<ScriptAny>;

}


export class ScriptDataHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptDataHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptDataHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<ScriptDataHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<ScriptDataHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<ScriptDataHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<ScriptDataHash>>;

}


export class ScriptHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<ScriptHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<ScriptHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<ScriptHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<ScriptHash>>;

}


export class ScriptHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptHashes>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptHashes>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptHashes>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptHashes>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptHashes>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptHashes>>;

  /**
  * @returns {Promise<ScriptHashes>}
  */
  static new: () => Promise<ScriptHashes>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<ScriptHash>}
  */
  get: (index: number) => Promise<ScriptHash>;

  /**
  * @param {ScriptHash} elem
  */
  add: (elem: ScriptHash) => Promise<void>;

}


export class ScriptNOfK extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptNOfK>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptNOfK>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptNOfK>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptNOfK>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptNOfK>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptNOfK>>;

  /**
  * @returns {Promise<number>}
  */
  n: () => Promise<number>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  native_scripts: () => Promise<NativeScripts>;

  /**
  * @param {number} n
  * @param {NativeScripts} native_scripts
  * @returns {Promise<ScriptNOfK>}
  */
  static new: (n: number, native_scripts: NativeScripts) => Promise<ScriptNOfK>;

}


export class ScriptPubkey extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptPubkey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptPubkey>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptPubkey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptPubkey>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptPubkey>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptPubkey>>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  addr_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @param {Ed25519KeyHash} addr_keyhash
  * @returns {Promise<ScriptPubkey>}
  */
  static new: (addr_keyhash: Ed25519KeyHash) => Promise<ScriptPubkey>;

}


export class ScriptRef extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<ScriptRef>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<ScriptRef>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<ScriptRef>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<ScriptRef>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<ScriptRef>>}
  */
  static from_json: (json: string) => Promise<Optional<ScriptRef>>;

  /**
  * @param {NativeScript} native_script
  * @returns {Promise<ScriptRef>}
  */
  static new_native_script: (native_script: NativeScript) => Promise<ScriptRef>;

  /**
  * @param {PlutusScript} plutus_script
  * @returns {Promise<ScriptRef>}
  */
  static new_plutus_script: (plutus_script: PlutusScript) => Promise<ScriptRef>;

  /**
  * @returns {Promise<boolean>}
  */
  is_native_script: () => Promise<boolean>;

  /**
  * @returns {Promise<boolean>}
  */
  is_plutus_script: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<NativeScript>>}
  */
  native_script: () => Promise<Optional<NativeScript>>;

  /**
  * @returns {Promise<Optional<PlutusScript>>}
  */
  plutus_script: () => Promise<Optional<PlutusScript>>;

}


export class SingleHostAddr extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<SingleHostAddr>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<SingleHostAddr>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<SingleHostAddr>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<SingleHostAddr>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<SingleHostAddr>>}
  */
  static from_json: (json: string) => Promise<Optional<SingleHostAddr>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  port: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<Ipv4>>}
  */
  ipv4: () => Promise<Optional<Ipv4>>;

  /**
  * @returns {Promise<Optional<Ipv6>>}
  */
  ipv6: () => Promise<Optional<Ipv6>>;

  /**
  * @param {Optional<number>} port
  * @param {Optional<Ipv4>} ipv4
  * @param {Optional<Ipv6>} ipv6
  * @returns {Promise<SingleHostAddr>}
  */
  static new: (port: Optional<number>, ipv4: Optional<Ipv4>, ipv6: Optional<Ipv6>) => Promise<SingleHostAddr>;

}


export class SingleHostName extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<SingleHostName>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<SingleHostName>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<SingleHostName>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<SingleHostName>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<SingleHostName>>}
  */
  static from_json: (json: string) => Promise<Optional<SingleHostName>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  port: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<DNSRecordAorAAAA>}
  */
  dns_name: () => Promise<DNSRecordAorAAAA>;

  /**
  * @param {Optional<number>} port
  * @param {DNSRecordAorAAAA} dns_name
  * @returns {Promise<SingleHostName>}
  */
  static new: (port: Optional<number>, dns_name: DNSRecordAorAAAA) => Promise<SingleHostName>;

}


export class StakeCredential extends Ptr {
  /**
  * @param {Ed25519KeyHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static from_keyhash: (hash: Ed25519KeyHash) => Promise<StakeCredential>;

  /**
  * @param {ScriptHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static from_scripthash: (hash: ScriptHash) => Promise<StakeCredential>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  to_keyhash: () => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  to_scripthash: () => Promise<Optional<ScriptHash>>;

  /**
  * @returns {Promise<StakeCredKind>}
  */
  kind: () => Promise<StakeCredKind>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<StakeCredential>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<StakeCredential>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<StakeCredential>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<StakeCredential>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<StakeCredential>>}
  */
  static from_json: (json: string) => Promise<Optional<StakeCredential>>;

}


export class StakeCredentials extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<StakeCredentials>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<StakeCredentials>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<StakeCredentials>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<StakeCredentials>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<StakeCredentials>>}
  */
  static from_json: (json: string) => Promise<Optional<StakeCredentials>>;

  /**
  * @returns {Promise<StakeCredentials>}
  */
  static new: () => Promise<StakeCredentials>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<StakeCredential>}
  */
  get: (index: number) => Promise<StakeCredential>;

  /**
  * @param {StakeCredential} elem
  */
  add: (elem: StakeCredential) => Promise<void>;

}


export class StakeDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<StakeDelegation>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<StakeDelegation>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<StakeDelegation>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<StakeDelegation>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<StakeDelegation>>}
  */
  static from_json: (json: string) => Promise<Optional<StakeDelegation>>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential: () => Promise<StakeCredential>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @param {StakeCredential} stake_credential
  * @param {Ed25519KeyHash} pool_keyhash
  * @returns {Promise<StakeDelegation>}
  */
  static new: (stake_credential: StakeCredential, pool_keyhash: Ed25519KeyHash) => Promise<StakeDelegation>;

}


export class StakeDeregistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<StakeDeregistration>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<StakeDeregistration>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<StakeDeregistration>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<StakeDeregistration>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<StakeDeregistration>>}
  */
  static from_json: (json: string) => Promise<Optional<StakeDeregistration>>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential: () => Promise<StakeCredential>;

  /**
  * @param {StakeCredential} stake_credential
  * @returns {Promise<StakeDeregistration>}
  */
  static new: (stake_credential: StakeCredential) => Promise<StakeDeregistration>;

}


export class StakeRegistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<StakeRegistration>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<StakeRegistration>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<StakeRegistration>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<StakeRegistration>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<StakeRegistration>>}
  */
  static from_json: (json: string) => Promise<Optional<StakeRegistration>>;

  /**
  * @returns {Promise<StakeCredential>}
  */
  stake_credential: () => Promise<StakeCredential>;

  /**
  * @param {StakeCredential} stake_credential
  * @returns {Promise<StakeRegistration>}
  */
  static new: (stake_credential: StakeCredential) => Promise<StakeRegistration>;

}


export class Strings extends Ptr {
  /**
  * @returns {Promise<Strings>}
  */
  static new: () => Promise<Strings>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<string>}
  */
  get: (index: number) => Promise<string>;

  /**
  * @param {string} elem
  */
  add: (elem: string) => Promise<void>;

}


export class TimelockExpiry extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TimelockExpiry>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TimelockExpiry>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TimelockExpiry>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TimelockExpiry>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TimelockExpiry>>}
  */
  static from_json: (json: string) => Promise<Optional<TimelockExpiry>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  slot: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<BigNum>}
  */
  slot_bignum: () => Promise<BigNum>;

  /**
  * @param {number} slot
  * @returns {Promise<TimelockExpiry>}
  */
  static new: (slot: number) => Promise<TimelockExpiry>;

  /**
  * @param {BigNum} slot
  * @returns {Promise<TimelockExpiry>}
  */
  static new_timelockexpiry: (slot: BigNum) => Promise<TimelockExpiry>;

}


export class TimelockStart extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TimelockStart>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TimelockStart>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TimelockStart>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TimelockStart>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TimelockStart>>}
  */
  static from_json: (json: string) => Promise<Optional<TimelockStart>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  slot: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<BigNum>}
  */
  slot_bignum: () => Promise<BigNum>;

  /**
  * @param {number} slot
  * @returns {Promise<TimelockStart>}
  */
  static new: (slot: number) => Promise<TimelockStart>;

  /**
  * @param {BigNum} slot
  * @returns {Promise<TimelockStart>}
  */
  static new_timelockstart: (slot: BigNum) => Promise<TimelockStart>;

}


export class Transaction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Transaction>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Transaction>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Transaction>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Transaction>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Transaction>>}
  */
  static from_json: (json: string) => Promise<Optional<Transaction>>;

  /**
  * @returns {Promise<TransactionBody>}
  */
  body: () => Promise<TransactionBody>;

  /**
  * @returns {Promise<TransactionWitnessSet>}
  */
  witness_set: () => Promise<TransactionWitnessSet>;

  /**
  * @returns {Promise<boolean>}
  */
  is_valid: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  auxiliary_data: () => Promise<Optional<AuxiliaryData>>;

  /**
  * @param {boolean} valid
  */
  set_is_valid: (valid: boolean) => Promise<void>;

  /**
  * @param {TransactionBody} body
  * @param {TransactionWitnessSet} witness_set
  * @param {Optional<AuxiliaryData>} auxiliary_data
  * @returns {Promise<Transaction>}
  */
  static new: (body: TransactionBody, witness_set: TransactionWitnessSet, auxiliary_data: Optional<AuxiliaryData>) => Promise<Transaction>;

}


export class TransactionBatch extends Ptr {
  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Transaction>}
  */
  get: (index: number) => Promise<Transaction>;

}


export class TransactionBatchList extends Ptr {
  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionBatch>}
  */
  get: (index: number) => Promise<TransactionBatch>;

}


export class TransactionBodies extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionBodies>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionBodies>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionBodies>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionBodies>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionBodies>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionBodies>>;

  /**
  * @returns {Promise<TransactionBodies>}
  */
  static new: () => Promise<TransactionBodies>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionBody>}
  */
  get: (index: number) => Promise<TransactionBody>;

  /**
  * @param {TransactionBody} elem
  */
  add: (elem: TransactionBody) => Promise<void>;

}


export class TransactionBody extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionBody>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionBody>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionBody>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionBody>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionBody>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionBody>>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<TransactionOutputs>}
  */
  outputs: () => Promise<TransactionOutputs>;

  /**
  * @returns {Promise<BigNum>}
  */
  fee: () => Promise<BigNum>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  ttl: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  ttl_bignum: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} ttl
  */
  set_ttl: (ttl: BigNum) => Promise<void>;

  /**
  */
  remove_ttl: () => Promise<void>;

  /**
  * @param {Certificates} certs
  */
  set_certs: (certs: Certificates) => Promise<void>;

  /**
  * @returns {Promise<Optional<Certificates>>}
  */
  certs: () => Promise<Optional<Certificates>>;

  /**
  * @param {Withdrawals} withdrawals
  */
  set_withdrawals: (withdrawals: Withdrawals) => Promise<void>;

  /**
  * @returns {Promise<Optional<Withdrawals>>}
  */
  withdrawals: () => Promise<Optional<Withdrawals>>;

  /**
  * @param {Update} update
  */
  set_update: (update: Update) => Promise<void>;

  /**
  * @returns {Promise<Optional<Update>>}
  */
  update: () => Promise<Optional<Update>>;

  /**
  * @param {AuxiliaryDataHash} auxiliary_data_hash
  */
  set_auxiliary_data_hash: (auxiliary_data_hash: AuxiliaryDataHash) => Promise<void>;

  /**
  * @returns {Promise<Optional<AuxiliaryDataHash>>}
  */
  auxiliary_data_hash: () => Promise<Optional<AuxiliaryDataHash>>;

  /**
  * @param {number} validity_start_interval
  */
  set_validity_start_interval: (validity_start_interval: number) => Promise<void>;

  /**
  * @param {BigNum} validity_start_interval
  */
  set_validity_start_interval_bignum: (validity_start_interval: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  validity_start_interval_bignum: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  validity_start_interval: () => Promise<Optional<number>>;

  /**
  * @param {Mint} mint
  */
  set_mint: (mint: Mint) => Promise<void>;

  /**
  * @returns {Promise<Optional<Mint>>}
  */
  mint: () => Promise<Optional<Mint>>;

  /**
  * @returns {Promise<Optional<Mint>>}
  */
  multiassets: () => Promise<Optional<Mint>>;

  /**
  * @param {TransactionInputs} reference_inputs
  */
  set_reference_inputs: (reference_inputs: TransactionInputs) => Promise<void>;

  /**
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  reference_inputs: () => Promise<Optional<TransactionInputs>>;

  /**
  * @param {ScriptDataHash} script_data_hash
  */
  set_script_data_hash: (script_data_hash: ScriptDataHash) => Promise<void>;

  /**
  * @returns {Promise<Optional<ScriptDataHash>>}
  */
  script_data_hash: () => Promise<Optional<ScriptDataHash>>;

  /**
  * @param {TransactionInputs} collateral
  */
  set_collateral: (collateral: TransactionInputs) => Promise<void>;

  /**
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  collateral: () => Promise<Optional<TransactionInputs>>;

  /**
  * @param {Ed25519KeyHashes} required_signers
  */
  set_required_signers: (required_signers: Ed25519KeyHashes) => Promise<void>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHashes>>}
  */
  required_signers: () => Promise<Optional<Ed25519KeyHashes>>;

  /**
  * @param {NetworkId} network_id
  */
  set_network_id: (network_id: NetworkId) => Promise<void>;

  /**
  * @returns {Promise<Optional<NetworkId>>}
  */
  network_id: () => Promise<Optional<NetworkId>>;

  /**
  * @param {TransactionOutput} collateral_return
  */
  set_collateral_return: (collateral_return: TransactionOutput) => Promise<void>;

  /**
  * @returns {Promise<Optional<TransactionOutput>>}
  */
  collateral_return: () => Promise<Optional<TransactionOutput>>;

  /**
  * @param {BigNum} total_collateral
  */
  set_total_collateral: (total_collateral: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  total_collateral: () => Promise<Optional<BigNum>>;

  /**
  * @param {TransactionInputs} inputs
  * @param {TransactionOutputs} outputs
  * @param {BigNum} fee
  * @param {Optional<number>} ttl
  * @returns {Promise<TransactionBody>}
  */
  static new: (inputs: TransactionInputs, outputs: TransactionOutputs, fee: BigNum, ttl: Optional<number>) => Promise<TransactionBody>;

  /**
  * @param {TransactionInputs} inputs
  * @param {TransactionOutputs} outputs
  * @param {BigNum} fee
  * @returns {Promise<TransactionBody>}
  */
  static new_tx_body: (inputs: TransactionInputs, outputs: TransactionOutputs, fee: BigNum) => Promise<TransactionBody>;

}


export class TransactionBuilder extends Ptr {
  /**
  * @param {TransactionUnspentOutputs} inputs
  * @param {CoinSelectionStrategyCIP2} strategy
  * @returns {Promise<void>}
  */
  add_inputs_from: (inputs: TransactionUnspentOutputs, strategy: CoinSelectionStrategyCIP2) => Promise<void>;

  /**
  * @param {TxInputsBuilder} inputs
  */
  set_inputs: (inputs: TxInputsBuilder) => Promise<void>;

  /**
  * @param {TxInputsBuilder} collateral
  */
  set_collateral: (collateral: TxInputsBuilder) => Promise<void>;

  /**
  * @param {TransactionOutput} collateral_return
  */
  set_collateral_return: (collateral_return: TransactionOutput) => Promise<void>;

  /**
  * @param {TransactionOutput} collateral_return
  * @returns {Promise<void>}
  */
  set_collateral_return_and_total: (collateral_return: TransactionOutput) => Promise<void>;

  /**
  * @param {BigNum} total_collateral
  */
  set_total_collateral: (total_collateral: BigNum) => Promise<void>;

  /**
  * @param {BigNum} total_collateral
  * @param {Address} return_address
  * @returns {Promise<void>}
  */
  set_total_collateral_and_return: (total_collateral: BigNum, return_address: Address) => Promise<void>;

  /**
  * @param {TransactionInput} reference_input
  */
  add_reference_input: (reference_input: TransactionInput) => Promise<void>;

  /**
  * @param {Ed25519KeyHash} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_key_input: (hash: Ed25519KeyHash, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {ScriptHash} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_script_input: (hash: ScriptHash, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {NativeScript} script
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_native_script_input: (script: NativeScript, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {PlutusWitness} witness
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_plutus_script_input: (witness: PlutusWitness, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {ByronAddress} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_bootstrap_input: (hash: ByronAddress, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {Address} address
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_input: (address: Address, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @returns {Promise<number>}
  */
  count_missing_input_scripts: () => Promise<number>;

  /**
  * @param {NativeScripts} scripts
  * @returns {Promise<number>}
  */
  add_required_native_input_scripts: (scripts: NativeScripts) => Promise<number>;

  /**
  * @param {PlutusWitnesses} scripts
  * @returns {Promise<number>}
  */
  add_required_plutus_input_scripts: (scripts: PlutusWitnesses) => Promise<number>;

  /**
  * @returns {Promise<Optional<NativeScripts>>}
  */
  get_native_input_scripts: () => Promise<Optional<NativeScripts>>;

  /**
  * @returns {Promise<Optional<PlutusWitnesses>>}
  */
  get_plutus_input_scripts: () => Promise<Optional<PlutusWitnesses>>;

  /**
  * @param {Address} address
  * @param {TransactionInput} input
  * @param {Value} amount
  * @returns {Promise<Optional<BigNum>>}
  */
  fee_for_input: (address: Address, input: TransactionInput, amount: Value) => Promise<Optional<BigNum>>;

  /**
  * @param {TransactionOutput} output
  * @returns {Promise<void>}
  */
  add_output: (output: TransactionOutput) => Promise<void>;

  /**
  * @param {TransactionOutput} output
  * @returns {Promise<Optional<BigNum>>}
  */
  fee_for_output: (output: TransactionOutput) => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} fee
  */
  set_fee: (fee: BigNum) => Promise<void>;

  /**
  * @param {number} ttl
  */
  set_ttl: (ttl: number) => Promise<void>;

  /**
  * @param {BigNum} ttl
  */
  set_ttl_bignum: (ttl: BigNum) => Promise<void>;

  /**
  * @param {number} validity_start_interval
  */
  set_validity_start_interval: (validity_start_interval: number) => Promise<void>;

  /**
  * @param {BigNum} validity_start_interval
  */
  set_validity_start_interval_bignum: (validity_start_interval: BigNum) => Promise<void>;

  /**
  * @param {Certificates} certs
  */
  set_certs: (certs: Certificates) => Promise<void>;

  /**
  * @param {Withdrawals} withdrawals
  */
  set_withdrawals: (withdrawals: Withdrawals) => Promise<void>;

  /**
  * @returns {Promise<Optional<AuxiliaryData>>}
  */
  get_auxiliary_data: () => Promise<Optional<AuxiliaryData>>;

  /**
  * @param {AuxiliaryData} auxiliary_data
  */
  set_auxiliary_data: (auxiliary_data: AuxiliaryData) => Promise<void>;

  /**
  * @param {GeneralTransactionMetadata} metadata
  */
  set_metadata: (metadata: GeneralTransactionMetadata) => Promise<void>;

  /**
  * @param {BigNum} key
  * @param {TransactionMetadatum} val
  */
  add_metadatum: (key: BigNum, val: TransactionMetadatum) => Promise<void>;

  /**
  * @param {BigNum} key
  * @param {string} val
  * @returns {Promise<void>}
  */
  add_json_metadatum: (key: BigNum, val: string) => Promise<void>;

  /**
  * @param {BigNum} key
  * @param {string} val
  * @param {MetadataJsonSchema} schema
  * @returns {Promise<void>}
  */
  add_json_metadatum_with_schema: (key: BigNum, val: string, schema: MetadataJsonSchema) => Promise<void>;

  /**
  * @param {MintBuilder} mint_builder
  */
  set_mint_builder: (mint_builder: MintBuilder) => Promise<void>;

  /**
  * @returns {Promise<Optional<MintBuilder>>}
  */
  get_mint_builder: () => Promise<Optional<MintBuilder>>;

  /**
  * @param {Mint} mint
  * @param {NativeScripts} mint_scripts
  * @returns {Promise<void>}
  */
  set_mint: (mint: Mint, mint_scripts: NativeScripts) => Promise<void>;

  /**
  * @returns {Promise<Optional<Mint>>}
  */
  get_mint: () => Promise<Optional<Mint>>;

  /**
  * @returns {Promise<Optional<NativeScripts>>}
  */
  get_mint_scripts: () => Promise<Optional<NativeScripts>>;

  /**
  * @param {NativeScript} policy_script
  * @param {MintAssets} mint_assets
  */
  set_mint_asset: (policy_script: NativeScript, mint_assets: MintAssets) => Promise<void>;

  /**
  * @param {NativeScript} policy_script
  * @param {AssetName} asset_name
  * @param {Int} amount
  */
  add_mint_asset: (policy_script: NativeScript, asset_name: AssetName, amount: Int) => Promise<void>;

  /**
  * @param {NativeScript} policy_script
  * @param {AssetName} asset_name
  * @param {Int} amount
  * @param {TransactionOutputAmountBuilder} output_builder
  * @param {BigNum} output_coin
  * @returns {Promise<void>}
  */
  add_mint_asset_and_output: (policy_script: NativeScript, asset_name: AssetName, amount: Int, output_builder: TransactionOutputAmountBuilder, output_coin: BigNum) => Promise<void>;

  /**
  * @param {NativeScript} policy_script
  * @param {AssetName} asset_name
  * @param {Int} amount
  * @param {TransactionOutputAmountBuilder} output_builder
  * @returns {Promise<void>}
  */
  add_mint_asset_and_output_min_required_coin: (policy_script: NativeScript, asset_name: AssetName, amount: Int, output_builder: TransactionOutputAmountBuilder) => Promise<void>;

  /**
  * @param {TransactionBuilderConfig} cfg
  * @returns {Promise<TransactionBuilder>}
  */
  static new: (cfg: TransactionBuilderConfig) => Promise<TransactionBuilder>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_reference_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  get_explicit_input: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  get_implicit_input: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  get_total_input: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  get_total_output: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  get_explicit_output: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  get_deposit: () => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  get_fee_if_set: () => Promise<Optional<BigNum>>;

  /**
  * @param {Address} address
  * @returns {Promise<Optional<boolean>>}
  */
  add_change_if_needed: (address: Address) => Promise<Optional<boolean>>;

  /**
  * @param {Costmdls} cost_models
  * @returns {Promise<void>}
  */
  calc_script_data_hash: (cost_models: Costmdls) => Promise<void>;

  /**
  * @param {ScriptDataHash} hash
  */
  set_script_data_hash: (hash: ScriptDataHash) => Promise<void>;

  /**
  */
  remove_script_data_hash: () => Promise<void>;

  /**
  * @param {Ed25519KeyHash} key
  */
  add_required_signer: (key: Ed25519KeyHash) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  full_size: () => Promise<Optional<number>>;

  /**
  * @returns {Promise<Uint32Array>}
  */
  output_sizes: () => Promise<Uint32Array>;

  /**
  * @returns {Promise<Optional<TransactionBody>>}
  */
  build: () => Promise<Optional<TransactionBody>>;

  /**
  * @returns {Promise<Optional<Transaction>>}
  */
  build_tx: () => Promise<Optional<Transaction>>;

  /**
  * @returns {Promise<Optional<Transaction>>}
  */
  build_tx_unsafe: () => Promise<Optional<Transaction>>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  min_fee: () => Promise<Optional<BigNum>>;

}


export class TransactionBuilderConfig extends Ptr {
}


export class TransactionBuilderConfigBuilder extends Ptr {
  /**
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  static new: () => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {LinearFee} fee_algo
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  fee_algo: (fee_algo: LinearFee) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {BigNum} coins_per_utxo_word
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  coins_per_utxo_word: (coins_per_utxo_word: BigNum) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {BigNum} coins_per_utxo_byte
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  coins_per_utxo_byte: (coins_per_utxo_byte: BigNum) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {ExUnitPrices} ex_unit_prices
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  ex_unit_prices: (ex_unit_prices: ExUnitPrices) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {BigNum} pool_deposit
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  pool_deposit: (pool_deposit: BigNum) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {BigNum} key_deposit
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  key_deposit: (key_deposit: BigNum) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {number} max_value_size
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  max_value_size: (max_value_size: number) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {number} max_tx_size
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  max_tx_size: (max_tx_size: number) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @param {boolean} prefer_pure_change
  * @returns {Promise<TransactionBuilderConfigBuilder>}
  */
  prefer_pure_change: (prefer_pure_change: boolean) => Promise<TransactionBuilderConfigBuilder>;

  /**
  * @returns {Promise<Optional<TransactionBuilderConfig>>}
  */
  build: () => Promise<Optional<TransactionBuilderConfig>>;

}


export class TransactionHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<TransactionHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<TransactionHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<TransactionHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<TransactionHash>>;

}


export class TransactionInput extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionInput>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionInput>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionInput>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionInput>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionInput>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionInput>>;

  /**
  * @returns {Promise<TransactionHash>}
  */
  transaction_id: () => Promise<TransactionHash>;

  /**
  * @returns {Promise<number>}
  */
  index: () => Promise<number>;

  /**
  * @param {TransactionHash} transaction_id
  * @param {number} index
  * @returns {Promise<TransactionInput>}
  */
  static new: (transaction_id: TransactionHash, index: number) => Promise<TransactionInput>;

}


export class TransactionInputs extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionInputs>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionInputs>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionInputs>>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  static new: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionInput>}
  */
  get: (index: number) => Promise<TransactionInput>;

  /**
  * @param {TransactionInput} elem
  */
  add: (elem: TransactionInput) => Promise<void>;

  /**
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  to_option: () => Promise<Optional<TransactionInputs>>;

}


export class TransactionMetadatum extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {MetadataMap} map
  * @returns {Promise<TransactionMetadatum>}
  */
  static new_map: (map: MetadataMap) => Promise<TransactionMetadatum>;

  /**
  * @param {MetadataList} list
  * @returns {Promise<TransactionMetadatum>}
  */
  static new_list: (list: MetadataList) => Promise<TransactionMetadatum>;

  /**
  * @param {Int} int_value
  * @returns {Promise<TransactionMetadatum>}
  */
  static new_int: (int_value: Int) => Promise<TransactionMetadatum>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  static new_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @param {string} text
  * @returns {Promise<Optional<TransactionMetadatum>>}
  */
  static new_text: (text: string) => Promise<Optional<TransactionMetadatum>>;

  /**
  * @returns {Promise<TransactionMetadatumKind>}
  */
  kind: () => Promise<TransactionMetadatumKind>;

  /**
  * @returns {Promise<Optional<MetadataMap>>}
  */
  as_map: () => Promise<Optional<MetadataMap>>;

  /**
  * @returns {Promise<Optional<MetadataList>>}
  */
  as_list: () => Promise<Optional<MetadataList>>;

  /**
  * @returns {Promise<Optional<Int>>}
  */
  as_int: () => Promise<Optional<Int>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  as_text: () => Promise<Optional<string>>;

}


export class TransactionMetadatumLabels extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionMetadatumLabels>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionMetadatumLabels>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionMetadatumLabels>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionMetadatumLabels>>;

  /**
  * @returns {Promise<TransactionMetadatumLabels>}
  */
  static new: () => Promise<TransactionMetadatumLabels>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<BigNum>}
  */
  get: (index: number) => Promise<BigNum>;

  /**
  * @param {BigNum} elem
  */
  add: (elem: BigNum) => Promise<void>;

}


export class TransactionOutput extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionOutput>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionOutput>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionOutput>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionOutput>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionOutput>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionOutput>>;

  /**
  * @returns {Promise<Address>}
  */
  address: () => Promise<Address>;

  /**
  * @returns {Promise<Value>}
  */
  amount: () => Promise<Value>;

  /**
  * @returns {Promise<Optional<DataHash>>}
  */
  data_hash: () => Promise<Optional<DataHash>>;

  /**
  * @returns {Promise<Optional<PlutusData>>}
  */
  plutus_data: () => Promise<Optional<PlutusData>>;

  /**
  * @returns {Promise<Optional<ScriptRef>>}
  */
  script_ref: () => Promise<Optional<ScriptRef>>;

  /**
  * @param {ScriptRef} script_ref
  */
  set_script_ref: (script_ref: ScriptRef) => Promise<void>;

  /**
  * @param {PlutusData} data
  */
  set_plutus_data: (data: PlutusData) => Promise<void>;

  /**
  * @param {DataHash} data_hash
  */
  set_data_hash: (data_hash: DataHash) => Promise<void>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_data: () => Promise<boolean>;

  /**
  * @returns {Promise<boolean>}
  */
  has_data_hash: () => Promise<boolean>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_ref: () => Promise<boolean>;

  /**
  * @param {Address} address
  * @param {Value} amount
  * @returns {Promise<TransactionOutput>}
  */
  static new: (address: Address, amount: Value) => Promise<TransactionOutput>;

}


export class TransactionOutputAmountBuilder extends Ptr {
  /**
  * @param {Value} amount
  * @returns {Promise<TransactionOutputAmountBuilder>}
  */
  with_value: (amount: Value) => Promise<TransactionOutputAmountBuilder>;

  /**
  * @param {BigNum} coin
  * @returns {Promise<TransactionOutputAmountBuilder>}
  */
  with_coin: (coin: BigNum) => Promise<TransactionOutputAmountBuilder>;

  /**
  * @param {BigNum} coin
  * @param {MultiAsset} multiasset
  * @returns {Promise<TransactionOutputAmountBuilder>}
  */
  with_coin_and_asset: (coin: BigNum, multiasset: MultiAsset) => Promise<TransactionOutputAmountBuilder>;

  /**
  * @param {MultiAsset} multiasset
  * @param {BigNum} coins_per_utxo_word
  * @returns {Promise<Optional<TransactionOutputAmountBuilder>>}
  */
  with_asset_and_min_required_coin: (multiasset: MultiAsset, coins_per_utxo_word: BigNum) => Promise<Optional<TransactionOutputAmountBuilder>>;

  /**
  * @param {MultiAsset} multiasset
  * @param {DataCost} data_cost
  * @returns {Promise<Optional<TransactionOutputAmountBuilder>>}
  */
  with_asset_and_min_required_coin_by_utxo_cost: (multiasset: MultiAsset, data_cost: DataCost) => Promise<Optional<TransactionOutputAmountBuilder>>;

  /**
  * @returns {Promise<Optional<TransactionOutput>>}
  */
  build: () => Promise<Optional<TransactionOutput>>;

}


export class TransactionOutputBuilder extends Ptr {
  /**
  * @returns {Promise<TransactionOutputBuilder>}
  */
  static new: () => Promise<TransactionOutputBuilder>;

  /**
  * @param {Address} address
  * @returns {Promise<TransactionOutputBuilder>}
  */
  with_address: (address: Address) => Promise<TransactionOutputBuilder>;

  /**
  * @param {DataHash} data_hash
  * @returns {Promise<TransactionOutputBuilder>}
  */
  with_data_hash: (data_hash: DataHash) => Promise<TransactionOutputBuilder>;

  /**
  * @param {PlutusData} data
  * @returns {Promise<TransactionOutputBuilder>}
  */
  with_plutus_data: (data: PlutusData) => Promise<TransactionOutputBuilder>;

  /**
  * @param {ScriptRef} script_ref
  * @returns {Promise<TransactionOutputBuilder>}
  */
  with_script_ref: (script_ref: ScriptRef) => Promise<TransactionOutputBuilder>;

  /**
  * @returns {Promise<Optional<TransactionOutputAmountBuilder>>}
  */
  next: () => Promise<Optional<TransactionOutputAmountBuilder>>;

}


export class TransactionOutputs extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionOutputs>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionOutputs>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionOutputs>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionOutputs>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionOutputs>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionOutputs>>;

  /**
  * @returns {Promise<TransactionOutputs>}
  */
  static new: () => Promise<TransactionOutputs>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionOutput>}
  */
  get: (index: number) => Promise<TransactionOutput>;

  /**
  * @param {TransactionOutput} elem
  */
  add: (elem: TransactionOutput) => Promise<void>;

}


export class TransactionUnspentOutput extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionUnspentOutput>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionUnspentOutput>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionUnspentOutput>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionUnspentOutput>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionUnspentOutput>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionUnspentOutput>>;

  /**
  * @param {TransactionInput} input
  * @param {TransactionOutput} output
  * @returns {Promise<TransactionUnspentOutput>}
  */
  static new: (input: TransactionInput, output: TransactionOutput) => Promise<TransactionUnspentOutput>;

  /**
  * @returns {Promise<TransactionInput>}
  */
  input: () => Promise<TransactionInput>;

  /**
  * @returns {Promise<TransactionOutput>}
  */
  output: () => Promise<TransactionOutput>;

}


export class TransactionUnspentOutputs extends Ptr {
  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionUnspentOutputs>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionUnspentOutputs>>;

  /**
  * @returns {Promise<TransactionUnspentOutputs>}
  */
  static new: () => Promise<TransactionUnspentOutputs>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionUnspentOutput>}
  */
  get: (index: number) => Promise<TransactionUnspentOutput>;

  /**
  * @param {TransactionUnspentOutput} elem
  */
  add: (elem: TransactionUnspentOutput) => Promise<void>;

}


export class TransactionWitnessSet extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionWitnessSet>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionWitnessSet>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionWitnessSet>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionWitnessSet>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionWitnessSet>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionWitnessSet>>;

  /**
  * @param {Vkeywitnesses} vkeys
  */
  set_vkeys: (vkeys: Vkeywitnesses) => Promise<void>;

  /**
  * @returns {Promise<Optional<Vkeywitnesses>>}
  */
  vkeys: () => Promise<Optional<Vkeywitnesses>>;

  /**
  * @param {NativeScripts} native_scripts
  */
  set_native_scripts: (native_scripts: NativeScripts) => Promise<void>;

  /**
  * @returns {Promise<Optional<NativeScripts>>}
  */
  native_scripts: () => Promise<Optional<NativeScripts>>;

  /**
  * @param {BootstrapWitnesses} bootstraps
  */
  set_bootstraps: (bootstraps: BootstrapWitnesses) => Promise<void>;

  /**
  * @returns {Promise<Optional<BootstrapWitnesses>>}
  */
  bootstraps: () => Promise<Optional<BootstrapWitnesses>>;

  /**
  * @param {PlutusScripts} plutus_scripts
  */
  set_plutus_scripts: (plutus_scripts: PlutusScripts) => Promise<void>;

  /**
  * @returns {Promise<Optional<PlutusScripts>>}
  */
  plutus_scripts: () => Promise<Optional<PlutusScripts>>;

  /**
  * @param {PlutusList} plutus_data
  */
  set_plutus_data: (plutus_data: PlutusList) => Promise<void>;

  /**
  * @returns {Promise<Optional<PlutusList>>}
  */
  plutus_data: () => Promise<Optional<PlutusList>>;

  /**
  * @param {Redeemers} redeemers
  */
  set_redeemers: (redeemers: Redeemers) => Promise<void>;

  /**
  * @returns {Promise<Optional<Redeemers>>}
  */
  redeemers: () => Promise<Optional<Redeemers>>;

  /**
  * @returns {Promise<TransactionWitnessSet>}
  */
  static new: () => Promise<TransactionWitnessSet>;

}


export class TransactionWitnessSets extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<TransactionWitnessSets>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<TransactionWitnessSets>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<TransactionWitnessSets>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<TransactionWitnessSets>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<TransactionWitnessSets>>}
  */
  static from_json: (json: string) => Promise<Optional<TransactionWitnessSets>>;

  /**
  * @returns {Promise<TransactionWitnessSets>}
  */
  static new: () => Promise<TransactionWitnessSets>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<TransactionWitnessSet>}
  */
  get: (index: number) => Promise<TransactionWitnessSet>;

  /**
  * @param {TransactionWitnessSet} elem
  */
  add: (elem: TransactionWitnessSet) => Promise<void>;

}


export class TxBuilderConstants extends Ptr {
  /**
  * @returns {Promise<Costmdls>}
  */
  static plutus_default_cost_models: () => Promise<Costmdls>;

  /**
  * @returns {Promise<Costmdls>}
  */
  static plutus_alonzo_cost_models: () => Promise<Costmdls>;

  /**
  * @returns {Promise<Costmdls>}
  */
  static plutus_vasil_cost_models: () => Promise<Costmdls>;

}


export class TxInputsBuilder extends Ptr {
  /**
  * @returns {Promise<TxInputsBuilder>}
  */
  static new: () => Promise<TxInputsBuilder>;

  /**
  * @param {Ed25519KeyHash} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_key_input: (hash: Ed25519KeyHash, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {ScriptHash} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_script_input: (hash: ScriptHash, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {NativeScript} script
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_native_script_input: (script: NativeScript, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {PlutusWitness} witness
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_plutus_script_input: (witness: PlutusWitness, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {ByronAddress} hash
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_bootstrap_input: (hash: ByronAddress, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @param {Address} address
  * @param {TransactionInput} input
  * @param {Value} amount
  */
  add_input: (address: Address, input: TransactionInput, amount: Value) => Promise<void>;

  /**
  * @returns {Promise<number>}
  */
  count_missing_input_scripts: () => Promise<number>;

  /**
  * @param {NativeScripts} scripts
  * @returns {Promise<number>}
  */
  add_required_native_input_scripts: (scripts: NativeScripts) => Promise<number>;

  /**
  * @param {PlutusWitnesses} scripts
  * @returns {Promise<number>}
  */
  add_required_plutus_input_scripts: (scripts: PlutusWitnesses) => Promise<number>;

  /**
  * @param {InputsWithScriptWitness} inputs_with_wit
  * @returns {Promise<number>}
  */
  add_required_script_input_witnesses: (inputs_with_wit: InputsWithScriptWitness) => Promise<number>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<Optional<NativeScripts>>}
  */
  get_native_input_scripts: () => Promise<Optional<NativeScripts>>;

  /**
  * @returns {Promise<Optional<PlutusWitnesses>>}
  */
  get_plutus_input_scripts: () => Promise<Optional<PlutusWitnesses>>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {Ed25519KeyHash} key
  */
  add_required_signer: (key: Ed25519KeyHash) => Promise<void>;

  /**
  * @param {Ed25519KeyHashes} keys
  */
  add_required_signers: (keys: Ed25519KeyHashes) => Promise<void>;

  /**
  * @returns {Promise<Optional<Value>>}
  */
  total_value: () => Promise<Optional<Value>>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<Optional<TransactionInputs>>}
  */
  inputs_option: () => Promise<Optional<TransactionInputs>>;

}


export class URL extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<URL>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<URL>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<URL>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<URL>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<URL>>}
  */
  static from_json: (json: string) => Promise<Optional<URL>>;

  /**
  * @param {string} url
  * @returns {Promise<Optional<URL>>}
  */
  static new: (url: string) => Promise<Optional<URL>>;

  /**
  * @returns {Promise<string>}
  */
  url: () => Promise<string>;

}


export class UnitInterval extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<UnitInterval>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<UnitInterval>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<UnitInterval>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<UnitInterval>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<UnitInterval>>}
  */
  static from_json: (json: string) => Promise<Optional<UnitInterval>>;

  /**
  * @returns {Promise<BigNum>}
  */
  numerator: () => Promise<BigNum>;

  /**
  * @returns {Promise<BigNum>}
  */
  denominator: () => Promise<BigNum>;

  /**
  * @param {BigNum} numerator
  * @param {BigNum} denominator
  * @returns {Promise<UnitInterval>}
  */
  static new: (numerator: BigNum, denominator: BigNum) => Promise<UnitInterval>;

}


export class Update extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Update>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Update>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Update>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Update>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Update>>}
  */
  static from_json: (json: string) => Promise<Optional<Update>>;

  /**
  * @returns {Promise<ProposedProtocolParameterUpdates>}
  */
  proposed_protocol_parameter_updates: () => Promise<ProposedProtocolParameterUpdates>;

  /**
  * @returns {Promise<number>}
  */
  epoch: () => Promise<number>;

  /**
  * @param {ProposedProtocolParameterUpdates} proposed_protocol_parameter_updates
  * @param {number} epoch
  * @returns {Promise<Update>}
  */
  static new: (proposed_protocol_parameter_updates: ProposedProtocolParameterUpdates, epoch: number) => Promise<Update>;

}


export class VRFCert extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<VRFCert>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<VRFCert>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<VRFCert>>}
  */
  static from_json: (json: string) => Promise<Optional<VRFCert>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  output: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  proof: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} output
  * @param {Uint8Array} proof
  * @returns {Promise<Optional<VRFCert>>}
  */
  static new: (output: Uint8Array, proof: Uint8Array) => Promise<Optional<VRFCert>>;

}


export class VRFKeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<VRFKeyHash>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<VRFKeyHash>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<VRFKeyHash>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<VRFKeyHash>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<VRFKeyHash>>}
  */
  static from_hex: (hex: string) => Promise<Optional<VRFKeyHash>>;

}


export class VRFVKey extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<VRFVKey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<VRFVKey>>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<Optional<string>>}
  */
  to_bech32: (prefix: string) => Promise<Optional<string>>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Optional<VRFVKey>>}
  */
  static from_bech32: (bech_str: string) => Promise<Optional<VRFVKey>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Optional<VRFVKey>>}
  */
  static from_hex: (hex: string) => Promise<Optional<VRFVKey>>;

}


export class Value extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Value>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Value>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Value>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Value>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Value>>}
  */
  static from_json: (json: string) => Promise<Optional<Value>>;

  /**
  * @param {BigNum} coin
  * @returns {Promise<Value>}
  */
  static new: (coin: BigNum) => Promise<Value>;

  /**
  * @param {MultiAsset} multiasset
  * @returns {Promise<Value>}
  */
  static new_from_assets: (multiasset: MultiAsset) => Promise<Value>;

  /**
  * @param {BigNum} coin
  * @param {MultiAsset} multiasset
  * @returns {Promise<Value>}
  */
  static new_with_assets: (coin: BigNum, multiasset: MultiAsset) => Promise<Value>;

  /**
  * @returns {Promise<Value>}
  */
  static zero: () => Promise<Value>;

  /**
  * @returns {Promise<boolean>}
  */
  is_zero: () => Promise<boolean>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @param {BigNum} coin
  */
  set_coin: (coin: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<MultiAsset>>}
  */
  multiasset: () => Promise<Optional<MultiAsset>>;

  /**
  * @param {MultiAsset} multiasset
  */
  set_multiasset: (multiasset: MultiAsset) => Promise<void>;

  /**
  * @param {Value} rhs
  * @returns {Promise<Optional<Value>>}
  */
  checked_add: (rhs: Value) => Promise<Optional<Value>>;

  /**
  * @param {Value} rhs_value
  * @returns {Promise<Optional<Value>>}
  */
  checked_sub: (rhs_value: Value) => Promise<Optional<Value>>;

  /**
  * @param {Value} rhs_value
  * @returns {Promise<Value>}
  */
  clamped_sub: (rhs_value: Value) => Promise<Value>;

  /**
  * @param {Value} rhs_value
  * @returns {Promise<Optional<number>>}
  */
  compare: (rhs_value: Value) => Promise<Optional<number>>;

}


export class Vkey extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Vkey>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Vkey>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Vkey>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Vkey>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Vkey>>}
  */
  static from_json: (json: string) => Promise<Optional<Vkey>>;

  /**
  * @param {PublicKey} pk
  * @returns {Promise<Vkey>}
  */
  static new: (pk: PublicKey) => Promise<Vkey>;

  /**
  * @returns {Promise<PublicKey>}
  */
  public_key: () => Promise<PublicKey>;

}


export class Vkeys extends Ptr {
  /**
  * @returns {Promise<Vkeys>}
  */
  static new: () => Promise<Vkeys>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Vkey>}
  */
  get: (index: number) => Promise<Vkey>;

  /**
  * @param {Vkey} elem
  */
  add: (elem: Vkey) => Promise<void>;

}


export class Vkeywitness extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Vkeywitness>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Vkeywitness>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Vkeywitness>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Vkeywitness>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Vkeywitness>>}
  */
  static from_json: (json: string) => Promise<Optional<Vkeywitness>>;

  /**
  * @param {Vkey} vkey
  * @param {Ed25519Signature} signature
  * @returns {Promise<Vkeywitness>}
  */
  static new: (vkey: Vkey, signature: Ed25519Signature) => Promise<Vkeywitness>;

  /**
  * @returns {Promise<Vkey>}
  */
  vkey: () => Promise<Vkey>;

  /**
  * @returns {Promise<Ed25519Signature>}
  */
  signature: () => Promise<Ed25519Signature>;

}


export class Vkeywitnesses extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Vkeywitnesses>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Vkeywitnesses>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Vkeywitnesses>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Vkeywitnesses>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Vkeywitnesses>>}
  */
  static from_json: (json: string) => Promise<Optional<Vkeywitnesses>>;

  /**
  * @returns {Promise<Vkeywitnesses>}
  */
  static new: () => Promise<Vkeywitnesses>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Vkeywitness>}
  */
  get: (index: number) => Promise<Vkeywitness>;

  /**
  * @param {Vkeywitness} elem
  */
  add: (elem: Vkeywitness) => Promise<void>;

}


export class Withdrawals extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Optional<Withdrawals>>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Optional<Withdrawals>>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Optional<Withdrawals>>}
  */
  static from_hex: (hex_str: string) => Promise<Optional<Withdrawals>>;

  /**
  * @returns {Promise<Optional<string>>}
  */
  to_json: () => Promise<Optional<string>>;

  /**
  * @param {string} json
  * @returns {Promise<Optional<Withdrawals>>}
  */
  static from_json: (json: string) => Promise<Optional<Withdrawals>>;

  /**
  * @returns {Promise<Withdrawals>}
  */
  static new: () => Promise<Withdrawals>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {RewardAddress} key
  * @param {BigNum} value
  * @returns {Promise<Optional<BigNum>>}
  */
  insert: (key: RewardAddress, value: BigNum) => Promise<Optional<BigNum>>;

  /**
  * @param {RewardAddress} key
  * @returns {Promise<Optional<BigNum>>}
  */
  get: (key: RewardAddress) => Promise<Optional<BigNum>>;

  /**
  * @returns {Promise<RewardAddresses>}
  */
  keys: () => Promise<RewardAddresses>;

}


/**
* @param {ExUnits} ex_units
* @param {ExUnitPrices} ex_unit_prices
* @returns {Promise<Optional<BigNum>>}
*/
export const calculate_ex_units_ceil_cost: (ex_units: ExUnits, ex_unit_prices: ExUnitPrices) => Promise<Optional<BigNum>>;

/**
* @param {Address} address
* @param {TransactionUnspentOutputs} utxos
* @param {TransactionBuilderConfig} config
* @returns {Promise<Optional<TransactionBatchList>>}
*/
export const create_send_all: (address: Address, utxos: TransactionUnspentOutputs, config: TransactionBuilderConfig) => Promise<Optional<TransactionBatchList>>;

/**
* @param {TransactionMetadatum} metadata
* @returns {Promise<Uint8Array>}
*/
export const decode_arbitrary_bytes_from_metadatum: (metadata: TransactionMetadatum) => Promise<Uint8Array>;

/**
* @param {TransactionMetadatum} metadatum
* @param {MetadataJsonSchema} schema
* @returns {Promise<Optional<string>>}
*/
export const decode_metadatum_to_json_str: (metadatum: TransactionMetadatum, schema: MetadataJsonSchema) => Promise<Optional<string>>;

/**
* @param {PlutusData} datum
* @param {PlutusDatumSchema} schema
* @returns {Promise<Optional<string>>}
*/
export const decode_plutus_datum_to_json_str: (datum: PlutusData, schema: PlutusDatumSchema) => Promise<Optional<string>>;

/**
* @param {string} password
* @param {string} data
* @returns {Promise<Optional<string>>}
*/
export const decrypt_with_password: (password: string, data: string) => Promise<Optional<string>>;

/**
* @param {Uint8Array} bytes
* @returns {Promise<TransactionMetadatum>}
*/
export const encode_arbitrary_bytes_as_metadatum: (bytes: Uint8Array) => Promise<TransactionMetadatum>;

/**
* @param {string} json
* @param {MetadataJsonSchema} schema
* @returns {Promise<Optional<TransactionMetadatum>>}
*/
export const encode_json_str_to_metadatum: (json: string, schema: MetadataJsonSchema) => Promise<Optional<TransactionMetadatum>>;

/**
* @param {string} json
* @param {string} self_xpub
* @param {ScriptSchema} schema
* @returns {Promise<Optional<NativeScript>>}
*/
export const encode_json_str_to_native_script: (json: string, self_xpub: string, schema: ScriptSchema) => Promise<Optional<NativeScript>>;

/**
* @param {string} json
* @param {PlutusDatumSchema} schema
* @returns {Promise<Optional<PlutusData>>}
*/
export const encode_json_str_to_plutus_datum: (json: string, schema: PlutusDatumSchema) => Promise<Optional<PlutusData>>;

/**
* @param {string} password
* @param {string} salt
* @param {string} nonce
* @param {string} data
* @returns {Promise<Optional<string>>}
*/
export const encrypt_with_password: (password: string, salt: string, nonce: string, data: string) => Promise<Optional<string>>;

/**
* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {Promise<Optional<BigNum>>}
*/
export const get_deposit: (txbody: TransactionBody, pool_deposit: BigNum, key_deposit: BigNum) => Promise<Optional<BigNum>>;

/**
* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {Promise<Optional<Value>>}
*/
export const get_implicit_input: (txbody: TransactionBody, pool_deposit: BigNum, key_deposit: BigNum) => Promise<Optional<Value>>;

/**
* @param {AuxiliaryData} auxiliary_data
* @returns {Promise<AuxiliaryDataHash>}
*/
export const hash_auxiliary_data: (auxiliary_data: AuxiliaryData) => Promise<AuxiliaryDataHash>;

/**
* @param {PlutusData} plutus_data
* @returns {Promise<DataHash>}
*/
export const hash_plutus_data: (plutus_data: PlutusData) => Promise<DataHash>;

/**
* @param {Redeemers} redeemers
* @param {Costmdls} cost_models
* @param {Optional<PlutusList>} datums
* @returns {Promise<ScriptDataHash>}
*/
export const hash_script_data: (redeemers: Redeemers, cost_models: Costmdls, datums: Optional<PlutusList>) => Promise<ScriptDataHash>;

/**
* @param {TransactionBody} tx_body
* @returns {Promise<TransactionHash>}
*/
export const hash_transaction: (tx_body: TransactionBody) => Promise<TransactionHash>;

/**
* @param {TransactionHash} tx_body_hash
* @param {ByronAddress} addr
* @param {LegacyDaedalusPrivateKey} key
* @returns {Promise<BootstrapWitness>}
*/
export const make_daedalus_bootstrap_witness: (tx_body_hash: TransactionHash, addr: ByronAddress, key: LegacyDaedalusPrivateKey) => Promise<BootstrapWitness>;

/**
* @param {TransactionHash} tx_body_hash
* @param {ByronAddress} addr
* @param {Bip32PrivateKey} key
* @returns {Promise<BootstrapWitness>}
*/
export const make_icarus_bootstrap_witness: (tx_body_hash: TransactionHash, addr: ByronAddress, key: Bip32PrivateKey) => Promise<BootstrapWitness>;

/**
* @param {TransactionHash} tx_body_hash
* @param {PrivateKey} sk
* @returns {Promise<Vkeywitness>}
*/
export const make_vkey_witness: (tx_body_hash: TransactionHash, sk: PrivateKey) => Promise<Vkeywitness>;

/**
* @param {TransactionOutput} output
* @param {DataCost} data_cost
* @returns {Promise<Optional<BigNum>>}
*/
export const min_ada_for_output: (output: TransactionOutput, data_cost: DataCost) => Promise<Optional<BigNum>>;

/**
* @param {Value} assets
* @param {boolean} has_data_hash
* @param {BigNum} coins_per_utxo_word
* @returns {Promise<Optional<BigNum>>}
*/
export const min_ada_required: (assets: Value, has_data_hash: boolean, coins_per_utxo_word: BigNum) => Promise<Optional<BigNum>>;

/**
* @param {Transaction} tx
* @param {LinearFee} linear_fee
* @returns {Promise<Optional<BigNum>>}
*/
export const min_fee: (tx: Transaction, linear_fee: LinearFee) => Promise<Optional<BigNum>>;

/**
* @param {Transaction} tx
* @param {ExUnitPrices} ex_unit_prices
* @returns {Promise<Optional<BigNum>>}
*/
export const min_script_fee: (tx: Transaction, ex_unit_prices: ExUnitPrices) => Promise<Optional<BigNum>>;

export enum CertificateKind {
  StakeRegistration = 0,
  StakeDeregistration = 1,
  StakeDelegation = 2,
  PoolRegistration = 3,
  PoolRetirement = 4,
  GenesisKeyDelegation = 5,
  MoveInstantaneousRewardsCert = 6,
}


export enum CoinSelectionStrategyCIP2 {
  LargestFirst = 0,
  RandomImprove = 1,
  LargestFirstMultiAsset = 2,
  RandomImproveMultiAsset = 3,
}


export enum LanguageKind {
  PlutusV1 = 0,
  PlutusV2 = 1,
}


export enum MIRKind {
  ToOtherPot = 0,
  ToStakeCredentials = 1,
}


export enum MIRPot {
  Reserves = 0,
  Treasury = 1,
}


export enum MetadataJsonSchema {
  NoConversions = 0,
  BasicConversions = 1,
  DetailedSchema = 2,
}


export enum NativeScriptKind {
  ScriptPubkey = 0,
  ScriptAll = 1,
  ScriptAny = 2,
  ScriptNOfK = 3,
  TimelockStart = 4,
  TimelockExpiry = 5,
}


export enum NetworkIdKind {
  Testnet = 0,
  Mainnet = 1,
}


export enum PlutusDataKind {
  ConstrPlutusData = 0,
  Map = 1,
  List = 2,
  Integer = 3,
  Bytes = 4,
}


export enum PlutusDatumSchema {
  BasicConversions = 0,
  DetailedSchema = 1,
}


export enum RedeemerTagKind {
  Spend = 0,
  Mint = 1,
  Cert = 2,
  Reward = 3,
}


export enum RelayKind {
  SingleHostAddr = 0,
  SingleHostName = 1,
  MultiHostName = 2,
}


export enum ScriptHashNamespace {
  NativeScript = 0,
  PlutusScript = 1,
  PlutusScriptV2 = 2,
}


export enum ScriptSchema {
  Wallet = 0,
  Node = 1,
}


export enum StakeCredKind {
  Key = 0,
  Script = 1,
}


export enum TransactionMetadatumKind {
  MetadataMap = 0,
  MetadataList = 1,
  Int = 2,
  Bytes = 3,
  Text = 4,
}


