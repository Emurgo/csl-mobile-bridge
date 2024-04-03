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
  * @returns {Promise<Address>}
  */
  static from_bytes: (data: Uint8Array) => Promise<Address>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Address>}
  */
  static from_json: (json: string) => Promise<Address>;

  /**
  * @returns {Promise<boolean>}
  */
  is_malformed: () => Promise<boolean>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Address>}
  */
  static from_hex: (hex_str: string) => Promise<Address>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Optional<string>} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: Optional<string>) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Address>}
  */
  static from_bech32: (bech_str: string) => Promise<Address>;

  /**
  * @returns {Promise<number>}
  */
  network_id: () => Promise<number>;

}


export class Anchor extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Anchor>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Anchor>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Anchor>}
  */
  static from_hex: (hex_str: string) => Promise<Anchor>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Anchor>}
  */
  static from_json: (json: string) => Promise<Anchor>;

  /**
  * @returns {Promise<URL>}
  */
  url: () => Promise<URL>;

  /**
  * @returns {Promise<AnchorDataHash>}
  */
  anchor_data_hash: () => Promise<AnchorDataHash>;

  /**
  * @param {URL} anchor_url
  * @param {AnchorDataHash} anchor_data_hash
  * @returns {Promise<Anchor>}
  */
  static new: (anchor_url: URL, anchor_data_hash: AnchorDataHash) => Promise<Anchor>;

}


export class AnchorDataHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<AnchorDataHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<AnchorDataHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<AnchorDataHash>}
  */
  static from_bech32: (bech_str: string) => Promise<AnchorDataHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<AnchorDataHash>}
  */
  static from_hex: (hex: string) => Promise<AnchorDataHash>;

}


export class AssetName extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<AssetName>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<AssetName>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<AssetName>}
  */
  static from_hex: (hex_str: string) => Promise<AssetName>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<AssetName>}
  */
  static from_json: (json: string) => Promise<AssetName>;

  /**
  * @param {Uint8Array} name
  * @returns {Promise<AssetName>}
  */
  static new: (name: Uint8Array) => Promise<AssetName>;

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
  * @returns {Promise<AssetNames>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<AssetNames>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<AssetNames>}
  */
  static from_hex: (hex_str: string) => Promise<AssetNames>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<AssetNames>}
  */
  static from_json: (json: string) => Promise<AssetNames>;

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
  * @returns {Promise<Assets>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Assets>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Assets>}
  */
  static from_hex: (hex_str: string) => Promise<Assets>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Assets>}
  */
  static from_json: (json: string) => Promise<Assets>;

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
  * @returns {Promise<AuxiliaryData>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<AuxiliaryData>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<AuxiliaryData>}
  */
  static from_hex: (hex_str: string) => Promise<AuxiliaryData>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<AuxiliaryData>}
  */
  static from_json: (json: string) => Promise<AuxiliaryData>;

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
  * @returns {Promise<AuxiliaryDataHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<AuxiliaryDataHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<AuxiliaryDataHash>}
  */
  static from_bech32: (bech_str: string) => Promise<AuxiliaryDataHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<AuxiliaryDataHash>}
  */
  static from_hex: (hex: string) => Promise<AuxiliaryDataHash>;

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
  * @param {Credential} payment
  * @param {Credential} stake
  * @returns {Promise<BaseAddress>}
  */
  static new: (network: number, payment: Credential, stake: Credential) => Promise<BaseAddress>;

  /**
  * @returns {Promise<Credential>}
  */
  payment_cred: () => Promise<Credential>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_cred: () => Promise<Credential>;

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
  * @returns {Promise<BigInt>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<BigInt>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<BigInt>}
  */
  static from_hex: (hex_str: string) => Promise<BigInt>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<BigInt>}
  */
  static from_json: (json: string) => Promise<BigInt>;

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
  * @returns {Promise<BigInt>}
  */
  static from_str: (text: string) => Promise<BigInt>;

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
  * @returns {Promise<BigNum>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<BigNum>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<BigNum>}
  */
  static from_hex: (hex_str: string) => Promise<BigNum>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<BigNum>}
  */
  static from_json: (json: string) => Promise<BigNum>;

  /**
  * @param {string} string
  * @returns {Promise<BigNum>}
  */
  static from_str: (string: string) => Promise<BigNum>;

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
  * @returns {Promise<BigNum>}
  */
  checked_mul: (other: BigNum) => Promise<BigNum>;

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  checked_add: (other: BigNum) => Promise<BigNum>;

  /**
  * @param {BigNum} other
  * @returns {Promise<BigNum>}
  */
  checked_sub: (other: BigNum) => Promise<BigNum>;

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
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_128_xprv: (bytes: Uint8Array) => Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_128_xprv: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Bip32PrivateKey>}
  */
  static generate_ed25519_bip32: () => Promise<Bip32PrivateKey>;

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
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Bip32PrivateKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_bech32: (bech32_str: string) => Promise<Bip32PrivateKey>;

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
  * @returns {Promise<Bip32PrivateKey>}
  */
  static from_hex: (hex_str: string) => Promise<Bip32PrivateKey>;

}


export class Bip32PublicKey extends Ptr {
  /**
  * @param {number} index
  * @returns {Promise<Bip32PublicKey>}
  */
  derive: (index: number) => Promise<Bip32PublicKey>;

  /**
  * @returns {Promise<PublicKey>}
  */
  to_raw_key: () => Promise<PublicKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Bip32PublicKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Bip32PublicKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<Bip32PublicKey>}
  */
  static from_bech32: (bech32_str: string) => Promise<Bip32PublicKey>;

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
  * @returns {Promise<Bip32PublicKey>}
  */
  static from_hex: (hex_str: string) => Promise<Bip32PublicKey>;

}


export class Block extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Block>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Block>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Block>}
  */
  static from_hex: (hex_str: string) => Promise<Block>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Block>}
  */
  static from_json: (json: string) => Promise<Block>;

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

  /**
  * @param {Uint8Array} data
  * @returns {Promise<Block>}
  */
  static from_wrapped_bytes: (data: Uint8Array) => Promise<Block>;

}


export class BlockHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<BlockHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<BlockHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<BlockHash>}
  */
  static from_bech32: (bech_str: string) => Promise<BlockHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<BlockHash>}
  */
  static from_hex: (hex: string) => Promise<BlockHash>;

}


export class BootstrapWitness extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<BootstrapWitness>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<BootstrapWitness>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<BootstrapWitness>}
  */
  static from_hex: (hex_str: string) => Promise<BootstrapWitness>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<BootstrapWitness>}
  */
  static from_json: (json: string) => Promise<BootstrapWitness>;

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
  * @returns {Promise<ByronAddress>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ByronAddress>;

  /**
  * @returns {Promise<number>}
  */
  byron_protocol_magic: () => Promise<number>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  attributes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<number>}
  */
  network_id: () => Promise<number>;

  /**
  * @param {string} s
  * @returns {Promise<ByronAddress>}
  */
  static from_base58: (s: string) => Promise<ByronAddress>;

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
  * @returns {Promise<Certificate>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Certificate>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Certificate>}
  */
  static from_hex: (hex_str: string) => Promise<Certificate>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Certificate>}
  */
  static from_json: (json: string) => Promise<Certificate>;

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
  * @param {CommitteeHotAuth} committee_hot_auth
  * @returns {Promise<Certificate>}
  */
  static new_committee_hot_auth: (committee_hot_auth: CommitteeHotAuth) => Promise<Certificate>;

  /**
  * @param {CommitteeColdResign} committee_cold_resign
  * @returns {Promise<Certificate>}
  */
  static new_committee_cold_resign: (committee_cold_resign: CommitteeColdResign) => Promise<Certificate>;

  /**
  * @param {DrepDeregistration} drep_deregistration
  * @returns {Promise<Certificate>}
  */
  static new_drep_deregistration: (drep_deregistration: DrepDeregistration) => Promise<Certificate>;

  /**
  * @param {DrepRegistration} drep_registration
  * @returns {Promise<Certificate>}
  */
  static new_drep_registration: (drep_registration: DrepRegistration) => Promise<Certificate>;

  /**
  * @param {DrepUpdate} drep_update
  * @returns {Promise<Certificate>}
  */
  static new_drep_update: (drep_update: DrepUpdate) => Promise<Certificate>;

  /**
  * @param {StakeAndVoteDelegation} stake_and_vote_delegation
  * @returns {Promise<Certificate>}
  */
  static new_stake_and_vote_delegation: (stake_and_vote_delegation: StakeAndVoteDelegation) => Promise<Certificate>;

  /**
  * @param {StakeRegistrationAndDelegation} stake_registration_and_delegation
  * @returns {Promise<Certificate>}
  */
  static new_stake_registration_and_delegation: (stake_registration_and_delegation: StakeRegistrationAndDelegation) => Promise<Certificate>;

  /**
  * @param {StakeVoteRegistrationAndDelegation} stake_vote_registration_and_delegation
  * @returns {Promise<Certificate>}
  */
  static new_stake_vote_registration_and_delegation: (stake_vote_registration_and_delegation: StakeVoteRegistrationAndDelegation) => Promise<Certificate>;

  /**
  * @param {VoteDelegation} vote_delegation
  * @returns {Promise<Certificate>}
  */
  static new_vote_delegation: (vote_delegation: VoteDelegation) => Promise<Certificate>;

  /**
  * @param {VoteRegistrationAndDelegation} vote_registration_and_delegation
  * @returns {Promise<Certificate>}
  */
  static new_vote_registration_and_delegation: (vote_registration_and_delegation: VoteRegistrationAndDelegation) => Promise<Certificate>;

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

  /**
  * @returns {Promise<Optional<CommitteeHotAuth>>}
  */
  as_committee_hot_auth: () => Promise<Optional<CommitteeHotAuth>>;

  /**
  * @returns {Promise<Optional<CommitteeColdResign>>}
  */
  as_committee_cold_resign: () => Promise<Optional<CommitteeColdResign>>;

  /**
  * @returns {Promise<Optional<DrepDeregistration>>}
  */
  as_drep_deregistration: () => Promise<Optional<DrepDeregistration>>;

  /**
  * @returns {Promise<Optional<DrepRegistration>>}
  */
  as_drep_registration: () => Promise<Optional<DrepRegistration>>;

  /**
  * @returns {Promise<Optional<DrepUpdate>>}
  */
  as_drep_update: () => Promise<Optional<DrepUpdate>>;

  /**
  * @returns {Promise<Optional<StakeAndVoteDelegation>>}
  */
  as_stake_and_vote_delegation: () => Promise<Optional<StakeAndVoteDelegation>>;

  /**
  * @returns {Promise<Optional<StakeRegistrationAndDelegation>>}
  */
  as_stake_registration_and_delegation: () => Promise<Optional<StakeRegistrationAndDelegation>>;

  /**
  * @returns {Promise<Optional<StakeVoteRegistrationAndDelegation>>}
  */
  as_stake_vote_registration_and_delegation: () => Promise<Optional<StakeVoteRegistrationAndDelegation>>;

  /**
  * @returns {Promise<Optional<VoteDelegation>>}
  */
  as_vote_delegation: () => Promise<Optional<VoteDelegation>>;

  /**
  * @returns {Promise<Optional<VoteRegistrationAndDelegation>>}
  */
  as_vote_registration_and_delegation: () => Promise<Optional<VoteRegistrationAndDelegation>>;

  /**
  * @returns {Promise<boolean>}
  */
  has_required_script_witness: () => Promise<boolean>;

}


export class Certificates extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Certificates>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Certificates>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Certificates>}
  */
  static from_hex: (hex_str: string) => Promise<Certificates>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Certificates>}
  */
  static from_json: (json: string) => Promise<Certificates>;

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


export class CertificatesBuilder extends Ptr {
  /**
  * @returns {Promise<CertificatesBuilder>}
  */
  static new: () => Promise<CertificatesBuilder>;

  /**
  * @param {Certificate} cert
  * @returns {Promise<void>}
  */
  add: (cert: Certificate) => Promise<void>;

  /**
  * @param {Certificate} cert
  * @param {PlutusWitness} witness
  * @returns {Promise<void>}
  */
  add_with_plutus_witness: (cert: Certificate, witness: PlutusWitness) => Promise<void>;

  /**
  * @param {Certificate} cert
  * @param {NativeScriptSource} native_script_source
  * @returns {Promise<void>}
  */
  add_with_native_script: (cert: Certificate, native_script_source: NativeScriptSource) => Promise<void>;

  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  get_plutus_witnesses: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  get_native_scripts: () => Promise<NativeScripts>;

  /**
  * @param {BigNum} pool_deposit
  * @param {BigNum} key_deposit
  * @returns {Promise<Value>}
  */
  get_certificates_refund: (pool_deposit: BigNum, key_deposit: BigNum) => Promise<Value>;

  /**
  * @param {BigNum} pool_deposit
  * @param {BigNum} key_deposit
  * @returns {Promise<BigNum>}
  */
  get_certificates_deposit: (pool_deposit: BigNum, key_deposit: BigNum) => Promise<BigNum>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_scripts: () => Promise<boolean>;

  /**
  * @returns {Promise<Certificates>}
  */
  build: () => Promise<Certificates>;

}


export class Committee extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Committee>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Committee>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Committee>}
  */
  static from_hex: (hex_str: string) => Promise<Committee>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Committee>}
  */
  static from_json: (json: string) => Promise<Committee>;

  /**
  * @param {UnitInterval} quorum_threshold
  * @returns {Promise<Committee>}
  */
  static new: (quorum_threshold: UnitInterval) => Promise<Committee>;

  /**
  * @returns {Promise<Credentials>}
  */
  members_keys: () => Promise<Credentials>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  quorum_threshold: () => Promise<UnitInterval>;

  /**
  * @param {Credential} committee_cold_credential
  * @param {number} epoch
  */
  add_member: (committee_cold_credential: Credential, epoch: number) => Promise<void>;

  /**
  * @param {Credential} committee_cold_credential
  * @returns {Promise<Optional<number>>}
  */
  get_member_epoch: (committee_cold_credential: Credential) => Promise<Optional<number>>;

}


export class CommitteeColdResign extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<CommitteeColdResign>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<CommitteeColdResign>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<CommitteeColdResign>}
  */
  static from_hex: (hex_str: string) => Promise<CommitteeColdResign>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<CommitteeColdResign>}
  */
  static from_json: (json: string) => Promise<CommitteeColdResign>;

  /**
  * @returns {Promise<Credential>}
  */
  committee_cold_key: () => Promise<Credential>;

  /**
  * @returns {Promise<Optional<Anchor>>}
  */
  anchor: () => Promise<Optional<Anchor>>;

  /**
  * @param {Credential} committee_cold_key
  * @returns {Promise<CommitteeColdResign>}
  */
  static new: (committee_cold_key: Credential) => Promise<CommitteeColdResign>;

  /**
  * @param {Credential} committee_cold_key
  * @param {Anchor} anchor
  * @returns {Promise<CommitteeColdResign>}
  */
  static new_with_anchor: (committee_cold_key: Credential, anchor: Anchor) => Promise<CommitteeColdResign>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class CommitteeHotAuth extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<CommitteeHotAuth>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<CommitteeHotAuth>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<CommitteeHotAuth>}
  */
  static from_hex: (hex_str: string) => Promise<CommitteeHotAuth>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<CommitteeHotAuth>}
  */
  static from_json: (json: string) => Promise<CommitteeHotAuth>;

  /**
  * @returns {Promise<Credential>}
  */
  committee_cold_key: () => Promise<Credential>;

  /**
  * @returns {Promise<Credential>}
  */
  committee_hot_key: () => Promise<Credential>;

  /**
  * @param {Credential} committee_cold_key
  * @param {Credential} committee_hot_key
  * @returns {Promise<CommitteeHotAuth>}
  */
  static new: (committee_cold_key: Credential, committee_hot_key: Credential) => Promise<CommitteeHotAuth>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class Constitution extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Constitution>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Constitution>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Constitution>}
  */
  static from_hex: (hex_str: string) => Promise<Constitution>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Constitution>}
  */
  static from_json: (json: string) => Promise<Constitution>;

  /**
  * @returns {Promise<Anchor>}
  */
  anchor: () => Promise<Anchor>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  script_hash: () => Promise<Optional<ScriptHash>>;

  /**
  * @param {Anchor} anchor
  * @returns {Promise<Constitution>}
  */
  static new: (anchor: Anchor) => Promise<Constitution>;

  /**
  * @param {Anchor} anchor
  * @param {ScriptHash} script_hash
  * @returns {Promise<Constitution>}
  */
  static new_with_script_hash: (anchor: Anchor, script_hash: ScriptHash) => Promise<Constitution>;

}


export class ConstrPlutusData extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<ConstrPlutusData>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ConstrPlutusData>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ConstrPlutusData>}
  */
  static from_hex: (hex_str: string) => Promise<ConstrPlutusData>;

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
  * @returns {Promise<CostModel>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<CostModel>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<CostModel>}
  */
  static from_hex: (hex_str: string) => Promise<CostModel>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<CostModel>}
  */
  static from_json: (json: string) => Promise<CostModel>;

  /**
  * @returns {Promise<CostModel>}
  */
  static new: () => Promise<CostModel>;

  /**
  * @param {number} operation
  * @param {Int} cost
  * @returns {Promise<Int>}
  */
  set: (operation: number, cost: Int) => Promise<Int>;

  /**
  * @param {number} operation
  * @returns {Promise<Int>}
  */
  get: (operation: number) => Promise<Int>;

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
  * @returns {Promise<Costmdls>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Costmdls>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Costmdls>}
  */
  static from_hex: (hex_str: string) => Promise<Costmdls>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Costmdls>}
  */
  static from_json: (json: string) => Promise<Costmdls>;

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


export class Credential extends Ptr {
  /**
  * @param {Ed25519KeyHash} hash
  * @returns {Promise<Credential>}
  */
  static from_keyhash: (hash: Ed25519KeyHash) => Promise<Credential>;

  /**
  * @param {ScriptHash} hash
  * @returns {Promise<Credential>}
  */
  static from_scripthash: (hash: ScriptHash) => Promise<Credential>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  to_keyhash: () => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  to_scripthash: () => Promise<Optional<ScriptHash>>;

  /**
  * @returns {Promise<CredKind>}
  */
  kind: () => Promise<CredKind>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_hash: () => Promise<boolean>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Credential>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Credential>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Credential>}
  */
  static from_hex: (hex_str: string) => Promise<Credential>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Credential>}
  */
  static from_json: (json: string) => Promise<Credential>;

}


export class Credentials extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Credentials>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Credentials>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Credentials>}
  */
  static from_hex: (hex_str: string) => Promise<Credentials>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Credentials>}
  */
  static from_json: (json: string) => Promise<Credentials>;

  /**
  * @returns {Promise<Credentials>}
  */
  static new: () => Promise<Credentials>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<Credential>}
  */
  get: (index: number) => Promise<Credential>;

  /**
  * @param {Credential} elem
  */
  add: (elem: Credential) => Promise<void>;

}


export class DNSRecordAorAAAA extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DNSRecordAorAAAA>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DNSRecordAorAAAA>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DNSRecordAorAAAA>}
  */
  static from_hex: (hex_str: string) => Promise<DNSRecordAorAAAA>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DNSRecordAorAAAA>}
  */
  static from_json: (json: string) => Promise<DNSRecordAorAAAA>;

  /**
  * @param {string} dns_name
  * @returns {Promise<DNSRecordAorAAAA>}
  */
  static new: (dns_name: string) => Promise<DNSRecordAorAAAA>;

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
  * @returns {Promise<DNSRecordSRV>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DNSRecordSRV>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DNSRecordSRV>}
  */
  static from_hex: (hex_str: string) => Promise<DNSRecordSRV>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DNSRecordSRV>}
  */
  static from_json: (json: string) => Promise<DNSRecordSRV>;

  /**
  * @param {string} dns_name
  * @returns {Promise<DNSRecordSRV>}
  */
  static new: (dns_name: string) => Promise<DNSRecordSRV>;

  /**
  * @returns {Promise<string>}
  */
  record: () => Promise<string>;

}


export class DRep extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DRep>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DRep>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DRep>}
  */
  static from_hex: (hex_str: string) => Promise<DRep>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DRep>}
  */
  static from_json: (json: string) => Promise<DRep>;

  /**
  * @param {Ed25519KeyHash} key_hash
  * @returns {Promise<DRep>}
  */
  static new_key_hash: (key_hash: Ed25519KeyHash) => Promise<DRep>;

  /**
  * @param {ScriptHash} script_hash
  * @returns {Promise<DRep>}
  */
  static new_script_hash: (script_hash: ScriptHash) => Promise<DRep>;

  /**
  * @returns {Promise<DRep>}
  */
  static new_always_abstain: () => Promise<DRep>;

  /**
  * @returns {Promise<DRep>}
  */
  static new_always_no_confidence: () => Promise<DRep>;

  /**
  * @returns {Promise<DRepKind>}
  */
  kind: () => Promise<DRepKind>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  to_key_hash: () => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  to_script_hash: () => Promise<Optional<ScriptHash>>;

}


export class DataCost extends Ptr {
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
  * @returns {Promise<DataHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DataHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<DataHash>}
  */
  static from_bech32: (bech_str: string) => Promise<DataHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<DataHash>}
  */
  static from_hex: (hex: string) => Promise<DataHash>;

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


export class DrepDeregistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DrepDeregistration>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DrepDeregistration>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DrepDeregistration>}
  */
  static from_hex: (hex_str: string) => Promise<DrepDeregistration>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DrepDeregistration>}
  */
  static from_json: (json: string) => Promise<DrepDeregistration>;

  /**
  * @returns {Promise<Credential>}
  */
  voting_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @param {Credential} voting_credential
  * @param {BigNum} coin
  * @returns {Promise<DrepDeregistration>}
  */
  static new: (voting_credential: Credential, coin: BigNum) => Promise<DrepDeregistration>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class DrepRegistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DrepRegistration>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DrepRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DrepRegistration>}
  */
  static from_hex: (hex_str: string) => Promise<DrepRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DrepRegistration>}
  */
  static from_json: (json: string) => Promise<DrepRegistration>;

  /**
  * @returns {Promise<Credential>}
  */
  voting_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @returns {Promise<Optional<Anchor>>}
  */
  anchor: () => Promise<Optional<Anchor>>;

  /**
  * @param {Credential} voting_credential
  * @param {BigNum} coin
  * @returns {Promise<DrepRegistration>}
  */
  static new: (voting_credential: Credential, coin: BigNum) => Promise<DrepRegistration>;

  /**
  * @param {Credential} voting_credential
  * @param {BigNum} coin
  * @param {Anchor} anchor
  * @returns {Promise<DrepRegistration>}
  */
  static new_with_anchor: (voting_credential: Credential, coin: BigNum, anchor: Anchor) => Promise<DrepRegistration>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class DrepUpdate extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DrepUpdate>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DrepUpdate>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DrepUpdate>}
  */
  static from_hex: (hex_str: string) => Promise<DrepUpdate>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DrepUpdate>}
  */
  static from_json: (json: string) => Promise<DrepUpdate>;

  /**
  * @returns {Promise<Credential>}
  */
  voting_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Optional<Anchor>>}
  */
  anchor: () => Promise<Optional<Anchor>>;

  /**
  * @param {Credential} voting_credential
  * @returns {Promise<DrepUpdate>}
  */
  static new: (voting_credential: Credential) => Promise<DrepUpdate>;

  /**
  * @param {Credential} voting_credential
  * @param {Anchor} anchor
  * @returns {Promise<DrepUpdate>}
  */
  static new_with_anchor: (voting_credential: Credential, anchor: Anchor) => Promise<DrepUpdate>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class DrepVotingThresholds extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<DrepVotingThresholds>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<DrepVotingThresholds>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<DrepVotingThresholds>}
  */
  static from_hex: (hex_str: string) => Promise<DrepVotingThresholds>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<DrepVotingThresholds>}
  */
  static from_json: (json: string) => Promise<DrepVotingThresholds>;

  /**
  * @param {UnitInterval} motion_no_confidence
  * @param {UnitInterval} committee_normal
  * @param {UnitInterval} committee_no_confidence
  * @param {UnitInterval} update_constitution
  * @param {UnitInterval} hard_fork_initiation
  * @param {UnitInterval} pp_network_group
  * @param {UnitInterval} pp_economic_group
  * @param {UnitInterval} pp_technical_group
  * @param {UnitInterval} pp_governance_group
  * @param {UnitInterval} treasury_withdrawal
  * @returns {Promise<DrepVotingThresholds>}
  */
  static new: (motion_no_confidence: UnitInterval, committee_normal: UnitInterval, committee_no_confidence: UnitInterval, update_constitution: UnitInterval, hard_fork_initiation: UnitInterval, pp_network_group: UnitInterval, pp_economic_group: UnitInterval, pp_technical_group: UnitInterval, pp_governance_group: UnitInterval, treasury_withdrawal: UnitInterval) => Promise<DrepVotingThresholds>;

  /**
  * @returns {Promise<DrepVotingThresholds>}
  */
  static new_default: () => Promise<DrepVotingThresholds>;

  /**
  * @param {UnitInterval} motion_no_confidence
  */
  set_motion_no_confidence: (motion_no_confidence: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} committee_normal
  */
  set_committee_normal: (committee_normal: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} committee_no_confidence
  */
  set_committee_no_confidence: (committee_no_confidence: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} update_constitution
  */
  set_update_constitution: (update_constitution: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} hard_fork_initiation
  */
  set_hard_fork_initiation: (hard_fork_initiation: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} pp_network_group
  */
  set_pp_network_group: (pp_network_group: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} pp_economic_group
  */
  set_pp_economic_group: (pp_economic_group: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} pp_technical_group
  */
  set_pp_technical_group: (pp_technical_group: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} pp_governance_group
  */
  set_pp_governance_group: (pp_governance_group: UnitInterval) => Promise<void>;

  /**
  * @param {UnitInterval} treasury_withdrawal
  */
  set_treasury_withdrawal: (treasury_withdrawal: UnitInterval) => Promise<void>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  motion_no_confidence: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  committee_normal: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  committee_no_confidence: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  update_constitution: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  hard_fork_initiation: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  pp_network_group: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  pp_economic_group: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  pp_technical_group: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  pp_governance_group: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  treasury_withdrawal: () => Promise<UnitInterval>;

}


export class Ed25519KeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ed25519KeyHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<Ed25519KeyHash>}
  */
  static from_bech32: (bech_str: string) => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<Ed25519KeyHash>}
  */
  static from_hex: (hex: string) => Promise<Ed25519KeyHash>;

}


export class Ed25519KeyHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ed25519KeyHashes>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Ed25519KeyHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Ed25519KeyHashes>}
  */
  static from_hex: (hex_str: string) => Promise<Ed25519KeyHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Ed25519KeyHashes>}
  */
  static from_json: (json: string) => Promise<Ed25519KeyHashes>;

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
  * @param {Ed25519KeyHash} elem
  * @returns {Promise<boolean>}
  */
  contains: (elem: Ed25519KeyHash) => Promise<boolean>;

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
  * @returns {Promise<Ed25519Signature>}
  */
  static from_bech32: (bech32_str: string) => Promise<Ed25519Signature>;

  /**
  * @param {string} input
  * @returns {Promise<Ed25519Signature>}
  */
  static from_hex: (input: string) => Promise<Ed25519Signature>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ed25519Signature>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Ed25519Signature>;

}


export class EnterpriseAddress extends Ptr {
  /**
  * @param {number} network
  * @param {Credential} payment
  * @returns {Promise<EnterpriseAddress>}
  */
  static new: (network: number, payment: Credential) => Promise<EnterpriseAddress>;

  /**
  * @returns {Promise<Credential>}
  */
  payment_cred: () => Promise<Credential>;

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
  * @returns {Promise<ExUnitPrices>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ExUnitPrices>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ExUnitPrices>}
  */
  static from_hex: (hex_str: string) => Promise<ExUnitPrices>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ExUnitPrices>}
  */
  static from_json: (json: string) => Promise<ExUnitPrices>;

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
  * @returns {Promise<ExUnits>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ExUnits>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ExUnits>}
  */
  static from_hex: (hex_str: string) => Promise<ExUnits>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ExUnits>}
  */
  static from_json: (json: string) => Promise<ExUnits>;

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
  * @returns {Promise<FixedTransaction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<FixedTransaction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<FixedTransaction>}
  */
  static from_hex: (hex_str: string) => Promise<FixedTransaction>;

  /**
  * @param {Uint8Array} raw_body
  * @param {Uint8Array} raw_witness_set
  * @param {boolean} is_valid
  * @returns {Promise<FixedTransaction>}
  */
  static new: (raw_body: Uint8Array, raw_witness_set: Uint8Array, is_valid: boolean) => Promise<FixedTransaction>;

  /**
  * @param {Uint8Array} raw_body
  * @param {Uint8Array} raw_witness_set
  * @param {Uint8Array} raw_auxiliary_data
  * @param {boolean} is_valid
  * @returns {Promise<FixedTransaction>}
  */
  static new_with_auxiliary: (raw_body: Uint8Array, raw_witness_set: Uint8Array, raw_auxiliary_data: Uint8Array, is_valid: boolean) => Promise<FixedTransaction>;

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
  * @returns {Promise<Optional<Uint8Array>>}
  */
  raw_auxiliary_data: () => Promise<Optional<Uint8Array>>;

}


export class GeneralTransactionMetadata extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<GeneralTransactionMetadata>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GeneralTransactionMetadata>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<GeneralTransactionMetadata>}
  */
  static from_hex: (hex_str: string) => Promise<GeneralTransactionMetadata>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GeneralTransactionMetadata>}
  */
  static from_json: (json: string) => Promise<GeneralTransactionMetadata>;

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
  * @returns {Promise<GenesisDelegateHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GenesisDelegateHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<GenesisDelegateHash>}
  */
  static from_bech32: (bech_str: string) => Promise<GenesisDelegateHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<GenesisDelegateHash>}
  */
  static from_hex: (hex: string) => Promise<GenesisDelegateHash>;

}


export class GenesisHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<GenesisHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GenesisHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<GenesisHash>}
  */
  static from_bech32: (bech_str: string) => Promise<GenesisHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<GenesisHash>}
  */
  static from_hex: (hex: string) => Promise<GenesisHash>;

}


export class GenesisHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<GenesisHashes>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GenesisHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<GenesisHashes>}
  */
  static from_hex: (hex_str: string) => Promise<GenesisHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GenesisHashes>}
  */
  static from_json: (json: string) => Promise<GenesisHashes>;

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
  * @returns {Promise<GenesisKeyDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GenesisKeyDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<GenesisKeyDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<GenesisKeyDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GenesisKeyDelegation>}
  */
  static from_json: (json: string) => Promise<GenesisKeyDelegation>;

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


export class GovernanceAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<GovernanceAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GovernanceAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<GovernanceAction>}
  */
  static from_hex: (hex_str: string) => Promise<GovernanceAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GovernanceAction>}
  */
  static from_json: (json: string) => Promise<GovernanceAction>;

  /**
  * @param {ParameterChangeAction} parameter_change_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_parameter_change_action: (parameter_change_action: ParameterChangeAction) => Promise<GovernanceAction>;

  /**
  * @param {HardForkInitiationAction} hard_fork_initiation_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_hard_fork_initiation_action: (hard_fork_initiation_action: HardForkInitiationAction) => Promise<GovernanceAction>;

  /**
  * @param {TreasuryWithdrawalsAction} treasury_withdrawals_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_treasury_withdrawals_action: (treasury_withdrawals_action: TreasuryWithdrawalsAction) => Promise<GovernanceAction>;

  /**
  * @param {NoConfidenceAction} no_confidence_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_no_confidence_action: (no_confidence_action: NoConfidenceAction) => Promise<GovernanceAction>;

  /**
  * @param {UpdateCommitteeAction} new_committee_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_new_committee_action: (new_committee_action: UpdateCommitteeAction) => Promise<GovernanceAction>;

  /**
  * @param {NewConstitutionAction} new_constitution_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_new_constitution_action: (new_constitution_action: NewConstitutionAction) => Promise<GovernanceAction>;

  /**
  * @param {InfoAction} info_action
  * @returns {Promise<GovernanceAction>}
  */
  static new_info_action: (info_action: InfoAction) => Promise<GovernanceAction>;

  /**
  * @returns {Promise<GovernanceActionKind>}
  */
  kind: () => Promise<GovernanceActionKind>;

  /**
  * @returns {Promise<Optional<ParameterChangeAction>>}
  */
  as_parameter_change_action: () => Promise<Optional<ParameterChangeAction>>;

  /**
  * @returns {Promise<Optional<HardForkInitiationAction>>}
  */
  as_hard_fork_initiation_action: () => Promise<Optional<HardForkInitiationAction>>;

  /**
  * @returns {Promise<Optional<TreasuryWithdrawalsAction>>}
  */
  as_treasury_withdrawals_action: () => Promise<Optional<TreasuryWithdrawalsAction>>;

  /**
  * @returns {Promise<Optional<NoConfidenceAction>>}
  */
  as_no_confidence_action: () => Promise<Optional<NoConfidenceAction>>;

  /**
  * @returns {Promise<Optional<UpdateCommitteeAction>>}
  */
  as_new_committee_action: () => Promise<Optional<UpdateCommitteeAction>>;

  /**
  * @returns {Promise<Optional<NewConstitutionAction>>}
  */
  as_new_constitution_action: () => Promise<Optional<NewConstitutionAction>>;

  /**
  * @returns {Promise<Optional<InfoAction>>}
  */
  as_info_action: () => Promise<Optional<InfoAction>>;

}


export class GovernanceActionId extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<GovernanceActionId>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<GovernanceActionId>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<GovernanceActionId>}
  */
  static from_hex: (hex_str: string) => Promise<GovernanceActionId>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GovernanceActionId>}
  */
  static from_json: (json: string) => Promise<GovernanceActionId>;

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
  * @returns {Promise<GovernanceActionId>}
  */
  static new: (transaction_id: TransactionHash, index: number) => Promise<GovernanceActionId>;

}


export class GovernanceActionIds extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<GovernanceActionIds>}
  */
  static from_json: (json: string) => Promise<GovernanceActionIds>;

  /**
  * @returns {Promise<GovernanceActionIds>}
  */
  static new: () => Promise<GovernanceActionIds>;

  /**
  * @param {GovernanceActionId} governance_action_id
  */
  add: (governance_action_id: GovernanceActionId) => Promise<void>;

  /**
  * @param {number} index
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  get: (index: number) => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class HardForkInitiationAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<HardForkInitiationAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<HardForkInitiationAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<HardForkInitiationAction>}
  */
  static from_hex: (hex_str: string) => Promise<HardForkInitiationAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<HardForkInitiationAction>}
  */
  static from_json: (json: string) => Promise<HardForkInitiationAction>;

  /**
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  gov_action_id: () => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<ProtocolVersion>}
  */
  protocol_version: () => Promise<ProtocolVersion>;

  /**
  * @param {ProtocolVersion} protocol_version
  * @returns {Promise<HardForkInitiationAction>}
  */
  static new: (protocol_version: ProtocolVersion) => Promise<HardForkInitiationAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @param {ProtocolVersion} protocol_version
  * @returns {Promise<HardForkInitiationAction>}
  */
  static new_with_action_id: (gov_action_id: GovernanceActionId, protocol_version: ProtocolVersion) => Promise<HardForkInitiationAction>;

}


export class Header extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Header>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Header>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Header>}
  */
  static from_hex: (hex_str: string) => Promise<Header>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Header>}
  */
  static from_json: (json: string) => Promise<Header>;

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
  * @returns {Promise<HeaderBody>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<HeaderBody>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<HeaderBody>}
  */
  static from_hex: (hex_str: string) => Promise<HeaderBody>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<HeaderBody>}
  */
  static from_json: (json: string) => Promise<HeaderBody>;

  /**
  * @returns {Promise<number>}
  */
  block_number: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  slot: () => Promise<number>;

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


export class InfoAction extends Ptr {
  /**
  * @returns {Promise<InfoAction>}
  */
  static new: () => Promise<InfoAction>;

}


export class Int extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Int>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Int>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Int>}
  */
  static from_hex: (hex_str: string) => Promise<Int>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Int>}
  */
  static from_json: (json: string) => Promise<Int>;

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
  * @returns {Promise<number>}
  */
  as_i32_or_fail: () => Promise<number>;

  /**
  * @returns {Promise<string>}
  */
  to_str: () => Promise<string>;

  /**
  * @param {string} string
  * @returns {Promise<Int>}
  */
  static from_str: (string: string) => Promise<Int>;

}


export class Ipv4 extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Ipv4>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Ipv4>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Ipv4>}
  */
  static from_hex: (hex_str: string) => Promise<Ipv4>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Ipv4>}
  */
  static from_json: (json: string) => Promise<Ipv4>;

  /**
  * @param {Uint8Array} data
  * @returns {Promise<Ipv4>}
  */
  static new: (data: Uint8Array) => Promise<Ipv4>;

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
  * @returns {Promise<Ipv6>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Ipv6>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Ipv6>}
  */
  static from_hex: (hex_str: string) => Promise<Ipv6>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Ipv6>}
  */
  static from_json: (json: string) => Promise<Ipv6>;

  /**
  * @param {Uint8Array} data
  * @returns {Promise<Ipv6>}
  */
  static new: (data: Uint8Array) => Promise<Ipv6>;

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
  * @returns {Promise<KESSignature>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<KESSignature>;

}


export class KESVKey extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<KESVKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<KESVKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<KESVKey>}
  */
  static from_bech32: (bech_str: string) => Promise<KESVKey>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<KESVKey>}
  */
  static from_hex: (hex: string) => Promise<KESVKey>;

}


export class Language extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Language>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Language>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Language>}
  */
  static from_hex: (hex_str: string) => Promise<Language>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Language>}
  */
  static from_json: (json: string) => Promise<Language>;

  /**
  * @returns {Promise<Language>}
  */
  static new_plutus_v1: () => Promise<Language>;

  /**
  * @returns {Promise<Language>}
  */
  static new_plutus_v2: () => Promise<Language>;

  /**
  * @returns {Promise<Language>}
  */
  static new_plutus_v3: () => Promise<Language>;

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
  * @returns {Promise<LegacyDaedalusPrivateKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<LegacyDaedalusPrivateKey>;

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
  * @returns {Promise<MIRToStakeCredentials>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MIRToStakeCredentials>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MIRToStakeCredentials>}
  */
  static from_hex: (hex_str: string) => Promise<MIRToStakeCredentials>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MIRToStakeCredentials>}
  */
  static from_json: (json: string) => Promise<MIRToStakeCredentials>;

  /**
  * @returns {Promise<MIRToStakeCredentials>}
  */
  static new: () => Promise<MIRToStakeCredentials>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {Credential} cred
  * @param {Int} delta
  * @returns {Promise<Optional<Int>>}
  */
  insert: (cred: Credential, delta: Int) => Promise<Optional<Int>>;

  /**
  * @param {Credential} cred
  * @returns {Promise<Optional<Int>>}
  */
  get: (cred: Credential) => Promise<Optional<Int>>;

  /**
  * @returns {Promise<Credentials>}
  */
  keys: () => Promise<Credentials>;

}


export class MalformedAddress extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  original_bytes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<Address>}
  */
  to_address: () => Promise<Address>;

  /**
  * @param {Address} addr
  * @returns {Promise<Optional<MalformedAddress>>}
  */
  static from_address: (addr: Address) => Promise<Optional<MalformedAddress>>;

}


export class MetadataList extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<MetadataList>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MetadataList>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MetadataList>}
  */
  static from_hex: (hex_str: string) => Promise<MetadataList>;

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
  * @returns {Promise<MetadataMap>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MetadataMap>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MetadataMap>}
  */
  static from_hex: (hex_str: string) => Promise<MetadataMap>;

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
  * @returns {Promise<TransactionMetadatum>}
  */
  get: (key: TransactionMetadatum) => Promise<TransactionMetadatum>;

  /**
  * @param {string} key
  * @returns {Promise<TransactionMetadatum>}
  */
  get_str: (key: string) => Promise<TransactionMetadatum>;

  /**
  * @param {number} key
  * @returns {Promise<TransactionMetadatum>}
  */
  get_i32: (key: number) => Promise<TransactionMetadatum>;

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
  * @returns {Promise<Mint>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Mint>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Mint>}
  */
  static from_hex: (hex_str: string) => Promise<Mint>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Mint>}
  */
  static from_json: (json: string) => Promise<Mint>;

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
  * @returns {Promise<Optional<MintsAssets>>}
  */
  get: (key: ScriptHash) => Promise<Optional<MintsAssets>>;

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
  * @returns {Promise<void>}
  */
  add_asset: (mint: MintWitness, asset_name: AssetName, amount: Int) => Promise<void>;

  /**
  * @param {MintWitness} mint
  * @param {AssetName} asset_name
  * @param {Int} amount
  * @returns {Promise<void>}
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
  * @returns {Promise<Redeemers>}
  */
  get_redeemers: () => Promise<Redeemers>;

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
  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MintsAssets>}
  */
  static from_json: (json: string) => Promise<MintsAssets>;

  /**
  * @returns {Promise<MintsAssets>}
  */
  static new: () => Promise<MintsAssets>;

  /**
  * @param {MintAssets} mint_assets
  */
  add: (mint_assets: MintAssets) => Promise<void>;

  /**
  * @param {number} index
  * @returns {Promise<Optional<MintAssets>>}
  */
  get: (index: number) => Promise<Optional<MintAssets>>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class MoveInstantaneousReward extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<MoveInstantaneousReward>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MoveInstantaneousReward>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MoveInstantaneousReward>}
  */
  static from_hex: (hex_str: string) => Promise<MoveInstantaneousReward>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MoveInstantaneousReward>}
  */
  static from_json: (json: string) => Promise<MoveInstantaneousReward>;

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
  * @returns {Promise<MoveInstantaneousRewardsCert>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MoveInstantaneousRewardsCert>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MoveInstantaneousRewardsCert>}
  */
  static from_hex: (hex_str: string) => Promise<MoveInstantaneousRewardsCert>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MoveInstantaneousRewardsCert>}
  */
  static from_json: (json: string) => Promise<MoveInstantaneousRewardsCert>;

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
  * @returns {Promise<MultiAsset>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MultiAsset>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MultiAsset>}
  */
  static from_hex: (hex_str: string) => Promise<MultiAsset>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MultiAsset>}
  */
  static from_json: (json: string) => Promise<MultiAsset>;

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
  * @returns {Promise<MultiHostName>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<MultiHostName>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<MultiHostName>}
  */
  static from_hex: (hex_str: string) => Promise<MultiHostName>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<MultiHostName>}
  */
  static from_json: (json: string) => Promise<MultiHostName>;

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
  * @returns {Promise<NativeScript>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<NativeScript>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<NativeScript>}
  */
  static from_hex: (hex_str: string) => Promise<NativeScript>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<NativeScript>}
  */
  static from_json: (json: string) => Promise<NativeScript>;

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


export class NativeScriptSource extends Ptr {
  /**
  * @param {NativeScript} script
  * @returns {Promise<NativeScriptSource>}
  */
  static new: (script: NativeScript) => Promise<NativeScriptSource>;

  /**
  * @param {ScriptHash} script_hash
  * @param {TransactionInput} input
  * @param {Ed25519KeyHashes} required_signers
  * @returns {Promise<NativeScriptSource>}
  */
  static new_ref_input: (script_hash: ScriptHash, input: TransactionInput, required_signers: Ed25519KeyHashes) => Promise<NativeScriptSource>;

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

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<NativeScripts>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<NativeScripts>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<NativeScripts>}
  */
  static from_hex: (hex_str: string) => Promise<NativeScripts>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<NativeScripts>}
  */
  static from_json: (json: string) => Promise<NativeScripts>;

}


export class NetworkId extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<NetworkId>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<NetworkId>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<NetworkId>}
  */
  static from_hex: (hex_str: string) => Promise<NetworkId>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<NetworkId>}
  */
  static from_json: (json: string) => Promise<NetworkId>;

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
  static mainnet: () => Promise<NetworkInfo>;

}


export class NewConstitutionAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<NewConstitutionAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<NewConstitutionAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<NewConstitutionAction>}
  */
  static from_hex: (hex_str: string) => Promise<NewConstitutionAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<NewConstitutionAction>}
  */
  static from_json: (json: string) => Promise<NewConstitutionAction>;

  /**
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  gov_action_id: () => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<Constitution>}
  */
  constitution: () => Promise<Constitution>;

  /**
  * @param {Constitution} constitution
  * @returns {Promise<NewConstitutionAction>}
  */
  static new: (constitution: Constitution) => Promise<NewConstitutionAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @param {Constitution} constitution
  * @returns {Promise<NewConstitutionAction>}
  */
  static new_with_action_id: (gov_action_id: GovernanceActionId, constitution: Constitution) => Promise<NewConstitutionAction>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_hash: () => Promise<boolean>;

}


export class NoConfidenceAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<NoConfidenceAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<NoConfidenceAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<NoConfidenceAction>}
  */
  static from_hex: (hex_str: string) => Promise<NoConfidenceAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<NoConfidenceAction>}
  */
  static from_json: (json: string) => Promise<NoConfidenceAction>;

  /**
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  gov_action_id: () => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<NoConfidenceAction>}
  */
  static new: () => Promise<NoConfidenceAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @returns {Promise<NoConfidenceAction>}
  */
  static new_with_action_id: (gov_action_id: GovernanceActionId) => Promise<NoConfidenceAction>;

}


export class Nonce extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Nonce>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Nonce>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Nonce>}
  */
  static from_hex: (hex_str: string) => Promise<Nonce>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Nonce>}
  */
  static from_json: (json: string) => Promise<Nonce>;

  /**
  * @returns {Promise<Nonce>}
  */
  static new_identity: () => Promise<Nonce>;

  /**
  * @param {Uint8Array} hash
  * @returns {Promise<Nonce>}
  */
  static new_from_hash: (hash: Uint8Array) => Promise<Nonce>;

  /**
  * @returns {Promise<Optional<Uint8Array>>}
  */
  get_hash: () => Promise<Optional<Uint8Array>>;

}


export class OperationalCert extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<OperationalCert>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<OperationalCert>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<OperationalCert>}
  */
  static from_hex: (hex_str: string) => Promise<OperationalCert>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<OperationalCert>}
  */
  static from_json: (json: string) => Promise<OperationalCert>;

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


export class OutputDatum extends Ptr {
  /**
  * @param {DataHash} data_hash
  * @returns {Promise<OutputDatum>}
  */
  static new_data_hash: (data_hash: DataHash) => Promise<OutputDatum>;

  /**
  * @param {PlutusData} data
  * @returns {Promise<OutputDatum>}
  */
  static new_data: (data: PlutusData) => Promise<OutputDatum>;

  /**
  * @returns {Promise<Optional<DataHash>>}
  */
  data_hash: () => Promise<Optional<DataHash>>;

  /**
  * @returns {Promise<Optional<PlutusData>>}
  */
  data: () => Promise<Optional<PlutusData>>;

}


export class ParameterChangeAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<ParameterChangeAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ParameterChangeAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ParameterChangeAction>}
  */
  static from_hex: (hex_str: string) => Promise<ParameterChangeAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ParameterChangeAction>}
  */
  static from_json: (json: string) => Promise<ParameterChangeAction>;

  /**
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  gov_action_id: () => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<ProtocolParamUpdate>}
  */
  protocol_param_updates: () => Promise<ProtocolParamUpdate>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  policy_hash: () => Promise<Optional<ScriptHash>>;

  /**
  * @param {ProtocolParamUpdate} protocol_param_updates
  * @returns {Promise<ParameterChangeAction>}
  */
  static new: (protocol_param_updates: ProtocolParamUpdate) => Promise<ParameterChangeAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @param {ProtocolParamUpdate} protocol_param_updates
  * @returns {Promise<ParameterChangeAction>}
  */
  static new_with_action_id: (gov_action_id: GovernanceActionId, protocol_param_updates: ProtocolParamUpdate) => Promise<ParameterChangeAction>;

  /**
  * @param {ProtocolParamUpdate} protocol_param_updates
  * @param {ScriptHash} policy_hash
  * @returns {Promise<ParameterChangeAction>}
  */
  static new_with_policy_hash: (protocol_param_updates: ProtocolParamUpdate, policy_hash: ScriptHash) => Promise<ParameterChangeAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @param {ProtocolParamUpdate} protocol_param_updates
  * @param {ScriptHash} policy_hash
  * @returns {Promise<ParameterChangeAction>}
  */
  static new_with_policy_hash_and_action_id: (gov_action_id: GovernanceActionId, protocol_param_updates: ProtocolParamUpdate, policy_hash: ScriptHash) => Promise<ParameterChangeAction>;

}


export class PlutusData extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusData>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PlutusData>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PlutusData>}
  */
  static from_hex: (hex_str: string) => Promise<PlutusData>;

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
  * @param {BigNum} alternative
  * @param {PlutusData} plutus_data
  * @returns {Promise<PlutusData>}
  */
  static new_single_value_constr_plutus_data: (alternative: BigNum, plutus_data: PlutusData) => Promise<PlutusData>;

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
  * @returns {Promise<Optional<Uint8Array>>}
  */
  as_bytes: () => Promise<Optional<Uint8Array>>;

  /**
  * @param {PlutusDatumSchema} schema
  * @returns {Promise<string>}
  */
  to_json: (schema: PlutusDatumSchema) => Promise<string>;

  /**
  * @param {string} json
  * @param {PlutusDatumSchema} schema
  * @returns {Promise<PlutusData>}
  */
  static from_json: (json: string, schema: PlutusDatumSchema) => Promise<PlutusData>;

  /**
  * @param {Address} address
  * @returns {Promise<PlutusData>}
  */
  static from_address: (address: Address) => Promise<PlutusData>;

}


export class PlutusList extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusList>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PlutusList>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PlutusList>}
  */
  static from_hex: (hex_str: string) => Promise<PlutusList>;

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
  * @returns {Promise<PlutusMap>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PlutusMap>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PlutusMap>}
  */
  static from_hex: (hex_str: string) => Promise<PlutusMap>;

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
  * @returns {Promise<PlutusScript>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PlutusScript>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PlutusScript>}
  */
  static from_hex: (hex_str: string) => Promise<PlutusScript>;

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
  * @returns {Promise<PlutusScript>}
  */
  static new_v3: (bytes: Uint8Array) => Promise<PlutusScript>;

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
  * @returns {Promise<PlutusScript>}
  */
  static from_bytes_v2: (bytes: Uint8Array) => Promise<PlutusScript>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusScript>}
  */
  static from_bytes_v3: (bytes: Uint8Array) => Promise<PlutusScript>;

  /**
  * @param {Uint8Array} bytes
  * @param {Language} language
  * @returns {Promise<PlutusScript>}
  */
  static from_bytes_with_version: (bytes: Uint8Array, language: Language) => Promise<PlutusScript>;

  /**
  * @param {string} hex_str
  * @param {Language} language
  * @returns {Promise<PlutusScript>}
  */
  static from_hex_with_version: (hex_str: string, language: Language) => Promise<PlutusScript>;

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
  * @param {Language} lang_ver
  * @returns {Promise<PlutusScriptSource>}
  */
  static new_ref_input: (script_hash: ScriptHash, input: TransactionInput, lang_ver: Language) => Promise<PlutusScriptSource>;

}


export class PlutusScripts extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PlutusScripts>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PlutusScripts>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PlutusScripts>}
  */
  static from_hex: (hex_str: string) => Promise<PlutusScripts>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PlutusScripts>}
  */
  static from_json: (json: string) => Promise<PlutusScripts>;

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
  * @returns {Promise<number>}
  */
  slot: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  tx_index: () => Promise<number>;

  /**
  * @returns {Promise<number>}
  */
  cert_index: () => Promise<number>;

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
  * @param {Credential} payment
  * @param {Pointer} stake
  * @returns {Promise<PointerAddress>}
  */
  static new: (network: number, payment: Credential, stake: Pointer) => Promise<PointerAddress>;

  /**
  * @returns {Promise<Credential>}
  */
  payment_cred: () => Promise<Credential>;

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
  * @returns {Promise<PoolMetadata>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolMetadata>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PoolMetadata>}
  */
  static from_hex: (hex_str: string) => Promise<PoolMetadata>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PoolMetadata>}
  */
  static from_json: (json: string) => Promise<PoolMetadata>;

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
  * @returns {Promise<PoolMetadataHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolMetadataHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<PoolMetadataHash>}
  */
  static from_bech32: (bech_str: string) => Promise<PoolMetadataHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<PoolMetadataHash>}
  */
  static from_hex: (hex: string) => Promise<PoolMetadataHash>;

}


export class PoolParams extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PoolParams>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolParams>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PoolParams>}
  */
  static from_hex: (hex_str: string) => Promise<PoolParams>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PoolParams>}
  */
  static from_json: (json: string) => Promise<PoolParams>;

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
  * @returns {Promise<PoolRegistration>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PoolRegistration>}
  */
  static from_hex: (hex_str: string) => Promise<PoolRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PoolRegistration>}
  */
  static from_json: (json: string) => Promise<PoolRegistration>;

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
  * @returns {Promise<PoolRetirement>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolRetirement>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PoolRetirement>}
  */
  static from_hex: (hex_str: string) => Promise<PoolRetirement>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PoolRetirement>}
  */
  static from_json: (json: string) => Promise<PoolRetirement>;

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


export class PoolVotingThresholds extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PoolVotingThresholds>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PoolVotingThresholds>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<PoolVotingThresholds>}
  */
  static from_hex: (hex_str: string) => Promise<PoolVotingThresholds>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<PoolVotingThresholds>}
  */
  static from_json: (json: string) => Promise<PoolVotingThresholds>;

  /**
  * @param {UnitInterval} motion_no_confidence
  * @param {UnitInterval} committee_normal
  * @param {UnitInterval} committee_no_confidence
  * @param {UnitInterval} hard_fork_initiation
  * @param {UnitInterval} security_relevant_threshold
  * @returns {Promise<PoolVotingThresholds>}
  */
  static new: (motion_no_confidence: UnitInterval, committee_normal: UnitInterval, committee_no_confidence: UnitInterval, hard_fork_initiation: UnitInterval, security_relevant_threshold: UnitInterval) => Promise<PoolVotingThresholds>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  motion_no_confidence: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  committee_normal: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  committee_no_confidence: () => Promise<UnitInterval>;

  /**
  * @returns {Promise<UnitInterval>}
  */
  hard_fork_initiation: () => Promise<UnitInterval>;

}


export class PrivateKey extends Ptr {
  /**
  * @returns {Promise<PublicKey>}
  */
  to_public: () => Promise<PublicKey>;

  /**
  * @returns {Promise<PrivateKey>}
  */
  static generate_ed25519: () => Promise<PrivateKey>;

  /**
  * @returns {Promise<PrivateKey>}
  */
  static generate_ed25519extended: () => Promise<PrivateKey>;

  /**
  * @param {string} bech32_str
  * @returns {Promise<PrivateKey>}
  */
  static from_bech32: (bech32_str: string) => Promise<PrivateKey>;

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
  * @returns {Promise<PrivateKey>}
  */
  static from_extended_bytes: (bytes: Uint8Array) => Promise<PrivateKey>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<PrivateKey>}
  */
  static from_normal_bytes: (bytes: Uint8Array) => Promise<PrivateKey>;

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
  * @returns {Promise<PrivateKey>}
  */
  static from_hex: (hex_str: string) => Promise<PrivateKey>;

}


export class ProposedProtocolParameterUpdates extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<ProposedProtocolParameterUpdates>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ProposedProtocolParameterUpdates>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ProposedProtocolParameterUpdates>}
  */
  static from_hex: (hex_str: string) => Promise<ProposedProtocolParameterUpdates>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ProposedProtocolParameterUpdates>}
  */
  static from_json: (json: string) => Promise<ProposedProtocolParameterUpdates>;

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
  * @returns {Promise<ProtocolParamUpdate>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ProtocolParamUpdate>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ProtocolParamUpdate>}
  */
  static from_hex: (hex_str: string) => Promise<ProtocolParamUpdate>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ProtocolParamUpdate>}
  */
  static from_json: (json: string) => Promise<ProtocolParamUpdate>;

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
  * @param {PoolVotingThresholds} pool_voting_thresholds
  */
  set_pool_voting_thresholds: (pool_voting_thresholds: PoolVotingThresholds) => Promise<void>;

  /**
  * @returns {Promise<Optional<PoolVotingThresholds>>}
  */
  pool_voting_thresholds: () => Promise<Optional<PoolVotingThresholds>>;

  /**
  * @param {DrepVotingThresholds} drep_voting_thresholds
  */
  set_drep_voting_thresholds: (drep_voting_thresholds: DrepVotingThresholds) => Promise<void>;

  /**
  * @returns {Promise<Optional<DrepVotingThresholds>>}
  */
  drep_voting_thresholds: () => Promise<Optional<DrepVotingThresholds>>;

  /**
  * @param {number} min_committee_size
  */
  set_min_committee_size: (min_committee_size: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  min_committee_size: () => Promise<Optional<number>>;

  /**
  * @param {number} committee_term_limit
  */
  set_committee_term_limit: (committee_term_limit: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  committee_term_limit: () => Promise<Optional<number>>;

  /**
  * @param {number} governance_action_validity_period
  */
  set_governance_action_validity_period: (governance_action_validity_period: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  governance_action_validity_period: () => Promise<Optional<number>>;

  /**
  * @param {BigNum} governance_action_deposit
  */
  set_governance_action_deposit: (governance_action_deposit: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  governance_action_deposit: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} drep_deposit
  */
  set_drep_deposit: (drep_deposit: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  drep_deposit: () => Promise<Optional<BigNum>>;

  /**
  * @param {number} drep_inactivity_period
  */
  set_drep_inactivity_period: (drep_inactivity_period: number) => Promise<void>;

  /**
  * @returns {Promise<Optional<number>>}
  */
  drep_inactivity_period: () => Promise<Optional<number>>;

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
  * @returns {Promise<ProtocolVersion>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ProtocolVersion>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ProtocolVersion>}
  */
  static from_hex: (hex_str: string) => Promise<ProtocolVersion>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ProtocolVersion>}
  */
  static from_json: (json: string) => Promise<ProtocolVersion>;

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
  * @returns {Promise<PublicKey>}
  */
  static from_bech32: (bech32_str: string) => Promise<PublicKey>;

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
  * @returns {Promise<PublicKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<PublicKey>;

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
  * @returns {Promise<PublicKey>}
  */
  static from_hex: (hex_str: string) => Promise<PublicKey>;

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
  * @returns {Promise<Redeemer>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Redeemer>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Redeemer>}
  */
  static from_hex: (hex_str: string) => Promise<Redeemer>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Redeemer>}
  */
  static from_json: (json: string) => Promise<Redeemer>;

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
  * @returns {Promise<RedeemerTag>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<RedeemerTag>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<RedeemerTag>}
  */
  static from_hex: (hex_str: string) => Promise<RedeemerTag>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<RedeemerTag>}
  */
  static from_json: (json: string) => Promise<RedeemerTag>;

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
  * @returns {Promise<RedeemerTag>}
  */
  static new_vote: () => Promise<RedeemerTag>;

  /**
  * @returns {Promise<RedeemerTag>}
  */
  static new_voting_proposal: () => Promise<RedeemerTag>;

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
  * @returns {Promise<Redeemers>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Redeemers>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Redeemers>}
  */
  static from_hex: (hex_str: string) => Promise<Redeemers>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Redeemers>}
  */
  static from_json: (json: string) => Promise<Redeemers>;

  /**
  * @returns {Promise<Redeemers>}
  */
  static new: () => Promise<Redeemers>;

  /**
  * @param {Redeemer} redeemers
  * @param {CborContainerType} serialization_format
  * @returns {Promise<Redeemers>}
  */
  static new_with_serialization_format: (redeemers: Redeemer, serialization_format: CborContainerType) => Promise<Redeemers>;

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
  * @returns {Promise<ExUnits>}
  */
  total_ex_units: () => Promise<ExUnits>;

}


export class Relay extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Relay>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Relay>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Relay>}
  */
  static from_hex: (hex_str: string) => Promise<Relay>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Relay>}
  */
  static from_json: (json: string) => Promise<Relay>;

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
  * @returns {Promise<Relays>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Relays>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Relays>}
  */
  static from_hex: (hex_str: string) => Promise<Relays>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Relays>}
  */
  static from_json: (json: string) => Promise<Relays>;

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
  * @param {Credential} payment
  * @returns {Promise<RewardAddress>}
  */
  static new: (network: number, payment: Credential) => Promise<RewardAddress>;

  /**
  * @returns {Promise<Credential>}
  */
  payment_cred: () => Promise<Credential>;

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
  * @returns {Promise<RewardAddresses>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<RewardAddresses>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<RewardAddresses>}
  */
  static from_hex: (hex_str: string) => Promise<RewardAddresses>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<RewardAddresses>}
  */
  static from_json: (json: string) => Promise<RewardAddresses>;

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
  * @returns {Promise<ScriptAll>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptAll>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptAll>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptAll>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptAll>}
  */
  static from_json: (json: string) => Promise<ScriptAll>;

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
  * @returns {Promise<ScriptAny>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptAny>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptAny>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptAny>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptAny>}
  */
  static from_json: (json: string) => Promise<ScriptAny>;

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
  * @returns {Promise<ScriptDataHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptDataHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<ScriptDataHash>}
  */
  static from_bech32: (bech_str: string) => Promise<ScriptDataHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<ScriptDataHash>}
  */
  static from_hex: (hex: string) => Promise<ScriptDataHash>;

}


export class ScriptHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<ScriptHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<ScriptHash>}
  */
  static from_bech32: (bech_str: string) => Promise<ScriptHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<ScriptHash>}
  */
  static from_hex: (hex: string) => Promise<ScriptHash>;

}


export class ScriptHashes extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<ScriptHashes>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptHashes>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptHashes>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptHashes>}
  */
  static from_json: (json: string) => Promise<ScriptHashes>;

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
  * @returns {Promise<ScriptNOfK>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptNOfK>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptNOfK>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptNOfK>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptNOfK>}
  */
  static from_json: (json: string) => Promise<ScriptNOfK>;

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
  * @returns {Promise<ScriptPubkey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptPubkey>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptPubkey>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptPubkey>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptPubkey>}
  */
  static from_json: (json: string) => Promise<ScriptPubkey>;

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
  * @returns {Promise<ScriptRef>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<ScriptRef>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<ScriptRef>}
  */
  static from_hex: (hex_str: string) => Promise<ScriptRef>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<ScriptRef>}
  */
  static from_json: (json: string) => Promise<ScriptRef>;

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
  * @returns {Promise<SingleHostAddr>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<SingleHostAddr>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<SingleHostAddr>}
  */
  static from_hex: (hex_str: string) => Promise<SingleHostAddr>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<SingleHostAddr>}
  */
  static from_json: (json: string) => Promise<SingleHostAddr>;

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
  * @returns {Promise<SingleHostName>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<SingleHostName>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<SingleHostName>}
  */
  static from_hex: (hex_str: string) => Promise<SingleHostName>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<SingleHostName>}
  */
  static from_json: (json: string) => Promise<SingleHostName>;

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


export class StakeAndVoteDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeAndVoteDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeAndVoteDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeAndVoteDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<StakeAndVoteDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeAndVoteDelegation>}
  */
  static from_json: (json: string) => Promise<StakeAndVoteDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<DRep>}
  */
  drep: () => Promise<DRep>;

  /**
  * @param {Credential} stake_credential
  * @param {Ed25519KeyHash} pool_keyhash
  * @param {DRep} drep
  * @returns {Promise<StakeAndVoteDelegation>}
  */
  static new: (stake_credential: Credential, pool_keyhash: Ed25519KeyHash, drep: DRep) => Promise<StakeAndVoteDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class StakeDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<StakeDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeDelegation>}
  */
  static from_json: (json: string) => Promise<StakeDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @param {Credential} stake_credential
  * @param {Ed25519KeyHash} pool_keyhash
  * @returns {Promise<StakeDelegation>}
  */
  static new: (stake_credential: Credential, pool_keyhash: Ed25519KeyHash) => Promise<StakeDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class StakeDeregistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeDeregistration>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeDeregistration>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeDeregistration>}
  */
  static from_hex: (hex_str: string) => Promise<StakeDeregistration>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeDeregistration>}
  */
  static from_json: (json: string) => Promise<StakeDeregistration>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  coin: () => Promise<Optional<BigNum>>;

  /**
  * @param {Credential} stake_credential
  * @returns {Promise<StakeDeregistration>}
  */
  static new: (stake_credential: Credential) => Promise<StakeDeregistration>;

  /**
  * @param {Credential} stake_credential
  * @param {BigNum} coin
  * @returns {Promise<StakeDeregistration>}
  */
  static new_with_coin: (stake_credential: Credential, coin: BigNum) => Promise<StakeDeregistration>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class StakeRegistration extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeRegistration>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeRegistration>}
  */
  static from_hex: (hex_str: string) => Promise<StakeRegistration>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeRegistration>}
  */
  static from_json: (json: string) => Promise<StakeRegistration>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  coin: () => Promise<Optional<BigNum>>;

  /**
  * @param {Credential} stake_credential
  * @returns {Promise<StakeRegistration>}
  */
  static new: (stake_credential: Credential) => Promise<StakeRegistration>;

  /**
  * @param {Credential} stake_credential
  * @param {BigNum} coin
  * @returns {Promise<StakeRegistration>}
  */
  static new_with_coin: (stake_credential: Credential, coin: BigNum) => Promise<StakeRegistration>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class StakeRegistrationAndDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeRegistrationAndDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeRegistrationAndDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<StakeRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeRegistrationAndDelegation>}
  */
  static from_json: (json: string) => Promise<StakeRegistrationAndDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @param {Credential} stake_credential
  * @param {Ed25519KeyHash} pool_keyhash
  * @param {BigNum} coin
  * @returns {Promise<StakeRegistrationAndDelegation>}
  */
  static new: (stake_credential: Credential, pool_keyhash: Ed25519KeyHash, coin: BigNum) => Promise<StakeRegistrationAndDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class StakeVoteRegistrationAndDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<StakeVoteRegistrationAndDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<StakeVoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<StakeVoteRegistrationAndDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<StakeVoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<StakeVoteRegistrationAndDelegation>}
  */
  static from_json: (json: string) => Promise<StakeVoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<Ed25519KeyHash>}
  */
  pool_keyhash: () => Promise<Ed25519KeyHash>;

  /**
  * @returns {Promise<DRep>}
  */
  drep: () => Promise<DRep>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @param {Credential} stake_credential
  * @param {Ed25519KeyHash} pool_keyhash
  * @param {DRep} drep
  * @param {BigNum} coin
  * @returns {Promise<StakeVoteRegistrationAndDelegation>}
  */
  static new: (stake_credential: Credential, pool_keyhash: Ed25519KeyHash, drep: DRep, coin: BigNum) => Promise<StakeVoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

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
  * @returns {Promise<TimelockExpiry>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TimelockExpiry>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TimelockExpiry>}
  */
  static from_hex: (hex_str: string) => Promise<TimelockExpiry>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TimelockExpiry>}
  */
  static from_json: (json: string) => Promise<TimelockExpiry>;

  /**
  * @returns {Promise<number>}
  */
  slot: () => Promise<number>;

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
  * @returns {Promise<TimelockStart>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TimelockStart>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TimelockStart>}
  */
  static from_hex: (hex_str: string) => Promise<TimelockStart>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TimelockStart>}
  */
  static from_json: (json: string) => Promise<TimelockStart>;

  /**
  * @returns {Promise<number>}
  */
  slot: () => Promise<number>;

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
  * @returns {Promise<Transaction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Transaction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Transaction>}
  */
  static from_hex: (hex_str: string) => Promise<Transaction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Transaction>}
  */
  static from_json: (json: string) => Promise<Transaction>;

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
  * @returns {Promise<TransactionBodies>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionBodies>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionBodies>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionBodies>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionBodies>}
  */
  static from_json: (json: string) => Promise<TransactionBodies>;

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
  * @returns {Promise<TransactionBody>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionBody>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionBody>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionBody>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionBody>}
  */
  static from_json: (json: string) => Promise<TransactionBody>;

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
  * @param {VotingProcedures} voting_procedures
  */
  set_voting_procedures: (voting_procedures: VotingProcedures) => Promise<void>;

  /**
  * @returns {Promise<Optional<VotingProcedures>>}
  */
  voting_procedures: () => Promise<Optional<VotingProcedures>>;

  /**
  * @param {VotingProposals} voting_proposals
  */
  set_voting_proposals: (voting_proposals: VotingProposals) => Promise<void>;

  /**
  * @returns {Promise<Optional<VotingProposals>>}
  */
  voting_proposals: () => Promise<Optional<VotingProposals>>;

  /**
  * @param {BigNum} donation
  */
  set_donation: (donation: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  donation: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} current_treasury_value
  */
  set_current_treasury_value: (current_treasury_value: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  current_treasury_value: () => Promise<Optional<BigNum>>;

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
  * @returns {Promise<void>}
  */
  add_regular_input: (address: Address, input: TransactionInput, amount: Value) => Promise<void>;

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
  * @returns {Promise<BigNum>}
  */
  fee_for_input: (address: Address, input: TransactionInput, amount: Value) => Promise<BigNum>;

  /**
  * @param {TransactionOutput} output
  * @returns {Promise<void>}
  */
  add_output: (output: TransactionOutput) => Promise<void>;

  /**
  * @param {TransactionOutput} output
  * @returns {Promise<BigNum>}
  */
  fee_for_output: (output: TransactionOutput) => Promise<BigNum>;

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
  * @returns {Promise<void>}
  */
  set_certs: (certs: Certificates) => Promise<void>;

  /**
  * @param {CertificatesBuilder} certs
  */
  set_certs_builder: (certs: CertificatesBuilder) => Promise<void>;

  /**
  * @param {Withdrawals} withdrawals
  * @returns {Promise<void>}
  */
  set_withdrawals: (withdrawals: Withdrawals) => Promise<void>;

  /**
  * @param {WithdrawalsBuilder} withdrawals
  */
  set_withdrawals_builder: (withdrawals: WithdrawalsBuilder) => Promise<void>;

  /**
  * @param {VotingBuilder} voting_builder
  */
  set_voting_builder: (voting_builder: VotingBuilder) => Promise<void>;

  /**
  * @param {VotingProposalBuilder} voting_proposal_builder
  */
  set_voting_proposal_builder: (voting_proposal_builder: VotingProposalBuilder) => Promise<void>;

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
  * @param {PlutusData} datum
  */
  add_extra_witness_datum: (datum: PlutusData) => Promise<void>;

  /**
  * @returns {Promise<Optional<PlutusList>>}
  */
  get_extra_witness_datums: () => Promise<Optional<PlutusList>>;

  /**
  * @param {BigNum} donation
  */
  set_donation: (donation: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  get_donation: () => Promise<Optional<BigNum>>;

  /**
  * @param {BigNum} current_treasury_value
  * @returns {Promise<void>}
  */
  set_current_treasury_value: (current_treasury_value: BigNum) => Promise<void>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  get_current_treasury_value: () => Promise<Optional<BigNum>>;

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
  * @returns {Promise<Value>}
  */
  get_explicit_input: () => Promise<Value>;

  /**
  * @returns {Promise<Value>}
  */
  get_implicit_input: () => Promise<Value>;

  /**
  * @returns {Promise<Value>}
  */
  get_total_input: () => Promise<Value>;

  /**
  * @returns {Promise<Value>}
  */
  get_total_output: () => Promise<Value>;

  /**
  * @returns {Promise<Value>}
  */
  get_explicit_output: () => Promise<Value>;

  /**
  * @returns {Promise<BigNum>}
  */
  get_deposit: () => Promise<BigNum>;

  /**
  * @returns {Promise<Optional<BigNum>>}
  */
  get_fee_if_set: () => Promise<Optional<BigNum>>;

  /**
  * @param {Address} address
  * @returns {Promise<boolean>}
  */
  add_change_if_needed: (address: Address) => Promise<boolean>;

  /**
  * @param {Address} address
  * @param {OutputDatum} plutus_data
  * @returns {Promise<boolean>}
  */
  add_change_if_needed_with_datum: (address: Address, plutus_data: OutputDatum) => Promise<boolean>;

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
  * @returns {Promise<number>}
  */
  full_size: () => Promise<number>;

  /**
  * @returns {Promise<Uint32Array>}
  */
  output_sizes: () => Promise<Uint32Array>;

  /**
  * @returns {Promise<TransactionBody>}
  */
  build: () => Promise<TransactionBody>;

  /**
  * @returns {Promise<Transaction>}
  */
  build_tx: () => Promise<Transaction>;

  /**
  * @returns {Promise<Transaction>}
  */
  build_tx_unsafe: () => Promise<Transaction>;

  /**
  * @returns {Promise<BigNum>}
  */
  min_fee: () => Promise<BigNum>;

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
  * @returns {Promise<TransactionBuilderConfig>}
  */
  build: () => Promise<TransactionBuilderConfig>;

}


export class TransactionHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<TransactionHash>}
  */
  static from_bech32: (bech_str: string) => Promise<TransactionHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<TransactionHash>}
  */
  static from_hex: (hex: string) => Promise<TransactionHash>;

}


export class TransactionInput extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionInput>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionInput>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionInput>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionInput>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionInput>}
  */
  static from_json: (json: string) => Promise<TransactionInput>;

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
  * @returns {Promise<TransactionInputs>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionInputs>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionInputs>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionInputs>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionInputs>}
  */
  static from_json: (json: string) => Promise<TransactionInputs>;

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
  * @returns {Promise<TransactionMetadatum>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionMetadatum>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionMetadatum>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionMetadatum>;

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
  * @returns {Promise<TransactionMetadatum>}
  */
  static new_bytes: (bytes: Uint8Array) => Promise<TransactionMetadatum>;

  /**
  * @param {string} text
  * @returns {Promise<TransactionMetadatum>}
  */
  static new_text: (text: string) => Promise<TransactionMetadatum>;

  /**
  * @returns {Promise<TransactionMetadatumKind>}
  */
  kind: () => Promise<TransactionMetadatumKind>;

  /**
  * @returns {Promise<MetadataMap>}
  */
  as_map: () => Promise<MetadataMap>;

  /**
  * @returns {Promise<MetadataList>}
  */
  as_list: () => Promise<MetadataList>;

  /**
  * @returns {Promise<Int>}
  */
  as_int: () => Promise<Int>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  as_bytes: () => Promise<Uint8Array>;

  /**
  * @returns {Promise<string>}
  */
  as_text: () => Promise<string>;

}


export class TransactionMetadatumLabels extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionMetadatumLabels>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionMetadatumLabels>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionMetadatumLabels>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionMetadatumLabels>;

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
  * @returns {Promise<TransactionOutput>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionOutput>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionOutput>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionOutput>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionOutput>}
  */
  static from_json: (json: string) => Promise<TransactionOutput>;

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

  /**
  * @returns {Promise<Optional<CborContainerType>>}
  */
  serialization_format: () => Promise<Optional<CborContainerType>>;

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
  * @param {DataCost} data_cost
  * @returns {Promise<TransactionOutputAmountBuilder>}
  */
  with_asset_and_min_required_coin_by_utxo_cost: (multiasset: MultiAsset, data_cost: DataCost) => Promise<TransactionOutputAmountBuilder>;

  /**
  * @returns {Promise<TransactionOutput>}
  */
  build: () => Promise<TransactionOutput>;

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
  * @returns {Promise<TransactionOutputAmountBuilder>}
  */
  next: () => Promise<TransactionOutputAmountBuilder>;

}


export class TransactionOutputs extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TransactionOutputs>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionOutputs>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionOutputs>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionOutputs>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionOutputs>}
  */
  static from_json: (json: string) => Promise<TransactionOutputs>;

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
  * @returns {Promise<TransactionUnspentOutput>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionUnspentOutput>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionUnspentOutput>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionUnspentOutput>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionUnspentOutput>}
  */
  static from_json: (json: string) => Promise<TransactionUnspentOutput>;

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
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionUnspentOutputs>}
  */
  static from_json: (json: string) => Promise<TransactionUnspentOutputs>;

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
  * @returns {Promise<TransactionWitnessSet>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionWitnessSet>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionWitnessSet>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionWitnessSet>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionWitnessSet>}
  */
  static from_json: (json: string) => Promise<TransactionWitnessSet>;

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
  * @returns {Promise<TransactionWitnessSets>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TransactionWitnessSets>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TransactionWitnessSets>}
  */
  static from_hex: (hex_str: string) => Promise<TransactionWitnessSets>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TransactionWitnessSets>}
  */
  static from_json: (json: string) => Promise<TransactionWitnessSets>;

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


export class TreasuryWithdrawals extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TreasuryWithdrawals>}
  */
  static from_json: (json: string) => Promise<TreasuryWithdrawals>;

  /**
  * @returns {Promise<TreasuryWithdrawals>}
  */
  static new: () => Promise<TreasuryWithdrawals>;

  /**
  * @param {RewardAddress} key
  * @returns {Promise<Optional<BigNum>>}
  */
  get: (key: RewardAddress) => Promise<Optional<BigNum>>;

  /**
  * @param {RewardAddress} key
  * @param {BigNum} value
  */
  insert: (key: RewardAddress, value: BigNum) => Promise<void>;

  /**
  * @returns {Promise<RewardAddresses>}
  */
  keys: () => Promise<RewardAddresses>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class TreasuryWithdrawalsAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<TreasuryWithdrawalsAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<TreasuryWithdrawalsAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<TreasuryWithdrawalsAction>}
  */
  static from_hex: (hex_str: string) => Promise<TreasuryWithdrawalsAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<TreasuryWithdrawalsAction>}
  */
  static from_json: (json: string) => Promise<TreasuryWithdrawalsAction>;

  /**
  * @returns {Promise<TreasuryWithdrawals>}
  */
  withdrawals: () => Promise<TreasuryWithdrawals>;

  /**
  * @returns {Promise<Optional<ScriptHash>>}
  */
  policy_hash: () => Promise<Optional<ScriptHash>>;

  /**
  * @param {TreasuryWithdrawals} withdrawals
  * @returns {Promise<TreasuryWithdrawalsAction>}
  */
  static new: (withdrawals: TreasuryWithdrawals) => Promise<TreasuryWithdrawalsAction>;

  /**
  * @param {TreasuryWithdrawals} withdrawals
  * @param {ScriptHash} policy_hash
  * @returns {Promise<TreasuryWithdrawalsAction>}
  */
  static new_with_policy_hash: (withdrawals: TreasuryWithdrawals, policy_hash: ScriptHash) => Promise<TreasuryWithdrawalsAction>;

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
  * @returns {Promise<void>}
  */
  add_regular_input: (address: Address, input: TransactionInput, amount: Value) => Promise<void>;

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
  * @returns {Promise<Value>}
  */
  total_value: () => Promise<Value>;

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
  * @returns {Promise<URL>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<URL>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<URL>}
  */
  static from_hex: (hex_str: string) => Promise<URL>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<URL>}
  */
  static from_json: (json: string) => Promise<URL>;

  /**
  * @param {string} url
  * @returns {Promise<URL>}
  */
  static new: (url: string) => Promise<URL>;

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
  * @returns {Promise<UnitInterval>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<UnitInterval>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<UnitInterval>}
  */
  static from_hex: (hex_str: string) => Promise<UnitInterval>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<UnitInterval>}
  */
  static from_json: (json: string) => Promise<UnitInterval>;

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
  * @returns {Promise<Update>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Update>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Update>}
  */
  static from_hex: (hex_str: string) => Promise<Update>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Update>}
  */
  static from_json: (json: string) => Promise<Update>;

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


export class UpdateCommitteeAction extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<UpdateCommitteeAction>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<UpdateCommitteeAction>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<UpdateCommitteeAction>}
  */
  static from_hex: (hex_str: string) => Promise<UpdateCommitteeAction>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<UpdateCommitteeAction>}
  */
  static from_json: (json: string) => Promise<UpdateCommitteeAction>;

  /**
  * @returns {Promise<Optional<GovernanceActionId>>}
  */
  gov_action_id: () => Promise<Optional<GovernanceActionId>>;

  /**
  * @returns {Promise<Committee>}
  */
  committee: () => Promise<Committee>;

  /**
  * @returns {Promise<Credentials>}
  */
  members_to_remove: () => Promise<Credentials>;

  /**
  * @param {Committee} committee
  * @param {Credentials} members_to_remove
  * @returns {Promise<UpdateCommitteeAction>}
  */
  static new: (committee: Committee, members_to_remove: Credentials) => Promise<UpdateCommitteeAction>;

  /**
  * @param {GovernanceActionId} gov_action_id
  * @param {Committee} committee
  * @param {Credentials} members_to_remove
  * @returns {Promise<UpdateCommitteeAction>}
  */
  static new_with_action_id: (gov_action_id: GovernanceActionId, committee: Committee, members_to_remove: Credentials) => Promise<UpdateCommitteeAction>;

}


export class VRFCert extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VRFCert>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VRFCert>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VRFCert>}
  */
  static from_hex: (hex_str: string) => Promise<VRFCert>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VRFCert>}
  */
  static from_json: (json: string) => Promise<VRFCert>;

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
  * @returns {Promise<VRFCert>}
  */
  static new: (output: Uint8Array, proof: Uint8Array) => Promise<VRFCert>;

}


export class VRFKeyHash extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VRFKeyHash>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VRFKeyHash>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<VRFKeyHash>}
  */
  static from_bech32: (bech_str: string) => Promise<VRFKeyHash>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<VRFKeyHash>}
  */
  static from_hex: (hex: string) => Promise<VRFKeyHash>;

}


export class VRFVKey extends Ptr {
  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VRFVKey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VRFVKey>;

  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {string} prefix
  * @returns {Promise<string>}
  */
  to_bech32: (prefix: string) => Promise<string>;

  /**
  * @param {string} bech_str
  * @returns {Promise<VRFVKey>}
  */
  static from_bech32: (bech_str: string) => Promise<VRFVKey>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex
  * @returns {Promise<VRFVKey>}
  */
  static from_hex: (hex: string) => Promise<VRFVKey>;

}


export class Value extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Value>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Value>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Value>}
  */
  static from_hex: (hex_str: string) => Promise<Value>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Value>}
  */
  static from_json: (json: string) => Promise<Value>;

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
  * @returns {Promise<Value>}
  */
  checked_add: (rhs: Value) => Promise<Value>;

  /**
  * @param {Value} rhs_value
  * @returns {Promise<Value>}
  */
  checked_sub: (rhs_value: Value) => Promise<Value>;

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
  * @returns {Promise<Vkey>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Vkey>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Vkey>}
  */
  static from_hex: (hex_str: string) => Promise<Vkey>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Vkey>}
  */
  static from_json: (json: string) => Promise<Vkey>;

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
  * @returns {Promise<Vkeywitness>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Vkeywitness>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Vkeywitness>}
  */
  static from_hex: (hex_str: string) => Promise<Vkeywitness>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Vkeywitness>}
  */
  static from_json: (json: string) => Promise<Vkeywitness>;

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
  * @returns {Promise<Vkeywitnesses>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Vkeywitnesses>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Vkeywitnesses>}
  */
  static from_hex: (hex_str: string) => Promise<Vkeywitnesses>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Vkeywitnesses>}
  */
  static from_json: (json: string) => Promise<Vkeywitnesses>;

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


export class VoteDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VoteDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VoteDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VoteDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<VoteDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VoteDelegation>}
  */
  static from_json: (json: string) => Promise<VoteDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<DRep>}
  */
  drep: () => Promise<DRep>;

  /**
  * @param {Credential} stake_credential
  * @param {DRep} drep
  * @returns {Promise<VoteDelegation>}
  */
  static new: (stake_credential: Credential, drep: DRep) => Promise<VoteDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class VoteRegistrationAndDelegation extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VoteRegistrationAndDelegation>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VoteRegistrationAndDelegation>}
  */
  static from_hex: (hex_str: string) => Promise<VoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VoteRegistrationAndDelegation>}
  */
  static from_json: (json: string) => Promise<VoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<Credential>}
  */
  stake_credential: () => Promise<Credential>;

  /**
  * @returns {Promise<DRep>}
  */
  drep: () => Promise<DRep>;

  /**
  * @returns {Promise<BigNum>}
  */
  coin: () => Promise<BigNum>;

  /**
  * @param {Credential} stake_credential
  * @param {DRep} drep
  * @param {BigNum} coin
  * @returns {Promise<VoteRegistrationAndDelegation>}
  */
  static new: (stake_credential: Credential, drep: DRep, coin: BigNum) => Promise<VoteRegistrationAndDelegation>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

}


export class Voter extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Voter>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Voter>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Voter>}
  */
  static from_hex: (hex_str: string) => Promise<Voter>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Voter>}
  */
  static from_json: (json: string) => Promise<Voter>;

  /**
  * @param {Credential} cred
  * @returns {Promise<Voter>}
  */
  static new_constitutional_committee_hot_key: (cred: Credential) => Promise<Voter>;

  /**
  * @param {Credential} cred
  * @returns {Promise<Voter>}
  */
  static new_drep: (cred: Credential) => Promise<Voter>;

  /**
  * @param {Ed25519KeyHash} key_hash
  * @returns {Promise<Voter>}
  */
  static new_staking_pool: (key_hash: Ed25519KeyHash) => Promise<Voter>;

  /**
  * @returns {Promise<VoterKind>}
  */
  kind: () => Promise<VoterKind>;

  /**
  * @returns {Promise<Optional<Credential>>}
  */
  to_constitutional_committee_hot_cred: () => Promise<Optional<Credential>>;

  /**
  * @returns {Promise<Optional<Credential>>}
  */
  to_drep_cred: () => Promise<Optional<Credential>>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  to_staking_pool_key_hash: () => Promise<Optional<Ed25519KeyHash>>;

  /**
  * @returns {Promise<boolean>}
  */
  has_script_credentials: () => Promise<boolean>;

  /**
  * @returns {Promise<Optional<Ed25519KeyHash>>}
  */
  to_key_hash: () => Promise<Optional<Ed25519KeyHash>>;

}


export class Voters extends Ptr {
  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Voters>}
  */
  static from_json: (json: string) => Promise<Voters>;

  /**
  * @returns {Promise<Voters>}
  */
  static new: () => Promise<Voters>;

  /**
  * @param {Voter} voter
  */
  add: (voter: Voter) => Promise<void>;

  /**
  * @param {number} index
  * @returns {Promise<Optional<Voter>>}
  */
  get: (index: number) => Promise<Optional<Voter>>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

}


export class VotingBuilder extends Ptr {
  /**
  * @returns {Promise<VotingBuilder>}
  */
  static new: () => Promise<VotingBuilder>;

  /**
  * @param {Voter} voter
  * @param {GovernanceActionId} gov_action_id
  * @param {VotingProcedure} voting_procedure
  * @returns {Promise<void>}
  */
  add: (voter: Voter, gov_action_id: GovernanceActionId, voting_procedure: VotingProcedure) => Promise<void>;

  /**
  * @param {Voter} voter
  * @param {GovernanceActionId} gov_action_id
  * @param {VotingProcedure} voting_procedure
  * @param {PlutusWitness} witness
  * @returns {Promise<void>}
  */
  add_with_plutus_witness: (voter: Voter, gov_action_id: GovernanceActionId, voting_procedure: VotingProcedure, witness: PlutusWitness) => Promise<void>;

  /**
  * @param {Voter} voter
  * @param {GovernanceActionId} gov_action_id
  * @param {VotingProcedure} voting_procedure
  * @param {NativeScriptSource} native_script_source
  * @returns {Promise<void>}
  */
  add_with_native_script: (voter: Voter, gov_action_id: GovernanceActionId, voting_procedure: VotingProcedure, native_script_source: NativeScriptSource) => Promise<void>;

  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  get_plutus_witnesses: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  get_native_scripts: () => Promise<NativeScripts>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_scripts: () => Promise<boolean>;

  /**
  * @returns {Promise<VotingProcedures>}
  */
  build: () => Promise<VotingProcedures>;

}


export class VotingProcedure extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VotingProcedure>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VotingProcedure>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VotingProcedure>}
  */
  static from_hex: (hex_str: string) => Promise<VotingProcedure>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VotingProcedure>}
  */
  static from_json: (json: string) => Promise<VotingProcedure>;

  /**
  * @param {VoteKind} vote
  * @returns {Promise<VotingProcedure>}
  */
  static new: (vote: VoteKind) => Promise<VotingProcedure>;

  /**
  * @param {VoteKind} vote
  * @param {Anchor} anchor
  * @returns {Promise<VotingProcedure>}
  */
  static new_with_anchor: (vote: VoteKind, anchor: Anchor) => Promise<VotingProcedure>;

  /**
  * @returns {Promise<VoteKind>}
  */
  vote_kind: () => Promise<VoteKind>;

  /**
  * @returns {Promise<Optional<Anchor>>}
  */
  anchor: () => Promise<Optional<Anchor>>;

}


export class VotingProcedures extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VotingProcedures>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VotingProcedures>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VotingProcedures>}
  */
  static from_hex: (hex_str: string) => Promise<VotingProcedures>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VotingProcedures>}
  */
  static from_json: (json: string) => Promise<VotingProcedures>;

  /**
  * @returns {Promise<VotingProcedures>}
  */
  static new: () => Promise<VotingProcedures>;

  /**
  * @param {Voter} voter
  * @param {GovernanceActionId} governance_action_id
  * @param {VotingProcedure} voting_procedure
  */
  insert: (voter: Voter, governance_action_id: GovernanceActionId, voting_procedure: VotingProcedure) => Promise<void>;

  /**
  * @param {Voter} voter
  * @param {GovernanceActionId} governance_action_id
  * @returns {Promise<Optional<VotingProcedure>>}
  */
  get: (voter: Voter, governance_action_id: GovernanceActionId) => Promise<Optional<VotingProcedure>>;

  /**
  * @returns {Promise<Voters>}
  */
  get_voters: () => Promise<Voters>;

  /**
  * @param {Voter} voter
  * @returns {Promise<GovernanceActionIds>}
  */
  get_governance_action_ids_by_voter: (voter: Voter) => Promise<GovernanceActionIds>;

}


export class VotingProposal extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VotingProposal>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VotingProposal>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VotingProposal>}
  */
  static from_hex: (hex_str: string) => Promise<VotingProposal>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VotingProposal>}
  */
  static from_json: (json: string) => Promise<VotingProposal>;

  /**
  * @returns {Promise<GovernanceAction>}
  */
  governance_action: () => Promise<GovernanceAction>;

  /**
  * @returns {Promise<Anchor>}
  */
  anchor: () => Promise<Anchor>;

  /**
  * @returns {Promise<RewardAddress>}
  */
  reward_account: () => Promise<RewardAddress>;

  /**
  * @returns {Promise<BigNum>}
  */
  deposit: () => Promise<BigNum>;

  /**
  * @param {GovernanceAction} governance_action
  * @param {Anchor} anchor
  * @param {RewardAddress} reward_account
  * @param {BigNum} deposit
  * @returns {Promise<VotingProposal>}
  */
  static new: (governance_action: GovernanceAction, anchor: Anchor, reward_account: RewardAddress, deposit: BigNum) => Promise<VotingProposal>;

}


export class VotingProposalBuilder extends Ptr {
  /**
  * @returns {Promise<VotingProposalBuilder>}
  */
  static new: () => Promise<VotingProposalBuilder>;

  /**
  * @param {VotingProposal} proposal
  * @returns {Promise<void>}
  */
  add: (proposal: VotingProposal) => Promise<void>;

  /**
  * @param {VotingProposal} proposal
  * @param {PlutusWitness} witness
  * @returns {Promise<void>}
  */
  add_with_plutus_witness: (proposal: VotingProposal, witness: PlutusWitness) => Promise<void>;

  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  get_plutus_witnesses: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_scripts: () => Promise<boolean>;

  /**
  * @returns {Promise<VotingProposals>}
  */
  build: () => Promise<VotingProposals>;

}


export class VotingProposals extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<VotingProposals>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<VotingProposals>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<VotingProposals>}
  */
  static from_hex: (hex_str: string) => Promise<VotingProposals>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<VotingProposals>}
  */
  static from_json: (json: string) => Promise<VotingProposals>;

  /**
  * @returns {Promise<VotingProposals>}
  */
  static new: () => Promise<VotingProposals>;

  /**
  * @returns {Promise<number>}
  */
  len: () => Promise<number>;

  /**
  * @param {number} index
  * @returns {Promise<VotingProposal>}
  */
  get: (index: number) => Promise<VotingProposal>;

  /**
  * @param {VotingProposal} proposal
  */
  add: (proposal: VotingProposal) => Promise<void>;

}


export class Withdrawals extends Ptr {
  /**
  * @returns {Promise<Uint8Array>}
  */
  to_bytes: () => Promise<Uint8Array>;

  /**
  * @param {Uint8Array} bytes
  * @returns {Promise<Withdrawals>}
  */
  static from_bytes: (bytes: Uint8Array) => Promise<Withdrawals>;

  /**
  * @returns {Promise<string>}
  */
  to_hex: () => Promise<string>;

  /**
  * @param {string} hex_str
  * @returns {Promise<Withdrawals>}
  */
  static from_hex: (hex_str: string) => Promise<Withdrawals>;

  /**
  * @returns {Promise<string>}
  */
  to_json: () => Promise<string>;

  /**
  * @param {string} json
  * @returns {Promise<Withdrawals>}
  */
  static from_json: (json: string) => Promise<Withdrawals>;

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


export class WithdrawalsBuilder extends Ptr {
  /**
  * @returns {Promise<WithdrawalsBuilder>}
  */
  static new: () => Promise<WithdrawalsBuilder>;

  /**
  * @param {RewardAddress} address
  * @param {BigNum} coin
  * @returns {Promise<void>}
  */
  add: (address: RewardAddress, coin: BigNum) => Promise<void>;

  /**
  * @param {RewardAddress} address
  * @param {BigNum} coin
  * @param {PlutusWitness} witness
  * @returns {Promise<void>}
  */
  add_with_plutus_witness: (address: RewardAddress, coin: BigNum, witness: PlutusWitness) => Promise<void>;

  /**
  * @param {RewardAddress} address
  * @param {BigNum} coin
  * @param {NativeScriptSource} native_script_source
  * @returns {Promise<void>}
  */
  add_with_native_script: (address: RewardAddress, coin: BigNum, native_script_source: NativeScriptSource) => Promise<void>;

  /**
  * @returns {Promise<PlutusWitnesses>}
  */
  get_plutus_witnesses: () => Promise<PlutusWitnesses>;

  /**
  * @returns {Promise<TransactionInputs>}
  */
  get_ref_inputs: () => Promise<TransactionInputs>;

  /**
  * @returns {Promise<NativeScripts>}
  */
  get_native_scripts: () => Promise<NativeScripts>;

  /**
  * @returns {Promise<Value>}
  */
  get_total_withdrawals: () => Promise<Value>;

  /**
  * @returns {Promise<boolean>}
  */
  has_plutus_scripts: () => Promise<boolean>;

  /**
  * @returns {Promise<Withdrawals>}
  */
  build: () => Promise<Withdrawals>;

}


/**
* @param {ExUnits} ex_units
* @param {ExUnitPrices} ex_unit_prices
* @returns {Promise<BigNum>}
*/
export const calculate_ex_units_ceil_cost: (ex_units: ExUnits, ex_unit_prices: ExUnitPrices) => Promise<BigNum>;

/**
* @param {Address} address
* @param {TransactionUnspentOutputs} utxos
* @param {TransactionBuilderConfig} config
* @returns {Promise<TransactionBatchList>}
*/
export const create_send_all: (address: Address, utxos: TransactionUnspentOutputs, config: TransactionBuilderConfig) => Promise<TransactionBatchList>;

/**
* @param {TransactionMetadatum} metadata
* @returns {Promise<Uint8Array>}
*/
export const decode_arbitrary_bytes_from_metadatum: (metadata: TransactionMetadatum) => Promise<Uint8Array>;

/**
* @param {TransactionMetadatum} metadatum
* @param {MetadataJsonSchema} schema
* @returns {Promise<string>}
*/
export const decode_metadatum_to_json_str: (metadatum: TransactionMetadatum, schema: MetadataJsonSchema) => Promise<string>;

/**
* @param {PlutusData} datum
* @param {PlutusDatumSchema} schema
* @returns {Promise<string>}
*/
export const decode_plutus_datum_to_json_str: (datum: PlutusData, schema: PlutusDatumSchema) => Promise<string>;

/**
* @param {string} password
* @param {string} data
* @returns {Promise<string>}
*/
export const decrypt_with_password: (password: string, data: string) => Promise<string>;

/**
* @param {Uint8Array} bytes
* @returns {Promise<TransactionMetadatum>}
*/
export const encode_arbitrary_bytes_as_metadatum: (bytes: Uint8Array) => Promise<TransactionMetadatum>;

/**
* @param {string} json
* @param {MetadataJsonSchema} schema
* @returns {Promise<TransactionMetadatum>}
*/
export const encode_json_str_to_metadatum: (json: string, schema: MetadataJsonSchema) => Promise<TransactionMetadatum>;

/**
* @param {string} json
* @param {string} self_xpub
* @param {ScriptSchema} schema
* @returns {Promise<NativeScript>}
*/
export const encode_json_str_to_native_script: (json: string, self_xpub: string, schema: ScriptSchema) => Promise<NativeScript>;

/**
* @param {string} json
* @param {PlutusDatumSchema} schema
* @returns {Promise<PlutusData>}
*/
export const encode_json_str_to_plutus_datum: (json: string, schema: PlutusDatumSchema) => Promise<PlutusData>;

/**
* @param {string} password
* @param {string} salt
* @param {string} nonce
* @param {string} data
* @returns {Promise<string>}
*/
export const encrypt_with_password: (password: string, salt: string, nonce: string, data: string) => Promise<string>;

/**
* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {Promise<BigNum>}
*/
export const get_deposit: (txbody: TransactionBody, pool_deposit: BigNum, key_deposit: BigNum) => Promise<BigNum>;

/**
* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {Promise<Value>}
*/
export const get_implicit_input: (txbody: TransactionBody, pool_deposit: BigNum, key_deposit: BigNum) => Promise<Value>;

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
* @returns {Promise<BigNum>}
*/
export const min_ada_for_output: (output: TransactionOutput, data_cost: DataCost) => Promise<BigNum>;

/**
* @param {Transaction} tx
* @param {LinearFee} linear_fee
* @returns {Promise<BigNum>}
*/
export const min_fee: (tx: Transaction, linear_fee: LinearFee) => Promise<BigNum>;

/**
* @param {Transaction} tx
* @param {ExUnitPrices} ex_unit_prices
* @returns {Promise<BigNum>}
*/
export const min_script_fee: (tx: Transaction, ex_unit_prices: ExUnitPrices) => Promise<BigNum>;

export enum CborContainerType {
  Array = 0,
  Map = 1,
}


export enum CertificateKind {
  StakeRegistration = 0,
  StakeDeregistration = 1,
  StakeDelegation = 2,
  PoolRegistration = 3,
  PoolRetirement = 4,
  GenesisKeyDelegation = 5,
  MoveInstantaneousRewardsCert = 6,
  CommitteeHotAuth = 7,
  CommitteeColdResign = 8,
  DrepDeregistration = 9,
  DrepRegistration = 10,
  DrepUpdate = 11,
  StakeAndVoteDelegation = 12,
  StakeRegistrationAndDelegation = 13,
  StakeVoteRegistrationAndDelegation = 14,
  VoteDelegation = 15,
  VoteRegistrationAndDelegation = 16,
}


export enum CoinSelectionStrategyCIP2 {
  LargestFirst = 0,
  RandomImprove = 1,
  LargestFirstMultiAsset = 2,
  RandomImproveMultiAsset = 3,
}


export enum CredKind {
  Key = 0,
  Script = 1,
}


export enum DRepKind {
  KeyHash = 0,
  ScriptHash = 1,
  AlwaysAbstain = 2,
  AlwaysNoConfidence = 3,
}


export enum GovernanceActionKind {
  ParameterChangeAction = 0,
  HardForkInitiationAction = 1,
  TreasuryWithdrawalsAction = 2,
  NoConfidenceAction = 3,
  UpdateCommitteeAction = 4,
  NewConstitutionAction = 5,
  InfoAction = 6,
}


export enum LanguageKind {
  PlutusV1 = 0,
  PlutusV2 = 1,
  PlutusV3 = 2,
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
  Vote = 4,
  VotingProposal = 5,
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
  PlutusScriptV3 = 3,
}


export enum ScriptSchema {
  Wallet = 0,
  Node = 1,
}


export enum TransactionMetadatumKind {
  MetadataMap = 0,
  MetadataList = 1,
  Int = 2,
  Bytes = 3,
  Text = 4,
}


export enum VoteKind {
  No = 0,
  Yes = 1,
  Abstain = 2,
}


export enum VoterKind {
  ConstitutionalCommitteeHotKeyHash = 0,
  ConstitutionalCommitteeHotScriptHash = 1,
  DRepKeyHash = 2,
  DRepScriptHash = 3,
  StakingPoolKeyHash = 4,
}


