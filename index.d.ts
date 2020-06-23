export type Optional<T> = T | undefined;

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

export class StakeCredential extends Ptr {

  /**
  * @param {AddrKeyHash} hash
  * @returns {Promise<StakeCredential>}
  */
  static from_keyhash(hash: AddrKeyHash): Promise<StakeCredential>
}
