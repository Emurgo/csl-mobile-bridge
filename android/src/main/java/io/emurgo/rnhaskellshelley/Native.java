package io.emurgo.rnhaskellshelley;

import java.util.Map;

final class Native {
    static final Native I;

    static {
        I = new Native();
        System.loadLibrary("react_native_haskell_shelley");
        I.initLibrary();
    }

    private Native() { }

    private native void initLibrary();

    // Address
    public final native Result<byte[]> addressToBytes(RPtr address);
    public final native Result<RPtr> addressFromBytes(byte[] bytes);

    // AddrKeyHash
    public final native Result<byte[]> addrKeyHashToBytes(RPtr addrKeyHash);
    public final native Result<RPtr> addrKeyHashFromBytes(byte[] bytes);

    public final native void ptrFree(RPtr ptr);
}
