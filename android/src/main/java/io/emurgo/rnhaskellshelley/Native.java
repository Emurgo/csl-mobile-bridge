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

    // StakeCredential
    public final native Result<RPtr> stakeCredentialFromKeyHash(RPtr addrKeyHash);
    public final native Result<RPtr> stakeCredentialToKeyHash(RPtr stakeCredential);
    public final native Result<Integer> stakeCredentialKind(RPtr stakeCredential);

    // BaseAddress
    public final native Result<RPtr> baseAddressNew(int network, RPtr payment, RPtr stake);
    public final native Result<RPtr> baseAddressPaymentCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressStakeCred(RPtr baseAddress);

    // UnitInterval
    public final native Result<byte[]> unitIntervalToBytes(RPtr unitInterval);
    public final native Result<RPtr> unitIntervalFromBytes(byte[] bytes);
    public final native Result<RPtr> unitIntervalNew(long index0, long index1);

    public final native void ptrFree(RPtr ptr);
}
