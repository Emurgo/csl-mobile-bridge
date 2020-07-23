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

    // BigNum
    public final native Result<RPtr> bigNumFromStr(String str);
    public final native Result<String> bigNumToStr(RPtr bigNum);

    // Bip32PrivateKey
    public final native Result<RPtr> bip32PrivateKeyDerive(RPtr bip32PrivateKey, long index);
    public final native Result<RPtr> bip32PrivateKeyGenerateEd25519Bip32();
    public final native Result<RPtr> bip32PrivateKeyToRawKey(RPtr bip32PrivateKey);
    public final native Result<RPtr> bip32PrivateKeyToPublic(RPtr bip32PrivateKey);
    public final native Result<RPtr> bip32PrivateKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> bip32PrivateKeyAsBytes(RPtr bip32PrivateKey);
    public final native Result<RPtr> bip32PrivateKeyFromBech32(String bech32Str);
    public final native Result<String> bip32PrivateKeyToBech32(RPtr bip32PrivateKey);
    public final native Result<RPtr> bip32PrivateKeyFromBip39Entropy(byte[] entropy, byte[] password);

    // ByronAddress
    public final native Result<String> byronAddressToBase58(RPtr byronAddress);
    public final native Result<RPtr> byronAddressFromBase58(String str);

    // Address
    public final native Result<byte[]> addressToBytes(RPtr address);
    public final native Result<RPtr> addressFromBytes(byte[] bytes);

    // Ed25519KeyHash
    public final native Result<byte[]> ed25519KeyHashToBytes(RPtr ed25519KeyHash);
    public final native Result<RPtr> ed25519KeyHashFromBytes(byte[] bytes);

    // TransactionHash
    public final native Result<byte[]> transactionHashToBytes(RPtr transactionHash);
    public final native Result<RPtr> transactionHashFromBytes(byte[] bytes);

    // StakeCredential
    public final native Result<RPtr> stakeCredentialFromKeyHash(RPtr keyHash);
    public final native Result<RPtr> stakeCredentialToKeyHash(RPtr stakeCredential);
    public final native Result<Integer> stakeCredentialKind(RPtr stakeCredential);

    // BaseAddress
    public final native Result<RPtr> baseAddressNew(int network, RPtr payment, RPtr stake);
    public final native Result<RPtr> baseAddressPaymentCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressStakeCred(RPtr baseAddress);

    // UnitInterval
    public final native Result<byte[]> unitIntervalToBytes(RPtr unitInterval);
    public final native Result<RPtr> unitIntervalFromBytes(byte[] bytes);
    public final native Result<RPtr> unitIntervalNew(RPtr numerator, RPtr denominator);

    // TransactionInput
    public final native Result<byte[]> transactionInputToBytes(RPtr transactionInput);
    public final native Result<RPtr> transactionInputFromBytes(byte[] bytes);
    public final native Result<RPtr> transactionInputTransactionId(RPtr transactionInput);
    public final native Result<Long> transactionInputIndex(RPtr transactionInput);
    public final native Result<RPtr> transactionInputNew(RPtr transactionId, long index);

    // TransactionOutput
    public final native Result<byte[]> transactionOutputToBytes(RPtr transactionOutput);
    public final native Result<RPtr> transactionOutputFromBytes(byte[] bytes);
    public final native Result<RPtr> transactionOutputNew(RPtr address, RPtr amount);

    // LinearFee
    public final native Result<RPtr> linearFeeCoefficient(RPtr linearFee);
    public final native Result<RPtr> linearFeeConstant(RPtr linearFee);
    public final native Result<RPtr> linearFeeNew(RPtr coefficient, RPtr constant);

    public final native void ptrFree(RPtr ptr);
}
