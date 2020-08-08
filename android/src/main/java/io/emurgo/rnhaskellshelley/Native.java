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

    // Utils
    public final native Result<RPtr> makeIcarusBootstrapWitness(RPtr txBodyHash, RPtr addr, RPtr key);
    public final native Result<RPtr> makeVkeyWitness(RPtr txBodyHash, RPtr sk);
    public final native Result<RPtr> hashTransaction(RPtr txBody);

    // BigNum
    public final native Result<RPtr> bigNumFromStr(String str);
    public final native Result<String> bigNumToStr(RPtr bigNum);
    public final native Result<RPtr> bigNumCheckedAdd(RPtr bigNum, RPtr other);
    public final native Result<RPtr> bigNumCheckedSub(RPtr bigNum, RPtr other);

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
    public final native Result<Boolean> byronAddressIsValid(String str);
    public final native Result<RPtr> byronAddressFromAddress(RPtr address);
    public final native Result<RPtr> byronAddressToAddress(RPtr byronAddress);

    // Address
    public final native Result<byte[]> addressToBytes(RPtr address);
    public final native Result<RPtr> addressFromBytes(byte[] bytes);
    public final native Result<String> addressToBech32(RPtr address);
    public final native Result<RPtr> addressFromBech32(String str);

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
    public final native Result<byte[]> stakeCredentialToBytes(RPtr stakeCredential);
    public final native Result<RPtr> stakeCredentialFromBytes(byte[] bytes);

    // BaseAddress
    public final native Result<RPtr> baseAddressNew(int network, RPtr payment, RPtr stake);
    public final native Result<RPtr> baseAddressPaymentCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressStakeCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressFromAddress(RPtr address);

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

    // Vkeywitnesses
    public final native Result<RPtr> vkeywitnessesNew();
    public final native Result<Long> vkeywitnessesLen(RPtr vkwitnesses);
    public final native Result<Void> vkeywitnessesAdd(RPtr vkwitnesses, RPtr item);

    // BootstrapWitnesses
    public final native Result<RPtr> bootstrapWitnessesNew();
    public final native Result<Long> bootstrapWitnessesLen(RPtr witnesses);
    public final native Result<Void> bootstrapWitnessesAdd(RPtr witnesses, RPtr item);

    // TransactionWitnessSet
    public final native Result<RPtr> transactionWitnessSetNew();
    public final native Result<Void> transactionWitnessSetSetVkeys(RPtr witnessSet, RPtr vkeys);
    public final native Result<Void> transactionWitnessSetSetBootstraps(RPtr witnessSet, RPtr bootstraps);

    // TransactionBody
    public final native Result<byte[]> transactionBodyToBytes(RPtr TransactionBody);
    public final native Result<RPtr> transactionBodyFromBytes(byte[] bytes);

    // Transaction
    public final native Result<RPtr> transactionBody(RPtr tx);
    public final native Result<RPtr> transactionNew(RPtr body, RPtr witnessSet);
    public final native Result<byte[]> transactionToBytes(RPtr Transaction);
    public final native Result<RPtr> transactionFromBytes(byte[] bytes);

    // TransactionBuilder
    public final native Result<Void> transactionBuilderAddKeyInput(RPtr txBuilder, RPtr hash, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddBootstrapInput(RPtr txBuilder, RPtr hash, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddOutput(RPtr txBuilder, RPtr input);
    public final native Result<Void> transactionBuilderSetFee(RPtr txBuilder, RPtr fee);
    public final native Result<Void> transactionBuilderSetTtl(RPtr txBuilder, long ttl);
    public final native Result<RPtr> transactionBuilderNew(RPtr linearFee, RPtr minimumUtxoVal, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> transactionBuilderGetExplicitInput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetImplicitInput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetExplicitOutput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetFeeOrCalc(RPtr txBuilder);
    public final native Result<Boolean> transactionBuilderAddChangeIfNeeded(RPtr txBuilder, RPtr address);
    public final native Result<RPtr> transactionBuilderBuild(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderEstimateFee(RPtr txBuilder);

    public final native void ptrFree(RPtr ptr);
}
