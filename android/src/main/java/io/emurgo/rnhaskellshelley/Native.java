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
    public final native Result<RPtr> minAdaRequired(RPtr assets, RPtr minUtxoVal);

    // BigNum
    public final native Result<RPtr> bigNumFromStr(String str);
    public final native Result<String> bigNumToStr(RPtr bigNum);
    public final native Result<RPtr> bigNumCheckedAdd(RPtr bigNum, RPtr other);
    public final native Result<RPtr> bigNumCheckedSub(RPtr bigNum, RPtr other);
    public final native Result<RPtr> bigNumClampedSub(RPtr bigNum, RPtr other);
    public final native Result<Integer> bigNumCompare(RPtr bigNum, RPtr rhs);

    // Value
    public final native Result<RPtr> valueNew(RPtr coin);
    public final native Result<RPtr> valueCoin(RPtr value);
    public final native Result<RPtr> valueSetCoin(RPtr value, RPtr coin);
    public final native Result<RPtr> valueMultiasset(RPtr value);
    public final native Result<RPtr> valueSetMultiasset(RPtr value, RPtr multiasset);
    public final native Result<RPtr> valueCheckedAdd(RPtr value, RPtr rhs);
    public final native Result<RPtr> valueCheckedSub(RPtr value, RPtr rhs);
    public final native Result<RPtr> valueClampedSub(RPtr value, RPtr rhs);
    public final native Result<Integer> valueCompare(RPtr value, RPtr rhs);

    // AssetName
    public final native Result<byte[]> assetNameToBytes(RPtr assetName);
    public final native Result<RPtr> assetNameFromBytes(byte[] bytes);
    public final native Result<RPtr> assetNameNew(byte[] bytes);
    public final native Result<byte[]> assetNameName(RPtr assetName);

    // AssetNames
    // public final native Result<byte[]> assetNamesToBytes(RPtr assetNames);
    // public final native Result<RPtr> assetNamesFromBytes(byte[] bytes);
    public final native Result<RPtr> assetNamesNew();
    public final native Result<Long> assetNamesLen(RPtr assetNames);
    public final native Result<RPtr> assetNamesGet(RPtr assetNames, long index);
    public final native Result<Void> assetNamesAdd(RPtr assetNames, RPtr item);

    // PublicKey
    public final native Result<RPtr> publicKeyFromBech32(String bech32);
    public final native Result<String> publicKeyToBech32(RPtr pubKey);
    public final native Result<RPtr> publicKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> publicKeyAsBytes(RPtr pubKey);
    // public final native Result<RPtr> publicKeyVerify(RPtr pubKey, byte[] bytes, RPtr signature);
    public final native Result<RPtr> publicKeyHash(RPtr pubKey);

    // PrivateKey
    public final native Result<RPtr> privateKeyToPublic(RPtr privateKey);
    public final native Result<byte[]> privateKeyAsBytes(RPtr privateKey);
    public final native Result<RPtr> privateKeyFromExtendedBytes(byte[] bytes);

    // Bip32PublicKey
    public final native Result<RPtr> bip32PublicKeyDerive(RPtr bip32PublicKey, long index);
    public final native Result<RPtr> bip32PublicKeyToRawKey(RPtr bip32PublicKey);
    public final native Result<RPtr> bip32PublicKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> bip32PublicKeyAsBytes(RPtr bip32PublicKey);
    public final native Result<RPtr> bip32PublicKeyFromBech32(String bech32Str);
    public final native Result<String> bip32PublicKeyToBech32(RPtr bip32PublicKey);
    public final native Result<byte[]> bip32PublicKeyChaincode(RPtr bip32PublicKey);

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
    public final native Result<Long> byronAddressByronProtocolMagic(RPtr byronAddress);
    public final native Result<byte[]> byronAddressAttributes(RPtr byronAddress);

    // Address
    public final native Result<byte[]> addressToBytes(RPtr address);
    public final native Result<RPtr> addressFromBytes(byte[] bytes);
    public final native Result<String> addressToBech32(RPtr address);
    public final native Result<String> addressToBech32WithPrefix(RPtr address, String prefix);
    public final native Result<RPtr> addressFromBech32(String str);
    public final native Result<Integer> addressNetworkId(RPtr address);

    // Ed25519Signature
    public final native Result<byte[]> ed25519SignatureToBytes(RPtr ed25519Signature);
    public final native Result<RPtr> ed25519SignatureFromBytes(byte[] bytes);

    // Ed25519KeyHash
    public final native Result<byte[]> ed25519KeyHashToBytes(RPtr ed25519KeyHash);
    public final native Result<RPtr> ed25519KeyHashFromBytes(byte[] bytes);

    // ScriptHash
    public final native Result<byte[]> scriptHashToBytes(RPtr scriptHash);
    public final native Result<RPtr> scriptHashFromBytes(byte[] bytes);

    // ScriptHashes
    public final native Result<byte[]> scriptHashesToBytes(RPtr scriptHashes);
    public final native Result<RPtr> scriptHashesFromBytes(byte[] bytes);
    public final native Result<RPtr> scriptHashesNew();
    public final native Result<Long> scriptHashesLen(RPtr scriptHashes);
    public final native Result<RPtr> scriptHashesGet(RPtr scriptHashes, long index);
    public final native Result<Void> scriptHashesAdd(RPtr scriptHashes, RPtr item);

    // Assets
    public final native Result<RPtr> assetsNew();
    public final native Result<Long> assetsLen(RPtr assets);
    public final native Result<RPtr> assetsInsert(RPtr assets, RPtr key, RPtr value);
    public final native Result<RPtr> assetsGet(RPtr assets, RPtr key);
    public final native Result<RPtr> assetsKeys(RPtr assets);

    // MultiAsset
    public final native Result<RPtr> multiAssetNew();
    public final native Result<Long> multiAssetLen(RPtr multiAsset);
    public final native Result<RPtr> multiAssetInsert(RPtr multiAsset, RPtr key, RPtr value);
    public final native Result<RPtr> multiAssetGet(RPtr multiAsset, RPtr key);
    public final native Result<RPtr> multiAssetKeys(RPtr multiAsset);
    public final native Result<RPtr> multiAssetSub(RPtr multiAsset, RPtr other);

    // TransactionHash
    public final native Result<byte[]> transactionHashToBytes(RPtr transactionHash);
    public final native Result<RPtr> transactionHashFromBytes(byte[] bytes);

    // StakeCredential
    public final native Result<RPtr> stakeCredentialFromKeyHash(RPtr keyHash);
    public final native Result<RPtr> stakeCredentialFromScriptHash(RPtr keyHash);
    public final native Result<RPtr> stakeCredentialToKeyHash(RPtr stakeCredential);
    public final native Result<RPtr> stakeCredentialToScriptHash(RPtr stakeCredential);
    public final native Result<Integer> stakeCredentialKind(RPtr stakeCredential);
    public final native Result<byte[]> stakeCredentialToBytes(RPtr stakeCredential);
    public final native Result<RPtr> stakeCredentialFromBytes(byte[] bytes);

    // StakeRegistration
    public final native Result<RPtr> stakeRegistrationNew(RPtr stakeCredential);
    public final native Result<RPtr> stakeRegistrationStakeCredential(RPtr stakeRegistration);
    public final native Result<byte[]> stakeRegistrationToBytes(RPtr stakeRegistration);
    public final native Result<RPtr> stakeRegistrationFromBytes(byte[] bytes);

    // StakeDeregistration
    public final native Result<RPtr> stakeDeregistrationNew(RPtr stakeCredential);
    public final native Result<RPtr> stakeDeregistrationStakeCredential(RPtr stakeDeregistration);
    public final native Result<byte[]> stakeDeregistrationToBytes(RPtr stakeDeregistration);
    public final native Result<RPtr> stakeDeregistrationFromBytes(byte[] bytes);

    // StakeDelegation
    public final native Result<RPtr> stakeDelegationNew(RPtr stakeCredential, RPtr poolKeyhash);
    public final native Result<RPtr> stakeDelegationStakeCredential(RPtr stakeDelegation);
    public final native Result<RPtr> stakeDelegationPoolKeyhash(RPtr stakeDelegation);
    public final native Result<byte[]> stakeDelegationToBytes(RPtr stakeDelegation);
    public final native Result<RPtr> stakeDelegationFromBytes(byte[] bytes);

    // Certificate
    public final native Result<RPtr> certificateNewStakeRegistration(RPtr stakeRegistration);
    public final native Result<RPtr> certificateNewStakeDeregistration(RPtr stakeDeregistration);
    public final native Result<RPtr> certificateNewStakeDelegation(RPtr stakeDelegation);
    public final native Result<RPtr> certificateAsStakeRegistration(RPtr certificate);
    public final native Result<RPtr> certificateAsStakeDeregistration(RPtr certificate);
    public final native Result<RPtr> certificateAsStakeDelegation(RPtr certificate);
    public final native Result<byte[]> certificateToBytes(RPtr certificate);
    public final native Result<RPtr> certificateFromBytes(byte[] bytes);

    // Certificates
    public final native Result<byte[]> certificatesToBytes(RPtr certificates);
    public final native Result<RPtr> certificatesFromBytes(byte[] bytes);
    public final native Result<RPtr> certificatesNew();
    public final native Result<Long> certificatesLen(RPtr certificates);
    public final native Result<RPtr> certificatesGet(RPtr certificates, long index);
    public final native Result<Void> certificatesAdd(RPtr certificates, RPtr item);

    // BaseAddress
    public final native Result<RPtr> baseAddressNew(int network, RPtr payment, RPtr stake);
    public final native Result<RPtr> baseAddressPaymentCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressStakeCred(RPtr baseAddress);
    public final native Result<RPtr> baseAddressToAddress(RPtr baseAddress);
    public final native Result<RPtr> baseAddressFromAddress(RPtr address);

    // RewardAddress
    public final native Result<RPtr> rewardAddressNew(int network, RPtr payment);
    public final native Result<RPtr> rewardAddressPaymentCred(RPtr baseAddress);
    public final native Result<RPtr> rewardAddressToAddress(RPtr baseAddress);
    public final native Result<RPtr> rewardAddressFromAddress(RPtr address);

    // RewardAddresses
    public final native Result<RPtr> rewardAddressesNew();
    public final native Result<Long> rewardAddressesLen(RPtr rewardAddresses);
    public final native Result<RPtr> rewardAddressesGet(RPtr rewardAddresses, long index);
    public final native Result<Void> rewardAddressesAdd(RPtr rewardAddresses, RPtr item);

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

    // TransactionInputs
    public final native Result<Long> transactionInputsLen(RPtr txInputs);
    public final native Result<RPtr> transactionInputsGet(RPtr txInputs, long index);


    // TransactionOutput
    public final native Result<byte[]> transactionOutputToBytes(RPtr transactionOutput);
    public final native Result<RPtr> transactionOutputFromBytes(byte[] bytes);
    public final native Result<RPtr> transactionOutputNew(RPtr address, RPtr amount);
    public final native Result<RPtr> transactionOutputAmount(RPtr transactionOutput);
    public final native Result<RPtr> transactionOutputAddress(RPtr transactionOutput);

    // TransactionOutputs
    public final native Result<Long> transactionOutputsLen(RPtr txOutputs);
    public final native Result<RPtr> transactionOutputsGet(RPtr txOutputs, long index);

    // LinearFee
    public final native Result<RPtr> linearFeeCoefficient(RPtr linearFee);
    public final native Result<RPtr> linearFeeConstant(RPtr linearFee);
    public final native Result<RPtr> linearFeeNew(RPtr coefficient, RPtr constant);

    // Vkey
    public final native Result<RPtr> vkeyNew(RPtr publicKey);

    // Vkeywitness
    public final native Result<byte[]> vkeywitnessToBytes(RPtr vkeywitness);
    public final native Result<RPtr> vkeywitnessFromBytes(byte[] bytes);
    public final native Result<RPtr> vkeywitnessNew(RPtr vkey, RPtr signature);
    public final native Result<RPtr> vkeywitnessSignature(RPtr vkwitnesses);

    // Vkeywitnesses
    public final native Result<RPtr> vkeywitnessesNew();
    public final native Result<Long> vkeywitnessesLen(RPtr vkwitnesses);
    public final native Result<Void> vkeywitnessesAdd(RPtr vkwitnesses, RPtr item);

    // BootstrapWitness
    public final native Result<byte[]> bootstrapWitnessToBytes(RPtr bootstrapWitness);
    public final native Result<RPtr> bootstrapWitnessFromBytes(byte[] bytes);
    public final native Result<RPtr> bootstrapWitnessNew(RPtr vkey, RPtr signature, byte[] chainCode, byte[] attributes);

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
    public final native Result<RPtr> transactionBodyInputs(RPtr TransactionBody);
    public final native Result<RPtr> transactionBodyOutputs(RPtr TransactionBody);
    public final native Result<RPtr> transactionBodyFee(RPtr TransactionBody);
    public final native Result<Long> transactionBodyTtl(RPtr TransactionBody);
    public final native Result<RPtr> transactionBodyWithdrawals(RPtr TransactionBody);
    public final native Result<RPtr> transactionBodyCerts(RPtr TransactionBody);

    // Transaction
    public final native Result<RPtr> transactionBody(RPtr tx);
    public final native Result<RPtr> transactionNew(RPtr body, RPtr witnessSet);
    public final native Result<byte[]> transactionToBytes(RPtr Transaction);
    public final native Result<RPtr> transactionFromBytes(byte[] bytes);

    // TransactionBuilder
    public final native Result<Void> transactionBuilderAddKeyInput(RPtr txBuilder, RPtr hash, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddScriptInput(RPtr txBuilder, RPtr hash, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddBootstrapInput(RPtr txBuilder, RPtr hash, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddInput(RPtr txBuilder, RPtr address, RPtr input, RPtr value);
    public final native Result<RPtr> transactionBuilderFeeForInput(RPtr txBuilder, RPtr address, RPtr input, RPtr value);
    public final native Result<Void> transactionBuilderAddOutput(RPtr txBuilder, RPtr output);
    public final native Result<RPtr> transactionBuilderFeeForOutput(RPtr txBuilder, RPtr output);
    public final native Result<Void> transactionBuilderSetFee(RPtr txBuilder, RPtr fee);
    public final native Result<Void> transactionBuilderSetTtl(RPtr txBuilder, long ttl);
    public final native Result<Void> transactionBuilderSetValidityStartInterval(RPtr txBuilder, long vsi);
    public final native Result<Void> transactionBuilderSetCerts(RPtr txBuilder, RPtr certs);
    public final native Result<Void> transactionBuilderSetWithdrawals(RPtr txBuilder, RPtr withdrawals);
    public final native Result<Void> transactionBuilderSetMetadata(RPtr txBuilder, RPtr metadata);
    public final native Result<RPtr> transactionBuilderNew(RPtr linearFee, RPtr minimumUtxoVal, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> transactionBuilderGetExplicitInput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetImplicitInput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetExplicitOutput(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetDeposit(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderGetFeeIfSet(RPtr txBuilder);
    public final native Result<Boolean> transactionBuilderAddChangeIfNeeded(RPtr txBuilder, RPtr address);
    public final native Result<RPtr> transactionBuilderBuild(RPtr txBuilder);
    public final native Result<RPtr> transactionBuilderMinFee(RPtr txBuilder);

    // Withdrawals
    public final native Result<RPtr> withdrawalsNew();
    public final native Result<Long> withdrawalsLen(RPtr withdrawals);
    public final native Result<RPtr> withdrawalsInsert(RPtr withdrawals, RPtr key, RPtr value);
    public final native Result<RPtr> withdrawalsGet(RPtr withdrawals, RPtr key);
    public final native Result<RPtr> withdrawalsKeys(RPtr withdrawals);


    public final native void ptrFree(RPtr ptr);
}
