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

    public final native void ptrFree(RPtr ptr);

    public final native Result<byte[]> certificateToBytes(RPtr self);
    public final native Result<RPtr> certificateFromBytes(byte[] bytes);
    public final native Result<String> certificateToHex(RPtr self);
    public final native Result<RPtr> certificateFromHex(String hexStr);
    public final native Result<String> certificateToJson(RPtr self);
    public final native Result<RPtr> certificateFromJson(String json);
    public final native Result<RPtr> certificateNewStakeRegistration(RPtr stakeRegistration);
    public final native Result<RPtr> certificateNewStakeDeregistration(RPtr stakeDeregistration);
    public final native Result<RPtr> certificateNewStakeDelegation(RPtr stakeDelegation);
    public final native Result<RPtr> certificateNewPoolRegistration(RPtr poolRegistration);
    public final native Result<RPtr> certificateNewPoolRetirement(RPtr poolRetirement);
    public final native Result<RPtr> certificateNewGenesisKeyDelegation(RPtr genesisKeyDelegation);
    public final native Result<RPtr> certificateNewMoveInstantaneousRewardsCert(RPtr moveInstantaneousRewardsCert);
    public final native Result<Integer> certificateKind(RPtr self);
    public final native Result<RPtr> certificateAsStakeRegistration(RPtr self);
    public final native Result<RPtr> certificateAsStakeDeregistration(RPtr self);
    public final native Result<RPtr> certificateAsStakeDelegation(RPtr self);
    public final native Result<RPtr> certificateAsPoolRegistration(RPtr self);
    public final native Result<RPtr> certificateAsPoolRetirement(RPtr self);
    public final native Result<RPtr> certificateAsGenesisKeyDelegation(RPtr self);
    public final native Result<RPtr> certificateAsMoveInstantaneousRewardsCert(RPtr self);

    public final native Result<byte[]> transactionWitnessSetToBytes(RPtr self);
    public final native Result<RPtr> transactionWitnessSetFromBytes(byte[] bytes);
    public final native Result<String> transactionWitnessSetToHex(RPtr self);
    public final native Result<RPtr> transactionWitnessSetFromHex(String hexStr);
    public final native Result<String> transactionWitnessSetToJson(RPtr self);
    public final native Result<RPtr> transactionWitnessSetFromJson(String json);
    public final native Result<Void> transactionWitnessSetSetVkeys(RPtr self, RPtr vkeys);
    public final native Result<RPtr> transactionWitnessSetVkeys(RPtr self);
    public final native Result<Void> transactionWitnessSetSetNativeScripts(RPtr self, RPtr nativeScripts);
    public final native Result<RPtr> transactionWitnessSetNativeScripts(RPtr self);
    public final native Result<Void> transactionWitnessSetSetBootstraps(RPtr self, RPtr bootstraps);
    public final native Result<RPtr> transactionWitnessSetBootstraps(RPtr self);
    public final native Result<Void> transactionWitnessSetSetPlutusScripts(RPtr self, RPtr plutusScripts);
    public final native Result<RPtr> transactionWitnessSetPlutusScripts(RPtr self);
    public final native Result<Void> transactionWitnessSetSetPlutusData(RPtr self, RPtr plutusData);
    public final native Result<RPtr> transactionWitnessSetPlutusData(RPtr self);
    public final native Result<Void> transactionWitnessSetSetRedeemers(RPtr self, RPtr redeemers);
    public final native Result<RPtr> transactionWitnessSetRedeemers(RPtr self);
    public final native Result<RPtr> transactionWitnessSetNew();

    public final native Result<RPtr> addressFromBytes(byte[] data);
    public final native Result<String> addressToJson(RPtr self);
    public final native Result<RPtr> addressFromJson(String json);
    public final native Result<String> addressToHex(RPtr self);
    public final native Result<RPtr> addressFromHex(String hexStr);
    public final native Result<byte[]> addressToBytes(RPtr self);
    public final native Result<String> addressToBech32(RPtr self);
    public final native Result<String> addressToBech32WithPrefix(RPtr self, String prefix);

    public final native Result<RPtr> addressFromBech32(String bechStr);
    public final native Result<Long> addressNetworkId(RPtr self);

    public final native Result<byte[]> blockToBytes(RPtr self);
    public final native Result<RPtr> blockFromBytes(byte[] bytes);
    public final native Result<String> blockToHex(RPtr self);
    public final native Result<RPtr> blockFromHex(String hexStr);
    public final native Result<String> blockToJson(RPtr self);
    public final native Result<RPtr> blockFromJson(String json);
    public final native Result<RPtr> blockHeader(RPtr self);
    public final native Result<RPtr> blockTransactionBodies(RPtr self);
    public final native Result<RPtr> blockTransactionWitnessSets(RPtr self);
    public final native Result<RPtr> blockAuxiliaryDataSet(RPtr self);
    public final native Result<String> blockInvalidTransactions(RPtr self);
    public final native Result<RPtr> blockNew(RPtr header, RPtr transactionBodies, RPtr transactionWitnessSets, RPtr auxiliaryDataSet, String invalidTransactions);

    public final native Result<RPtr> vkeysNew();
    public final native Result<Long> vkeysLen(RPtr self);
    public final native Result<RPtr> vkeysGet(RPtr self, long index);
    public final native Result<Void> vkeysAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> ipv4ToBytes(RPtr self);
    public final native Result<RPtr> ipv4FromBytes(byte[] bytes);
    public final native Result<String> ipv4ToHex(RPtr self);
    public final native Result<RPtr> ipv4FromHex(String hexStr);
    public final native Result<String> ipv4ToJson(RPtr self);
    public final native Result<RPtr> ipv4FromJson(String json);
    public final native Result<RPtr> ipv4New(byte[] data);
    public final native Result<byte[]> ipv4Ip(RPtr self);

    public final native Result<byte[]> certificatesToBytes(RPtr self);
    public final native Result<RPtr> certificatesFromBytes(byte[] bytes);
    public final native Result<String> certificatesToHex(RPtr self);
    public final native Result<RPtr> certificatesFromHex(String hexStr);
    public final native Result<String> certificatesToJson(RPtr self);
    public final native Result<RPtr> certificatesFromJson(String json);
    public final native Result<RPtr> certificatesNew();
    public final native Result<Long> certificatesLen(RPtr self);
    public final native Result<RPtr> certificatesGet(RPtr self, long index);
    public final native Result<Void> certificatesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> protocolVersionToBytes(RPtr self);
    public final native Result<RPtr> protocolVersionFromBytes(byte[] bytes);
    public final native Result<String> protocolVersionToHex(RPtr self);
    public final native Result<RPtr> protocolVersionFromHex(String hexStr);
    public final native Result<String> protocolVersionToJson(RPtr self);
    public final native Result<RPtr> protocolVersionFromJson(String json);
    public final native Result<Long> protocolVersionMajor(RPtr self);
    public final native Result<Long> protocolVersionMinor(RPtr self);
    public final native Result<RPtr> protocolVersionNew(long major, long minor);

    public final native Result<byte[]> metadataListToBytes(RPtr self);
    public final native Result<RPtr> metadataListFromBytes(byte[] bytes);
    public final native Result<String> metadataListToHex(RPtr self);
    public final native Result<RPtr> metadataListFromHex(String hexStr);
    public final native Result<RPtr> metadataListNew();
    public final native Result<Long> metadataListLen(RPtr self);
    public final native Result<RPtr> metadataListGet(RPtr self, long index);
    public final native Result<Void> metadataListAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> transactionMetadatumLabelsToBytes(RPtr self);
    public final native Result<RPtr> transactionMetadatumLabelsFromBytes(byte[] bytes);
    public final native Result<String> transactionMetadatumLabelsToHex(RPtr self);
    public final native Result<RPtr> transactionMetadatumLabelsFromHex(String hexStr);
    public final native Result<RPtr> transactionMetadatumLabelsNew();
    public final native Result<Long> transactionMetadatumLabelsLen(RPtr self);
    public final native Result<RPtr> transactionMetadatumLabelsGet(RPtr self, long index);
    public final native Result<Void> transactionMetadatumLabelsAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> transactionBodyToBytes(RPtr self);
    public final native Result<RPtr> transactionBodyFromBytes(byte[] bytes);
    public final native Result<String> transactionBodyToHex(RPtr self);
    public final native Result<RPtr> transactionBodyFromHex(String hexStr);
    public final native Result<String> transactionBodyToJson(RPtr self);
    public final native Result<RPtr> transactionBodyFromJson(String json);
    public final native Result<RPtr> transactionBodyInputs(RPtr self);
    public final native Result<RPtr> transactionBodyOutputs(RPtr self);
    public final native Result<RPtr> transactionBodyFee(RPtr self);
    public final native Result<Long> transactionBodyTtl(RPtr self);
    public final native Result<RPtr> transactionBodyTtlBignum(RPtr self);
    public final native Result<Void> transactionBodySetTtl(RPtr self, RPtr ttl);
    public final native Result<Void> transactionBodyRemoveTtl(RPtr self);
    public final native Result<Void> transactionBodySetCerts(RPtr self, RPtr certs);
    public final native Result<RPtr> transactionBodyCerts(RPtr self);
    public final native Result<Void> transactionBodySetWithdrawals(RPtr self, RPtr withdrawals);
    public final native Result<RPtr> transactionBodyWithdrawals(RPtr self);
    public final native Result<Void> transactionBodySetUpdate(RPtr self, RPtr update);
    public final native Result<RPtr> transactionBodyUpdate(RPtr self);
    public final native Result<Void> transactionBodySetAuxiliaryDataHash(RPtr self, RPtr auxiliaryDataHash);
    public final native Result<RPtr> transactionBodyAuxiliaryDataHash(RPtr self);
    public final native Result<Void> transactionBodySetValidityStartInterval(RPtr self, long validityStartInterval);
    public final native Result<Void> transactionBodySetValidityStartIntervalBignum(RPtr self, RPtr validityStartInterval);
    public final native Result<RPtr> transactionBodyValidityStartIntervalBignum(RPtr self);
    public final native Result<Long> transactionBodyValidityStartInterval(RPtr self);
    public final native Result<Void> transactionBodySetMint(RPtr self, RPtr mint);
    public final native Result<RPtr> transactionBodyMint(RPtr self);
    public final native Result<RPtr> transactionBodyMultiassets(RPtr self);
    public final native Result<Void> transactionBodySetReferenceInputs(RPtr self, RPtr referenceInputs);
    public final native Result<RPtr> transactionBodyReferenceInputs(RPtr self);
    public final native Result<Void> transactionBodySetScriptDataHash(RPtr self, RPtr scriptDataHash);
    public final native Result<RPtr> transactionBodyScriptDataHash(RPtr self);
    public final native Result<Void> transactionBodySetCollateral(RPtr self, RPtr collateral);
    public final native Result<RPtr> transactionBodyCollateral(RPtr self);
    public final native Result<Void> transactionBodySetRequiredSigners(RPtr self, RPtr requiredSigners);
    public final native Result<RPtr> transactionBodyRequiredSigners(RPtr self);
    public final native Result<Void> transactionBodySetNetworkId(RPtr self, RPtr networkId);
    public final native Result<RPtr> transactionBodyNetworkId(RPtr self);
    public final native Result<Void> transactionBodySetCollateralReturn(RPtr self, RPtr collateralReturn);
    public final native Result<RPtr> transactionBodyCollateralReturn(RPtr self);
    public final native Result<Void> transactionBodySetTotalCollateral(RPtr self, RPtr totalCollateral);
    public final native Result<RPtr> transactionBodyTotalCollateral(RPtr self);
    public final native Result<RPtr> transactionBodyNew(RPtr inputs, RPtr outputs, RPtr fee);
    public final native Result<RPtr> transactionBodyNewWithTtl(RPtr inputs, RPtr outputs, RPtr fee, long ttl);

    public final native Result<RPtr> transactionBodyNewTxBody(RPtr inputs, RPtr outputs, RPtr fee);

    public final native Result<RPtr> genesisHashFromBytes(byte[] bytes);
    public final native Result<byte[]> genesisHashToBytes(RPtr self);
    public final native Result<String> genesisHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> genesisHashFromBech32(String bechStr);
    public final native Result<String> genesisHashToHex(RPtr self);
    public final native Result<RPtr> genesisHashFromHex(String hex);

    public final native Result<byte[]> transactionInputToBytes(RPtr self);
    public final native Result<RPtr> transactionInputFromBytes(byte[] bytes);
    public final native Result<String> transactionInputToHex(RPtr self);
    public final native Result<RPtr> transactionInputFromHex(String hexStr);
    public final native Result<String> transactionInputToJson(RPtr self);
    public final native Result<RPtr> transactionInputFromJson(String json);
    public final native Result<RPtr> transactionInputTransactionId(RPtr self);
    public final native Result<Long> transactionInputIndex(RPtr self);
    public final native Result<RPtr> transactionInputNew(RPtr transactionId, long index);

    public final native Result<byte[]> plutusScriptToBytes(RPtr self);
    public final native Result<RPtr> plutusScriptFromBytes(byte[] bytes);
    public final native Result<String> plutusScriptToHex(RPtr self);
    public final native Result<RPtr> plutusScriptFromHex(String hexStr);
    public final native Result<RPtr> plutusScriptNew(byte[] bytes);
    public final native Result<RPtr> plutusScriptNewV2(byte[] bytes);
    public final native Result<RPtr> plutusScriptNewWithVersion(byte[] bytes, RPtr language);
    public final native Result<byte[]> plutusScriptBytes(RPtr self);
    public final native Result<RPtr> plutusScriptFromBytesV2(byte[] bytes);
    public final native Result<RPtr> plutusScriptFromBytesWithVersion(byte[] bytes, RPtr language);
    public final native Result<RPtr> plutusScriptFromHexWithVersion(String hexStr, RPtr language);
    public final native Result<RPtr> plutusScriptHash(RPtr self);
    public final native Result<RPtr> plutusScriptLanguageVersion(RPtr self);

    public final native Result<byte[]> poolMetadataToBytes(RPtr self);
    public final native Result<RPtr> poolMetadataFromBytes(byte[] bytes);
    public final native Result<String> poolMetadataToHex(RPtr self);
    public final native Result<RPtr> poolMetadataFromHex(String hexStr);
    public final native Result<String> poolMetadataToJson(RPtr self);
    public final native Result<RPtr> poolMetadataFromJson(String json);
    public final native Result<RPtr> poolMetadataUrl(RPtr self);
    public final native Result<RPtr> poolMetadataPoolMetadataHash(RPtr self);
    public final native Result<RPtr> poolMetadataNew(RPtr url, RPtr poolMetadataHash);

    public final native Result<Void> transactionBuilderAddInputsFrom(RPtr self, RPtr inputs, int strategy);
    public final native Result<Void> transactionBuilderSetInputs(RPtr self, RPtr inputs);
    public final native Result<Void> transactionBuilderSetCollateral(RPtr self, RPtr collateral);
    public final native Result<Void> transactionBuilderSetCollateralReturn(RPtr self, RPtr collateralReturn);
    public final native Result<Void> transactionBuilderSetCollateralReturnAndTotal(RPtr self, RPtr collateralReturn);
    public final native Result<Void> transactionBuilderSetTotalCollateral(RPtr self, RPtr totalCollateral);
    public final native Result<Void> transactionBuilderSetTotalCollateralAndReturn(RPtr self, RPtr totalCollateral, RPtr returnAddress);
    public final native Result<Void> transactionBuilderAddReferenceInput(RPtr self, RPtr referenceInput);
    public final native Result<Void> transactionBuilderAddKeyInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddScriptInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddNativeScriptInput(RPtr self, RPtr script, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddPlutusScriptInput(RPtr self, RPtr witness, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddBootstrapInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddInput(RPtr self, RPtr address, RPtr input, RPtr amount);
    public final native Result<Long> transactionBuilderCountMissingInputScripts(RPtr self);
    public final native Result<Long> transactionBuilderAddRequiredNativeInputScripts(RPtr self, RPtr scripts);
    public final native Result<Long> transactionBuilderAddRequiredPlutusInputScripts(RPtr self, RPtr scripts);
    public final native Result<RPtr> transactionBuilderGetNativeInputScripts(RPtr self);
    public final native Result<RPtr> transactionBuilderGetPlutusInputScripts(RPtr self);
    public final native Result<RPtr> transactionBuilderFeeForInput(RPtr self, RPtr address, RPtr input, RPtr amount);
    public final native Result<Void> transactionBuilderAddOutput(RPtr self, RPtr output);
    public final native Result<RPtr> transactionBuilderFeeForOutput(RPtr self, RPtr output);
    public final native Result<Void> transactionBuilderSetFee(RPtr self, RPtr fee);
    public final native Result<Void> transactionBuilderSetTtl(RPtr self, long ttl);
    public final native Result<Void> transactionBuilderSetTtlBignum(RPtr self, RPtr ttl);
    public final native Result<Void> transactionBuilderSetValidityStartInterval(RPtr self, long validityStartInterval);
    public final native Result<Void> transactionBuilderSetValidityStartIntervalBignum(RPtr self, RPtr validityStartInterval);
    public final native Result<Void> transactionBuilderSetCerts(RPtr self, RPtr certs);
    public final native Result<Void> transactionBuilderSetWithdrawals(RPtr self, RPtr withdrawals);
    public final native Result<RPtr> transactionBuilderGetAuxiliaryData(RPtr self);
    public final native Result<Void> transactionBuilderSetAuxiliaryData(RPtr self, RPtr auxiliaryData);
    public final native Result<Void> transactionBuilderSetMetadata(RPtr self, RPtr metadata);
    public final native Result<Void> transactionBuilderAddMetadatum(RPtr self, RPtr key, RPtr val);
    public final native Result<Void> transactionBuilderAddJsonMetadatum(RPtr self, RPtr key, String val);
    public final native Result<Void> transactionBuilderAddJsonMetadatumWithSchema(RPtr self, RPtr key, String val, int schema);
    public final native Result<Void> transactionBuilderSetMintBuilder(RPtr self, RPtr mintBuilder);
    public final native Result<RPtr> transactionBuilderGetMintBuilder(RPtr self);
    public final native Result<Void> transactionBuilderSetMint(RPtr self, RPtr mint, RPtr mintScripts);
    public final native Result<RPtr> transactionBuilderGetMint(RPtr self);
    public final native Result<RPtr> transactionBuilderGetMintScripts(RPtr self);
    public final native Result<Void> transactionBuilderSetMintAsset(RPtr self, RPtr policyScript, RPtr mintAssets);
    public final native Result<Void> transactionBuilderAddMintAsset(RPtr self, RPtr policyScript, RPtr assetName, RPtr amount);
    public final native Result<Void> transactionBuilderAddMintAssetAndOutput(RPtr self, RPtr policyScript, RPtr assetName, RPtr amount, RPtr outputBuilder, RPtr outputCoin);
    public final native Result<Void> transactionBuilderAddMintAssetAndOutputMinRequiredCoin(RPtr self, RPtr policyScript, RPtr assetName, RPtr amount, RPtr outputBuilder);
    public final native Result<RPtr> transactionBuilderNew(RPtr cfg);
    public final native Result<RPtr> transactionBuilderGetReferenceInputs(RPtr self);
    public final native Result<RPtr> transactionBuilderGetExplicitInput(RPtr self);
    public final native Result<RPtr> transactionBuilderGetImplicitInput(RPtr self);
    public final native Result<RPtr> transactionBuilderGetTotalInput(RPtr self);
    public final native Result<RPtr> transactionBuilderGetTotalOutput(RPtr self);
    public final native Result<RPtr> transactionBuilderGetExplicitOutput(RPtr self);
    public final native Result<RPtr> transactionBuilderGetDeposit(RPtr self);
    public final native Result<RPtr> transactionBuilderGetFeeIfSet(RPtr self);
    public final native Result<Boolean> transactionBuilderAddChangeIfNeeded(RPtr self, RPtr address);
    public final native Result<Void> transactionBuilderCalcScriptDataHash(RPtr self, RPtr costModels);
    public final native Result<Void> transactionBuilderSetScriptDataHash(RPtr self, RPtr hash);
    public final native Result<Void> transactionBuilderRemoveScriptDataHash(RPtr self);
    public final native Result<Void> transactionBuilderAddRequiredSigner(RPtr self, RPtr key);
    public final native Result<Long> transactionBuilderFullSize(RPtr self);
    public final native Result<String> transactionBuilderOutputSizes(RPtr self);
    public final native Result<RPtr> transactionBuilderBuild(RPtr self);
    public final native Result<RPtr> transactionBuilderBuildTx(RPtr self);
    public final native Result<RPtr> transactionBuilderBuildTxUnsafe(RPtr self);
    public final native Result<RPtr> transactionBuilderMinFee(RPtr self);

    public final native Result<byte[]> transactionOutputsToBytes(RPtr self);
    public final native Result<RPtr> transactionOutputsFromBytes(byte[] bytes);
    public final native Result<String> transactionOutputsToHex(RPtr self);
    public final native Result<RPtr> transactionOutputsFromHex(String hexStr);
    public final native Result<String> transactionOutputsToJson(RPtr self);
    public final native Result<RPtr> transactionOutputsFromJson(String json);
    public final native Result<RPtr> transactionOutputsNew();
    public final native Result<Long> transactionOutputsLen(RPtr self);
    public final native Result<RPtr> transactionOutputsGet(RPtr self, long index);
    public final native Result<Void> transactionOutputsAdd(RPtr self, RPtr elem);

    public final native Result<RPtr> inputsWithScriptWitnessNew();
    public final native Result<Void> inputsWithScriptWitnessAdd(RPtr self, RPtr input);
    public final native Result<RPtr> inputsWithScriptWitnessGet(RPtr self, long index);
    public final native Result<Long> inputsWithScriptWitnessLen(RPtr self);

    public final native Result<byte[]> poolRegistrationToBytes(RPtr self);
    public final native Result<RPtr> poolRegistrationFromBytes(byte[] bytes);
    public final native Result<String> poolRegistrationToHex(RPtr self);
    public final native Result<RPtr> poolRegistrationFromHex(String hexStr);
    public final native Result<String> poolRegistrationToJson(RPtr self);
    public final native Result<RPtr> poolRegistrationFromJson(String json);
    public final native Result<RPtr> poolRegistrationPoolParams(RPtr self);
    public final native Result<RPtr> poolRegistrationNew(RPtr poolParams);

    public final native Result<byte[]> transactionUnspentOutputToBytes(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputFromBytes(byte[] bytes);
    public final native Result<String> transactionUnspentOutputToHex(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputFromHex(String hexStr);
    public final native Result<String> transactionUnspentOutputToJson(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputFromJson(String json);
    public final native Result<RPtr> transactionUnspentOutputNew(RPtr input, RPtr output);
    public final native Result<RPtr> transactionUnspentOutputInput(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputOutput(RPtr self);

    public final native Result<RPtr> mintAssetsNew();
    public final native Result<RPtr> mintAssetsNewFromEntry(RPtr key, RPtr value);
    public final native Result<Long> mintAssetsLen(RPtr self);
    public final native Result<RPtr> mintAssetsInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> mintAssetsGet(RPtr self, RPtr key);
    public final native Result<RPtr> mintAssetsKeys(RPtr self);

    public final native Result<byte[]> vkeywitnessToBytes(RPtr self);
    public final native Result<RPtr> vkeywitnessFromBytes(byte[] bytes);
    public final native Result<String> vkeywitnessToHex(RPtr self);
    public final native Result<RPtr> vkeywitnessFromHex(String hexStr);
    public final native Result<String> vkeywitnessToJson(RPtr self);
    public final native Result<RPtr> vkeywitnessFromJson(String json);
    public final native Result<RPtr> vkeywitnessNew(RPtr vkey, RPtr signature);
    public final native Result<RPtr> vkeywitnessVkey(RPtr self);
    public final native Result<RPtr> vkeywitnessSignature(RPtr self);

    public final native Result<byte[]> redeemerToBytes(RPtr self);
    public final native Result<RPtr> redeemerFromBytes(byte[] bytes);
    public final native Result<String> redeemerToHex(RPtr self);
    public final native Result<RPtr> redeemerFromHex(String hexStr);
    public final native Result<String> redeemerToJson(RPtr self);
    public final native Result<RPtr> redeemerFromJson(String json);
    public final native Result<RPtr> redeemerTag(RPtr self);
    public final native Result<RPtr> redeemerIndex(RPtr self);
    public final native Result<RPtr> redeemerData(RPtr self);
    public final native Result<RPtr> redeemerExUnits(RPtr self);
    public final native Result<RPtr> redeemerNew(RPtr tag, RPtr index, RPtr data, RPtr exUnits);

    public final native Result<byte[]> singleHostNameToBytes(RPtr self);
    public final native Result<RPtr> singleHostNameFromBytes(byte[] bytes);
    public final native Result<String> singleHostNameToHex(RPtr self);
    public final native Result<RPtr> singleHostNameFromHex(String hexStr);
    public final native Result<String> singleHostNameToJson(RPtr self);
    public final native Result<RPtr> singleHostNameFromJson(String json);
    public final native Result<Long> singleHostNamePort(RPtr self);
    public final native Result<RPtr> singleHostNameDnsName(RPtr self);
    public final native Result<RPtr> singleHostNameNew(RPtr dnsName);
    public final native Result<RPtr> singleHostNameNewWithPort(long port, RPtr dnsName);


    public final native Result<byte[]> relaysToBytes(RPtr self);
    public final native Result<RPtr> relaysFromBytes(byte[] bytes);
    public final native Result<String> relaysToHex(RPtr self);
    public final native Result<RPtr> relaysFromHex(String hexStr);
    public final native Result<String> relaysToJson(RPtr self);
    public final native Result<RPtr> relaysFromJson(String json);
    public final native Result<RPtr> relaysNew();
    public final native Result<Long> relaysLen(RPtr self);
    public final native Result<RPtr> relaysGet(RPtr self, long index);
    public final native Result<Void> relaysAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> costmdlsToBytes(RPtr self);
    public final native Result<RPtr> costmdlsFromBytes(byte[] bytes);
    public final native Result<String> costmdlsToHex(RPtr self);
    public final native Result<RPtr> costmdlsFromHex(String hexStr);
    public final native Result<String> costmdlsToJson(RPtr self);
    public final native Result<RPtr> costmdlsFromJson(String json);
    public final native Result<RPtr> costmdlsNew();
    public final native Result<Long> costmdlsLen(RPtr self);
    public final native Result<RPtr> costmdlsInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> costmdlsGet(RPtr self, RPtr key);
    public final native Result<RPtr> costmdlsKeys(RPtr self);
    public final native Result<RPtr> costmdlsRetainLanguageVersions(RPtr self, RPtr languages);

    public final native Result<byte[]> redeemerTagToBytes(RPtr self);
    public final native Result<RPtr> redeemerTagFromBytes(byte[] bytes);
    public final native Result<String> redeemerTagToHex(RPtr self);
    public final native Result<RPtr> redeemerTagFromHex(String hexStr);
    public final native Result<String> redeemerTagToJson(RPtr self);
    public final native Result<RPtr> redeemerTagFromJson(String json);
    public final native Result<RPtr> redeemerTagNewSpend();
    public final native Result<RPtr> redeemerTagNewMint();
    public final native Result<RPtr> redeemerTagNewCert();
    public final native Result<RPtr> redeemerTagNewReward();
    public final native Result<Integer> redeemerTagKind(RPtr self);

    public final native Result<RPtr> scriptDataHashFromBytes(byte[] bytes);
    public final native Result<byte[]> scriptDataHashToBytes(RPtr self);
    public final native Result<String> scriptDataHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> scriptDataHashFromBech32(String bechStr);
    public final native Result<String> scriptDataHashToHex(RPtr self);
    public final native Result<RPtr> scriptDataHashFromHex(String hex);

    public final native Result<byte[]> costModelToBytes(RPtr self);
    public final native Result<RPtr> costModelFromBytes(byte[] bytes);
    public final native Result<String> costModelToHex(RPtr self);
    public final native Result<RPtr> costModelFromHex(String hexStr);
    public final native Result<String> costModelToJson(RPtr self);
    public final native Result<RPtr> costModelFromJson(String json);
    public final native Result<RPtr> costModelNew();
    public final native Result<RPtr> costModelSet(RPtr self, long operation, RPtr cost);
    public final native Result<RPtr> costModelGet(RPtr self, long operation);
    public final native Result<Long> costModelLen(RPtr self);

    public final native Result<byte[]> ed25519SignatureToBytes(RPtr self);
    public final native Result<String> ed25519SignatureToBech32(RPtr self);
    public final native Result<String> ed25519SignatureToHex(RPtr self);
    public final native Result<RPtr> ed25519SignatureFromBech32(String bech32Str);
    public final native Result<RPtr> ed25519SignatureFromHex(String input);
    public final native Result<RPtr> ed25519SignatureFromBytes(byte[] bytes);

    public final native Result<RPtr> bip32PrivateKeyDerive(RPtr self, long index);
    public final native Result<RPtr> bip32PrivateKeyFrom_128Xprv(byte[] bytes);
    public final native Result<byte[]> bip32PrivateKeyTo_128Xprv(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyGenerateEd25519Bip32();
    public final native Result<RPtr> bip32PrivateKeyToRawKey(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyToPublic(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> bip32PrivateKeyAsBytes(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyFromBech32(String bech32Str);
    public final native Result<String> bip32PrivateKeyToBech32(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyFromBip39Entropy(byte[] entropy, byte[] password);
    public final native Result<byte[]> bip32PrivateKeyChaincode(RPtr self);
    public final native Result<String> bip32PrivateKeyToHex(RPtr self);
    public final native Result<RPtr> bip32PrivateKeyFromHex(String hexStr);

    public final native Result<RPtr> vkeywitnessesNew();
    public final native Result<Long> vkeywitnessesLen(RPtr self);
    public final native Result<RPtr> vkeywitnessesGet(RPtr self, long index);
    public final native Result<Void> vkeywitnessesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> transactionMetadatumToBytes(RPtr self);
    public final native Result<RPtr> transactionMetadatumFromBytes(byte[] bytes);
    public final native Result<String> transactionMetadatumToHex(RPtr self);
    public final native Result<RPtr> transactionMetadatumFromHex(String hexStr);
    public final native Result<RPtr> transactionMetadatumNewMap(RPtr map);
    public final native Result<RPtr> transactionMetadatumNewList(RPtr list);
    public final native Result<RPtr> transactionMetadatumNewInt(RPtr intValue);
    public final native Result<RPtr> transactionMetadatumNewBytes(byte[] bytes);
    public final native Result<RPtr> transactionMetadatumNewText(String text);
    public final native Result<Integer> transactionMetadatumKind(RPtr self);
    public final native Result<RPtr> transactionMetadatumAsMap(RPtr self);
    public final native Result<RPtr> transactionMetadatumAsList(RPtr self);
    public final native Result<RPtr> transactionMetadatumAsInt(RPtr self);
    public final native Result<byte[]> transactionMetadatumAsBytes(RPtr self);
    public final native Result<String> transactionMetadatumAsText(RPtr self);

    public final native Result<byte[]> rewardAddressesToBytes(RPtr self);
    public final native Result<RPtr> rewardAddressesFromBytes(byte[] bytes);
    public final native Result<String> rewardAddressesToHex(RPtr self);
    public final native Result<RPtr> rewardAddressesFromHex(String hexStr);
    public final native Result<String> rewardAddressesToJson(RPtr self);
    public final native Result<RPtr> rewardAddressesFromJson(String json);
    public final native Result<RPtr> rewardAddressesNew();
    public final native Result<Long> rewardAddressesLen(RPtr self);
    public final native Result<RPtr> rewardAddressesGet(RPtr self, long index);
    public final native Result<Void> rewardAddressesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> plutusListToBytes(RPtr self);
    public final native Result<RPtr> plutusListFromBytes(byte[] bytes);
    public final native Result<String> plutusListToHex(RPtr self);
    public final native Result<RPtr> plutusListFromHex(String hexStr);
    public final native Result<RPtr> plutusListNew();
    public final native Result<Long> plutusListLen(RPtr self);
    public final native Result<RPtr> plutusListGet(RPtr self, long index);
    public final native Result<Void> plutusListAdd(RPtr self, RPtr elem);

    public final native Result<RPtr> transactionHashFromBytes(byte[] bytes);
    public final native Result<byte[]> transactionHashToBytes(RPtr self);
    public final native Result<String> transactionHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> transactionHashFromBech32(String bechStr);
    public final native Result<String> transactionHashToHex(RPtr self);
    public final native Result<RPtr> transactionHashFromHex(String hex);

    public final native Result<byte[]> poolParamsToBytes(RPtr self);
    public final native Result<RPtr> poolParamsFromBytes(byte[] bytes);
    public final native Result<String> poolParamsToHex(RPtr self);
    public final native Result<RPtr> poolParamsFromHex(String hexStr);
    public final native Result<String> poolParamsToJson(RPtr self);
    public final native Result<RPtr> poolParamsFromJson(String json);
    public final native Result<RPtr> poolParamsOperator(RPtr self);
    public final native Result<RPtr> poolParamsVrfKeyhash(RPtr self);
    public final native Result<RPtr> poolParamsPledge(RPtr self);
    public final native Result<RPtr> poolParamsCost(RPtr self);
    public final native Result<RPtr> poolParamsMargin(RPtr self);
    public final native Result<RPtr> poolParamsRewardAccount(RPtr self);
    public final native Result<RPtr> poolParamsPoolOwners(RPtr self);
    public final native Result<RPtr> poolParamsRelays(RPtr self);
    public final native Result<RPtr> poolParamsPoolMetadata(RPtr self);
    public final native Result<RPtr> poolParamsNew(RPtr operator, RPtr vrfKeyhash, RPtr pledge, RPtr cost, RPtr margin, RPtr rewardAccount, RPtr poolOwners, RPtr relays);
    public final native Result<RPtr> poolParamsNewWithPoolMetadata(RPtr operator, RPtr vrfKeyhash, RPtr pledge, RPtr cost, RPtr margin, RPtr rewardAccount, RPtr poolOwners, RPtr relays, RPtr poolMetadata);


    public final native Result<RPtr> auxiliaryDataSetNew();
    public final native Result<Long> auxiliaryDataSetLen(RPtr self);
    public final native Result<RPtr> auxiliaryDataSetInsert(RPtr self, long txIndex, RPtr data);
    public final native Result<RPtr> auxiliaryDataSetGet(RPtr self, long txIndex);
    public final native Result<String> auxiliaryDataSetIndices(RPtr self);

    public final native Result<byte[]> genesisKeyDelegationToBytes(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationFromBytes(byte[] bytes);
    public final native Result<String> genesisKeyDelegationToHex(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationFromHex(String hexStr);
    public final native Result<String> genesisKeyDelegationToJson(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationFromJson(String json);
    public final native Result<RPtr> genesisKeyDelegationGenesishash(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationGenesisDelegateHash(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationVrfKeyhash(RPtr self);
    public final native Result<RPtr> genesisKeyDelegationNew(RPtr genesishash, RPtr genesisDelegateHash, RPtr vrfKeyhash);

    public final native Result<byte[]> uRLToBytes(RPtr self);
    public final native Result<RPtr> uRLFromBytes(byte[] bytes);
    public final native Result<String> uRLToHex(RPtr self);
    public final native Result<RPtr> uRLFromHex(String hexStr);
    public final native Result<String> uRLToJson(RPtr self);
    public final native Result<RPtr> uRLFromJson(String json);
    public final native Result<RPtr> uRLNew(String url);
    public final native Result<String> uRLUrl(RPtr self);

    public final native Result<byte[]> constrPlutusDataToBytes(RPtr self);
    public final native Result<RPtr> constrPlutusDataFromBytes(byte[] bytes);
    public final native Result<String> constrPlutusDataToHex(RPtr self);
    public final native Result<RPtr> constrPlutusDataFromHex(String hexStr);
    public final native Result<RPtr> constrPlutusDataAlternative(RPtr self);
    public final native Result<RPtr> constrPlutusDataData(RPtr self);
    public final native Result<RPtr> constrPlutusDataNew(RPtr alternative, RPtr data);

    public final native Result<byte[]> dNSRecordSRVToBytes(RPtr self);
    public final native Result<RPtr> dNSRecordSRVFromBytes(byte[] bytes);
    public final native Result<String> dNSRecordSRVToHex(RPtr self);
    public final native Result<RPtr> dNSRecordSRVFromHex(String hexStr);
    public final native Result<String> dNSRecordSRVToJson(RPtr self);
    public final native Result<RPtr> dNSRecordSRVFromJson(String json);
    public final native Result<RPtr> dNSRecordSRVNew(String dnsName);
    public final native Result<String> dNSRecordSRVRecord(RPtr self);

    public final native Result<RPtr> enterpriseAddressNew(long network, RPtr payment);
    public final native Result<RPtr> enterpriseAddressPaymentCred(RPtr self);
    public final native Result<RPtr> enterpriseAddressToAddress(RPtr self);
    public final native Result<RPtr> enterpriseAddressFromAddress(RPtr addr);

    public final native Result<RPtr> blockHashFromBytes(byte[] bytes);
    public final native Result<byte[]> blockHashToBytes(RPtr self);
    public final native Result<String> blockHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> blockHashFromBech32(String bechStr);
    public final native Result<String> blockHashToHex(RPtr self);
    public final native Result<RPtr> blockHashFromHex(String hex);

    public final native Result<RPtr> vRFKeyHashFromBytes(byte[] bytes);
    public final native Result<byte[]> vRFKeyHashToBytes(RPtr self);
    public final native Result<String> vRFKeyHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> vRFKeyHashFromBech32(String bechStr);
    public final native Result<String> vRFKeyHashToHex(RPtr self);
    public final native Result<RPtr> vRFKeyHashFromHex(String hex);


    public final native Result<byte[]> stakeDelegationToBytes(RPtr self);
    public final native Result<RPtr> stakeDelegationFromBytes(byte[] bytes);
    public final native Result<String> stakeDelegationToHex(RPtr self);
    public final native Result<RPtr> stakeDelegationFromHex(String hexStr);
    public final native Result<String> stakeDelegationToJson(RPtr self);
    public final native Result<RPtr> stakeDelegationFromJson(String json);
    public final native Result<RPtr> stakeDelegationStakeCredential(RPtr self);
    public final native Result<RPtr> stakeDelegationPoolKeyhash(RPtr self);
    public final native Result<RPtr> stakeDelegationNew(RPtr stakeCredential, RPtr poolKeyhash);

    public final native Result<byte[]> mintToBytes(RPtr self);
    public final native Result<RPtr> mintFromBytes(byte[] bytes);
    public final native Result<String> mintToHex(RPtr self);
    public final native Result<RPtr> mintFromHex(String hexStr);
    public final native Result<String> mintToJson(RPtr self);
    public final native Result<RPtr> mintFromJson(String json);
    public final native Result<RPtr> mintNew();
    public final native Result<RPtr> mintNewFromEntry(RPtr key, RPtr value);
    public final native Result<Long> mintLen(RPtr self);
    public final native Result<RPtr> mintInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> mintGet(RPtr self, RPtr key);
    public final native Result<RPtr> mintGetAll(RPtr self, RPtr key);
    public final native Result<RPtr> mintKeys(RPtr self);
    public final native Result<RPtr> mintAsPositiveMultiasset(RPtr self);
    public final native Result<RPtr> mintAsNegativeMultiasset(RPtr self);

    public final native Result<byte[]> stakeCredentialsToBytes(RPtr self);
    public final native Result<RPtr> stakeCredentialsFromBytes(byte[] bytes);
    public final native Result<String> stakeCredentialsToHex(RPtr self);
    public final native Result<RPtr> stakeCredentialsFromHex(String hexStr);
    public final native Result<String> stakeCredentialsToJson(RPtr self);
    public final native Result<RPtr> stakeCredentialsFromJson(String json);
    public final native Result<RPtr> stakeCredentialsNew();
    public final native Result<Long> stakeCredentialsLen(RPtr self);
    public final native Result<RPtr> stakeCredentialsGet(RPtr self, long index);
    public final native Result<Void> stakeCredentialsAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> metadataMapToBytes(RPtr self);
    public final native Result<RPtr> metadataMapFromBytes(byte[] bytes);
    public final native Result<String> metadataMapToHex(RPtr self);
    public final native Result<RPtr> metadataMapFromHex(String hexStr);
    public final native Result<RPtr> metadataMapNew();
    public final native Result<Long> metadataMapLen(RPtr self);
    public final native Result<RPtr> metadataMapInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> metadataMapInsertStr(RPtr self, String key, RPtr value);
    public final native Result<RPtr> metadataMapInsertI32(RPtr self, long key, RPtr value);
    public final native Result<RPtr> metadataMapGet(RPtr self, RPtr key);
    public final native Result<RPtr> metadataMapGetStr(RPtr self, String key);
    public final native Result<RPtr> metadataMapGetI32(RPtr self, long key);
    public final native Result<Boolean> metadataMapHas(RPtr self, RPtr key);
    public final native Result<RPtr> metadataMapKeys(RPtr self);

    public final native Result<byte[]> vRFCertToBytes(RPtr self);
    public final native Result<RPtr> vRFCertFromBytes(byte[] bytes);
    public final native Result<String> vRFCertToHex(RPtr self);
    public final native Result<RPtr> vRFCertFromHex(String hexStr);
    public final native Result<String> vRFCertToJson(RPtr self);
    public final native Result<RPtr> vRFCertFromJson(String json);
    public final native Result<byte[]> vRFCertOutput(RPtr self);
    public final native Result<byte[]> vRFCertProof(RPtr self);
    public final native Result<RPtr> vRFCertNew(byte[] output, byte[] proof);

    public final native Result<byte[]> bigNumToBytes(RPtr self);
    public final native Result<RPtr> bigNumFromBytes(byte[] bytes);
    public final native Result<String> bigNumToHex(RPtr self);
    public final native Result<RPtr> bigNumFromHex(String hexStr);
    public final native Result<String> bigNumToJson(RPtr self);
    public final native Result<RPtr> bigNumFromJson(String json);
    public final native Result<RPtr> bigNumFromStr(String string);
    public final native Result<String> bigNumToStr(RPtr self);
    public final native Result<RPtr> bigNumZero();
    public final native Result<RPtr> bigNumOne();
    public final native Result<Boolean> bigNumIsZero(RPtr self);
    public final native Result<RPtr> bigNumDivFloor(RPtr self, RPtr other);
    public final native Result<RPtr> bigNumCheckedMul(RPtr self, RPtr other);
    public final native Result<RPtr> bigNumCheckedAdd(RPtr self, RPtr other);
    public final native Result<RPtr> bigNumCheckedSub(RPtr self, RPtr other);
    public final native Result<RPtr> bigNumClampedSub(RPtr self, RPtr other);
    public final native Result<Long> bigNumCompare(RPtr self, RPtr rhsValue);
    public final native Result<Boolean> bigNumLessThan(RPtr self, RPtr rhsValue);
    public final native Result<RPtr> bigNumMax(RPtr a, RPtr b);

    public final native Result<byte[]> withdrawalsToBytes(RPtr self);
    public final native Result<RPtr> withdrawalsFromBytes(byte[] bytes);
    public final native Result<String> withdrawalsToHex(RPtr self);
    public final native Result<RPtr> withdrawalsFromHex(String hexStr);
    public final native Result<String> withdrawalsToJson(RPtr self);
    public final native Result<RPtr> withdrawalsFromJson(String json);
    public final native Result<RPtr> withdrawalsNew();
    public final native Result<Long> withdrawalsLen(RPtr self);
    public final native Result<RPtr> withdrawalsInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> withdrawalsGet(RPtr self, RPtr key);
    public final native Result<RPtr> withdrawalsKeys(RPtr self);

    public final native Result<byte[]> moveInstantaneousRewardToBytes(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardFromBytes(byte[] bytes);
    public final native Result<String> moveInstantaneousRewardToHex(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardFromHex(String hexStr);
    public final native Result<String> moveInstantaneousRewardToJson(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardFromJson(String json);
    public final native Result<RPtr> moveInstantaneousRewardNewToOtherPot(int pot, RPtr amount);
    public final native Result<RPtr> moveInstantaneousRewardNewToStakeCreds(int pot, RPtr amounts);
    public final native Result<Integer> moveInstantaneousRewardPot(RPtr self);
    public final native Result<Integer> moveInstantaneousRewardKind(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardAsToOtherPot(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardAsToStakeCreds(RPtr self);

    public final native Result<byte[]> ipv6ToBytes(RPtr self);
    public final native Result<RPtr> ipv6FromBytes(byte[] bytes);
    public final native Result<String> ipv6ToHex(RPtr self);
    public final native Result<RPtr> ipv6FromHex(String hexStr);
    public final native Result<String> ipv6ToJson(RPtr self);
    public final native Result<RPtr> ipv6FromJson(String json);
    public final native Result<RPtr> ipv6New(byte[] data);
    public final native Result<byte[]> ipv6Ip(RPtr self);

    public final native Result<byte[]> vkeyToBytes(RPtr self);
    public final native Result<RPtr> vkeyFromBytes(byte[] bytes);
    public final native Result<String> vkeyToHex(RPtr self);
    public final native Result<RPtr> vkeyFromHex(String hexStr);
    public final native Result<String> vkeyToJson(RPtr self);
    public final native Result<RPtr> vkeyFromJson(String json);
    public final native Result<RPtr> vkeyNew(RPtr pk);
    public final native Result<RPtr> vkeyPublicKey(RPtr self);

    public final native Result<String> transactionUnspentOutputsToJson(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputsFromJson(String json);
    public final native Result<RPtr> transactionUnspentOutputsNew();
    public final native Result<Long> transactionUnspentOutputsLen(RPtr self);
    public final native Result<RPtr> transactionUnspentOutputsGet(RPtr self, long index);
    public final native Result<Void> transactionUnspentOutputsAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> proposedProtocolParameterUpdatesToBytes(RPtr self);
    public final native Result<RPtr> proposedProtocolParameterUpdatesFromBytes(byte[] bytes);
    public final native Result<String> proposedProtocolParameterUpdatesToHex(RPtr self);
    public final native Result<RPtr> proposedProtocolParameterUpdatesFromHex(String hexStr);
    public final native Result<String> proposedProtocolParameterUpdatesToJson(RPtr self);
    public final native Result<RPtr> proposedProtocolParameterUpdatesFromJson(String json);
    public final native Result<RPtr> proposedProtocolParameterUpdatesNew();
    public final native Result<Long> proposedProtocolParameterUpdatesLen(RPtr self);
    public final native Result<RPtr> proposedProtocolParameterUpdatesInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> proposedProtocolParameterUpdatesGet(RPtr self, RPtr key);
    public final native Result<RPtr> proposedProtocolParameterUpdatesKeys(RPtr self);

    public final native Result<RPtr> transactionOutputAmountBuilderWithValue(RPtr self, RPtr amount);
    public final native Result<RPtr> transactionOutputAmountBuilderWithCoin(RPtr self, RPtr coin);
    public final native Result<RPtr> transactionOutputAmountBuilderWithCoinAndAsset(RPtr self, RPtr coin, RPtr multiasset);
    public final native Result<RPtr> transactionOutputAmountBuilderWithAssetAndMinRequiredCoin(RPtr self, RPtr multiasset, RPtr coinsPerUtxoWord);
    public final native Result<RPtr> transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(RPtr self, RPtr multiasset, RPtr dataCost);
    public final native Result<RPtr> transactionOutputAmountBuilderBuild(RPtr self);

    public final native Result<byte[]> assetNamesToBytes(RPtr self);
    public final native Result<RPtr> assetNamesFromBytes(byte[] bytes);
    public final native Result<String> assetNamesToHex(RPtr self);
    public final native Result<RPtr> assetNamesFromHex(String hexStr);
    public final native Result<String> assetNamesToJson(RPtr self);
    public final native Result<RPtr> assetNamesFromJson(String json);
    public final native Result<RPtr> assetNamesNew();
    public final native Result<Long> assetNamesLen(RPtr self);
    public final native Result<RPtr> assetNamesGet(RPtr self, long index);
    public final native Result<Void> assetNamesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> generalTransactionMetadataToBytes(RPtr self);
    public final native Result<RPtr> generalTransactionMetadataFromBytes(byte[] bytes);
    public final native Result<String> generalTransactionMetadataToHex(RPtr self);
    public final native Result<RPtr> generalTransactionMetadataFromHex(String hexStr);
    public final native Result<String> generalTransactionMetadataToJson(RPtr self);
    public final native Result<RPtr> generalTransactionMetadataFromJson(String json);
    public final native Result<RPtr> generalTransactionMetadataNew();
    public final native Result<Long> generalTransactionMetadataLen(RPtr self);
    public final native Result<RPtr> generalTransactionMetadataInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> generalTransactionMetadataGet(RPtr self, RPtr key);
    public final native Result<RPtr> generalTransactionMetadataKeys(RPtr self);

    public final native Result<byte[]> transactionInputsToBytes(RPtr self);
    public final native Result<RPtr> transactionInputsFromBytes(byte[] bytes);
    public final native Result<String> transactionInputsToHex(RPtr self);
    public final native Result<RPtr> transactionInputsFromHex(String hexStr);
    public final native Result<String> transactionInputsToJson(RPtr self);
    public final native Result<RPtr> transactionInputsFromJson(String json);
    public final native Result<RPtr> transactionInputsNew();
    public final native Result<Long> transactionInputsLen(RPtr self);
    public final native Result<RPtr> transactionInputsGet(RPtr self, long index);
    public final native Result<Void> transactionInputsAdd(RPtr self, RPtr elem);
    public final native Result<RPtr> transactionInputsToOption(RPtr self);

    public final native Result<byte[]> updateToBytes(RPtr self);
    public final native Result<RPtr> updateFromBytes(byte[] bytes);
    public final native Result<String> updateToHex(RPtr self);
    public final native Result<RPtr> updateFromHex(String hexStr);
    public final native Result<String> updateToJson(RPtr self);
    public final native Result<RPtr> updateFromJson(String json);
    public final native Result<RPtr> updateProposedProtocolParameterUpdates(RPtr self);
    public final native Result<Long> updateEpoch(RPtr self);
    public final native Result<RPtr> updateNew(RPtr proposedProtocolParameterUpdates, long epoch);

    public final native Result<RPtr> linearFeeConstant(RPtr self);
    public final native Result<RPtr> linearFeeCoefficient(RPtr self);
    public final native Result<RPtr> linearFeeNew(RPtr coefficient, RPtr constant);

    public final native Result<RPtr> stringsNew();
    public final native Result<Long> stringsLen(RPtr self);
    public final native Result<String> stringsGet(RPtr self, long index);
    public final native Result<Void> stringsAdd(RPtr self, String elem);

    public final native Result<byte[]> timelockStartToBytes(RPtr self);
    public final native Result<RPtr> timelockStartFromBytes(byte[] bytes);
    public final native Result<String> timelockStartToHex(RPtr self);
    public final native Result<RPtr> timelockStartFromHex(String hexStr);
    public final native Result<String> timelockStartToJson(RPtr self);
    public final native Result<RPtr> timelockStartFromJson(String json);
    public final native Result<Long> timelockStartSlot(RPtr self);
    public final native Result<RPtr> timelockStartSlotBignum(RPtr self);
    public final native Result<RPtr> timelockStartNew(long slot);
    public final native Result<RPtr> timelockStartNewTimelockstart(RPtr slot);

    public final native Result<byte[]> ed25519KeyHashesToBytes(RPtr self);
    public final native Result<RPtr> ed25519KeyHashesFromBytes(byte[] bytes);
    public final native Result<String> ed25519KeyHashesToHex(RPtr self);
    public final native Result<RPtr> ed25519KeyHashesFromHex(String hexStr);
    public final native Result<String> ed25519KeyHashesToJson(RPtr self);
    public final native Result<RPtr> ed25519KeyHashesFromJson(String json);
    public final native Result<RPtr> ed25519KeyHashesNew();
    public final native Result<Long> ed25519KeyHashesLen(RPtr self);
    public final native Result<RPtr> ed25519KeyHashesGet(RPtr self, long index);
    public final native Result<Void> ed25519KeyHashesAdd(RPtr self, RPtr elem);
    public final native Result<RPtr> ed25519KeyHashesToOption(RPtr self);

    public final native Result<byte[]> multiAssetToBytes(RPtr self);
    public final native Result<RPtr> multiAssetFromBytes(byte[] bytes);
    public final native Result<String> multiAssetToHex(RPtr self);
    public final native Result<RPtr> multiAssetFromHex(String hexStr);
    public final native Result<String> multiAssetToJson(RPtr self);
    public final native Result<RPtr> multiAssetFromJson(String json);
    public final native Result<RPtr> multiAssetNew();
    public final native Result<Long> multiAssetLen(RPtr self);
    public final native Result<RPtr> multiAssetInsert(RPtr self, RPtr policyId, RPtr assets);
    public final native Result<RPtr> multiAssetGet(RPtr self, RPtr policyId);
    public final native Result<RPtr> multiAssetSetAsset(RPtr self, RPtr policyId, RPtr assetName, RPtr value);
    public final native Result<RPtr> multiAssetGetAsset(RPtr self, RPtr policyId, RPtr assetName);
    public final native Result<RPtr> multiAssetKeys(RPtr self);
    public final native Result<RPtr> multiAssetSub(RPtr self, RPtr rhsMa);

    public final native Result<byte[]> kESSignatureToBytes(RPtr self);
    public final native Result<RPtr> kESSignatureFromBytes(byte[] bytes);

    public final native Result<RPtr> publicKeysNew();
    public final native Result<Long> publicKeysSize(RPtr self);
    public final native Result<RPtr> publicKeysGet(RPtr self, long index);
    public final native Result<Void> publicKeysAdd(RPtr self, RPtr key);

    public final native Result<byte[]> scriptHashesToBytes(RPtr self);
    public final native Result<RPtr> scriptHashesFromBytes(byte[] bytes);
    public final native Result<String> scriptHashesToHex(RPtr self);
    public final native Result<RPtr> scriptHashesFromHex(String hexStr);
    public final native Result<String> scriptHashesToJson(RPtr self);
    public final native Result<RPtr> scriptHashesFromJson(String json);
    public final native Result<RPtr> scriptHashesNew();
    public final native Result<Long> scriptHashesLen(RPtr self);
    public final native Result<RPtr> scriptHashesGet(RPtr self, long index);
    public final native Result<Void> scriptHashesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> headerToBytes(RPtr self);
    public final native Result<RPtr> headerFromBytes(byte[] bytes);
    public final native Result<String> headerToHex(RPtr self);
    public final native Result<RPtr> headerFromHex(String hexStr);
    public final native Result<String> headerToJson(RPtr self);
    public final native Result<RPtr> headerFromJson(String json);
    public final native Result<RPtr> headerHeaderBody(RPtr self);
    public final native Result<RPtr> headerBodySignature(RPtr self);
    public final native Result<RPtr> headerNew(RPtr headerBody, RPtr bodySignature);

    public final native Result<byte[]> dNSRecordAorAAAAToBytes(RPtr self);
    public final native Result<RPtr> dNSRecordAorAAAAFromBytes(byte[] bytes);
    public final native Result<String> dNSRecordAorAAAAToHex(RPtr self);
    public final native Result<RPtr> dNSRecordAorAAAAFromHex(String hexStr);
    public final native Result<String> dNSRecordAorAAAAToJson(RPtr self);
    public final native Result<RPtr> dNSRecordAorAAAAFromJson(String json);
    public final native Result<RPtr> dNSRecordAorAAAANew(String dnsName);
    public final native Result<String> dNSRecordAorAAAARecord(RPtr self);

    public final native Result<RPtr> poolMetadataHashFromBytes(byte[] bytes);
    public final native Result<byte[]> poolMetadataHashToBytes(RPtr self);
    public final native Result<String> poolMetadataHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> poolMetadataHashFromBech32(String bechStr);
    public final native Result<String> poolMetadataHashToHex(RPtr self);
    public final native Result<RPtr> poolMetadataHashFromHex(String hex);

    public final native Result<RPtr> inputWithScriptWitnessNewWithNativeScriptWitness(RPtr input, RPtr witness);
    public final native Result<RPtr> inputWithScriptWitnessNewWithPlutusWitness(RPtr input, RPtr witness);
    public final native Result<RPtr> inputWithScriptWitnessInput(RPtr self);

    public final native Result<RPtr> plutusScriptSourceNew(RPtr script);
    public final native Result<RPtr> plutusScriptSourceNewRefInput(RPtr scriptHash, RPtr input);
    public final native Result<RPtr> plutusScriptSourceNewRefInputWithLangVer(RPtr scriptHash, RPtr input, RPtr langVer);

    public final native Result<RPtr> plutusWitnessNew(RPtr script, RPtr datum, RPtr redeemer);
    public final native Result<RPtr> plutusWitnessNewWithRef(RPtr script, RPtr datum, RPtr redeemer);
    public final native Result<RPtr> plutusWitnessNewWithoutDatum(RPtr script, RPtr redeemer);
    public final native Result<RPtr> plutusWitnessScript(RPtr self);
    public final native Result<RPtr> plutusWitnessDatum(RPtr self);
    public final native Result<RPtr> plutusWitnessRedeemer(RPtr self);

    public final native Result<RPtr> privateKeyToPublic(RPtr self);
    public final native Result<RPtr> privateKeyGenerateEd25519();
    public final native Result<RPtr> privateKeyGenerateEd25519extended();
    public final native Result<RPtr> privateKeyFromBech32(String bech32Str);
    public final native Result<String> privateKeyToBech32(RPtr self);
    public final native Result<byte[]> privateKeyAsBytes(RPtr self);
    public final native Result<RPtr> privateKeyFromExtendedBytes(byte[] bytes);
    public final native Result<RPtr> privateKeyFromNormalBytes(byte[] bytes);
    public final native Result<RPtr> privateKeySign(RPtr self, byte[] message);
    public final native Result<String> privateKeyToHex(RPtr self);
    public final native Result<RPtr> privateKeyFromHex(String hexStr);

    public final native Result<byte[]> languageToBytes(RPtr self);
    public final native Result<RPtr> languageFromBytes(byte[] bytes);
    public final native Result<String> languageToHex(RPtr self);
    public final native Result<RPtr> languageFromHex(String hexStr);
    public final native Result<String> languageToJson(RPtr self);
    public final native Result<RPtr> languageFromJson(String json);
    public final native Result<RPtr> languageNewPlutusV1();
    public final native Result<RPtr> languageNewPlutusV2();
    public final native Result<Integer> languageKind(RPtr self);

    public final native Result<byte[]> scriptAllToBytes(RPtr self);
    public final native Result<RPtr> scriptAllFromBytes(byte[] bytes);
    public final native Result<String> scriptAllToHex(RPtr self);
    public final native Result<RPtr> scriptAllFromHex(String hexStr);
    public final native Result<String> scriptAllToJson(RPtr self);
    public final native Result<RPtr> scriptAllFromJson(String json);
    public final native Result<RPtr> scriptAllNativeScripts(RPtr self);
    public final native Result<RPtr> scriptAllNew(RPtr nativeScripts);

    public final native Result<byte[]> operationalCertToBytes(RPtr self);
    public final native Result<RPtr> operationalCertFromBytes(byte[] bytes);
    public final native Result<String> operationalCertToHex(RPtr self);
    public final native Result<RPtr> operationalCertFromHex(String hexStr);
    public final native Result<String> operationalCertToJson(RPtr self);
    public final native Result<RPtr> operationalCertFromJson(String json);
    public final native Result<RPtr> operationalCertHotVkey(RPtr self);
    public final native Result<Long> operationalCertSequenceNumber(RPtr self);
    public final native Result<Long> operationalCertKesPeriod(RPtr self);
    public final native Result<RPtr> operationalCertSigma(RPtr self);
    public final native Result<RPtr> operationalCertNew(RPtr hotVkey, long sequenceNumber, long kesPeriod, RPtr sigma);

    public final native Result<RPtr> plutusWitnessesNew();
    public final native Result<Long> plutusWitnessesLen(RPtr self);
    public final native Result<RPtr> plutusWitnessesGet(RPtr self, long index);
    public final native Result<Void> plutusWitnessesAdd(RPtr self, RPtr elem);

    public final native Result<RPtr> scriptHashFromBytes(byte[] bytes);
    public final native Result<byte[]> scriptHashToBytes(RPtr self);
    public final native Result<String> scriptHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> scriptHashFromBech32(String bechStr);
    public final native Result<String> scriptHashToHex(RPtr self);
    public final native Result<RPtr> scriptHashFromHex(String hex);

    public final native Result<byte[]> stakeRegistrationToBytes(RPtr self);
    public final native Result<RPtr> stakeRegistrationFromBytes(byte[] bytes);
    public final native Result<String> stakeRegistrationToHex(RPtr self);
    public final native Result<RPtr> stakeRegistrationFromHex(String hexStr);
    public final native Result<String> stakeRegistrationToJson(RPtr self);
    public final native Result<RPtr> stakeRegistrationFromJson(String json);
    public final native Result<RPtr> stakeRegistrationStakeCredential(RPtr self);
    public final native Result<RPtr> stakeRegistrationNew(RPtr stakeCredential);

    public final native Result<RPtr> transactionBuilderConfigBuilderNew();
    public final native Result<RPtr> transactionBuilderConfigBuilderFeeAlgo(RPtr self, RPtr feeAlgo);
    public final native Result<RPtr> transactionBuilderConfigBuilderCoinsPerUtxoWord(RPtr self, RPtr coinsPerUtxoWord);
    public final native Result<RPtr> transactionBuilderConfigBuilderCoinsPerUtxoByte(RPtr self, RPtr coinsPerUtxoByte);
    public final native Result<RPtr> transactionBuilderConfigBuilderExUnitPrices(RPtr self, RPtr exUnitPrices);
    public final native Result<RPtr> transactionBuilderConfigBuilderPoolDeposit(RPtr self, RPtr poolDeposit);
    public final native Result<RPtr> transactionBuilderConfigBuilderKeyDeposit(RPtr self, RPtr keyDeposit);
    public final native Result<RPtr> transactionBuilderConfigBuilderMaxValueSize(RPtr self, long maxValueSize);
    public final native Result<RPtr> transactionBuilderConfigBuilderMaxTxSize(RPtr self, long maxTxSize);
    public final native Result<RPtr> transactionBuilderConfigBuilderPreferPureChange(RPtr self, boolean preferPureChange);
    public final native Result<RPtr> transactionBuilderConfigBuilderBuild(RPtr self);

    public final native Result<byte[]> assetsToBytes(RPtr self);
    public final native Result<RPtr> assetsFromBytes(byte[] bytes);
    public final native Result<String> assetsToHex(RPtr self);
    public final native Result<RPtr> assetsFromHex(String hexStr);
    public final native Result<String> assetsToJson(RPtr self);
    public final native Result<RPtr> assetsFromJson(String json);
    public final native Result<RPtr> assetsNew();
    public final native Result<Long> assetsLen(RPtr self);
    public final native Result<RPtr> assetsInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> assetsGet(RPtr self, RPtr key);
    public final native Result<RPtr> assetsKeys(RPtr self);

    public final native Result<byte[]> unitIntervalToBytes(RPtr self);
    public final native Result<RPtr> unitIntervalFromBytes(byte[] bytes);
    public final native Result<String> unitIntervalToHex(RPtr self);
    public final native Result<RPtr> unitIntervalFromHex(String hexStr);
    public final native Result<String> unitIntervalToJson(RPtr self);
    public final native Result<RPtr> unitIntervalFromJson(String json);
    public final native Result<RPtr> unitIntervalNumerator(RPtr self);
    public final native Result<RPtr> unitIntervalDenominator(RPtr self);
    public final native Result<RPtr> unitIntervalNew(RPtr numerator, RPtr denominator);

    public final native Result<RPtr> kESVKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> kESVKeyToBytes(RPtr self);
    public final native Result<String> kESVKeyToBech32(RPtr self, String prefix);
    public final native Result<RPtr> kESVKeyFromBech32(String bechStr);
    public final native Result<String> kESVKeyToHex(RPtr self);
    public final native Result<RPtr> kESVKeyFromHex(String hex);

    public final native Result<byte[]> multiHostNameToBytes(RPtr self);
    public final native Result<RPtr> multiHostNameFromBytes(byte[] bytes);
    public final native Result<String> multiHostNameToHex(RPtr self);
    public final native Result<RPtr> multiHostNameFromHex(String hexStr);
    public final native Result<String> multiHostNameToJson(RPtr self);
    public final native Result<RPtr> multiHostNameFromJson(String json);
    public final native Result<RPtr> multiHostNameDnsName(RPtr self);
    public final native Result<RPtr> multiHostNameNew(RPtr dnsName);

    public final native Result<RPtr> legacyDaedalusPrivateKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> legacyDaedalusPrivateKeyAsBytes(RPtr self);
    public final native Result<byte[]> legacyDaedalusPrivateKeyChaincode(RPtr self);

    public final native Result<byte[]> nonceToBytes(RPtr self);
    public final native Result<RPtr> nonceFromBytes(byte[] bytes);
    public final native Result<String> nonceToHex(RPtr self);
    public final native Result<RPtr> nonceFromHex(String hexStr);
    public final native Result<String> nonceToJson(RPtr self);
    public final native Result<RPtr> nonceFromJson(String json);
    public final native Result<RPtr> nonceNewIdentity();
    public final native Result<RPtr> nonceNewFromHash(byte[] hash);
    public final native Result<byte[]> nonceGetHash(RPtr self);

    public final native Result<RPtr> baseAddressNew(long network, RPtr payment, RPtr stake);
    public final native Result<RPtr> baseAddressPaymentCred(RPtr self);
    public final native Result<RPtr> baseAddressStakeCred(RPtr self);
    public final native Result<RPtr> baseAddressToAddress(RPtr self);
    public final native Result<RPtr> baseAddressFromAddress(RPtr addr);

    public final native Result<byte[]> exUnitPricesToBytes(RPtr self);
    public final native Result<RPtr> exUnitPricesFromBytes(byte[] bytes);
    public final native Result<String> exUnitPricesToHex(RPtr self);
    public final native Result<RPtr> exUnitPricesFromHex(String hexStr);
    public final native Result<String> exUnitPricesToJson(RPtr self);
    public final native Result<RPtr> exUnitPricesFromJson(String json);
    public final native Result<RPtr> exUnitPricesMemPrice(RPtr self);
    public final native Result<RPtr> exUnitPricesStepPrice(RPtr self);
    public final native Result<RPtr> exUnitPricesNew(RPtr memPrice, RPtr stepPrice);

    public final native Result<byte[]> assetNameToBytes(RPtr self);
    public final native Result<RPtr> assetNameFromBytes(byte[] bytes);
    public final native Result<String> assetNameToHex(RPtr self);
    public final native Result<RPtr> assetNameFromHex(String hexStr);
    public final native Result<String> assetNameToJson(RPtr self);
    public final native Result<RPtr> assetNameFromJson(String json);
    public final native Result<RPtr> assetNameNew(byte[] name);
    public final native Result<byte[]> assetNameName(RPtr self);

    public final native Result<byte[]> nativeScriptToBytes(RPtr self);
    public final native Result<RPtr> nativeScriptFromBytes(byte[] bytes);
    public final native Result<String> nativeScriptToHex(RPtr self);
    public final native Result<RPtr> nativeScriptFromHex(String hexStr);
    public final native Result<String> nativeScriptToJson(RPtr self);
    public final native Result<RPtr> nativeScriptFromJson(String json);
    public final native Result<RPtr> nativeScriptHash(RPtr self);
    public final native Result<RPtr> nativeScriptNewScriptPubkey(RPtr scriptPubkey);
    public final native Result<RPtr> nativeScriptNewScriptAll(RPtr scriptAll);
    public final native Result<RPtr> nativeScriptNewScriptAny(RPtr scriptAny);
    public final native Result<RPtr> nativeScriptNewScriptNOfK(RPtr scriptNOfK);
    public final native Result<RPtr> nativeScriptNewTimelockStart(RPtr timelockStart);
    public final native Result<RPtr> nativeScriptNewTimelockExpiry(RPtr timelockExpiry);
    public final native Result<Integer> nativeScriptKind(RPtr self);
    public final native Result<RPtr> nativeScriptAsScriptPubkey(RPtr self);
    public final native Result<RPtr> nativeScriptAsScriptAll(RPtr self);
    public final native Result<RPtr> nativeScriptAsScriptAny(RPtr self);
    public final native Result<RPtr> nativeScriptAsScriptNOfK(RPtr self);
    public final native Result<RPtr> nativeScriptAsTimelockStart(RPtr self);
    public final native Result<RPtr> nativeScriptAsTimelockExpiry(RPtr self);
    public final native Result<RPtr> nativeScriptGetRequiredSigners(RPtr self);

    public final native Result<String> byronAddressToBase58(RPtr self);
    public final native Result<byte[]> byronAddressToBytes(RPtr self);
    public final native Result<RPtr> byronAddressFromBytes(byte[] bytes);
    public final native Result<Long> byronAddressByronProtocolMagic(RPtr self);
    public final native Result<byte[]> byronAddressAttributes(RPtr self);
    public final native Result<Long> byronAddressNetworkId(RPtr self);
    public final native Result<RPtr> byronAddressFromBase58(String s);
    public final native Result<RPtr> byronAddressIcarusFromKey(RPtr key, long protocolMagic);
    public final native Result<Boolean> byronAddressIsValid(String s);
    public final native Result<RPtr> byronAddressToAddress(RPtr self);
    public final native Result<RPtr> byronAddressFromAddress(RPtr addr);

    public final native Result<byte[]> bigIntToBytes(RPtr self);
    public final native Result<RPtr> bigIntFromBytes(byte[] bytes);
    public final native Result<String> bigIntToHex(RPtr self);
    public final native Result<RPtr> bigIntFromHex(String hexStr);
    public final native Result<String> bigIntToJson(RPtr self);
    public final native Result<RPtr> bigIntFromJson(String json);
    public final native Result<Boolean> bigIntIsZero(RPtr self);
    public final native Result<RPtr> bigIntAsU64(RPtr self);
    public final native Result<RPtr> bigIntAsInt(RPtr self);
    public final native Result<RPtr> bigIntFromStr(String text);
    public final native Result<String> bigIntToStr(RPtr self);
    public final native Result<RPtr> bigIntAdd(RPtr self, RPtr other);
    public final native Result<RPtr> bigIntMul(RPtr self, RPtr other);
    public final native Result<RPtr> bigIntOne();
    public final native Result<RPtr> bigIntIncrement(RPtr self);
    public final native Result<RPtr> bigIntDivCeil(RPtr self, RPtr other);

    public final native Result<RPtr> pointerNew(long slot, long txIndex, long certIndex);
    public final native Result<RPtr> pointerNewPointer(RPtr slot, RPtr txIndex, RPtr certIndex);
    public final native Result<Long> pointerSlot(RPtr self);
    public final native Result<Long> pointerTxIndex(RPtr self);
    public final native Result<Long> pointerCertIndex(RPtr self);
    public final native Result<RPtr> pointerSlotBignum(RPtr self);
    public final native Result<RPtr> pointerTxIndexBignum(RPtr self);
    public final native Result<RPtr> pointerCertIndexBignum(RPtr self);

    public final native Result<byte[]> protocolParamUpdateToBytes(RPtr self);
    public final native Result<RPtr> protocolParamUpdateFromBytes(byte[] bytes);
    public final native Result<String> protocolParamUpdateToHex(RPtr self);
    public final native Result<RPtr> protocolParamUpdateFromHex(String hexStr);
    public final native Result<String> protocolParamUpdateToJson(RPtr self);
    public final native Result<RPtr> protocolParamUpdateFromJson(String json);
    public final native Result<Void> protocolParamUpdateSetMinfeeA(RPtr self, RPtr minfeeA);
    public final native Result<RPtr> protocolParamUpdateMinfeeA(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMinfeeB(RPtr self, RPtr minfeeB);
    public final native Result<RPtr> protocolParamUpdateMinfeeB(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxBlockBodySize(RPtr self, long maxBlockBodySize);
    public final native Result<Long> protocolParamUpdateMaxBlockBodySize(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxTxSize(RPtr self, long maxTxSize);
    public final native Result<Long> protocolParamUpdateMaxTxSize(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxBlockHeaderSize(RPtr self, long maxBlockHeaderSize);
    public final native Result<Long> protocolParamUpdateMaxBlockHeaderSize(RPtr self);
    public final native Result<Void> protocolParamUpdateSetKeyDeposit(RPtr self, RPtr keyDeposit);
    public final native Result<RPtr> protocolParamUpdateKeyDeposit(RPtr self);
    public final native Result<Void> protocolParamUpdateSetPoolDeposit(RPtr self, RPtr poolDeposit);
    public final native Result<RPtr> protocolParamUpdatePoolDeposit(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxEpoch(RPtr self, long maxEpoch);
    public final native Result<Long> protocolParamUpdateMaxEpoch(RPtr self);
    public final native Result<Void> protocolParamUpdateSetNOpt(RPtr self, long nOpt);
    public final native Result<Long> protocolParamUpdateNOpt(RPtr self);
    public final native Result<Void> protocolParamUpdateSetPoolPledgeInfluence(RPtr self, RPtr poolPledgeInfluence);
    public final native Result<RPtr> protocolParamUpdatePoolPledgeInfluence(RPtr self);
    public final native Result<Void> protocolParamUpdateSetExpansionRate(RPtr self, RPtr expansionRate);
    public final native Result<RPtr> protocolParamUpdateExpansionRate(RPtr self);
    public final native Result<Void> protocolParamUpdateSetTreasuryGrowthRate(RPtr self, RPtr treasuryGrowthRate);
    public final native Result<RPtr> protocolParamUpdateTreasuryGrowthRate(RPtr self);
    public final native Result<RPtr> protocolParamUpdateD(RPtr self);
    public final native Result<RPtr> protocolParamUpdateExtraEntropy(RPtr self);
    public final native Result<Void> protocolParamUpdateSetProtocolVersion(RPtr self, RPtr protocolVersion);
    public final native Result<RPtr> protocolParamUpdateProtocolVersion(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMinPoolCost(RPtr self, RPtr minPoolCost);
    public final native Result<RPtr> protocolParamUpdateMinPoolCost(RPtr self);
    public final native Result<Void> protocolParamUpdateSetAdaPerUtxoByte(RPtr self, RPtr adaPerUtxoByte);
    public final native Result<RPtr> protocolParamUpdateAdaPerUtxoByte(RPtr self);
    public final native Result<Void> protocolParamUpdateSetCostModels(RPtr self, RPtr costModels);
    public final native Result<RPtr> protocolParamUpdateCostModels(RPtr self);
    public final native Result<Void> protocolParamUpdateSetExecutionCosts(RPtr self, RPtr executionCosts);
    public final native Result<RPtr> protocolParamUpdateExecutionCosts(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxTxExUnits(RPtr self, RPtr maxTxExUnits);
    public final native Result<RPtr> protocolParamUpdateMaxTxExUnits(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxBlockExUnits(RPtr self, RPtr maxBlockExUnits);
    public final native Result<RPtr> protocolParamUpdateMaxBlockExUnits(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxValueSize(RPtr self, long maxValueSize);
    public final native Result<Long> protocolParamUpdateMaxValueSize(RPtr self);
    public final native Result<Void> protocolParamUpdateSetCollateralPercentage(RPtr self, long collateralPercentage);
    public final native Result<Long> protocolParamUpdateCollateralPercentage(RPtr self);
    public final native Result<Void> protocolParamUpdateSetMaxCollateralInputs(RPtr self, long maxCollateralInputs);
    public final native Result<Long> protocolParamUpdateMaxCollateralInputs(RPtr self);
    public final native Result<RPtr> protocolParamUpdateNew();

    public final native Result<RPtr> dataHashFromBytes(byte[] bytes);
    public final native Result<byte[]> dataHashToBytes(RPtr self);
    public final native Result<String> dataHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> dataHashFromBech32(String bechStr);
    public final native Result<String> dataHashToHex(RPtr self);
    public final native Result<RPtr> dataHashFromHex(String hex);

    public final native Result<byte[]> transactionOutputToBytes(RPtr self);
    public final native Result<RPtr> transactionOutputFromBytes(byte[] bytes);
    public final native Result<String> transactionOutputToHex(RPtr self);
    public final native Result<RPtr> transactionOutputFromHex(String hexStr);
    public final native Result<String> transactionOutputToJson(RPtr self);
    public final native Result<RPtr> transactionOutputFromJson(String json);
    public final native Result<RPtr> transactionOutputAddress(RPtr self);
    public final native Result<RPtr> transactionOutputAmount(RPtr self);
    public final native Result<RPtr> transactionOutputDataHash(RPtr self);
    public final native Result<RPtr> transactionOutputPlutusData(RPtr self);
    public final native Result<RPtr> transactionOutputScriptRef(RPtr self);
    public final native Result<Void> transactionOutputSetScriptRef(RPtr self, RPtr scriptRef);
    public final native Result<Void> transactionOutputSetPlutusData(RPtr self, RPtr data);
    public final native Result<Void> transactionOutputSetDataHash(RPtr self, RPtr dataHash);
    public final native Result<Boolean> transactionOutputHasPlutusData(RPtr self);
    public final native Result<Boolean> transactionOutputHasDataHash(RPtr self);
    public final native Result<Boolean> transactionOutputHasScriptRef(RPtr self);
    public final native Result<RPtr> transactionOutputNew(RPtr address, RPtr amount);

    public final native Result<byte[]> redeemersToBytes(RPtr self);
    public final native Result<RPtr> redeemersFromBytes(byte[] bytes);
    public final native Result<String> redeemersToHex(RPtr self);
    public final native Result<RPtr> redeemersFromHex(String hexStr);
    public final native Result<String> redeemersToJson(RPtr self);
    public final native Result<RPtr> redeemersFromJson(String json);
    public final native Result<RPtr> redeemersNew();
    public final native Result<Long> redeemersLen(RPtr self);
    public final native Result<RPtr> redeemersGet(RPtr self, long index);
    public final native Result<Void> redeemersAdd(RPtr self, RPtr elem);
    public final native Result<RPtr> redeemersTotalExUnits(RPtr self);

    public final native Result<RPtr> nativeScriptsNew();
    public final native Result<Long> nativeScriptsLen(RPtr self);
    public final native Result<RPtr> nativeScriptsGet(RPtr self, long index);
    public final native Result<Void> nativeScriptsAdd(RPtr self, RPtr elem);

    public final native Result<RPtr> txBuilderConstantsPlutusDefaultCostModels();
    public final native Result<RPtr> txBuilderConstantsPlutusAlonzoCostModels();
    public final native Result<RPtr> txBuilderConstantsPlutusVasilCostModels();

    public final native Result<byte[]> plutusMapToBytes(RPtr self);
    public final native Result<RPtr> plutusMapFromBytes(byte[] bytes);
    public final native Result<String> plutusMapToHex(RPtr self);
    public final native Result<RPtr> plutusMapFromHex(String hexStr);
    public final native Result<RPtr> plutusMapNew();
    public final native Result<Long> plutusMapLen(RPtr self);
    public final native Result<RPtr> plutusMapInsert(RPtr self, RPtr key, RPtr value);
    public final native Result<RPtr> plutusMapGet(RPtr self, RPtr key);
    public final native Result<RPtr> plutusMapKeys(RPtr self);

    public final native Result<byte[]> poolRetirementToBytes(RPtr self);
    public final native Result<RPtr> poolRetirementFromBytes(byte[] bytes);
    public final native Result<String> poolRetirementToHex(RPtr self);
    public final native Result<RPtr> poolRetirementFromHex(String hexStr);
    public final native Result<String> poolRetirementToJson(RPtr self);
    public final native Result<RPtr> poolRetirementFromJson(String json);
    public final native Result<RPtr> poolRetirementPoolKeyhash(RPtr self);
    public final native Result<Long> poolRetirementEpoch(RPtr self);
    public final native Result<RPtr> poolRetirementNew(RPtr poolKeyhash, long epoch);

    public final native Result<byte[]> intToBytes(RPtr self);
    public final native Result<RPtr> intFromBytes(byte[] bytes);
    public final native Result<String> intToHex(RPtr self);
    public final native Result<RPtr> intFromHex(String hexStr);
    public final native Result<String> intToJson(RPtr self);
    public final native Result<RPtr> intFromJson(String json);
    public final native Result<RPtr> intNew(RPtr x);
    public final native Result<RPtr> intNewNegative(RPtr x);
    public final native Result<RPtr> intNewI32(long x);
    public final native Result<Boolean> intIsPositive(RPtr self);
    public final native Result<RPtr> intAsPositive(RPtr self);
    public final native Result<RPtr> intAsNegative(RPtr self);
    public final native Result<Long> intAsI32(RPtr self);
    public final native Result<Long> intAsI32OrNothing(RPtr self);
    public final native Result<Long> intAsI32OrFail(RPtr self);
    public final native Result<String> intToStr(RPtr self);
    public final native Result<RPtr> intFromStr(String string);

    public final native Result<byte[]> plutusScriptsToBytes(RPtr self);
    public final native Result<RPtr> plutusScriptsFromBytes(byte[] bytes);
    public final native Result<String> plutusScriptsToHex(RPtr self);
    public final native Result<RPtr> plutusScriptsFromHex(String hexStr);
    public final native Result<String> plutusScriptsToJson(RPtr self);
    public final native Result<RPtr> plutusScriptsFromJson(String json);
    public final native Result<RPtr> plutusScriptsNew();
    public final native Result<Long> plutusScriptsLen(RPtr self);
    public final native Result<RPtr> plutusScriptsGet(RPtr self, long index);
    public final native Result<Void> plutusScriptsAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> timelockExpiryToBytes(RPtr self);
    public final native Result<RPtr> timelockExpiryFromBytes(byte[] bytes);
    public final native Result<String> timelockExpiryToHex(RPtr self);
    public final native Result<RPtr> timelockExpiryFromHex(String hexStr);
    public final native Result<String> timelockExpiryToJson(RPtr self);
    public final native Result<RPtr> timelockExpiryFromJson(String json);
    public final native Result<Long> timelockExpirySlot(RPtr self);
    public final native Result<RPtr> timelockExpirySlotBignum(RPtr self);
    public final native Result<RPtr> timelockExpiryNew(long slot);
    public final native Result<RPtr> timelockExpiryNewTimelockexpiry(RPtr slot);

    public final native Result<RPtr> mintWitnessNewNativeScript(RPtr nativeScript);
    public final native Result<RPtr> mintWitnessNewPlutusScript(RPtr plutusScript, RPtr redeemer);

    public final native Result<RPtr> stakeCredentialFromKeyhash(RPtr hash);
    public final native Result<RPtr> stakeCredentialFromScripthash(RPtr hash);
    public final native Result<RPtr> stakeCredentialToKeyhash(RPtr self);
    public final native Result<RPtr> stakeCredentialToScripthash(RPtr self);
    public final native Result<Integer> stakeCredentialKind(RPtr self);
    public final native Result<byte[]> stakeCredentialToBytes(RPtr self);
    public final native Result<RPtr> stakeCredentialFromBytes(byte[] bytes);
    public final native Result<String> stakeCredentialToHex(RPtr self);
    public final native Result<RPtr> stakeCredentialFromHex(String hexStr);
    public final native Result<String> stakeCredentialToJson(RPtr self);
    public final native Result<RPtr> stakeCredentialFromJson(String json);

    public final native Result<RPtr> mintBuilderNew();
    public final native Result<Void> mintBuilderAddAsset(RPtr self, RPtr mint, RPtr assetName, RPtr amount);
    public final native Result<Void> mintBuilderSetAsset(RPtr self, RPtr mint, RPtr assetName, RPtr amount);
    public final native Result<RPtr> mintBuilderBuild(RPtr self);
    public final native Result<RPtr> mintBuilderGetNativeScripts(RPtr self);
    public final native Result<RPtr> mintBuilderGetPlutusWitnesses(RPtr self);
    public final native Result<RPtr> mintBuilderGetRedeeemers(RPtr self);
    public final native Result<Boolean> mintBuilderHasPlutusScripts(RPtr self);
    public final native Result<Boolean> mintBuilderHasNativeScripts(RPtr self);

    public final native Result<byte[]> transactionWitnessSetsToBytes(RPtr self);
    public final native Result<RPtr> transactionWitnessSetsFromBytes(byte[] bytes);
    public final native Result<String> transactionWitnessSetsToHex(RPtr self);
    public final native Result<RPtr> transactionWitnessSetsFromHex(String hexStr);
    public final native Result<String> transactionWitnessSetsToJson(RPtr self);
    public final native Result<RPtr> transactionWitnessSetsFromJson(String json);
    public final native Result<RPtr> transactionWitnessSetsNew();
    public final native Result<Long> transactionWitnessSetsLen(RPtr self);
    public final native Result<RPtr> transactionWitnessSetsGet(RPtr self, long index);
    public final native Result<Void> transactionWitnessSetsAdd(RPtr self, RPtr elem);

    public final native Result<RPtr> languagesNew();
    public final native Result<Long> languagesLen(RPtr self);
    public final native Result<RPtr> languagesGet(RPtr self, long index);
    public final native Result<Void> languagesAdd(RPtr self, RPtr elem);
    public final native Result<RPtr> languagesList();

    public final native Result<RPtr> datumSourceNew(RPtr datum);
    public final native Result<RPtr> datumSourceNewRefInput(RPtr input);

    public final native Result<byte[]> stakeDeregistrationToBytes(RPtr self);
    public final native Result<RPtr> stakeDeregistrationFromBytes(byte[] bytes);
    public final native Result<String> stakeDeregistrationToHex(RPtr self);
    public final native Result<RPtr> stakeDeregistrationFromHex(String hexStr);
    public final native Result<String> stakeDeregistrationToJson(RPtr self);
    public final native Result<RPtr> stakeDeregistrationFromJson(String json);
    public final native Result<RPtr> stakeDeregistrationStakeCredential(RPtr self);
    public final native Result<RPtr> stakeDeregistrationNew(RPtr stakeCredential);

    public final native Result<RPtr> txInputsBuilderNew();
    public final native Result<Void> txInputsBuilderAddKeyInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> txInputsBuilderAddScriptInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> txInputsBuilderAddNativeScriptInput(RPtr self, RPtr script, RPtr input, RPtr amount);
    public final native Result<Void> txInputsBuilderAddPlutusScriptInput(RPtr self, RPtr witness, RPtr input, RPtr amount);
    public final native Result<Void> txInputsBuilderAddBootstrapInput(RPtr self, RPtr hash, RPtr input, RPtr amount);
    public final native Result<Void> txInputsBuilderAddInput(RPtr self, RPtr address, RPtr input, RPtr amount);
    public final native Result<Long> txInputsBuilderCountMissingInputScripts(RPtr self);
    public final native Result<Long> txInputsBuilderAddRequiredNativeInputScripts(RPtr self, RPtr scripts);
    public final native Result<Long> txInputsBuilderAddRequiredPlutusInputScripts(RPtr self, RPtr scripts);
    public final native Result<Long> txInputsBuilderAddRequiredScriptInputWitnesses(RPtr self, RPtr inputsWithWit);
    public final native Result<RPtr> txInputsBuilderGetRefInputs(RPtr self);
    public final native Result<RPtr> txInputsBuilderGetNativeInputScripts(RPtr self);
    public final native Result<RPtr> txInputsBuilderGetPlutusInputScripts(RPtr self);
    public final native Result<Long> txInputsBuilderLen(RPtr self);
    public final native Result<Void> txInputsBuilderAddRequiredSigner(RPtr self, RPtr key);
    public final native Result<Void> txInputsBuilderAddRequiredSigners(RPtr self, RPtr keys);
    public final native Result<RPtr> txInputsBuilderTotalValue(RPtr self);
    public final native Result<RPtr> txInputsBuilderInputs(RPtr self);
    public final native Result<RPtr> txInputsBuilderInputsOption(RPtr self);

    public final native Result<byte[]> valueToBytes(RPtr self);
    public final native Result<RPtr> valueFromBytes(byte[] bytes);
    public final native Result<String> valueToHex(RPtr self);
    public final native Result<RPtr> valueFromHex(String hexStr);
    public final native Result<String> valueToJson(RPtr self);
    public final native Result<RPtr> valueFromJson(String json);
    public final native Result<RPtr> valueNew(RPtr coin);
    public final native Result<RPtr> valueNewFromAssets(RPtr multiasset);
    public final native Result<RPtr> valueNewWithAssets(RPtr coin, RPtr multiasset);
    public final native Result<RPtr> valueZero();
    public final native Result<Boolean> valueIsZero(RPtr self);
    public final native Result<RPtr> valueCoin(RPtr self);
    public final native Result<Void> valueSetCoin(RPtr self, RPtr coin);
    public final native Result<RPtr> valueMultiasset(RPtr self);
    public final native Result<Void> valueSetMultiasset(RPtr self, RPtr multiasset);
    public final native Result<RPtr> valueCheckedAdd(RPtr self, RPtr rhs);
    public final native Result<RPtr> valueCheckedSub(RPtr self, RPtr rhsValue);
    public final native Result<RPtr> valueClampedSub(RPtr self, RPtr rhsValue);
    public final native Result<Long> valueCompare(RPtr self, RPtr rhsValue);

    public final native Result<RPtr> bip32PublicKeyDerive(RPtr self, long index);
    public final native Result<RPtr> bip32PublicKeyToRawKey(RPtr self);
    public final native Result<RPtr> bip32PublicKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> bip32PublicKeyAsBytes(RPtr self);
    public final native Result<RPtr> bip32PublicKeyFromBech32(String bech32Str);
    public final native Result<String> bip32PublicKeyToBech32(RPtr self);
    public final native Result<byte[]> bip32PublicKeyChaincode(RPtr self);
    public final native Result<String> bip32PublicKeyToHex(RPtr self);
    public final native Result<RPtr> bip32PublicKeyFromHex(String hexStr);

    public final native Result<byte[]> auxiliaryDataToBytes(RPtr self);
    public final native Result<RPtr> auxiliaryDataFromBytes(byte[] bytes);
    public final native Result<String> auxiliaryDataToHex(RPtr self);
    public final native Result<RPtr> auxiliaryDataFromHex(String hexStr);
    public final native Result<String> auxiliaryDataToJson(RPtr self);
    public final native Result<RPtr> auxiliaryDataFromJson(String json);
    public final native Result<RPtr> auxiliaryDataNew();
    public final native Result<RPtr> auxiliaryDataMetadata(RPtr self);
    public final native Result<Void> auxiliaryDataSetMetadata(RPtr self, RPtr metadata);
    public final native Result<RPtr> auxiliaryDataNativeScripts(RPtr self);
    public final native Result<Void> auxiliaryDataSetNativeScripts(RPtr self, RPtr nativeScripts);
    public final native Result<RPtr> auxiliaryDataPlutusScripts(RPtr self);
    public final native Result<Void> auxiliaryDataSetPlutusScripts(RPtr self, RPtr plutusScripts);

    public final native Result<byte[]> scriptNOfKToBytes(RPtr self);
    public final native Result<RPtr> scriptNOfKFromBytes(byte[] bytes);
    public final native Result<String> scriptNOfKToHex(RPtr self);
    public final native Result<RPtr> scriptNOfKFromHex(String hexStr);
    public final native Result<String> scriptNOfKToJson(RPtr self);
    public final native Result<RPtr> scriptNOfKFromJson(String json);
    public final native Result<Long> scriptNOfKN(RPtr self);
    public final native Result<RPtr> scriptNOfKNativeScripts(RPtr self);
    public final native Result<RPtr> scriptNOfKNew(long n, RPtr nativeScripts);

    public final native Result<byte[]> scriptRefToBytes(RPtr self);
    public final native Result<RPtr> scriptRefFromBytes(byte[] bytes);
    public final native Result<String> scriptRefToHex(RPtr self);
    public final native Result<RPtr> scriptRefFromHex(String hexStr);
    public final native Result<String> scriptRefToJson(RPtr self);
    public final native Result<RPtr> scriptRefFromJson(String json);
    public final native Result<RPtr> scriptRefNewNativeScript(RPtr nativeScript);
    public final native Result<RPtr> scriptRefNewPlutusScript(RPtr plutusScript);
    public final native Result<Boolean> scriptRefIsNativeScript(RPtr self);
    public final native Result<Boolean> scriptRefIsPlutusScript(RPtr self);
    public final native Result<RPtr> scriptRefNativeScript(RPtr self);
    public final native Result<RPtr> scriptRefPlutusScript(RPtr self);

    public final native Result<byte[]> transactionBodiesToBytes(RPtr self);
    public final native Result<RPtr> transactionBodiesFromBytes(byte[] bytes);
    public final native Result<String> transactionBodiesToHex(RPtr self);
    public final native Result<RPtr> transactionBodiesFromHex(String hexStr);
    public final native Result<String> transactionBodiesToJson(RPtr self);
    public final native Result<RPtr> transactionBodiesFromJson(String json);
    public final native Result<RPtr> transactionBodiesNew();
    public final native Result<Long> transactionBodiesLen(RPtr self);
    public final native Result<RPtr> transactionBodiesGet(RPtr self, long index);
    public final native Result<Void> transactionBodiesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> networkIdToBytes(RPtr self);
    public final native Result<RPtr> networkIdFromBytes(byte[] bytes);
    public final native Result<String> networkIdToHex(RPtr self);
    public final native Result<RPtr> networkIdFromHex(String hexStr);
    public final native Result<String> networkIdToJson(RPtr self);
    public final native Result<RPtr> networkIdFromJson(String json);
    public final native Result<RPtr> networkIdTestnet();
    public final native Result<RPtr> networkIdMainnet();
    public final native Result<Integer> networkIdKind(RPtr self);

    public final native Result<RPtr> dataCostNewCoinsPerWord(RPtr coinsPerWord);
    public final native Result<RPtr> dataCostNewCoinsPerByte(RPtr coinsPerByte);
    public final native Result<RPtr> dataCostCoinsPerByte(RPtr self);

    public final native Result<RPtr> publicKeyFromBech32(String bech32Str);
    public final native Result<String> publicKeyToBech32(RPtr self);
    public final native Result<byte[]> publicKeyAsBytes(RPtr self);
    public final native Result<RPtr> publicKeyFromBytes(byte[] bytes);
    public final native Result<Boolean> publicKeyVerify(RPtr self, byte[] data, RPtr signature);
    public final native Result<RPtr> publicKeyHash(RPtr self);
    public final native Result<String> publicKeyToHex(RPtr self);
    public final native Result<RPtr> publicKeyFromHex(String hexStr);

    public final native Result<byte[]> genesisHashesToBytes(RPtr self);
    public final native Result<RPtr> genesisHashesFromBytes(byte[] bytes);
    public final native Result<String> genesisHashesToHex(RPtr self);
    public final native Result<RPtr> genesisHashesFromHex(String hexStr);
    public final native Result<String> genesisHashesToJson(RPtr self);
    public final native Result<RPtr> genesisHashesFromJson(String json);
    public final native Result<RPtr> genesisHashesNew();
    public final native Result<Long> genesisHashesLen(RPtr self);
    public final native Result<RPtr> genesisHashesGet(RPtr self, long index);
    public final native Result<Void> genesisHashesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> headerBodyToBytes(RPtr self);
    public final native Result<RPtr> headerBodyFromBytes(byte[] bytes);
    public final native Result<String> headerBodyToHex(RPtr self);
    public final native Result<RPtr> headerBodyFromHex(String hexStr);
    public final native Result<String> headerBodyToJson(RPtr self);
    public final native Result<RPtr> headerBodyFromJson(String json);
    public final native Result<Long> headerBodyBlockNumber(RPtr self);
    public final native Result<Long> headerBodySlot(RPtr self);
    public final native Result<RPtr> headerBodySlotBignum(RPtr self);
    public final native Result<RPtr> headerBodyPrevHash(RPtr self);
    public final native Result<RPtr> headerBodyIssuerVkey(RPtr self);
    public final native Result<RPtr> headerBodyVrfVkey(RPtr self);
    public final native Result<Boolean> headerBodyHasNonceAndLeaderVrf(RPtr self);
    public final native Result<RPtr> headerBodyNonceVrfOrNothing(RPtr self);
    public final native Result<RPtr> headerBodyLeaderVrfOrNothing(RPtr self);
    public final native Result<Boolean> headerBodyHasVrfResult(RPtr self);
    public final native Result<RPtr> headerBodyVrfResultOrNothing(RPtr self);
    public final native Result<Long> headerBodyBlockBodySize(RPtr self);
    public final native Result<RPtr> headerBodyBlockBodyHash(RPtr self);
    public final native Result<RPtr> headerBodyOperationalCert(RPtr self);
    public final native Result<RPtr> headerBodyProtocolVersion(RPtr self);
    public final native Result<RPtr> headerBodyNew(long blockNumber, long slot, RPtr issuerVkey, RPtr vrfVkey, RPtr vrfResult, long blockBodySize, RPtr blockBodyHash, RPtr operationalCert, RPtr protocolVersion);
    public final native Result<RPtr> headerBodyNewWithPrevHash(long blockNumber, long slot, RPtr prevHash, RPtr issuerVkey, RPtr vrfVkey, RPtr vrfResult, long blockBodySize, RPtr blockBodyHash, RPtr operationalCert, RPtr protocolVersion);

    public final native Result<RPtr> headerBodyNewHeaderbody(long blockNumber, RPtr slot, RPtr issuerVkey, RPtr vrfVkey, RPtr vrfResult, long blockBodySize, RPtr blockBodyHash, RPtr operationalCert, RPtr protocolVersion);
    public final native Result<RPtr> headerBodyNewHeaderbodyWithPrevHash(long blockNumber, RPtr slot, RPtr prevHash, RPtr issuerVkey, RPtr vrfVkey, RPtr vrfResult, long blockBodySize, RPtr blockBodyHash, RPtr operationalCert, RPtr protocolVersion);


    public final native Result<byte[]> mIRToStakeCredentialsToBytes(RPtr self);
    public final native Result<RPtr> mIRToStakeCredentialsFromBytes(byte[] bytes);
    public final native Result<String> mIRToStakeCredentialsToHex(RPtr self);
    public final native Result<RPtr> mIRToStakeCredentialsFromHex(String hexStr);
    public final native Result<String> mIRToStakeCredentialsToJson(RPtr self);
    public final native Result<RPtr> mIRToStakeCredentialsFromJson(String json);
    public final native Result<RPtr> mIRToStakeCredentialsNew();
    public final native Result<Long> mIRToStakeCredentialsLen(RPtr self);
    public final native Result<RPtr> mIRToStakeCredentialsInsert(RPtr self, RPtr cred, RPtr delta);
    public final native Result<RPtr> mIRToStakeCredentialsGet(RPtr self, RPtr cred);
    public final native Result<RPtr> mIRToStakeCredentialsKeys(RPtr self);

    public final native Result<byte[]> singleHostAddrToBytes(RPtr self);
    public final native Result<RPtr> singleHostAddrFromBytes(byte[] bytes);
    public final native Result<String> singleHostAddrToHex(RPtr self);
    public final native Result<RPtr> singleHostAddrFromHex(String hexStr);
    public final native Result<String> singleHostAddrToJson(RPtr self);
    public final native Result<RPtr> singleHostAddrFromJson(String json);
    public final native Result<Long> singleHostAddrPort(RPtr self);
    public final native Result<RPtr> singleHostAddrIpv4(RPtr self);
    public final native Result<RPtr> singleHostAddrIpv6(RPtr self);
    public final native Result<RPtr> singleHostAddrNew();
    public final native Result<RPtr> singleHostAddrNewWithPort(long port);
    public final native Result<RPtr> singleHostAddrNewWithIpv4(RPtr ipv4);
    public final native Result<RPtr> singleHostAddrNewWithPortIpv4(long port, RPtr ipv4);
    public final native Result<RPtr> singleHostAddrNewWithIpv6(RPtr ipv6);
    public final native Result<RPtr> singleHostAddrNewWithPortIpv6(long port, RPtr ipv6);
    public final native Result<RPtr> singleHostAddrNewWithIpv4Ipv6(RPtr ipv4, RPtr ipv6);
    public final native Result<RPtr> singleHostAddrNewWithPortIpv4Ipv6(long port, RPtr ipv4, RPtr ipv6);


    public final native Result<byte[]> moveInstantaneousRewardsCertToBytes(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardsCertFromBytes(byte[] bytes);
    public final native Result<String> moveInstantaneousRewardsCertToHex(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardsCertFromHex(String hexStr);
    public final native Result<String> moveInstantaneousRewardsCertToJson(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardsCertFromJson(String json);
    public final native Result<RPtr> moveInstantaneousRewardsCertMoveInstantaneousReward(RPtr self);
    public final native Result<RPtr> moveInstantaneousRewardsCertNew(RPtr moveInstantaneousReward);

    public final native Result<RPtr> genesisDelegateHashFromBytes(byte[] bytes);
    public final native Result<byte[]> genesisDelegateHashToBytes(RPtr self);
    public final native Result<String> genesisDelegateHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> genesisDelegateHashFromBech32(String bechStr);
    public final native Result<String> genesisDelegateHashToHex(RPtr self);
    public final native Result<RPtr> genesisDelegateHashFromHex(String hex);

    public final native Result<byte[]> transactionToBytes(RPtr self);
    public final native Result<RPtr> transactionFromBytes(byte[] bytes);
    public final native Result<String> transactionToHex(RPtr self);
    public final native Result<RPtr> transactionFromHex(String hexStr);
    public final native Result<String> transactionToJson(RPtr self);
    public final native Result<RPtr> transactionFromJson(String json);
    public final native Result<RPtr> transactionBody(RPtr self);
    public final native Result<RPtr> transactionWitnessSet(RPtr self);
    public final native Result<Boolean> transactionIsValid(RPtr self);
    public final native Result<RPtr> transactionAuxiliaryData(RPtr self);
    public final native Result<Void> transactionSetIsValid(RPtr self, boolean valid);
    public final native Result<RPtr> transactionNew(RPtr body, RPtr witnessSet);
    public final native Result<RPtr> transactionNewWithAuxiliaryData(RPtr body, RPtr witnessSet, RPtr auxiliaryData);


    public final native Result<RPtr> vRFVKeyFromBytes(byte[] bytes);
    public final native Result<byte[]> vRFVKeyToBytes(RPtr self);
    public final native Result<String> vRFVKeyToBech32(RPtr self, String prefix);
    public final native Result<RPtr> vRFVKeyFromBech32(String bechStr);
    public final native Result<String> vRFVKeyToHex(RPtr self);
    public final native Result<RPtr> vRFVKeyFromHex(String hex);

    public final native Result<RPtr> transactionOutputBuilderNew();
    public final native Result<RPtr> transactionOutputBuilderWithAddress(RPtr self, RPtr address);
    public final native Result<RPtr> transactionOutputBuilderWithDataHash(RPtr self, RPtr dataHash);
    public final native Result<RPtr> transactionOutputBuilderWithPlutusData(RPtr self, RPtr data);
    public final native Result<RPtr> transactionOutputBuilderWithScriptRef(RPtr self, RPtr scriptRef);
    public final native Result<RPtr> transactionOutputBuilderNext(RPtr self);

    public final native Result<RPtr> networkInfoNew(long networkId, long protocolMagic);
    public final native Result<Long> networkInfoNetworkId(RPtr self);
    public final native Result<Long> networkInfoProtocolMagic(RPtr self);
    public final native Result<RPtr> networkInfoTestnet();
    public final native Result<RPtr> networkInfoMainnet();

    public final native Result<RPtr> ed25519KeyHashFromBytes(byte[] bytes);
    public final native Result<byte[]> ed25519KeyHashToBytes(RPtr self);
    public final native Result<String> ed25519KeyHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> ed25519KeyHashFromBech32(String bechStr);
    public final native Result<String> ed25519KeyHashToHex(RPtr self);
    public final native Result<RPtr> ed25519KeyHashFromHex(String hex);

    public final native Result<byte[]> bootstrapWitnessToBytes(RPtr self);
    public final native Result<RPtr> bootstrapWitnessFromBytes(byte[] bytes);
    public final native Result<String> bootstrapWitnessToHex(RPtr self);
    public final native Result<RPtr> bootstrapWitnessFromHex(String hexStr);
    public final native Result<String> bootstrapWitnessToJson(RPtr self);
    public final native Result<RPtr> bootstrapWitnessFromJson(String json);
    public final native Result<RPtr> bootstrapWitnessVkey(RPtr self);
    public final native Result<RPtr> bootstrapWitnessSignature(RPtr self);
    public final native Result<byte[]> bootstrapWitnessChainCode(RPtr self);
    public final native Result<byte[]> bootstrapWitnessAttributes(RPtr self);
    public final native Result<RPtr> bootstrapWitnessNew(RPtr vkey, RPtr signature, byte[] chainCode, byte[] attributes);

    public final native Result<RPtr> rewardAddressNew(long network, RPtr payment);
    public final native Result<RPtr> rewardAddressPaymentCred(RPtr self);
    public final native Result<RPtr> rewardAddressToAddress(RPtr self);
    public final native Result<RPtr> rewardAddressFromAddress(RPtr addr);

    public final native Result<RPtr> auxiliaryDataHashFromBytes(byte[] bytes);
    public final native Result<byte[]> auxiliaryDataHashToBytes(RPtr self);
    public final native Result<String> auxiliaryDataHashToBech32(RPtr self, String prefix);
    public final native Result<RPtr> auxiliaryDataHashFromBech32(String bechStr);
    public final native Result<String> auxiliaryDataHashToHex(RPtr self);
    public final native Result<RPtr> auxiliaryDataHashFromHex(String hex);

    public final native Result<RPtr> bootstrapWitnessesNew();
    public final native Result<Long> bootstrapWitnessesLen(RPtr self);
    public final native Result<RPtr> bootstrapWitnessesGet(RPtr self, long index);
    public final native Result<Void> bootstrapWitnessesAdd(RPtr self, RPtr elem);

    public final native Result<byte[]> exUnitsToBytes(RPtr self);
    public final native Result<RPtr> exUnitsFromBytes(byte[] bytes);
    public final native Result<String> exUnitsToHex(RPtr self);
    public final native Result<RPtr> exUnitsFromHex(String hexStr);
    public final native Result<String> exUnitsToJson(RPtr self);
    public final native Result<RPtr> exUnitsFromJson(String json);
    public final native Result<RPtr> exUnitsMem(RPtr self);
    public final native Result<RPtr> exUnitsSteps(RPtr self);
    public final native Result<RPtr> exUnitsNew(RPtr mem, RPtr steps);

    public final native Result<byte[]> relayToBytes(RPtr self);
    public final native Result<RPtr> relayFromBytes(byte[] bytes);
    public final native Result<String> relayToHex(RPtr self);
    public final native Result<RPtr> relayFromHex(String hexStr);
    public final native Result<String> relayToJson(RPtr self);
    public final native Result<RPtr> relayFromJson(String json);
    public final native Result<RPtr> relayNewSingleHostAddr(RPtr singleHostAddr);
    public final native Result<RPtr> relayNewSingleHostName(RPtr singleHostName);
    public final native Result<RPtr> relayNewMultiHostName(RPtr multiHostName);
    public final native Result<Integer> relayKind(RPtr self);
    public final native Result<RPtr> relayAsSingleHostAddr(RPtr self);
    public final native Result<RPtr> relayAsSingleHostName(RPtr self);
    public final native Result<RPtr> relayAsMultiHostName(RPtr self);


    public final native Result<byte[]> scriptAnyToBytes(RPtr self);
    public final native Result<RPtr> scriptAnyFromBytes(byte[] bytes);
    public final native Result<String> scriptAnyToHex(RPtr self);
    public final native Result<RPtr> scriptAnyFromHex(String hexStr);
    public final native Result<String> scriptAnyToJson(RPtr self);
    public final native Result<RPtr> scriptAnyFromJson(String json);
    public final native Result<RPtr> scriptAnyNativeScripts(RPtr self);
    public final native Result<RPtr> scriptAnyNew(RPtr nativeScripts);

    public final native Result<byte[]> scriptPubkeyToBytes(RPtr self);
    public final native Result<RPtr> scriptPubkeyFromBytes(byte[] bytes);
    public final native Result<String> scriptPubkeyToHex(RPtr self);
    public final native Result<RPtr> scriptPubkeyFromHex(String hexStr);
    public final native Result<String> scriptPubkeyToJson(RPtr self);
    public final native Result<RPtr> scriptPubkeyFromJson(String json);
    public final native Result<RPtr> scriptPubkeyAddrKeyhash(RPtr self);
    public final native Result<RPtr> scriptPubkeyNew(RPtr addrKeyhash);

    public final native Result<RPtr> pointerAddressNew(long network, RPtr payment, RPtr stake);
    public final native Result<RPtr> pointerAddressPaymentCred(RPtr self);
    public final native Result<RPtr> pointerAddressStakePointer(RPtr self);
    public final native Result<RPtr> pointerAddressToAddress(RPtr self);
    public final native Result<RPtr> pointerAddressFromAddress(RPtr addr);

    public final native Result<byte[]> plutusDataToBytes(RPtr self);
    public final native Result<RPtr> plutusDataFromBytes(byte[] bytes);
    public final native Result<String> plutusDataToHex(RPtr self);
    public final native Result<RPtr> plutusDataFromHex(String hexStr);
    public final native Result<RPtr> plutusDataNewConstrPlutusData(RPtr constrPlutusData);
    public final native Result<RPtr> plutusDataNewEmptyConstrPlutusData(RPtr alternative);
    public final native Result<RPtr> plutusDataNewMap(RPtr map);
    public final native Result<RPtr> plutusDataNewList(RPtr list);
    public final native Result<RPtr> plutusDataNewInteger(RPtr integer);
    public final native Result<RPtr> plutusDataNewBytes(byte[] bytes);
    public final native Result<Integer> plutusDataKind(RPtr self);
    public final native Result<RPtr> plutusDataAsConstrPlutusData(RPtr self);
    public final native Result<RPtr> plutusDataAsMap(RPtr self);
    public final native Result<RPtr> plutusDataAsList(RPtr self);
    public final native Result<RPtr> plutusDataAsInteger(RPtr self);
    public final native Result<byte[]> plutusDataAsBytes(RPtr self);
    public final native Result<String> plutusDataToJson(RPtr self, int schema);
    public final native Result<RPtr> plutusDataFromJson(String json, int schema);

    public final native Result<RPtr> hashPlutusData(RPtr plutusData);
    public final native Result<RPtr> calculateExUnitsCeilCost(RPtr exUnits, RPtr exUnitPrices);
    public final native Result<RPtr> makeDaedalusBootstrapWitness(RPtr txBodyHash, RPtr addr, RPtr key);
    public final native Result<String> encryptWithPassword(String password, String salt, String nonce, String data);
    public final native Result<String> decodeMetadatumToJsonStr(RPtr metadatum, int schema);
    public final native Result<RPtr> hashScriptData(RPtr redeemers, RPtr costModels);
    public final native Result<RPtr> hashScriptDataWithDatums(RPtr redeemers, RPtr costModels, RPtr datums);

    public final native Result<byte[]> decodeArbitraryBytesFromMetadatum(RPtr metadata);
    public final native Result<RPtr> getImplicitInput(RPtr txbody, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> minFee(RPtr tx, RPtr linearFee);
    public final native Result<RPtr> getDeposit(RPtr txbody, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> encodeJsonStrToNativeScript(String json, String selfXpub, int schema);
    public final native Result<RPtr> makeVkeyWitness(RPtr txBodyHash, RPtr sk);
    public final native Result<RPtr> encodeJsonStrToPlutusDatum(String json, int schema);
    public final native Result<String> decodePlutusDatumToJsonStr(RPtr datum, int schema);
    public final native Result<RPtr> makeIcarusBootstrapWitness(RPtr txBodyHash, RPtr addr, RPtr key);
    public final native Result<String> decryptWithPassword(String password, String data);
    public final native Result<RPtr> hashAuxiliaryData(RPtr auxiliaryData);
    public final native Result<RPtr> minScriptFee(RPtr tx, RPtr exUnitPrices);
    public final native Result<RPtr> minAdaRequired(RPtr assets, boolean hasDataHash, RPtr coinsPerUtxoWord);
    public final native Result<RPtr> hashTransaction(RPtr txBody);
    public final native Result<RPtr> minAdaForOutput(RPtr output, RPtr dataCost);
    public final native Result<RPtr> encodeArbitraryBytesAsMetadatum(byte[] bytes);
    public final native Result<RPtr> encodeJsonStrToMetadatum(String json, int schema);
}
