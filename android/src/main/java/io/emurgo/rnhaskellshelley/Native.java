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
























































































































































    public final native Result<RPtr> encodeJsonStrToNativeScript(String json, String selfXpub, int schema);
    public final native Result<RPtr> minScriptFee(RPtr tx, RPtr exUnitPrices);
    public final native Result<RPtr> minAdaRequired(RPtr assets, boolean hasDataHash, RPtr coinsPerUtxoWord);
    public final native Result<RPtr> hashTransaction(RPtr txBody);
    public final native Result<RPtr> makeDaedalusBootstrapWitness(RPtr txBodyHash, RPtr addr, RPtr key);
    public final native Result<String> decodePlutusDatumToJsonStr(RPtr datum, int schema);
    public final native Result<byte[]> decodeArbitraryBytesFromMetadatum(RPtr metadata);
    public final native Result<String> decodeMetadatumToJsonStr(RPtr metadatum, int schema);
    public final native Result<RPtr> hashAuxiliaryData(RPtr auxiliaryData);
    public final native Result<RPtr> encodeArbitraryBytesAsMetadatum(byte[] bytes);
    public final native Result<RPtr> getImplicitInput(RPtr txbody, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> createSendAll(RPtr address, RPtr utxos, RPtr config);
    public final native Result<RPtr> minAdaForOutput(RPtr output, RPtr dataCost);
    public final native Result<String> encryptWithPassword(String password, String salt, String nonce, String data);
    public final native Result<RPtr> makeVkeyWitness(RPtr txBodyHash, RPtr sk);
    public final native Result<RPtr> encodeJsonStrToMetadatum(String json, int schema);
    public final native Result<RPtr> makeIcarusBootstrapWitness(RPtr txBodyHash, RPtr addr, RPtr key);
    public final native Result<String> decryptWithPassword(String password, String data);
    public final native Result<RPtr> minFee(RPtr tx, RPtr linearFee);
    public final native Result<RPtr> getDeposit(RPtr txbody, RPtr poolDeposit, RPtr keyDeposit);
    public final native Result<RPtr> hashScriptData(RPtr redeemers, RPtr costModels);
    public final native Result<RPtr> hashScriptDataWithDatums(RPtr redeemers, RPtr costModels, RPtr datums);

    public final native Result<RPtr> calculateExUnitsCeilCost(RPtr exUnits, RPtr exUnitPrices);
    public final native Result<RPtr> hashPlutusData(RPtr plutusData);
    public final native Result<RPtr> encodeJsonStrToPlutusDatum(String json, int schema);
}
