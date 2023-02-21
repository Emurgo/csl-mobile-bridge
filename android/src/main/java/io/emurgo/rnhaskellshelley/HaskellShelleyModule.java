package io.emurgo.rnhaskellshelley;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import android.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class HaskellShelleyModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    public HaskellShelleyModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "HaskellShelley";
    }

    @ReactMethod
    public final void ptrFree(String ptr, Promise promise) {
        try {
            (new RPtr(ptr)).free();
            promise.resolve(null);
        } catch (Throwable err) {
            promise.reject(err);
        }
    }























































































































































    @ReactMethod
    public final void encodeJsonStrToNativeScript(String json, String selfXpub, Double schema, Promise promise) {
        Native.I
            .encodeJsonStrToNativeScript(json, selfXpub, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void minScriptFee(String tx, String exUnitPrices, Promise promise) {
        Native.I
            .minScriptFee(new RPtr(tx), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void minAdaRequired(String assets, Boolean hasDataHash, String coinsPerUtxoWord, Promise promise) {
        Native.I
            .minAdaRequired(new RPtr(assets), hasDataHash, new RPtr(coinsPerUtxoWord))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void hashTransaction(String txBody, Promise promise) {
        Native.I
            .hashTransaction(new RPtr(txBody))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void makeDaedalusBootstrapWitness(String txBodyHash, String addr, String key, Promise promise) {
        Native.I
            .makeDaedalusBootstrapWitness(new RPtr(txBodyHash), new RPtr(addr), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void decodePlutusDatumToJsonStr(String datum, Double schema, Promise promise) {
        Native.I
            .decodePlutusDatumToJsonStr(new RPtr(datum), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void decodeArbitraryBytesFromMetadatum(String metadata, Promise promise) {
        Native.I
            .decodeArbitraryBytesFromMetadatum(new RPtr(metadata))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void decodeMetadatumToJsonStr(String metadatum, Double schema, Promise promise) {
        Native.I
            .decodeMetadatumToJsonStr(new RPtr(metadatum), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void hashAuxiliaryData(String auxiliaryData, Promise promise) {
        Native.I
            .hashAuxiliaryData(new RPtr(auxiliaryData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void encodeArbitraryBytesAsMetadatum(String bytes, Promise promise) {
        Native.I
            .encodeArbitraryBytesAsMetadatum(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void getImplicitInput(String txbody, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .getImplicitInput(new RPtr(txbody), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void createSendAll(String address, String utxos, String config, Promise promise) {
        Native.I
            .createSendAll(new RPtr(address), new RPtr(utxos), new RPtr(config))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void minAdaForOutput(String output, String dataCost, Promise promise) {
        Native.I
            .minAdaForOutput(new RPtr(output), new RPtr(dataCost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void encryptWithPassword(String password, String salt, String nonce, String data, Promise promise) {
        Native.I
            .encryptWithPassword(password, salt, nonce, data)
            .pour(promise);
    }

    @ReactMethod
    public final void makeVkeyWitness(String txBodyHash, String sk, Promise promise) {
        Native.I
            .makeVkeyWitness(new RPtr(txBodyHash), new RPtr(sk))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void encodeJsonStrToMetadatum(String json, Double schema, Promise promise) {
        Native.I
            .encodeJsonStrToMetadatum(json, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void makeIcarusBootstrapWitness(String txBodyHash, String addr, String key, Promise promise) {
        Native.I
            .makeIcarusBootstrapWitness(new RPtr(txBodyHash), new RPtr(addr), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void decryptWithPassword(String password, String data, Promise promise) {
        Native.I
            .decryptWithPassword(password, data)
            .pour(promise);
    }

    @ReactMethod
    public final void minFee(String tx, String linearFee, Promise promise) {
        Native.I
            .minFee(new RPtr(tx), new RPtr(linearFee))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void getDeposit(String txbody, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .getDeposit(new RPtr(txbody), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void hashScriptData(String redeemers, String costModels, Promise promise) {
        Native.I
            .hashScriptData(new RPtr(redeemers), new RPtr(costModels))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void hashScriptDataWithDatums(String redeemers, String costModels, String datums, Promise promise) {
        Native.I
            .hashScriptDataWithDatums(new RPtr(redeemers), new RPtr(costModels), new RPtr(datums))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void calculateExUnitsCeilCost(String exUnits, String exUnitPrices, Promise promise) {
        Native.I
            .calculateExUnitsCeilCost(new RPtr(exUnits), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void hashPlutusData(String plutusData, Promise promise) {
        Native.I
            .hashPlutusData(new RPtr(plutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void encodeJsonStrToPlutusDatum(String json, Double schema, Promise promise) {
        Native.I
            .encodeJsonStrToPlutusDatum(json, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

}
