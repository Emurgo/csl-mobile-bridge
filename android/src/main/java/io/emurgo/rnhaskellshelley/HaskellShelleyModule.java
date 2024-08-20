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
    public final void csl_bridge_addressFromBytes(String data, Promise promise) {
        Native.I
            .csl_bridge_addressFromBytes(Base64.decode(data, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_addressToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_addressFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressKind(String self, Promise promise) {
        Native.I
            .csl_bridge_addressKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressPaymentCred(String self, Promise promise) {
        Native.I
            .csl_bridge_addressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressIsMalformed(String self, Promise promise) {
        Native.I
            .csl_bridge_addressIsMalformed(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_addressToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_addressFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_addressToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_addressToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressToBech32WithPrefix(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_addressToBech32WithPrefix(new RPtr(self), prefix)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_addressFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_addressFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_addressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_addressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_anchorToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_anchorFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_anchorFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_anchorFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorUrl(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorUrl(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorAnchorDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorAnchorDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorNew(String anchorUrl, String anchorDataHash, Promise promise) {
        Native.I
            .csl_bridge_anchorNew(new RPtr(anchorUrl), new RPtr(anchorDataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_anchorDataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorDataHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorDataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorDataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorDataHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_anchorDataHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_anchorDataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_assetNameToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_assetNameFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_assetNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_assetNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameNew(String name, Promise promise) {
        Native.I
            .csl_bridge_assetNameNew(Base64.decode(name, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNameName(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNameName(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_assetNamesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNamesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_assetNamesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNamesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_assetNamesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNamesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_assetNamesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesNew( Promise promise) {
        Native.I
            .csl_bridge_assetNamesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_assetNamesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_assetNamesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetNamesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_assetNamesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_assetsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_assetsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_assetsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_assetsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_assetsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_assetsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_assetsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsNew( Promise promise) {
        Native.I
            .csl_bridge_assetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_assetsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_assetsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_assetsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_assetsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_assetsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_auxiliaryDataToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataNew( Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataMetadata(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataMetadata(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetMetadata(String self, String metadata, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetMetadata(new RPtr(self), new RPtr(metadata))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetNativeScripts(String self, String nativeScripts, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetNativeScripts(new RPtr(self), new RPtr(nativeScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataPlutusScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetPlutusScripts(String self, String plutusScripts, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetPlutusScripts(new RPtr(self), new RPtr(plutusScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataPreferAlonzoFormat(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataPreferAlonzoFormat(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetPreferAlonzoFormat(String self, Boolean prefer, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetPreferAlonzoFormat(new RPtr(self), prefer)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetNew( Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetLen(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetInsert(String self, Double txIndex, String data, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetInsert(new RPtr(self), txIndex.longValue(), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetGet(String self, Double txIndex, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetGet(new RPtr(self), txIndex.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_auxiliaryDataSetIndices(String self, Promise promise) {
        Native.I
            .csl_bridge_auxiliaryDataSetIndices(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_baseAddressNew(Double network, String payment, String stake, Promise promise) {
        Native.I
            .csl_bridge_baseAddressNew(network.longValue(), new RPtr(payment), new RPtr(stake))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_baseAddressPaymentCred(String self, Promise promise) {
        Native.I
            .csl_bridge_baseAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_baseAddressStakeCred(String self, Promise promise) {
        Native.I
            .csl_bridge_baseAddressStakeCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_baseAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_baseAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_baseAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_baseAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_baseAddressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_baseAddressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bigIntToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bigIntFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bigIntFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_bigIntFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntIsZero(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntAsU64(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntAsU64(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntAsInt(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntAsInt(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntFromStr(String text, Promise promise) {
        Native.I
            .csl_bridge_bigIntFromStr(text)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntToStr(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntAdd(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigIntAdd(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntSub(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigIntSub(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntMul(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigIntMul(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntPow(String self, Double exp, Promise promise) {
        Native.I
            .csl_bridge_bigIntPow(new RPtr(self), exp.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntOne( Promise promise) {
        Native.I
            .csl_bridge_bigIntOne()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntZero( Promise promise) {
        Native.I
            .csl_bridge_bigIntZero()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntAbs(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntAbs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntIncrement(String self, Promise promise) {
        Native.I
            .csl_bridge_bigIntIncrement(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntDivCeil(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigIntDivCeil(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigIntDivFloor(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigIntDivFloor(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bigNumToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bigNumToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bigNumFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bigNumToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bigNumFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_bigNumToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_bigNumFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumFromStr(String string, Promise promise) {
        Native.I
            .csl_bridge_bigNumFromStr(string)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumToStr(String self, Promise promise) {
        Native.I
            .csl_bridge_bigNumToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumZero( Promise promise) {
        Native.I
            .csl_bridge_bigNumZero()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumOne( Promise promise) {
        Native.I
            .csl_bridge_bigNumOne()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumIsZero(String self, Promise promise) {
        Native.I
            .csl_bridge_bigNumIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumDivFloor(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigNumDivFloor(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumCheckedMul(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigNumCheckedMul(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumCheckedAdd(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigNumCheckedAdd(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumCheckedSub(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigNumCheckedSub(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumClampedSub(String self, String other, Promise promise) {
        Native.I
            .csl_bridge_bigNumClampedSub(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumCompare(String self, String rhsValue, Promise promise) {
        Native.I
            .csl_bridge_bigNumCompare(new RPtr(self), new RPtr(rhsValue))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumLessThan(String self, String rhsValue, Promise promise) {
        Native.I
            .csl_bridge_bigNumLessThan(new RPtr(self), new RPtr(rhsValue))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumMaxValue( Promise promise) {
        Native.I
            .csl_bridge_bigNumMaxValue()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bigNumMax(String a, String b, Promise promise) {
        Native.I
            .csl_bridge_bigNumMax(new RPtr(a), new RPtr(b))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyDerive(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyDerive(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyFrom_128Xprv(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyFrom_128Xprv(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyTo_128Xprv(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyTo_128Xprv(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyGenerateEd25519Bip32( Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyGenerateEd25519Bip32()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyToRawKey(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyToRawKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyToPublic(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyToPublic(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyFromBip39Entropy(String entropy, String password, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyFromBip39Entropy(Base64.decode(entropy, Base64.DEFAULT), Base64.decode(password, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyChaincode(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PrivateKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bip32PrivateKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bip32PublicKeyDerive(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyDerive(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyToRawKey(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyToRawKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyChaincode(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bip32PublicKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bip32PublicKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_blockToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_blockToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_blockFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_blockToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_blockFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_blockToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_blockFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHeader(String self, Promise promise) {
        Native.I
            .csl_bridge_blockHeader(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockTransactionBodies(String self, Promise promise) {
        Native.I
            .csl_bridge_blockTransactionBodies(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockTransactionWitnessSets(String self, Promise promise) {
        Native.I
            .csl_bridge_blockTransactionWitnessSets(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockAuxiliaryDataSet(String self, Promise promise) {
        Native.I
            .csl_bridge_blockAuxiliaryDataSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockInvalidTransactions(String self, Promise promise) {
        Native.I
            .csl_bridge_blockInvalidTransactions(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockNew(String header, String transactionBodies, String transactionWitnessSets, String auxiliaryDataSet, String invalidTransactions, Promise promise) {
        Native.I
            .csl_bridge_blockNew(new RPtr(header), new RPtr(transactionBodies), new RPtr(transactionWitnessSets), new RPtr(auxiliaryDataSet), invalidTransactions)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_blockHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_blockHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_blockHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_blockHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_blockHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_blockHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_blockHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_blockHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bootstrapWitnessToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessVkey(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessSignature(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessSignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessChainCode(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessChainCode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessAttributes(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessAttributes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessNew(String vkey, String signature, String chainCode, String attributes, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessNew(new RPtr(vkey), new RPtr(signature), Base64.decode(chainCode, Base64.DEFAULT), Base64.decode(attributes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesNew( Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_bootstrapWitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_bootstrapWitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_byronAddressToBase58(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressToBase58(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_byronAddressFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressByronProtocolMagic(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressByronProtocolMagic(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressAttributes(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressAttributes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressFromBase58(String s, Promise promise) {
        Native.I
            .csl_bridge_byronAddressFromBase58(s)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressIcarusFromKey(String key, Double protocolMagic, Promise promise) {
        Native.I
            .csl_bridge_byronAddressIcarusFromKey(new RPtr(key), protocolMagic.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressIsValid(String s, Promise promise) {
        Native.I
            .csl_bridge_byronAddressIsValid(s)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_byronAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_byronAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_byronAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_certificateToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_certificateFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_certificateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_certificateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeRegistration(String stakeRegistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeRegistration(new RPtr(stakeRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewRegCert(String stakeRegistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewRegCert(new RPtr(stakeRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeDeregistration(String stakeDeregistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeDeregistration(new RPtr(stakeDeregistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewUnregCert(String stakeDeregistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewUnregCert(new RPtr(stakeDeregistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeDelegation(String stakeDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeDelegation(new RPtr(stakeDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewPoolRegistration(String poolRegistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewPoolRegistration(new RPtr(poolRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewPoolRetirement(String poolRetirement, Promise promise) {
        Native.I
            .csl_bridge_certificateNewPoolRetirement(new RPtr(poolRetirement))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewGenesisKeyDelegation(String genesisKeyDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewGenesisKeyDelegation(new RPtr(genesisKeyDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewMoveInstantaneousRewardsCert(String moveInstantaneousRewardsCert, Promise promise) {
        Native.I
            .csl_bridge_certificateNewMoveInstantaneousRewardsCert(new RPtr(moveInstantaneousRewardsCert))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewCommitteeHotAuth(String committeeHotAuth, Promise promise) {
        Native.I
            .csl_bridge_certificateNewCommitteeHotAuth(new RPtr(committeeHotAuth))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewCommitteeColdResign(String committeeColdResign, Promise promise) {
        Native.I
            .csl_bridge_certificateNewCommitteeColdResign(new RPtr(committeeColdResign))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewDrepDeregistration(String drepDeregistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewDrepDeregistration(new RPtr(drepDeregistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewDrepRegistration(String drepRegistration, Promise promise) {
        Native.I
            .csl_bridge_certificateNewDrepRegistration(new RPtr(drepRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewDrepUpdate(String drepUpdate, Promise promise) {
        Native.I
            .csl_bridge_certificateNewDrepUpdate(new RPtr(drepUpdate))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeAndVoteDelegation(String stakeAndVoteDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeAndVoteDelegation(new RPtr(stakeAndVoteDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeRegistrationAndDelegation(String stakeRegistrationAndDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeRegistrationAndDelegation(new RPtr(stakeRegistrationAndDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewStakeVoteRegistrationAndDelegation(String stakeVoteRegistrationAndDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewStakeVoteRegistrationAndDelegation(new RPtr(stakeVoteRegistrationAndDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewVoteDelegation(String voteDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewVoteDelegation(new RPtr(voteDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateNewVoteRegistrationAndDelegation(String voteRegistrationAndDelegation, Promise promise) {
        Native.I
            .csl_bridge_certificateNewVoteRegistrationAndDelegation(new RPtr(voteRegistrationAndDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateKind(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeRegistration(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeRegistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsRegCert(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsRegCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeDeregistration(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeDeregistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsUnregCert(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsUnregCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsPoolRegistration(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsPoolRegistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsPoolRetirement(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsPoolRetirement(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsGenesisKeyDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsGenesisKeyDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsMoveInstantaneousRewardsCert(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsMoveInstantaneousRewardsCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsCommitteeHotAuth(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsCommitteeHotAuth(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsCommitteeColdResign(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsCommitteeColdResign(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsDrepDeregistration(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsDrepDeregistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsDrepRegistration(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsDrepRegistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsDrepUpdate(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsDrepUpdate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeAndVoteDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeAndVoteDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeRegistrationAndDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeRegistrationAndDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsStakeVoteRegistrationAndDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsStakeVoteRegistrationAndDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsVoteDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsVoteDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateAsVoteRegistrationAndDelegation(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateAsVoteRegistrationAndDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificateHasRequiredScriptWitness(String self, Promise promise) {
        Native.I
            .csl_bridge_certificateHasRequiredScriptWitness(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_certificatesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_certificatesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_certificatesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_certificatesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesNew( Promise promise) {
        Native.I
            .csl_bridge_certificatesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_certificatesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_certificatesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_certificatesBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderAdd(String self, String cert, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderAdd(new RPtr(self), new RPtr(cert))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderAddWithPlutusWitness(String self, String cert, String witness, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderAddWithPlutusWitness(new RPtr(self), new RPtr(cert), new RPtr(witness))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderAddWithNativeScript(String self, String cert, String nativeScriptSource, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderAddWithNativeScript(new RPtr(self), new RPtr(cert), new RPtr(nativeScriptSource))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderGetNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderGetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderGetCertificatesRefund(String self, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderGetCertificatesRefund(new RPtr(self), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderGetCertificatesDeposit(String self, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderGetCertificatesDeposit(new RPtr(self), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_certificatesBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_certificatesBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_changeConfigNew(String address, Promise promise) {
        Native.I
            .csl_bridge_changeConfigNew(new RPtr(address))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_changeConfigChangeAddress(String self, String address, Promise promise) {
        Native.I
            .csl_bridge_changeConfigChangeAddress(new RPtr(self), new RPtr(address))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_changeConfigChangePlutusData(String self, String plutusData, Promise promise) {
        Native.I
            .csl_bridge_changeConfigChangePlutusData(new RPtr(self), new RPtr(plutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_changeConfigChangeScriptRef(String self, String scriptRef, Promise promise) {
        Native.I
            .csl_bridge_changeConfigChangeScriptRef(new RPtr(self), new RPtr(scriptRef))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_committeeToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_committeeFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_committeeFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_committeeFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeNew(String quorumThreshold, Promise promise) {
        Native.I
            .csl_bridge_committeeNew(new RPtr(quorumThreshold))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeMembersKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeMembersKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeQuorumThreshold(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeQuorumThreshold(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeAddMember(String self, String committeeColdCredential, Double epoch, Promise promise) {
        Native.I
            .csl_bridge_committeeAddMember(new RPtr(self), new RPtr(committeeColdCredential), epoch.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeGetMemberEpoch(String self, String committeeColdCredential, Promise promise) {
        Native.I
            .csl_bridge_committeeGetMemberEpoch(new RPtr(self), new RPtr(committeeColdCredential))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_committeeColdResignToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignCommitteeColdKey(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignCommitteeColdKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignNew(String committeeColdKey, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignNew(new RPtr(committeeColdKey))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignNewWithAnchor(String committeeColdKey, String anchor, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignNewWithAnchor(new RPtr(committeeColdKey), new RPtr(anchor))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeColdResignHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeColdResignHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_committeeHotAuthToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthCommitteeColdKey(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthCommitteeColdKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthCommitteeHotKey(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthCommitteeHotKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthNew(String committeeColdKey, String committeeHotKey, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthNew(new RPtr(committeeColdKey), new RPtr(committeeHotKey))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_committeeHotAuthHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_committeeHotAuthHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_constitutionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_constitutionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_constitutionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_constitutionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_constitutionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_constitutionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_constitutionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_constitutionAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_constitutionScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionNew(String anchor, Promise promise) {
        Native.I
            .csl_bridge_constitutionNew(new RPtr(anchor))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constitutionNewWithScriptHash(String anchor, String scriptHash, Promise promise) {
        Native.I
            .csl_bridge_constitutionNewWithScriptHash(new RPtr(anchor), new RPtr(scriptHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_constrPlutusDataToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataAlternative(String self, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataAlternative(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataData(String self, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_constrPlutusDataNew(String alternative, String data, Promise promise) {
        Native.I
            .csl_bridge_constrPlutusDataNew(new RPtr(alternative), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_costModelToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_costModelToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_costModelFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_costModelToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_costModelFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_costModelToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_costModelFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelNew( Promise promise) {
        Native.I
            .csl_bridge_costModelNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelSet(String self, Double operation, String cost, Promise promise) {
        Native.I
            .csl_bridge_costModelSet(new RPtr(self), operation.longValue(), new RPtr(cost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelGet(String self, Double operation, Promise promise) {
        Native.I
            .csl_bridge_costModelGet(new RPtr(self), operation.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costModelLen(String self, Promise promise) {
        Native.I
            .csl_bridge_costModelLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_costmdlsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_costmdlsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_costmdlsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_costmdlsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_costmdlsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_costmdlsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_costmdlsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsNew( Promise promise) {
        Native.I
            .csl_bridge_costmdlsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_costmdlsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_costmdlsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_costmdlsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_costmdlsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_costmdlsRetainLanguageVersions(String self, String languages, Promise promise) {
        Native.I
            .csl_bridge_costmdlsRetainLanguageVersions(new RPtr(self), new RPtr(languages))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_credentialFromKeyhash(String hash, Promise promise) {
        Native.I
            .csl_bridge_credentialFromKeyhash(new RPtr(hash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialFromScripthash(String hash, Promise promise) {
        Native.I
            .csl_bridge_credentialFromScripthash(new RPtr(hash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialToKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialToKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialToScripthash(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialToScripthash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialKind(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialHasScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialHasScriptHash(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_credentialFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_credentialFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_credentialFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_credentialsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_credentialsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_credentialsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_credentialsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsNew( Promise promise) {
        Native.I
            .csl_bridge_credentialsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_credentialsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_credentialsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_credentialsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_credentialsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAAFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAAFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAANew(String dnsName, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAANew(dnsName)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordAorAAAARecord(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordAorAAAARecord(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dNSRecordSRVToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVNew(String dnsName, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVNew(dnsName)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dNSRecordSRVRecord(String self, Promise promise) {
        Native.I
            .csl_bridge_dNSRecordSRVRecord(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dRepToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dRepFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dRepFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dRepFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepNewKeyHash(String keyHash, Promise promise) {
        Native.I
            .csl_bridge_dRepNewKeyHash(new RPtr(keyHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepNewScriptHash(String scriptHash, Promise promise) {
        Native.I
            .csl_bridge_dRepNewScriptHash(new RPtr(scriptHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepNewAlwaysAbstain( Promise promise) {
        Native.I
            .csl_bridge_dRepNewAlwaysAbstain()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepNewAlwaysNoConfidence( Promise promise) {
        Native.I
            .csl_bridge_dRepNewAlwaysNoConfidence()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepNewFromCredential(String cred, Promise promise) {
        Native.I
            .csl_bridge_dRepNewFromCredential(new RPtr(cred))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepKind(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepToKeyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToKeyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepToScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_dRepFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dRepDeregistrationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationVotingCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationVotingCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationNew(String votingCredential, String coin, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationNew(new RPtr(votingCredential), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepDeregistrationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepDeregistrationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dRepRegistrationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationVotingCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationVotingCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationNew(String votingCredential, String coin, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationNew(new RPtr(votingCredential), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationNewWithAnchor(String votingCredential, String coin, String anchor, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationNewWithAnchor(new RPtr(votingCredential), new RPtr(coin), new RPtr(anchor))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepRegistrationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepRegistrationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dRepUpdateToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateVotingCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateVotingCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateNew(String votingCredential, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateNew(new RPtr(votingCredential))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateNewWithAnchor(String votingCredential, String anchor, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateNewWithAnchor(new RPtr(votingCredential), new RPtr(anchor))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepUpdateHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepUpdateHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsNew(String motionNoConfidence, String committeeNormal, String committeeNoConfidence, String updateConstitution, String hardForkInitiation, String ppNetworkGroup, String ppEconomicGroup, String ppTechnicalGroup, String ppGovernanceGroup, String treasuryWithdrawal, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsNew(new RPtr(motionNoConfidence), new RPtr(committeeNormal), new RPtr(committeeNoConfidence), new RPtr(updateConstitution), new RPtr(hardForkInitiation), new RPtr(ppNetworkGroup), new RPtr(ppEconomicGroup), new RPtr(ppTechnicalGroup), new RPtr(ppGovernanceGroup), new RPtr(treasuryWithdrawal))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetMotionNoConfidence(String self, String motionNoConfidence, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetMotionNoConfidence(new RPtr(self), new RPtr(motionNoConfidence))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetCommitteeNormal(String self, String committeeNormal, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetCommitteeNormal(new RPtr(self), new RPtr(committeeNormal))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetCommitteeNoConfidence(String self, String committeeNoConfidence, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetCommitteeNoConfidence(new RPtr(self), new RPtr(committeeNoConfidence))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetUpdateConstitution(String self, String updateConstitution, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetUpdateConstitution(new RPtr(self), new RPtr(updateConstitution))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetHardForkInitiation(String self, String hardForkInitiation, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetHardForkInitiation(new RPtr(self), new RPtr(hardForkInitiation))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetPpNetworkGroup(String self, String ppNetworkGroup, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetPpNetworkGroup(new RPtr(self), new RPtr(ppNetworkGroup))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetPpEconomicGroup(String self, String ppEconomicGroup, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetPpEconomicGroup(new RPtr(self), new RPtr(ppEconomicGroup))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetPpTechnicalGroup(String self, String ppTechnicalGroup, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetPpTechnicalGroup(new RPtr(self), new RPtr(ppTechnicalGroup))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetPpGovernanceGroup(String self, String ppGovernanceGroup, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetPpGovernanceGroup(new RPtr(self), new RPtr(ppGovernanceGroup))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsSetTreasuryWithdrawal(String self, String treasuryWithdrawal, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsSetTreasuryWithdrawal(new RPtr(self), new RPtr(treasuryWithdrawal))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsMotionNoConfidence(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsMotionNoConfidence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsCommitteeNormal(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsCommitteeNormal(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsCommitteeNoConfidence(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsCommitteeNoConfidence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsUpdateConstitution(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsUpdateConstitution(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsHardForkInitiation(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsHardForkInitiation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsPpNetworkGroup(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsPpNetworkGroup(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsPpEconomicGroup(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsPpEconomicGroup(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsPpTechnicalGroup(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsPpTechnicalGroup(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsPpGovernanceGroup(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsPpGovernanceGroup(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dRepVotingThresholdsTreasuryWithdrawal(String self, Promise promise) {
        Native.I
            .csl_bridge_dRepVotingThresholdsTreasuryWithdrawal(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dataCostNewCoinsPerByte(String coinsPerByte, Promise promise) {
        Native.I
            .csl_bridge_dataCostNewCoinsPerByte(new RPtr(coinsPerByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataCostCoinsPerByte(String self, Promise promise) {
        Native.I
            .csl_bridge_dataCostCoinsPerByte(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_dataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_dataHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_dataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_dataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_dataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_dataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_dataHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_dataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_datumSourceNew(String datum, Promise promise) {
        Native.I
            .csl_bridge_datumSourceNew(new RPtr(datum))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_datumSourceNewRefInput(String input, Promise promise) {
        Native.I
            .csl_bridge_datumSourceNewRefInput(new RPtr(input))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_ed25519KeyHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesNew( Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesContains(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesContains(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519KeyHashesToOption(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519KeyHashesToOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_ed25519SignatureToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519SignatureToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519SignatureToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519SignatureFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519SignatureFromHex(String input, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureFromHex(input)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ed25519SignatureFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_ed25519SignatureFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_enterpriseAddressNew(Double network, String payment, Promise promise) {
        Native.I
            .csl_bridge_enterpriseAddressNew(network.longValue(), new RPtr(payment))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_enterpriseAddressPaymentCred(String self, Promise promise) {
        Native.I
            .csl_bridge_enterpriseAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_enterpriseAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_enterpriseAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_enterpriseAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_enterpriseAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_enterpriseAddressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_enterpriseAddressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_exUnitPricesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesMemPrice(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesMemPrice(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesStepPrice(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesStepPrice(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitPricesNew(String memPrice, String stepPrice, Promise promise) {
        Native.I
            .csl_bridge_exUnitPricesNew(new RPtr(memPrice), new RPtr(stepPrice))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_exUnitsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_exUnitsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_exUnitsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_exUnitsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsMem(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitsMem(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsSteps(String self, Promise promise) {
        Native.I
            .csl_bridge_exUnitsSteps(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_exUnitsNew(String mem, String steps, Promise promise) {
        Native.I
            .csl_bridge_exUnitsNew(new RPtr(mem), new RPtr(steps))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_fixedBlockFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockHeader(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockHeader(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockTransactionBodies(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockTransactionBodies(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockTransactionWitnessSets(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockTransactionWitnessSets(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockAuxiliaryDataSet(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockAuxiliaryDataSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockInvalidTransactions(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockInvalidTransactions(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedBlockBlockHash(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedBlockBlockHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_fixedTransactionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionNew(String rawBody, String rawWitnessSet, Boolean isValid, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionNew(Base64.decode(rawBody, Base64.DEFAULT), Base64.decode(rawWitnessSet, Base64.DEFAULT), isValid)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionNewWithAuxiliary(String rawBody, String rawWitnessSet, String rawAuxiliaryData, Boolean isValid, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionNewWithAuxiliary(Base64.decode(rawBody, Base64.DEFAULT), Base64.decode(rawWitnessSet, Base64.DEFAULT), Base64.decode(rawAuxiliaryData, Base64.DEFAULT), isValid)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBody(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionRawBody(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionRawBody(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionSetBody(String self, String rawBody, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionSetBody(new RPtr(self), Base64.decode(rawBody, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionSetWitnessSet(String self, String rawWitnessSet, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionSetWitnessSet(new RPtr(self), Base64.decode(rawWitnessSet, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionWitnessSet(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionWitnessSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionRawWitnessSet(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionRawWitnessSet(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionSetIsValid(String self, Boolean valid, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionSetIsValid(new RPtr(self), valid)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionIsValid(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionIsValid(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionSetAuxiliaryData(String self, String rawAuxiliaryData, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionSetAuxiliaryData(new RPtr(self), Base64.decode(rawAuxiliaryData, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionAuxiliaryData(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionAuxiliaryData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionRawAuxiliaryData(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionRawAuxiliaryData(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesNew( Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodiesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodiesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_fixedTransactionBodyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodyTransactionBody(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodyTransactionBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodyTxHash(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodyTxHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedTransactionBodyOriginalBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedTransactionBodyOriginalBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_fixedVersionedBlockFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_fixedVersionedBlockFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedVersionedBlockFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_fixedVersionedBlockFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedVersionedBlockBlock(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedVersionedBlockBlock(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_fixedVersionedBlockEra(String self, Promise promise) {
        Native.I
            .csl_bridge_fixedVersionedBlockEra(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataNew( Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataLen(String self, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_generalTransactionMetadataKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_generalTransactionMetadataKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_genesisDelegateHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisDelegateHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisDelegateHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisDelegateHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisDelegateHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisDelegateHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_genesisDelegateHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_genesisHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_genesisHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_genesisHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_genesisHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_genesisHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_genesisHashesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesNew( Promise promise) {
        Native.I
            .csl_bridge_genesisHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_genesisHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationGenesishash(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationGenesishash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationGenesisDelegateHash(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationGenesisDelegateHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationVrfKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationVrfKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_genesisKeyDelegationNew(String genesishash, String genesisDelegateHash, String vrfKeyhash, Promise promise) {
        Native.I
            .csl_bridge_genesisKeyDelegationNew(new RPtr(genesishash), new RPtr(genesisDelegateHash), new RPtr(vrfKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_governanceActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_governanceActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_governanceActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_governanceActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewParameterChangeAction(String parameterChangeAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewParameterChangeAction(new RPtr(parameterChangeAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewHardForkInitiationAction(String hardForkInitiationAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewHardForkInitiationAction(new RPtr(hardForkInitiationAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewTreasuryWithdrawalsAction(String treasuryWithdrawalsAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewTreasuryWithdrawalsAction(new RPtr(treasuryWithdrawalsAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewNoConfidenceAction(String noConfidenceAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewNoConfidenceAction(new RPtr(noConfidenceAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewNewCommitteeAction(String newCommitteeAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewNewCommitteeAction(new RPtr(newCommitteeAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewNewConstitutionAction(String newConstitutionAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewNewConstitutionAction(new RPtr(newConstitutionAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionNewInfoAction(String infoAction, Promise promise) {
        Native.I
            .csl_bridge_governanceActionNewInfoAction(new RPtr(infoAction))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionKind(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsParameterChangeAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsParameterChangeAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsHardForkInitiationAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsHardForkInitiationAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsTreasuryWithdrawalsAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsTreasuryWithdrawalsAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsNoConfidenceAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsNoConfidenceAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsNewCommitteeAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsNewCommitteeAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsNewConstitutionAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsNewConstitutionAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionAsInfoAction(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionAsInfoAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_governanceActionIdToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdTransactionId(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdTransactionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdIndex(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdIndex(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdNew(String transactionId, Double index, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdNew(new RPtr(transactionId), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_governanceActionIdsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdsNew( Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdsAdd(String self, String governanceActionId, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsAdd(new RPtr(self), new RPtr(governanceActionId))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_governanceActionIdsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_governanceActionIdsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionGovActionId(String self, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionGovActionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionProtocolVersion(String self, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionProtocolVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionNew(String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionNew(new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hardForkInitiationActionNewWithActionId(String govActionId, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_hardForkInitiationActionNewWithActionId(new RPtr(govActionId), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_headerToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_headerToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_headerFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_headerToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_headerFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_headerToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_headerFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerHeaderBody(String self, Promise promise) {
        Native.I
            .csl_bridge_headerHeaderBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodySignature(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodySignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerNew(String headerBody, String bodySignature, Promise promise) {
        Native.I
            .csl_bridge_headerNew(new RPtr(headerBody), new RPtr(bodySignature))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_headerBodyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_headerBodyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_headerBodyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_headerBodyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyBlockNumber(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyBlockNumber(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodySlot(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodySlot(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodySlotBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodySlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyPrevHash(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyPrevHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyIssuerVkey(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyIssuerVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyVrfVkey(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyVrfVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyHasNonceAndLeaderVrf(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyHasNonceAndLeaderVrf(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyNonceVrfOrNothing(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyNonceVrfOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyLeaderVrfOrNothing(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyLeaderVrfOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyHasVrfResult(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyHasVrfResult(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyVrfResultOrNothing(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyVrfResultOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyBlockBodySize(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyBlockBodySize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyBlockBodyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyBlockBodyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyOperationalCert(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyOperationalCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyProtocolVersion(String self, Promise promise) {
        Native.I
            .csl_bridge_headerBodyProtocolVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyNew(Double blockNumber, Double slot, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_headerBodyNew(blockNumber.longValue(), slot.longValue(), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyNewWithPrevHash(Double blockNumber, Double slot, String prevHash, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_headerBodyNewWithPrevHash(blockNumber.longValue(), slot.longValue(), new RPtr(prevHash), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_headerBodyNewHeaderbody(Double blockNumber, String slot, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_headerBodyNewHeaderbody(blockNumber.longValue(), new RPtr(slot), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_headerBodyNewHeaderbodyWithPrevHash(Double blockNumber, String slot, String prevHash, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_headerBodyNewHeaderbodyWithPrevHash(blockNumber.longValue(), new RPtr(slot), new RPtr(prevHash), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_infoActionNew( Promise promise) {
        Native.I
            .csl_bridge_infoActionNew()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_intToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_intToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_intFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_intToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_intFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_intToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_intFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intNew(String x, Promise promise) {
        Native.I
            .csl_bridge_intNew(new RPtr(x))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intNewNegative(String x, Promise promise) {
        Native.I
            .csl_bridge_intNewNegative(new RPtr(x))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intNewI32(Double x, Promise promise) {
        Native.I
            .csl_bridge_intNewI32(x.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intIsPositive(String self, Promise promise) {
        Native.I
            .csl_bridge_intIsPositive(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intAsPositive(String self, Promise promise) {
        Native.I
            .csl_bridge_intAsPositive(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intAsNegative(String self, Promise promise) {
        Native.I
            .csl_bridge_intAsNegative(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intAsI32(String self, Promise promise) {
        Native.I
            .csl_bridge_intAsI32(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intAsI32OrNothing(String self, Promise promise) {
        Native.I
            .csl_bridge_intAsI32OrNothing(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intAsI32OrFail(String self, Promise promise) {
        Native.I
            .csl_bridge_intAsI32OrFail(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intToStr(String self, Promise promise) {
        Native.I
            .csl_bridge_intToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_intFromStr(String string, Promise promise) {
        Native.I
            .csl_bridge_intFromStr(string)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_ipv4ToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv4ToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4FromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_ipv4FromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4ToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv4ToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4FromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_ipv4FromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4ToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv4ToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4FromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_ipv4FromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4New(String data, Promise promise) {
        Native.I
            .csl_bridge_ipv4New(Base64.decode(data, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv4Ip(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv4Ip(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_ipv6ToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv6ToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6FromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_ipv6FromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6ToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv6ToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6FromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_ipv6FromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6ToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv6ToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6FromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_ipv6FromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6New(String data, Promise promise) {
        Native.I
            .csl_bridge_ipv6New(Base64.decode(data, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_ipv6Ip(String self, Promise promise) {
        Native.I
            .csl_bridge_ipv6Ip(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_kESSignatureToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_kESSignatureToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESSignatureFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_kESSignatureFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_kESVKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESVKeyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESVKeyToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESVKeyFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESVKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_kESVKeyFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_kESVKeyFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_languageToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_languageToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_languageFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_languageToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_languageFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_languageToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_languageFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageNewPlutusV1( Promise promise) {
        Native.I
            .csl_bridge_languageNewPlutusV1()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageNewPlutusV2( Promise promise) {
        Native.I
            .csl_bridge_languageNewPlutusV2()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageNewPlutusV3( Promise promise) {
        Native.I
            .csl_bridge_languageNewPlutusV3()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languageKind(String self, Promise promise) {
        Native.I
            .csl_bridge_languageKind(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_languagesNew( Promise promise) {
        Native.I
            .csl_bridge_languagesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languagesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_languagesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languagesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_languagesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languagesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_languagesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_languagesList( Promise promise) {
        Native.I
            .csl_bridge_languagesList()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_legacyDaedalusPrivateKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_legacyDaedalusPrivateKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_legacyDaedalusPrivateKeyAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_legacyDaedalusPrivateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_legacyDaedalusPrivateKeyChaincode(String self, Promise promise) {
        Native.I
            .csl_bridge_legacyDaedalusPrivateKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_linearFeeConstant(String self, Promise promise) {
        Native.I
            .csl_bridge_linearFeeConstant(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_linearFeeCoefficient(String self, Promise promise) {
        Native.I
            .csl_bridge_linearFeeCoefficient(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_linearFeeNew(String coefficient, String constant, Promise promise) {
        Native.I
            .csl_bridge_linearFeeNew(new RPtr(coefficient), new RPtr(constant))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsNew( Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsInsert(String self, String cred, String delta, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsInsert(new RPtr(self), new RPtr(cred), new RPtr(delta))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsGet(String self, String cred, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsGet(new RPtr(self), new RPtr(cred))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mIRToStakeCredentialsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_mIRToStakeCredentialsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_malformedAddressOriginalBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_malformedAddressOriginalBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_malformedAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_malformedAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_malformedAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_malformedAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_metadataListToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataListToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_metadataListFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataListToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_metadataListFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListNew( Promise promise) {
        Native.I
            .csl_bridge_metadataListNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListLen(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataListLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_metadataListGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataListAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_metadataListAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_metadataMapToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataMapToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_metadataMapFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataMapToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_metadataMapFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapNew( Promise promise) {
        Native.I
            .csl_bridge_metadataMapNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapLen(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataMapLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_metadataMapInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapInsertStr(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_metadataMapInsertStr(new RPtr(self), key, new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapInsertI32(String self, Double key, String value, Promise promise) {
        Native.I
            .csl_bridge_metadataMapInsertI32(new RPtr(self), key.longValue(), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_metadataMapGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapGetStr(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_metadataMapGetStr(new RPtr(self), key)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapGetI32(String self, Double key, Promise promise) {
        Native.I
            .csl_bridge_metadataMapGetI32(new RPtr(self), key.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapHas(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_metadataMapHas(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_metadataMapKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_metadataMapKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mintToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_mintToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_mintFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_mintToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_mintFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_mintToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_mintFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintNew( Promise promise) {
        Native.I
            .csl_bridge_mintNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintNewFromEntry(String key, String value, Promise promise) {
        Native.I
            .csl_bridge_mintNewFromEntry(new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintLen(String self, Promise promise) {
        Native.I
            .csl_bridge_mintLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_mintInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_mintGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_mintKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAsPositiveMultiasset(String self, Promise promise) {
        Native.I
            .csl_bridge_mintAsPositiveMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAsNegativeMultiasset(String self, Promise promise) {
        Native.I
            .csl_bridge_mintAsNegativeMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mintAssetsNew( Promise promise) {
        Native.I
            .csl_bridge_mintAssetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAssetsNewFromEntry(String key, String value, Promise promise) {
        Native.I
            .csl_bridge_mintAssetsNewFromEntry(new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAssetsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_mintAssetsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAssetsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_mintAssetsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAssetsGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_mintAssetsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintAssetsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_mintAssetsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mintBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_mintBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderAddAsset(String self, String mint, String assetName, String amount, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderAddAsset(new RPtr(self), new RPtr(mint), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderSetAsset(String self, String mint, String assetName, String amount, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderSetAsset(new RPtr(self), new RPtr(mint), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderGetNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderGetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderGetRedeemers(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderGetRedeemers(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintBuilderHasNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_mintBuilderHasNativeScripts(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mintWitnessNewNativeScript(String nativeScript, Promise promise) {
        Native.I
            .csl_bridge_mintWitnessNewNativeScript(new RPtr(nativeScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintWitnessNewPlutusScript(String plutusScript, String redeemer, Promise promise) {
        Native.I
            .csl_bridge_mintWitnessNewPlutusScript(new RPtr(plutusScript), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_mintsAssetsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintsAssetsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintsAssetsNew( Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintsAssetsAdd(String self, String mintAssets, Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsAdd(new RPtr(self), new RPtr(mintAssets))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintsAssetsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_mintsAssetsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_mintsAssetsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardNewToOtherPot(Double pot, String amount, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardNewToOtherPot(pot.intValue(), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardNewToStakeCreds(Double pot, String amounts, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardNewToStakeCreds(pot.intValue(), new RPtr(amounts))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardPot(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardPot(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardKind(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardAsToOtherPot(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardAsToOtherPot(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardAsToStakeCreds(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardAsToStakeCreds(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertMoveInstantaneousReward(String self, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertMoveInstantaneousReward(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_moveInstantaneousRewardsCertNew(String moveInstantaneousReward, Promise promise) {
        Native.I
            .csl_bridge_moveInstantaneousRewardsCertNew(new RPtr(moveInstantaneousReward))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_multiAssetToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_multiAssetToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_multiAssetFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_multiAssetToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_multiAssetFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_multiAssetToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_multiAssetFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetNew( Promise promise) {
        Native.I
            .csl_bridge_multiAssetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetLen(String self, Promise promise) {
        Native.I
            .csl_bridge_multiAssetLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetInsert(String self, String policyId, String assets, Promise promise) {
        Native.I
            .csl_bridge_multiAssetInsert(new RPtr(self), new RPtr(policyId), new RPtr(assets))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetGet(String self, String policyId, Promise promise) {
        Native.I
            .csl_bridge_multiAssetGet(new RPtr(self), new RPtr(policyId))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetSetAsset(String self, String policyId, String assetName, String value, Promise promise) {
        Native.I
            .csl_bridge_multiAssetSetAsset(new RPtr(self), new RPtr(policyId), new RPtr(assetName), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetGetAsset(String self, String policyId, String assetName, Promise promise) {
        Native.I
            .csl_bridge_multiAssetGetAsset(new RPtr(self), new RPtr(policyId), new RPtr(assetName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_multiAssetKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiAssetSub(String self, String rhsMa, Promise promise) {
        Native.I
            .csl_bridge_multiAssetSub(new RPtr(self), new RPtr(rhsMa))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_multiHostNameToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameDnsName(String self, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameDnsName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_multiHostNameNew(String dnsName, Promise promise) {
        Native.I
            .csl_bridge_multiHostNameNew(new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_nativeScriptToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewScriptPubkey(String scriptPubkey, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewScriptPubkey(new RPtr(scriptPubkey))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewScriptAll(String scriptAll, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewScriptAll(new RPtr(scriptAll))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewScriptAny(String scriptAny, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewScriptAny(new RPtr(scriptAny))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewScriptNOfK(String scriptNOfK, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewScriptNOfK(new RPtr(scriptNOfK))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewTimelockStart(String timelockStart, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewTimelockStart(new RPtr(timelockStart))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptNewTimelockExpiry(String timelockExpiry, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptNewTimelockExpiry(new RPtr(timelockExpiry))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptKind(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsScriptPubkey(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsScriptPubkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsScriptAll(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsScriptAll(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsScriptAny(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsScriptAny(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsScriptNOfK(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsScriptNOfK(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsTimelockStart(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsTimelockStart(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptAsTimelockExpiry(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptAsTimelockExpiry(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptGetRequiredSigners(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptGetRequiredSigners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_nativeScriptSourceNew(String script, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptSourceNew(new RPtr(script))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptSourceNewRefInput(String scriptHash, String input, Double scriptSize, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptSourceNewRefInput(new RPtr(scriptHash), new RPtr(input), scriptSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptSourceSetRequiredSigners(String self, String keyHashes, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptSourceSetRequiredSigners(new RPtr(self), new RPtr(keyHashes))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptSourceGetRefScriptSize(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptSourceGetRefScriptSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_nativeScriptsNew( Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nativeScriptsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_nativeScriptsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_networkIdToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_networkIdToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_networkIdFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_networkIdToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_networkIdFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_networkIdToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_networkIdFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdTestnet( Promise promise) {
        Native.I
            .csl_bridge_networkIdTestnet()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdMainnet( Promise promise) {
        Native.I
            .csl_bridge_networkIdMainnet()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkIdKind(String self, Promise promise) {
        Native.I
            .csl_bridge_networkIdKind(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_networkInfoNew(Double networkId, Double protocolMagic, Promise promise) {
        Native.I
            .csl_bridge_networkInfoNew(networkId.longValue(), protocolMagic.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkInfoNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_networkInfoNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkInfoProtocolMagic(String self, Promise promise) {
        Native.I
            .csl_bridge_networkInfoProtocolMagic(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkInfoTestnetPreview( Promise promise) {
        Native.I
            .csl_bridge_networkInfoTestnetPreview()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkInfoTestnetPreprod( Promise promise) {
        Native.I
            .csl_bridge_networkInfoTestnetPreprod()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_networkInfoMainnet( Promise promise) {
        Native.I
            .csl_bridge_networkInfoMainnet()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_newConstitutionActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionGovActionId(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionGovActionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionConstitution(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionConstitution(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionNew(String constitution, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionNew(new RPtr(constitution))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionNewWithActionId(String govActionId, String constitution, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionNewWithActionId(new RPtr(govActionId), new RPtr(constitution))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_newConstitutionActionHasScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_newConstitutionActionHasScriptHash(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_noConfidenceActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionGovActionId(String self, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionGovActionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionNew( Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_noConfidenceActionNewWithActionId(String govActionId, Promise promise) {
        Native.I
            .csl_bridge_noConfidenceActionNewWithActionId(new RPtr(govActionId))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_nonceToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_nonceToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_nonceFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_nonceToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_nonceFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_nonceToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_nonceFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceNewIdentity( Promise promise) {
        Native.I
            .csl_bridge_nonceNewIdentity()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceNewFromHash(String hash, Promise promise) {
        Native.I
            .csl_bridge_nonceNewFromHash(Base64.decode(hash, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_nonceGetHash(String self, Promise promise) {
        Native.I
            .csl_bridge_nonceGetHash(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_operationalCertToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_operationalCertFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_operationalCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_operationalCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertHotVkey(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertHotVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertSequenceNumber(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertSequenceNumber(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertKesPeriod(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertKesPeriod(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertSigma(String self, Promise promise) {
        Native.I
            .csl_bridge_operationalCertSigma(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_operationalCertNew(String hotVkey, Double sequenceNumber, Double kesPeriod, String sigma, Promise promise) {
        Native.I
            .csl_bridge_operationalCertNew(new RPtr(hotVkey), sequenceNumber.longValue(), kesPeriod.longValue(), new RPtr(sigma))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_outputDatumNewDataHash(String dataHash, Promise promise) {
        Native.I
            .csl_bridge_outputDatumNewDataHash(new RPtr(dataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_outputDatumNewData(String data, Promise promise) {
        Native.I
            .csl_bridge_outputDatumNewData(new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_outputDatumDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_outputDatumDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_outputDatumData(String self, Promise promise) {
        Native.I
            .csl_bridge_outputDatumData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_parameterChangeActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionGovActionId(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionGovActionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionProtocolParamUpdates(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionProtocolParamUpdates(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionPolicyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionPolicyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionNew(String protocolParamUpdates, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionNew(new RPtr(protocolParamUpdates))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionNewWithActionId(String govActionId, String protocolParamUpdates, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionNewWithActionId(new RPtr(govActionId), new RPtr(protocolParamUpdates))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionNewWithPolicyHash(String protocolParamUpdates, String policyHash, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionNewWithPolicyHash(new RPtr(protocolParamUpdates), new RPtr(policyHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_parameterChangeActionNewWithPolicyHashAndActionId(String govActionId, String protocolParamUpdates, String policyHash, Promise promise) {
        Native.I
            .csl_bridge_parameterChangeActionNewWithPolicyHashAndActionId(new RPtr(govActionId), new RPtr(protocolParamUpdates), new RPtr(policyHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusDataToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusDataFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_plutusDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewConstrPlutusData(String constrPlutusData, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewConstrPlutusData(new RPtr(constrPlutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewEmptyConstrPlutusData(String alternative, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewEmptyConstrPlutusData(new RPtr(alternative))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewSingleValueConstrPlutusData(String alternative, String plutusData, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewSingleValueConstrPlutusData(new RPtr(alternative), new RPtr(plutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewMap(String map, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewMap(new RPtr(map))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewList(String list, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewList(new RPtr(list))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewInteger(String integer, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewInteger(new RPtr(integer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataNewBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusDataNewBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataKind(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataAsConstrPlutusData(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataAsConstrPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataAsMap(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataAsMap(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataAsList(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataAsList(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataAsInteger(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataAsInteger(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusDataAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataToJson(String self, Double schema, Promise promise) {
        Native.I
            .csl_bridge_plutusDataToJson(new RPtr(self), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataFromJson(String json, Double schema, Promise promise) {
        Native.I
            .csl_bridge_plutusDataFromJson(json, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusDataFromAddress(String address, Promise promise) {
        Native.I
            .csl_bridge_plutusDataFromAddress(new RPtr(address))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusListToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusListToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusListFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusListToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_plutusListFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListNew( Promise promise) {
        Native.I
            .csl_bridge_plutusListNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListLen(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusListLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_plutusListGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusListAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_plutusListAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusMapToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusMapToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusMapFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusMapToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_plutusMapFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapNew( Promise promise) {
        Native.I
            .csl_bridge_plutusMapNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapLen(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusMapLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapInsert(String self, String key, String values, Promise promise) {
        Native.I
            .csl_bridge_plutusMapInsert(new RPtr(self), new RPtr(key), new RPtr(values))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_plutusMapGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusMapKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusMapValuesNew( Promise promise) {
        Native.I
            .csl_bridge_plutusMapValuesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapValuesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusMapValuesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapValuesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_plutusMapValuesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusMapValuesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_plutusMapValuesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusScriptToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptNew(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptNew(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptNewV2(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptNewV2(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptNewV3(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptNewV3(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptNewWithVersion(String bytes, String language, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptNewWithVersion(Base64.decode(bytes, Base64.DEFAULT), new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromBytesV2(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromBytesV2(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromBytesV3(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromBytesV3(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromBytesWithVersion(String bytes, String language, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromBytesWithVersion(Base64.decode(bytes, Base64.DEFAULT), new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptFromHexWithVersion(String hexStr, String language, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptFromHexWithVersion(hexStr, new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptHash(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptLanguageVersion(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptLanguageVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusScriptSourceNew(String script, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptSourceNew(new RPtr(script))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptSourceNewRefInput(String scriptHash, String input, String langVer, Double scriptSize, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptSourceNewRefInput(new RPtr(scriptHash), new RPtr(input), new RPtr(langVer), scriptSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptSourceSetRequiredSigners(String self, String keyHashes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptSourceSetRequiredSigners(new RPtr(self), new RPtr(keyHashes))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptSourceGetRefScriptSize(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptSourceGetRefScriptSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusScriptsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsNew( Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusScriptsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_plutusScriptsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusWitnessNew(String script, String datum, String redeemer, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessNew(new RPtr(script), new RPtr(datum), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessNewWithRef(String script, String datum, String redeemer, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessNewWithRef(new RPtr(script), new RPtr(datum), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessNewWithoutDatum(String script, String redeemer, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessNewWithoutDatum(new RPtr(script), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessNewWithRefWithoutDatum(String script, String redeemer, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessNewWithRefWithoutDatum(new RPtr(script), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessScript(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessDatum(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessDatum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessRedeemer(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessRedeemer(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_plutusWitnessesNew( Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_plutusWitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_plutusWitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_pointerNew(Double slot, Double txIndex, Double certIndex, Promise promise) {
        Native.I
            .csl_bridge_pointerNew(slot.longValue(), txIndex.longValue(), certIndex.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerNewPointer(String slot, String txIndex, String certIndex, Promise promise) {
        Native.I
            .csl_bridge_pointerNewPointer(new RPtr(slot), new RPtr(txIndex), new RPtr(certIndex))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerSlot(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerSlot(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerTxIndex(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerTxIndex(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerCertIndex(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerCertIndex(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerSlotBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerSlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerTxIndexBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerTxIndexBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerCertIndexBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerCertIndexBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_pointerAddressNew(Double network, String payment, String stake, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressNew(network.longValue(), new RPtr(payment), new RPtr(stake))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerAddressPaymentCred(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerAddressStakePointer(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressStakePointer(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_pointerAddressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_pointerAddressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_poolMetadataToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataUrl(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataUrl(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataPoolMetadataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataPoolMetadataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataNew(String url, String poolMetadataHash, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataNew(new RPtr(url), new RPtr(poolMetadataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_poolMetadataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolMetadataHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_poolMetadataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_poolParamsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolParamsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_poolParamsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_poolParamsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsOperator(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsOperator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsVrfKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsVrfKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsPledge(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsPledge(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsCost(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsCost(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsMargin(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsMargin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsRewardAccount(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsRewardAccount(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsPoolOwners(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsPoolOwners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsRelays(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsRelays(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsPoolMetadata(String self, Promise promise) {
        Native.I
            .csl_bridge_poolParamsPoolMetadata(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsNew(String operator, String vrfKeyhash, String pledge, String cost, String margin, String rewardAccount, String poolOwners, String relays, Promise promise) {
        Native.I
            .csl_bridge_poolParamsNew(new RPtr(operator), new RPtr(vrfKeyhash), new RPtr(pledge), new RPtr(cost), new RPtr(margin), new RPtr(rewardAccount), new RPtr(poolOwners), new RPtr(relays))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolParamsNewWithPoolMetadata(String operator, String vrfKeyhash, String pledge, String cost, String margin, String rewardAccount, String poolOwners, String relays, String poolMetadata, Promise promise) {
        Native.I
            .csl_bridge_poolParamsNewWithPoolMetadata(new RPtr(operator), new RPtr(vrfKeyhash), new RPtr(pledge), new RPtr(cost), new RPtr(margin), new RPtr(rewardAccount), new RPtr(poolOwners), new RPtr(relays), new RPtr(poolMetadata))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_poolRegistrationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationPoolParams(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationPoolParams(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRegistrationNew(String poolParams, Promise promise) {
        Native.I
            .csl_bridge_poolRegistrationNew(new RPtr(poolParams))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_poolRetirementToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementPoolKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementEpoch(String self, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementEpoch(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolRetirementNew(String poolKeyhash, Double epoch, Promise promise) {
        Native.I
            .csl_bridge_poolRetirementNew(new RPtr(poolKeyhash), epoch.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsNew(String motionNoConfidence, String committeeNormal, String committeeNoConfidence, String hardForkInitiation, String securityRelevantThreshold, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsNew(new RPtr(motionNoConfidence), new RPtr(committeeNormal), new RPtr(committeeNoConfidence), new RPtr(hardForkInitiation), new RPtr(securityRelevantThreshold))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsMotionNoConfidence(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsMotionNoConfidence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsCommitteeNormal(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsCommitteeNormal(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsCommitteeNoConfidence(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsCommitteeNoConfidence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsHardForkInitiation(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsHardForkInitiation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_poolVotingThresholdsSecurityRelevantThreshold(String self, Promise promise) {
        Native.I
            .csl_bridge_poolVotingThresholdsSecurityRelevantThreshold(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_privateKeyToPublic(String self, Promise promise) {
        Native.I
            .csl_bridge_privateKeyToPublic(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyGenerateEd25519( Promise promise) {
        Native.I
            .csl_bridge_privateKeyGenerateEd25519()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyGenerateEd25519extended( Promise promise) {
        Native.I
            .csl_bridge_privateKeyGenerateEd25519extended()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_privateKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_privateKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_privateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyFromExtendedBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_privateKeyFromExtendedBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyFromNormalBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_privateKeyFromNormalBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeySign(String self, String message, Promise promise) {
        Native.I
            .csl_bridge_privateKeySign(new RPtr(self), Base64.decode(message, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_privateKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_privateKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_privateKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesNew( Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_proposedProtocolParameterUpdatesKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_proposedProtocolParameterUpdatesKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_protocolParamUpdateToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMinfeeA(String self, String minfeeA, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMinfeeA(new RPtr(self), new RPtr(minfeeA))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMinfeeA(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMinfeeA(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMinfeeB(String self, String minfeeB, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMinfeeB(new RPtr(self), new RPtr(minfeeB))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMinfeeB(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMinfeeB(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxBlockBodySize(String self, Double maxBlockBodySize, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxBlockBodySize(new RPtr(self), maxBlockBodySize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxBlockBodySize(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxBlockBodySize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxTxSize(String self, Double maxTxSize, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxTxSize(new RPtr(self), maxTxSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxTxSize(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxTxSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxBlockHeaderSize(String self, Double maxBlockHeaderSize, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxBlockHeaderSize(new RPtr(self), maxBlockHeaderSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxBlockHeaderSize(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxBlockHeaderSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetKeyDeposit(String self, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetKeyDeposit(new RPtr(self), new RPtr(keyDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateKeyDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateKeyDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetPoolDeposit(String self, String poolDeposit, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetPoolDeposit(new RPtr(self), new RPtr(poolDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdatePoolDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdatePoolDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxEpoch(String self, Double maxEpoch, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxEpoch(new RPtr(self), maxEpoch.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxEpoch(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxEpoch(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetNOpt(String self, Double nOpt, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetNOpt(new RPtr(self), nOpt.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateNOpt(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateNOpt(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetPoolPledgeInfluence(String self, String poolPledgeInfluence, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetPoolPledgeInfluence(new RPtr(self), new RPtr(poolPledgeInfluence))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdatePoolPledgeInfluence(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdatePoolPledgeInfluence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetExpansionRate(String self, String expansionRate, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetExpansionRate(new RPtr(self), new RPtr(expansionRate))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateExpansionRate(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateExpansionRate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetTreasuryGrowthRate(String self, String treasuryGrowthRate, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetTreasuryGrowthRate(new RPtr(self), new RPtr(treasuryGrowthRate))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateTreasuryGrowthRate(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateTreasuryGrowthRate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateD(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateD(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateExtraEntropy(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateExtraEntropy(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetProtocolVersion(String self, String protocolVersion, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetProtocolVersion(new RPtr(self), new RPtr(protocolVersion))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateProtocolVersion(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateProtocolVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMinPoolCost(String self, String minPoolCost, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMinPoolCost(new RPtr(self), new RPtr(minPoolCost))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMinPoolCost(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMinPoolCost(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetAdaPerUtxoByte(String self, String adaPerUtxoByte, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetAdaPerUtxoByte(new RPtr(self), new RPtr(adaPerUtxoByte))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateAdaPerUtxoByte(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateAdaPerUtxoByte(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetCostModels(String self, String costModels, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetCostModels(new RPtr(self), new RPtr(costModels))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateCostModels(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateCostModels(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetExecutionCosts(String self, String executionCosts, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetExecutionCosts(new RPtr(self), new RPtr(executionCosts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateExecutionCosts(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateExecutionCosts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxTxExUnits(String self, String maxTxExUnits, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxTxExUnits(new RPtr(self), new RPtr(maxTxExUnits))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxTxExUnits(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxTxExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxBlockExUnits(String self, String maxBlockExUnits, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxBlockExUnits(new RPtr(self), new RPtr(maxBlockExUnits))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxBlockExUnits(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxBlockExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxValueSize(String self, Double maxValueSize, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxValueSize(new RPtr(self), maxValueSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxValueSize(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxValueSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetCollateralPercentage(String self, Double collateralPercentage, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetCollateralPercentage(new RPtr(self), collateralPercentage.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateCollateralPercentage(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateCollateralPercentage(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMaxCollateralInputs(String self, Double maxCollateralInputs, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMaxCollateralInputs(new RPtr(self), maxCollateralInputs.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMaxCollateralInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMaxCollateralInputs(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetPoolVotingThresholds(String self, String poolVotingThresholds, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetPoolVotingThresholds(new RPtr(self), new RPtr(poolVotingThresholds))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdatePoolVotingThresholds(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdatePoolVotingThresholds(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetDrepVotingThresholds(String self, String drepVotingThresholds, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetDrepVotingThresholds(new RPtr(self), new RPtr(drepVotingThresholds))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateDrepVotingThresholds(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateDrepVotingThresholds(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetMinCommitteeSize(String self, Double minCommitteeSize, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetMinCommitteeSize(new RPtr(self), minCommitteeSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateMinCommitteeSize(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateMinCommitteeSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetCommitteeTermLimit(String self, Double committeeTermLimit, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetCommitteeTermLimit(new RPtr(self), committeeTermLimit.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateCommitteeTermLimit(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateCommitteeTermLimit(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetGovernanceActionValidityPeriod(String self, Double governanceActionValidityPeriod, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetGovernanceActionValidityPeriod(new RPtr(self), governanceActionValidityPeriod.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateGovernanceActionValidityPeriod(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateGovernanceActionValidityPeriod(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetGovernanceActionDeposit(String self, String governanceActionDeposit, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetGovernanceActionDeposit(new RPtr(self), new RPtr(governanceActionDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateGovernanceActionDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateGovernanceActionDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetDrepDeposit(String self, String drepDeposit, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetDrepDeposit(new RPtr(self), new RPtr(drepDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateDrepDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateDrepDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetDrepInactivityPeriod(String self, Double drepInactivityPeriod, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetDrepInactivityPeriod(new RPtr(self), drepInactivityPeriod.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateDrepInactivityPeriod(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateDrepInactivityPeriod(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateSetRefScriptCoinsPerByte(String self, String refScriptCoinsPerByte, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateSetRefScriptCoinsPerByte(new RPtr(self), new RPtr(refScriptCoinsPerByte))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateRefScriptCoinsPerByte(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateRefScriptCoinsPerByte(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolParamUpdateNew( Promise promise) {
        Native.I
            .csl_bridge_protocolParamUpdateNew()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_protocolVersionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionMajor(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionMajor(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionMinor(String self, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionMinor(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_protocolVersionNew(Double major, Double minor, Promise promise) {
        Native.I
            .csl_bridge_protocolVersionNew(major.longValue(), minor.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_publicKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .csl_bridge_publicKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyToBech32(String self, Promise promise) {
        Native.I
            .csl_bridge_publicKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_publicKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_publicKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyVerify(String self, String data, String signature, Promise promise) {
        Native.I
            .csl_bridge_publicKeyVerify(new RPtr(self), Base64.decode(data, Base64.DEFAULT), new RPtr(signature))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_publicKeyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_publicKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_publicKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_publicKeysNew( Promise promise) {
        Native.I
            .csl_bridge_publicKeysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeysSize(String self, Promise promise) {
        Native.I
            .csl_bridge_publicKeysSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeysGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_publicKeysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_publicKeysAdd(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_publicKeysAdd(new RPtr(self), new RPtr(key))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_redeemerToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_redeemerFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_redeemerFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_redeemerFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTag(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerTag(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerIndex(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerIndex(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerData(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerExUnits(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerNew(String tag, String index, String data, String exUnits, Promise promise) {
        Native.I
            .csl_bridge_redeemerNew(new RPtr(tag), new RPtr(index), new RPtr(data), new RPtr(exUnits))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_redeemerTagToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewSpend( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewSpend()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewMint( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewMint()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewCert( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewCert()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewReward( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewReward()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewVote( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewVote()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagNewVotingProposal( Promise promise) {
        Native.I
            .csl_bridge_redeemerTagNewVotingProposal()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemerTagKind(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemerTagKind(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_redeemersToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemersToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_redeemersFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemersToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_redeemersFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemersToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_redeemersFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersNew( Promise promise) {
        Native.I
            .csl_bridge_redeemersNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersLen(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemersLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_redeemersGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_redeemersAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_redeemersTotalExUnits(String self, Promise promise) {
        Native.I
            .csl_bridge_redeemersTotalExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_relayToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_relayToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_relayFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_relayToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_relayFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_relayToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_relayFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayNewSingleHostAddr(String singleHostAddr, Promise promise) {
        Native.I
            .csl_bridge_relayNewSingleHostAddr(new RPtr(singleHostAddr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayNewSingleHostName(String singleHostName, Promise promise) {
        Native.I
            .csl_bridge_relayNewSingleHostName(new RPtr(singleHostName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayNewMultiHostName(String multiHostName, Promise promise) {
        Native.I
            .csl_bridge_relayNewMultiHostName(new RPtr(multiHostName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayKind(String self, Promise promise) {
        Native.I
            .csl_bridge_relayKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayAsSingleHostAddr(String self, Promise promise) {
        Native.I
            .csl_bridge_relayAsSingleHostAddr(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayAsSingleHostName(String self, Promise promise) {
        Native.I
            .csl_bridge_relayAsSingleHostName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relayAsMultiHostName(String self, Promise promise) {
        Native.I
            .csl_bridge_relayAsMultiHostName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_relaysToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_relaysToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_relaysFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_relaysToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_relaysFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_relaysToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_relaysFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysNew( Promise promise) {
        Native.I
            .csl_bridge_relaysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysLen(String self, Promise promise) {
        Native.I
            .csl_bridge_relaysLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_relaysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_relaysAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_relaysAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_rewardAddressNew(Double network, String payment, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressNew(network.longValue(), new RPtr(payment))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressPaymentCred(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressToAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressFromAddress(String addr, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressNetworkId(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_rewardAddressesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesNew( Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_rewardAddressesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_rewardAddressesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptAllToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAllToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptAllFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAllToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptAllFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAllToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptAllFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAllNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAllNew(String nativeScripts, Promise promise) {
        Native.I
            .csl_bridge_scriptAllNew(new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptAnyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptAnyNew(String nativeScripts, Promise promise) {
        Native.I
            .csl_bridge_scriptAnyNew(new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptDataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptDataHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptDataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptDataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptDataHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptDataHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_scriptDataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_scriptHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_scriptHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_scriptHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptHashesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesNew( Promise promise) {
        Native.I
            .csl_bridge_scriptHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_scriptHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptNOfKToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKN(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKN(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptNOfKNew(Double n, String nativeScripts, Promise promise) {
        Native.I
            .csl_bridge_scriptNOfKNew(n.longValue(), new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptPubkeyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyAddrKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyAddrKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptPubkeyNew(String addrKeyhash, Promise promise) {
        Native.I
            .csl_bridge_scriptPubkeyNew(new RPtr(addrKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_scriptRefToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_scriptRefFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_scriptRefFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_scriptRefFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefNewNativeScript(String nativeScript, Promise promise) {
        Native.I
            .csl_bridge_scriptRefNewNativeScript(new RPtr(nativeScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefNewPlutusScript(String plutusScript, Promise promise) {
        Native.I
            .csl_bridge_scriptRefNewPlutusScript(new RPtr(plutusScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefIsNativeScript(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefIsNativeScript(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefIsPlutusScript(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefIsPlutusScript(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefNativeScript(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefNativeScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefPlutusScript(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefPlutusScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_scriptRefToUnwrappedBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_scriptRefToUnwrappedBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_singleHostAddrToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrPort(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrPort(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrIpv4(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrIpv4(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrIpv6(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrIpv6(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNew( Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithPort(Double port, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithPort(port.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithIpv4(String ipv4, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithIpv4(new RPtr(ipv4))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithPortIpv4(Double port, String ipv4, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithPortIpv4(port.longValue(), new RPtr(ipv4))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithIpv6(String ipv6, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithIpv6(new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithPortIpv6(Double port, String ipv6, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithPortIpv6(port.longValue(), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithIpv4Ipv6(String ipv4, String ipv6, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithIpv4Ipv6(new RPtr(ipv4), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostAddrNewWithPortIpv4Ipv6(Double port, String ipv4, String ipv6, Promise promise) {
        Native.I
            .csl_bridge_singleHostAddrNewWithPortIpv4Ipv6(port.longValue(), new RPtr(ipv4), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_singleHostNameToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNamePort(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostNamePort(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameDnsName(String self, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameDnsName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameNew(String dnsName, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameNew(new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_singleHostNameNewWithPort(Double port, String dnsName, Promise promise) {
        Native.I
            .csl_bridge_singleHostNameNewWithPort(port.longValue(), new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationPoolKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationDrep(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationDrep(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationNew(String stakeCredential, String poolKeyhash, String drep, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash), new RPtr(drep))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeAndVoteDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeAndVoteDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stakeDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationPoolKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationNew(String stakeCredential, String poolKeyhash, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stakeDeregistrationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationNew(String stakeCredential, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationNew(new RPtr(stakeCredential))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationNewWithExplicitRefund(String stakeCredential, String coin, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationNewWithExplicitRefund(new RPtr(stakeCredential), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeDeregistrationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeDeregistrationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stakeRegistrationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationNew(String stakeCredential, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationNew(new RPtr(stakeCredential))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationNewWithExplicitDeposit(String stakeCredential, String coin, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationNewWithExplicitDeposit(new RPtr(stakeCredential), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationPoolKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationNew(String stakeCredential, String poolKeyhash, String coin, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeRegistrationAndDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeRegistrationAndDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationPoolKeyhash(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationDrep(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationDrep(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationNew(String stakeCredential, String poolKeyhash, String drep, String coin, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash), new RPtr(drep), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stakeVoteRegistrationAndDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_stakeVoteRegistrationAndDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_stringsNew( Promise promise) {
        Native.I
            .csl_bridge_stringsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stringsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_stringsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stringsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_stringsGet(new RPtr(self), index.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_stringsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_stringsAdd(new RPtr(self), elem)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_timelockExpiryToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpirySlot(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockExpirySlot(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpirySlotBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockExpirySlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryNew(Double slot, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryNew(slot.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockExpiryNewTimelockexpiry(String slot, Promise promise) {
        Native.I
            .csl_bridge_timelockExpiryNewTimelockexpiry(new RPtr(slot))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_timelockStartToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockStartToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_timelockStartFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockStartToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_timelockStartFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockStartToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_timelockStartFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartSlot(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockStartSlot(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartSlotBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_timelockStartSlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartNew(Double slot, Promise promise) {
        Native.I
            .csl_bridge_timelockStartNew(slot.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_timelockStartNewTimelockstart(String slot, Promise promise) {
        Native.I
            .csl_bridge_timelockStartNewTimelockstart(new RPtr(slot))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBody(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSet(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionIsValid(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionIsValid(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionAuxiliaryData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionAuxiliaryData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionSetIsValid(String self, Boolean valid, Promise promise) {
        Native.I
            .csl_bridge_transactionSetIsValid(new RPtr(self), valid)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionNew(String body, String witnessSet, Promise promise) {
        Native.I
            .csl_bridge_transactionNew(new RPtr(body), new RPtr(witnessSet))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionNewWithAuxiliaryData(String body, String witnessSet, String auxiliaryData, Promise promise) {
        Native.I
            .csl_bridge_transactionNewWithAuxiliaryData(new RPtr(body), new RPtr(witnessSet), new RPtr(auxiliaryData))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_transactionBatchLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBatchLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBatchGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionBatchGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionBatchListLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBatchListLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBatchListGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionBatchListGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionBodiesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesNew( Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodiesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionBodiesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionBodyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyOutputs(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyOutputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyFee(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyFee(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyTtl(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyTtl(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyTtlBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyTtlBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetTtl(String self, String ttl, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetTtl(new RPtr(self), new RPtr(ttl))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyRemoveTtl(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyRemoveTtl(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetCerts(String self, String certs, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetCerts(new RPtr(self), new RPtr(certs))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyCerts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyCerts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetWithdrawals(String self, String withdrawals, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetWithdrawals(new RPtr(self), new RPtr(withdrawals))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyWithdrawals(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyWithdrawals(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetUpdate(String self, String update, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetUpdate(new RPtr(self), new RPtr(update))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyUpdate(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyUpdate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetAuxiliaryDataHash(String self, String auxiliaryDataHash, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetAuxiliaryDataHash(new RPtr(self), new RPtr(auxiliaryDataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyAuxiliaryDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyAuxiliaryDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetValidityStartInterval(String self, Double validityStartInterval, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetValidityStartInterval(new RPtr(self), validityStartInterval.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetValidityStartIntervalBignum(String self, String validityStartInterval, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetValidityStartIntervalBignum(new RPtr(self), new RPtr(validityStartInterval))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyValidityStartIntervalBignum(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyValidityStartIntervalBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyValidityStartInterval(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyValidityStartInterval(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetMint(String self, String mint, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetMint(new RPtr(self), new RPtr(mint))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyMint(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyMint(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetReferenceInputs(String self, String referenceInputs, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetReferenceInputs(new RPtr(self), new RPtr(referenceInputs))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyReferenceInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyReferenceInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetScriptDataHash(String self, String scriptDataHash, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetScriptDataHash(new RPtr(self), new RPtr(scriptDataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyScriptDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyScriptDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetCollateral(String self, String collateral, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetCollateral(new RPtr(self), new RPtr(collateral))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyCollateral(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyCollateral(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetRequiredSigners(String self, String requiredSigners, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetRequiredSigners(new RPtr(self), new RPtr(requiredSigners))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyRequiredSigners(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyRequiredSigners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetNetworkId(String self, String networkId, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetNetworkId(new RPtr(self), new RPtr(networkId))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyNetworkId(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyNetworkId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetCollateralReturn(String self, String collateralReturn, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetCollateralReturn(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyCollateralReturn(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyCollateralReturn(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetTotalCollateral(String self, String totalCollateral, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetTotalCollateral(new RPtr(self), new RPtr(totalCollateral))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyTotalCollateral(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyTotalCollateral(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetVotingProcedures(String self, String votingProcedures, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetVotingProcedures(new RPtr(self), new RPtr(votingProcedures))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyVotingProcedures(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyVotingProcedures(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetVotingProposals(String self, String votingProposals, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetVotingProposals(new RPtr(self), new RPtr(votingProposals))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyVotingProposals(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyVotingProposals(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetDonation(String self, String donation, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetDonation(new RPtr(self), new RPtr(donation))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyDonation(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyDonation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodySetCurrentTreasuryValue(String self, String currentTreasuryValue, Promise promise) {
        Native.I
            .csl_bridge_transactionBodySetCurrentTreasuryValue(new RPtr(self), new RPtr(currentTreasuryValue))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyCurrentTreasuryValue(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyCurrentTreasuryValue(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyNew(String inputs, String outputs, String fee, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyNew(new RPtr(inputs), new RPtr(outputs), new RPtr(fee))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBodyNewWithTtl(String inputs, String outputs, String fee, Double ttl, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyNewWithTtl(new RPtr(inputs), new RPtr(outputs), new RPtr(fee), ttl.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionBodyNewTxBody(String inputs, String outputs, String fee, Promise promise) {
        Native.I
            .csl_bridge_transactionBodyNewTxBody(new RPtr(inputs), new RPtr(outputs), new RPtr(fee))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionBuilderAddInputsFrom(String self, String inputs, Double strategy, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddInputsFrom(new RPtr(self), new RPtr(inputs), strategy.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetInputs(String self, String inputs, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetInputs(new RPtr(self), new RPtr(inputs))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCollateral(String self, String collateral, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCollateral(new RPtr(self), new RPtr(collateral))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCollateralReturn(String self, String collateralReturn, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCollateralReturn(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveCollateralReturn(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveCollateralReturn(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCollateralReturnAndTotal(String self, String collateralReturn, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCollateralReturnAndTotal(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetTotalCollateral(String self, String totalCollateral, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetTotalCollateral(new RPtr(self), new RPtr(totalCollateral))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveTotalCollateral(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveTotalCollateral(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetTotalCollateralAndReturn(String self, String totalCollateral, String returnAddress, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetTotalCollateralAndReturn(new RPtr(self), new RPtr(totalCollateral), new RPtr(returnAddress))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddReferenceInput(String self, String referenceInput, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddReferenceInput(new RPtr(self), new RPtr(referenceInput))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddScriptReferenceInput(String self, String referenceInput, Double scriptSize, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddScriptReferenceInput(new RPtr(self), new RPtr(referenceInput), scriptSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddKeyInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddKeyInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddNativeScriptInput(String self, String script, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddNativeScriptInput(new RPtr(self), new RPtr(script), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddPlutusScriptInput(String self, String witness, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddPlutusScriptInput(new RPtr(self), new RPtr(witness), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddBootstrapInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddBootstrapInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddRegularInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddRegularInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddInputsFromAndChange(String self, String inputs, Double strategy, String changeConfig, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddInputsFromAndChange(new RPtr(self), new RPtr(inputs), strategy.intValue(), new RPtr(changeConfig))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddInputsFromAndChangeWithCollateralReturn(String self, String inputs, Double strategy, String changeConfig, String collateralPercentage, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddInputsFromAndChangeWithCollateralReturn(new RPtr(self), new RPtr(inputs), strategy.intValue(), new RPtr(changeConfig), new RPtr(collateralPercentage))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetNativeInputScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetNativeInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetPlutusInputScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetPlutusInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderFeeForInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderFeeForInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddOutput(String self, String output, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddOutput(new RPtr(self), new RPtr(output))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderFeeForOutput(String self, String output, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderFeeForOutput(new RPtr(self), new RPtr(output))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetFee(String self, String fee, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetFee(new RPtr(self), new RPtr(fee))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetTtl(String self, Double ttl, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetTtl(new RPtr(self), ttl.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetTtlBignum(String self, String ttl, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetTtlBignum(new RPtr(self), new RPtr(ttl))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveTtl(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveTtl(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetValidityStartInterval(String self, Double validityStartInterval, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetValidityStartInterval(new RPtr(self), validityStartInterval.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetValidityStartIntervalBignum(String self, String validityStartInterval, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetValidityStartIntervalBignum(new RPtr(self), new RPtr(validityStartInterval))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveValidityStartInterval(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveValidityStartInterval(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCerts(String self, String certs, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCerts(new RPtr(self), new RPtr(certs))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveCerts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveCerts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCertsBuilder(String self, String certs, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCertsBuilder(new RPtr(self), new RPtr(certs))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetWithdrawals(String self, String withdrawals, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetWithdrawals(new RPtr(self), new RPtr(withdrawals))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetWithdrawalsBuilder(String self, String withdrawals, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetWithdrawalsBuilder(new RPtr(self), new RPtr(withdrawals))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetVotingBuilder(String self, String votingBuilder, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetVotingBuilder(new RPtr(self), new RPtr(votingBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetVotingProposalBuilder(String self, String votingProposalBuilder, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetVotingProposalBuilder(new RPtr(self), new RPtr(votingProposalBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveWithdrawals(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveWithdrawals(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetAuxiliaryData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetAuxiliaryData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetAuxiliaryData(String self, String auxiliaryData, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetAuxiliaryData(new RPtr(self), new RPtr(auxiliaryData))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveAuxiliaryData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveAuxiliaryData(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetMetadata(String self, String metadata, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetMetadata(new RPtr(self), new RPtr(metadata))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddMetadatum(String self, String key, String val, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddMetadatum(new RPtr(self), new RPtr(key), new RPtr(val))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddJsonMetadatum(String self, String key, String val, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddJsonMetadatum(new RPtr(self), new RPtr(key), val)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddJsonMetadatumWithSchema(String self, String key, String val, Double schema, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddJsonMetadatumWithSchema(new RPtr(self), new RPtr(key), val, schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetMintBuilder(String self, String mintBuilder, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetMintBuilder(new RPtr(self), new RPtr(mintBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveMintBuilder(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveMintBuilder(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetMintBuilder(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetMintBuilder(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetMint(String self, String mint, String mintScripts, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetMint(new RPtr(self), new RPtr(mint), new RPtr(mintScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetMint(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetMint(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetMintScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetMintScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetMintAsset(String self, String policyScript, String mintAssets, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetMintAsset(new RPtr(self), new RPtr(policyScript), new RPtr(mintAssets))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddMintAsset(String self, String policyScript, String assetName, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddMintAsset(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddMintAssetAndOutput(String self, String policyScript, String assetName, String amount, String outputBuilder, String outputCoin, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddMintAssetAndOutput(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount), new RPtr(outputBuilder), new RPtr(outputCoin))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddMintAssetAndOutputMinRequiredCoin(String self, String policyScript, String assetName, String amount, String outputBuilder, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddMintAssetAndOutputMinRequiredCoin(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount), new RPtr(outputBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddExtraWitnessDatum(String self, String datum, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddExtraWitnessDatum(new RPtr(self), new RPtr(datum))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetExtraWitnessDatums(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetExtraWitnessDatums(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetDonation(String self, String donation, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetDonation(new RPtr(self), new RPtr(donation))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetDonation(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetDonation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetCurrentTreasuryValue(String self, String currentTreasuryValue, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetCurrentTreasuryValue(new RPtr(self), new RPtr(currentTreasuryValue))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetCurrentTreasuryValue(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetCurrentTreasuryValue(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderNew(String cfg, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderNew(new RPtr(cfg))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetReferenceInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetReferenceInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetExplicitInput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetExplicitInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetImplicitInput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetImplicitInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetTotalInput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetTotalInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetTotalOutput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetTotalOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetExplicitOutput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetExplicitOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderGetFeeIfSet(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderGetFeeIfSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddChangeIfNeeded(String self, String address, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddChangeIfNeeded(new RPtr(self), new RPtr(address))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddChangeIfNeededWithDatum(String self, String address, String plutusData, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddChangeIfNeededWithDatum(new RPtr(self), new RPtr(address), new RPtr(plutusData))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderCalcScriptDataHash(String self, String costModels, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderCalcScriptDataHash(new RPtr(self), new RPtr(costModels))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderSetScriptDataHash(String self, String hash, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderSetScriptDataHash(new RPtr(self), new RPtr(hash))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderRemoveScriptDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderRemoveScriptDataHash(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderAddRequiredSigner(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderAddRequiredSigner(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderFullSize(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderFullSize(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderOutputSizes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderOutputSizes(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderBuildTx(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderBuildTx(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderBuildTxUnsafe(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderBuildTxUnsafe(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderMinFee(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderMinFee(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderFeeAlgo(String self, String feeAlgo, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderFeeAlgo(new RPtr(self), new RPtr(feeAlgo))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderCoinsPerUtxoByte(String self, String coinsPerUtxoByte, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderCoinsPerUtxoByte(new RPtr(self), new RPtr(coinsPerUtxoByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderExUnitPrices(String self, String exUnitPrices, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderExUnitPrices(new RPtr(self), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderPoolDeposit(String self, String poolDeposit, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderPoolDeposit(new RPtr(self), new RPtr(poolDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderKeyDeposit(String self, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderKeyDeposit(new RPtr(self), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderMaxValueSize(String self, Double maxValueSize, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderMaxValueSize(new RPtr(self), maxValueSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderMaxTxSize(String self, Double maxTxSize, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderMaxTxSize(new RPtr(self), maxTxSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderRefScriptCoinsPerByte(String self, String refScriptCoinsPerByte, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderRefScriptCoinsPerByte(new RPtr(self), new RPtr(refScriptCoinsPerByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderPreferPureChange(String self, Boolean preferPureChange, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderPreferPureChange(new RPtr(self), preferPureChange)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderDeduplicateExplicitRefInputsWithRegularInputs(String self, Boolean deduplicateExplicitRefInputsWithRegularInputs, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderDeduplicateExplicitRefInputsWithRegularInputs(new RPtr(self), deduplicateExplicitRefInputsWithRegularInputs)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionBuilderConfigBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionBuilderConfigBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_transactionHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_transactionHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_transactionHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionInputToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionInputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionInputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionInputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputTransactionId(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputTransactionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputIndex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputIndex(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputNew(String transactionId, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionInputNew(new RPtr(transactionId), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionInputsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsNew( Promise promise) {
        Native.I
            .csl_bridge_transactionInputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionInputsToOption(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionInputsToOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionMetadatumToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumNewMap(String map, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumNewMap(new RPtr(map))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumNewList(String list, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumNewList(new RPtr(list))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumNewInt(String intValue, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumNewInt(new RPtr(intValue))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumNewBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumNewBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumNewText(String text, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumNewText(text)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumKind(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumAsMap(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumAsMap(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumAsList(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumAsList(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumAsInt(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumAsInt(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumAsBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumAsText(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumAsText(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsNew( Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionMetadatumLabelsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionMetadatumLabelsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionOutputToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAddress(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAmount(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmount(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputPlutusData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputScriptRef(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputScriptRef(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputSetScriptRef(String self, String scriptRef, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputSetScriptRef(new RPtr(self), new RPtr(scriptRef))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputSetPlutusData(String self, String data, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputSetPlutusData(new RPtr(self), new RPtr(data))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputSetDataHash(String self, String dataHash, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputSetDataHash(new RPtr(self), new RPtr(dataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputHasPlutusData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputHasPlutusData(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputHasDataHash(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputHasDataHash(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputHasScriptRef(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputHasScriptRef(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputNew(String address, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputNew(new RPtr(address), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputSerializationFormat(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputSerializationFormat(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionOutputAmountBuilderWithValue(String self, String amount, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmountBuilderWithValue(new RPtr(self), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAmountBuilderWithCoin(String self, String coin, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmountBuilderWithCoin(new RPtr(self), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAmountBuilderWithCoinAndAsset(String self, String coin, String multiasset, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmountBuilderWithCoinAndAsset(new RPtr(self), new RPtr(coin), new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(String self, String multiasset, String dataCost, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(new RPtr(self), new RPtr(multiasset), new RPtr(dataCost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputAmountBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputAmountBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderWithAddress(String self, String address, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderWithAddress(new RPtr(self), new RPtr(address))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderWithDataHash(String self, String dataHash, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderWithDataHash(new RPtr(self), new RPtr(dataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderWithPlutusData(String self, String data, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderWithPlutusData(new RPtr(self), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderWithScriptRef(String self, String scriptRef, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderWithScriptRef(new RPtr(self), new RPtr(scriptRef))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputBuilderNext(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputBuilderNext(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionOutputsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsNew( Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionOutputsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionOutputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputNew(String input, String output, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputNew(new RPtr(input), new RPtr(output))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputInput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputOutput(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsNew( Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionUnspentOutputsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionUnspentOutputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionWitnessSetToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetVkeys(String self, String vkeys, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetVkeys(new RPtr(self), new RPtr(vkeys))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetVkeys(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetVkeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetNativeScripts(String self, String nativeScripts, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetNativeScripts(new RPtr(self), new RPtr(nativeScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetBootstraps(String self, String bootstraps, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetBootstraps(new RPtr(self), new RPtr(bootstraps))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetBootstraps(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetBootstraps(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetPlutusScripts(String self, String plutusScripts, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetPlutusScripts(new RPtr(self), new RPtr(plutusScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetPlutusScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetPlutusData(String self, String plutusData, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetPlutusData(new RPtr(self), new RPtr(plutusData))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetPlutusData(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetSetRedeemers(String self, String redeemers, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetSetRedeemers(new RPtr(self), new RPtr(redeemers))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetRedeemers(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetRedeemers(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetNew( Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsNew( Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_transactionWitnessSetsAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_transactionWitnessSetsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsNew( Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionWithdrawals(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionWithdrawals(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionPolicyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionPolicyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionNew(String withdrawals, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionNew(new RPtr(withdrawals))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_treasuryWithdrawalsActionNewWithPolicyHash(String withdrawals, String policyHash, Promise promise) {
        Native.I
            .csl_bridge_treasuryWithdrawalsActionNewWithPolicyHash(new RPtr(withdrawals), new RPtr(policyHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_txBuilderConstantsPlutusDefaultCostModels( Promise promise) {
        Native.I
            .csl_bridge_txBuilderConstantsPlutusDefaultCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txBuilderConstantsPlutusAlonzoCostModels( Promise promise) {
        Native.I
            .csl_bridge_txBuilderConstantsPlutusAlonzoCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txBuilderConstantsPlutusVasilCostModels( Promise promise) {
        Native.I
            .csl_bridge_txBuilderConstantsPlutusVasilCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txBuilderConstantsPlutusConwayCostModels( Promise promise) {
        Native.I
            .csl_bridge_txBuilderConstantsPlutusConwayCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_txInputsBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddKeyInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddKeyInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddNativeScriptInput(String self, String script, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddNativeScriptInput(new RPtr(self), new RPtr(script), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddPlutusScriptInput(String self, String witness, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddPlutusScriptInput(new RPtr(self), new RPtr(witness), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddBootstrapInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddBootstrapInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddRegularInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddRegularInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderGetNativeInputScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderGetNativeInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderGetPlutusInputScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderGetPlutusInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderLen(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddRequiredSigner(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddRequiredSigner(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderAddRequiredSigners(String self, String keys, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderAddRequiredSigners(new RPtr(self), new RPtr(keys))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderTotalValue(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderTotalValue(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_txInputsBuilderInputsOption(String self, Promise promise) {
        Native.I
            .csl_bridge_txInputsBuilderInputsOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_uRLToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_uRLToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_uRLFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_uRLToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_uRLFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_uRLToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_uRLFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLNew(String url, Promise promise) {
        Native.I
            .csl_bridge_uRLNew(url)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_uRLUrl(String self, Promise promise) {
        Native.I
            .csl_bridge_uRLUrl(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_unitIntervalToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalNumerator(String self, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalNumerator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalDenominator(String self, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalDenominator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_unitIntervalNew(String numerator, String denominator, Promise promise) {
        Native.I
            .csl_bridge_unitIntervalNew(new RPtr(numerator), new RPtr(denominator))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_updateToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_updateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_updateFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_updateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_updateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_updateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_updateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateProposedProtocolParameterUpdates(String self, Promise promise) {
        Native.I
            .csl_bridge_updateProposedProtocolParameterUpdates(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateEpoch(String self, Promise promise) {
        Native.I
            .csl_bridge_updateEpoch(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateNew(String proposedProtocolParameterUpdates, Double epoch, Promise promise) {
        Native.I
            .csl_bridge_updateNew(new RPtr(proposedProtocolParameterUpdates), epoch.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_updateCommitteeActionToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionGovActionId(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionGovActionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionCommittee(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionCommittee(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionMembersToRemove(String self, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionMembersToRemove(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionNew(String committee, String membersToRemove, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionNew(new RPtr(committee), new RPtr(membersToRemove))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_updateCommitteeActionNewWithActionId(String govActionId, String committee, String membersToRemove, Promise promise) {
        Native.I
            .csl_bridge_updateCommitteeActionNewWithActionId(new RPtr(govActionId), new RPtr(committee), new RPtr(membersToRemove))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vRFCertToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vRFCertFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_vRFCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_vRFCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertOutput(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFCertOutput(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertProof(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFCertProof(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFCertNew(String output, String proof, Promise promise) {
        Native.I
            .csl_bridge_vRFCertNew(Base64.decode(output, Base64.DEFAULT), Base64.decode(proof, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vRFKeyHashFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFKeyHashToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFKeyHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFKeyHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFKeyHashToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFKeyHashFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_vRFKeyHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vRFVKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFVKeyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFVKeyToBech32(String self, String prefix, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFVKeyFromBech32(String bechStr, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFVKeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vRFVKeyFromHex(String hex, Promise promise) {
        Native.I
            .csl_bridge_vRFVKeyFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_valueToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_valueToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_valueFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_valueToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_valueFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_valueToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_valueFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueNew(String coin, Promise promise) {
        Native.I
            .csl_bridge_valueNew(new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueNewFromAssets(String multiasset, Promise promise) {
        Native.I
            .csl_bridge_valueNewFromAssets(new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueNewWithAssets(String coin, String multiasset, Promise promise) {
        Native.I
            .csl_bridge_valueNewWithAssets(new RPtr(coin), new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueZero( Promise promise) {
        Native.I
            .csl_bridge_valueZero()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueIsZero(String self, Promise promise) {
        Native.I
            .csl_bridge_valueIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_valueCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueSetCoin(String self, String coin, Promise promise) {
        Native.I
            .csl_bridge_valueSetCoin(new RPtr(self), new RPtr(coin))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueMultiasset(String self, Promise promise) {
        Native.I
            .csl_bridge_valueMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueSetMultiasset(String self, String multiasset, Promise promise) {
        Native.I
            .csl_bridge_valueSetMultiasset(new RPtr(self), new RPtr(multiasset))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueCheckedAdd(String self, String rhs, Promise promise) {
        Native.I
            .csl_bridge_valueCheckedAdd(new RPtr(self), new RPtr(rhs))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueCheckedSub(String self, String rhsValue, Promise promise) {
        Native.I
            .csl_bridge_valueCheckedSub(new RPtr(self), new RPtr(rhsValue))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueClampedSub(String self, String rhsValue, Promise promise) {
        Native.I
            .csl_bridge_valueClampedSub(new RPtr(self), new RPtr(rhsValue))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_valueCompare(String self, String rhsValue, Promise promise) {
        Native.I
            .csl_bridge_valueCompare(new RPtr(self), new RPtr(rhsValue))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_versionedBlockToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockNew(String block, Double eraCode, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockNew(new RPtr(block), eraCode.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockBlock(String self, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockBlock(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_versionedBlockEra(String self, Promise promise) {
        Native.I
            .csl_bridge_versionedBlockEra(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vkeyToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vkeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_vkeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_vkeyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyNew(String pk, Promise promise) {
        Native.I
            .csl_bridge_vkeyNew(new RPtr(pk))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeyPublicKey(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeyPublicKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vkeysNew( Promise promise) {
        Native.I
            .csl_bridge_vkeysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeysLen(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeysLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeysGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_vkeysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeysAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_vkeysAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vkeywitnessToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessNew(String vkey, String signature, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessNew(new RPtr(vkey), new RPtr(signature))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessVkey(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessSignature(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessSignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_vkeywitnessesToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesNew( Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesLen(String self, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_vkeywitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .csl_bridge_vkeywitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_voteDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationDrep(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationDrep(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationNew(String stakeCredential, String drep, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationNew(new RPtr(stakeCredential), new RPtr(drep))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_voteDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationDrep(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationDrep(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationCoin(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationNew(String stakeCredential, String drep, String coin, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationNew(new RPtr(stakeCredential), new RPtr(drep), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voteRegistrationAndDelegationHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_voteRegistrationAndDelegationHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_voterToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_voterFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_voterFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_voterFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterNewConstitutionalCommitteeHotKey(String cred, Promise promise) {
        Native.I
            .csl_bridge_voterNewConstitutionalCommitteeHotKey(new RPtr(cred))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterNewDrep(String cred, Promise promise) {
        Native.I
            .csl_bridge_voterNewDrep(new RPtr(cred))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterNewStakingPool(String keyHash, Promise promise) {
        Native.I
            .csl_bridge_voterNewStakingPool(new RPtr(keyHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterKind(String self, Promise promise) {
        Native.I
            .csl_bridge_voterKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToConstitutionalCommitteeHotKey(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToConstitutionalCommitteeHotKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToDrepCred(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToDrepCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToStakingPoolKeyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToStakingPoolKeyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterHasScriptCredentials(String self, Promise promise) {
        Native.I
            .csl_bridge_voterHasScriptCredentials(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_voterToKeyHash(String self, Promise promise) {
        Native.I
            .csl_bridge_voterToKeyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votersToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_votersToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votersFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_votersFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votersNew( Promise promise) {
        Native.I
            .csl_bridge_votersNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votersAdd(String self, String voter, Promise promise) {
        Native.I
            .csl_bridge_votersAdd(new RPtr(self), new RPtr(voter))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votersGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_votersGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votersLen(String self, Promise promise) {
        Native.I
            .csl_bridge_votersLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_votingBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderAdd(String self, String voter, String govActionId, String votingProcedure, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderAdd(new RPtr(self), new RPtr(voter), new RPtr(govActionId), new RPtr(votingProcedure))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderAddWithPlutusWitness(String self, String voter, String govActionId, String votingProcedure, String witness, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderAddWithPlutusWitness(new RPtr(self), new RPtr(voter), new RPtr(govActionId), new RPtr(votingProcedure), new RPtr(witness))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderAddWithNativeScript(String self, String voter, String govActionId, String votingProcedure, String nativeScriptSource, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderAddWithNativeScript(new RPtr(self), new RPtr(voter), new RPtr(govActionId), new RPtr(votingProcedure), new RPtr(nativeScriptSource))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderGetNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderGetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_votingBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingProcedureToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureNew(Double vote, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureNew(vote.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureNewWithAnchor(Double vote, String anchor, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureNewWithAnchor(vote.intValue(), new RPtr(anchor))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureVoteKind(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureVoteKind(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProcedureAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProcedureAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingProceduresToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresNew( Promise promise) {
        Native.I
            .csl_bridge_votingProceduresNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresInsert(String self, String voter, String governanceActionId, String votingProcedure, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresInsert(new RPtr(self), new RPtr(voter), new RPtr(governanceActionId), new RPtr(votingProcedure))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresGet(String self, String voter, String governanceActionId, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresGet(new RPtr(self), new RPtr(voter), new RPtr(governanceActionId))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresGetVoters(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresGetVoters(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProceduresGetGovernanceActionIdsByVoter(String self, String voter, Promise promise) {
        Native.I
            .csl_bridge_votingProceduresGetGovernanceActionIdsByVoter(new RPtr(self), new RPtr(voter))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingProposalToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_votingProposalFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_votingProposalFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_votingProposalFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalGovernanceAction(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalGovernanceAction(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalAnchor(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalAnchor(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalRewardAccount(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalRewardAccount(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalDeposit(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalNew(String governanceAction, String anchor, String rewardAccount, String deposit, Promise promise) {
        Native.I
            .csl_bridge_votingProposalNew(new RPtr(governanceAction), new RPtr(anchor), new RPtr(rewardAccount), new RPtr(deposit))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingProposalBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderAdd(String self, String proposal, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderAdd(new RPtr(self), new RPtr(proposal))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderAddWithPlutusWitness(String self, String proposal, String witness, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderAddWithPlutusWitness(new RPtr(self), new RPtr(proposal), new RPtr(witness))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_votingProposalsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsNew( Promise promise) {
        Native.I
            .csl_bridge_votingProposalsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsGet(String self, Double index, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_votingProposalsAdd(String self, String proposal, Promise promise) {
        Native.I
            .csl_bridge_votingProposalsAdd(new RPtr(self), new RPtr(proposal))
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_withdrawalsToBytes(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsFromBytes(String bytes, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsToHex(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsFromHex(String hexStr, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsToJson(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsFromJson(String json, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsNew( Promise promise) {
        Native.I
            .csl_bridge_withdrawalsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsLen(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsLen(new RPtr(self))
            .map(Utils::boxedLongToDouble)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsGet(String self, String key, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsKeys(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderNew( Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderAdd(String self, String address, String coin, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderAdd(new RPtr(self), new RPtr(address), new RPtr(coin))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderAddWithPlutusWitness(String self, String address, String coin, String witness, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderAddWithPlutusWitness(new RPtr(self), new RPtr(address), new RPtr(coin), new RPtr(witness))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderAddWithNativeScript(String self, String address, String coin, String nativeScriptSource, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderAddWithNativeScript(new RPtr(self), new RPtr(address), new RPtr(coin), new RPtr(nativeScriptSource))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderGetNativeScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderGetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderGetTotalWithdrawals(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderGetTotalWithdrawals(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_withdrawalsBuilderBuild(String self, Promise promise) {
        Native.I
            .csl_bridge_withdrawalsBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_calculateExUnitsCeilCost(String exUnits, String exUnitPrices, Promise promise) {
        Native.I
            .csl_bridge_calculateExUnitsCeilCost(new RPtr(exUnits), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_createSendAll(String address, String utxos, String config, Promise promise) {
        Native.I
            .csl_bridge_createSendAll(new RPtr(address), new RPtr(utxos), new RPtr(config))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_decodeArbitraryBytesFromMetadatum(String metadata, Promise promise) {
        Native.I
            .csl_bridge_decodeArbitraryBytesFromMetadatum(new RPtr(metadata))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_decodeMetadatumToJsonStr(String metadatum, Double schema, Promise promise) {
        Native.I
            .csl_bridge_decodeMetadatumToJsonStr(new RPtr(metadatum), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_decodePlutusDatumToJsonStr(String datum, Double schema, Promise promise) {
        Native.I
            .csl_bridge_decodePlutusDatumToJsonStr(new RPtr(datum), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_decryptWithPassword(String password, String data, Promise promise) {
        Native.I
            .csl_bridge_decryptWithPassword(password, data)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_encodeArbitraryBytesAsMetadatum(String bytes, Promise promise) {
        Native.I
            .csl_bridge_encodeArbitraryBytesAsMetadatum(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_encodeJsonStrToMetadatum(String json, Double schema, Promise promise) {
        Native.I
            .csl_bridge_encodeJsonStrToMetadatum(json, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_encodeJsonStrToNativeScript(String json, String selfXpub, Double schema, Promise promise) {
        Native.I
            .csl_bridge_encodeJsonStrToNativeScript(json, selfXpub, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_encodeJsonStrToPlutusDatum(String json, Double schema, Promise promise) {
        Native.I
            .csl_bridge_encodeJsonStrToPlutusDatum(json, schema.intValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_encryptWithPassword(String password, String salt, String nonce, String data, Promise promise) {
        Native.I
            .csl_bridge_encryptWithPassword(password, salt, nonce, data)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_getDeposit(String txbody, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_getDeposit(new RPtr(txbody), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_getImplicitInput(String txbody, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
            .csl_bridge_getImplicitInput(new RPtr(txbody), new RPtr(poolDeposit), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hashAuxiliaryData(String auxiliaryData, Promise promise) {
        Native.I
            .csl_bridge_hashAuxiliaryData(new RPtr(auxiliaryData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hashPlutusData(String plutusData, Promise promise) {
        Native.I
            .csl_bridge_hashPlutusData(new RPtr(plutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hashScriptData(String redeemers, String costModels, Promise promise) {
        Native.I
            .csl_bridge_hashScriptData(new RPtr(redeemers), new RPtr(costModels))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_hashScriptDataWithDatums(String redeemers, String costModels, String datums, Promise promise) {
        Native.I
            .csl_bridge_hashScriptDataWithDatums(new RPtr(redeemers), new RPtr(costModels), new RPtr(datums))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void csl_bridge_hashTransaction(String txBody, Promise promise) {
        Native.I
            .csl_bridge_hashTransaction(new RPtr(txBody))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_makeDaedalusBootstrapWitness(String txBodyHash, String addr, String key, Promise promise) {
        Native.I
            .csl_bridge_makeDaedalusBootstrapWitness(new RPtr(txBodyHash), new RPtr(addr), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_makeIcarusBootstrapWitness(String txBodyHash, String addr, String key, Promise promise) {
        Native.I
            .csl_bridge_makeIcarusBootstrapWitness(new RPtr(txBodyHash), new RPtr(addr), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_makeVkeyWitness(String txBodyHash, String sk, Promise promise) {
        Native.I
            .csl_bridge_makeVkeyWitness(new RPtr(txBodyHash), new RPtr(sk))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_minAdaForOutput(String output, String dataCost, Promise promise) {
        Native.I
            .csl_bridge_minAdaForOutput(new RPtr(output), new RPtr(dataCost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_minFee(String tx, String linearFee, Promise promise) {
        Native.I
            .csl_bridge_minFee(new RPtr(tx), new RPtr(linearFee))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_minRefScriptFee(Double totalRefScriptsSize, String refScriptCoinsPerByte, Promise promise) {
        Native.I
            .csl_bridge_minRefScriptFee(totalRefScriptsSize.longValue(), new RPtr(refScriptCoinsPerByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void csl_bridge_minScriptFee(String tx, String exUnitPrices, Promise promise) {
        Native.I
            .csl_bridge_minScriptFee(new RPtr(tx), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

}
