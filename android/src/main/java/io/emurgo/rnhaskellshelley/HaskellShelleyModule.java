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
    public final void certificateToBytes(String self, Promise promise) {
        Native.I
            .certificateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void certificateFromBytes(String bytes, Promise promise) {
        Native.I
            .certificateFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateToHex(String self, Promise promise) {
        Native.I
            .certificateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void certificateFromHex(String hexStr, Promise promise) {
        Native.I
            .certificateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateToJson(String self, Promise promise) {
        Native.I
            .certificateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void certificateFromJson(String json, Promise promise) {
        Native.I
            .certificateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewStakeRegistration(String stakeRegistration, Promise promise) {
        Native.I
            .certificateNewStakeRegistration(new RPtr(stakeRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewStakeDeregistration(String stakeDeregistration, Promise promise) {
        Native.I
            .certificateNewStakeDeregistration(new RPtr(stakeDeregistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewStakeDelegation(String stakeDelegation, Promise promise) {
        Native.I
            .certificateNewStakeDelegation(new RPtr(stakeDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewPoolRegistration(String poolRegistration, Promise promise) {
        Native.I
            .certificateNewPoolRegistration(new RPtr(poolRegistration))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewPoolRetirement(String poolRetirement, Promise promise) {
        Native.I
            .certificateNewPoolRetirement(new RPtr(poolRetirement))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewGenesisKeyDelegation(String genesisKeyDelegation, Promise promise) {
        Native.I
            .certificateNewGenesisKeyDelegation(new RPtr(genesisKeyDelegation))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateNewMoveInstantaneousRewardsCert(String moveInstantaneousRewardsCert, Promise promise) {
        Native.I
            .certificateNewMoveInstantaneousRewardsCert(new RPtr(moveInstantaneousRewardsCert))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateKind(String self, Promise promise) {
        Native.I
            .certificateKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsStakeRegistration(String self, Promise promise) {
        Native.I
            .certificateAsStakeRegistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsStakeDeregistration(String self, Promise promise) {
        Native.I
            .certificateAsStakeDeregistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsStakeDelegation(String self, Promise promise) {
        Native.I
            .certificateAsStakeDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsPoolRegistration(String self, Promise promise) {
        Native.I
            .certificateAsPoolRegistration(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsPoolRetirement(String self, Promise promise) {
        Native.I
            .certificateAsPoolRetirement(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsGenesisKeyDelegation(String self, Promise promise) {
        Native.I
            .certificateAsGenesisKeyDelegation(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificateAsMoveInstantaneousRewardsCert(String self, Promise promise) {
        Native.I
            .certificateAsMoveInstantaneousRewardsCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionWitnessSetToBytes(String self, Promise promise) {
        Native.I
            .transactionWitnessSetToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionWitnessSetFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetToHex(String self, Promise promise) {
        Native.I
            .transactionWitnessSetToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionWitnessSetFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetToJson(String self, Promise promise) {
        Native.I
            .transactionWitnessSetToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetFromJson(String json, Promise promise) {
        Native.I
            .transactionWitnessSetFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetVkeys(String self, String vkeys, Promise promise) {
        Native.I
            .transactionWitnessSetSetVkeys(new RPtr(self), new RPtr(vkeys))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetVkeys(String self, Promise promise) {
        Native.I
            .transactionWitnessSetVkeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetNativeScripts(String self, String nativeScripts, Promise promise) {
        Native.I
            .transactionWitnessSetSetNativeScripts(new RPtr(self), new RPtr(nativeScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetNativeScripts(String self, Promise promise) {
        Native.I
            .transactionWitnessSetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetBootstraps(String self, String bootstraps, Promise promise) {
        Native.I
            .transactionWitnessSetSetBootstraps(new RPtr(self), new RPtr(bootstraps))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetBootstraps(String self, Promise promise) {
        Native.I
            .transactionWitnessSetBootstraps(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetPlutusScripts(String self, String plutusScripts, Promise promise) {
        Native.I
            .transactionWitnessSetSetPlutusScripts(new RPtr(self), new RPtr(plutusScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetPlutusScripts(String self, Promise promise) {
        Native.I
            .transactionWitnessSetPlutusScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetPlutusData(String self, String plutusData, Promise promise) {
        Native.I
            .transactionWitnessSetSetPlutusData(new RPtr(self), new RPtr(plutusData))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetPlutusData(String self, Promise promise) {
        Native.I
            .transactionWitnessSetPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetRedeemers(String self, String redeemers, Promise promise) {
        Native.I
            .transactionWitnessSetSetRedeemers(new RPtr(self), new RPtr(redeemers))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetRedeemers(String self, Promise promise) {
        Native.I
            .transactionWitnessSetRedeemers(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetNew( Promise promise) {
        Native.I
            .transactionWitnessSetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void addressFromBytes(String data, Promise promise) {
        Native.I
            .addressFromBytes(Base64.encodeToString(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void addressToJson(String self, Promise promise) {
        Native.I
            .addressToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void addressFromJson(String json, Promise promise) {
        Native.I
            .addressFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void addressToHex(String self, Promise promise) {
        Native.I
            .addressToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void addressFromHex(String hexStr, Promise promise) {
        Native.I
            .addressFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void addressToBytes(String self, Promise promise) {
        Native.I
            .addressToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void addressToBech32(String self, Promise promise) {
        Native.I
            .addressToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void addressToBech32WithPrefix(String self, String prefix, Promise promise) {
        Native.I
            .addressToBech32WithPrefix(new RPtr(self), prefix)
            .pour(promise);
    }


    @ReactMethod
    public final void addressFromBech32(String bechStr, Promise promise) {
        Native.I
            .addressFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void addressNetworkId(String self, Promise promise) {
        Native.I
            .addressNetworkId(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }


    @ReactMethod
    public final void blockToBytes(String self, Promise promise) {
        Native.I
            .blockToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void blockFromBytes(String bytes, Promise promise) {
        Native.I
            .blockFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockToHex(String self, Promise promise) {
        Native.I
            .blockToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void blockFromHex(String hexStr, Promise promise) {
        Native.I
            .blockFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockToJson(String self, Promise promise) {
        Native.I
            .blockToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void blockFromJson(String json, Promise promise) {
        Native.I
            .blockFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockHeader(String self, Promise promise) {
        Native.I
            .blockHeader(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockTransactionBodies(String self, Promise promise) {
        Native.I
            .blockTransactionBodies(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockTransactionWitnessSets(String self, Promise promise) {
        Native.I
            .blockTransactionWitnessSets(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockAuxiliaryDataSet(String self, Promise promise) {
        Native.I
            .blockAuxiliaryDataSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockInvalidTransactions(String self, Promise promise) {
        Native.I
            .blockInvalidTransactions(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void blockNew(String header, String transactionBodies, String transactionWitnessSets, String auxiliaryDataSet, String invalidTransactions, Promise promise) {
        Native.I
            .blockNew(new RPtr(header), new RPtr(transactionBodies), new RPtr(transactionWitnessSets), new RPtr(auxiliaryDataSet), invalidTransactions)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void vkeysNew( Promise promise) {
        Native.I
            .vkeysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeysLen(String self, Promise promise) {
        Native.I
            .vkeysLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeysGet(String self, Double index, Promise promise) {
        Native.I
            .vkeysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeysAdd(String self, String elem, Promise promise) {
        Native.I
            .vkeysAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void ipv4ToBytes(String self, Promise promise) {
        Native.I
            .ipv4ToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4FromBytes(String bytes, Promise promise) {
        Native.I
            .ipv4FromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4ToHex(String self, Promise promise) {
        Native.I
            .ipv4ToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4FromHex(String hexStr, Promise promise) {
        Native.I
            .ipv4FromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4ToJson(String self, Promise promise) {
        Native.I
            .ipv4ToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4FromJson(String json, Promise promise) {
        Native.I
            .ipv4FromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4New(String data, Promise promise) {
        Native.I
            .ipv4New(Base64.encodeToString(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv4Ip(String self, Promise promise) {
        Native.I
            .ipv4Ip(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void certificatesToBytes(String self, Promise promise) {
        Native.I
            .certificatesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesFromBytes(String bytes, Promise promise) {
        Native.I
            .certificatesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesToHex(String self, Promise promise) {
        Native.I
            .certificatesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesFromHex(String hexStr, Promise promise) {
        Native.I
            .certificatesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesToJson(String self, Promise promise) {
        Native.I
            .certificatesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesFromJson(String json, Promise promise) {
        Native.I
            .certificatesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesNew( Promise promise) {
        Native.I
            .certificatesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesLen(String self, Promise promise) {
        Native.I
            .certificatesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesGet(String self, Double index, Promise promise) {
        Native.I
            .certificatesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void certificatesAdd(String self, String elem, Promise promise) {
        Native.I
            .certificatesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void protocolVersionToBytes(String self, Promise promise) {
        Native.I
            .protocolVersionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionFromBytes(String bytes, Promise promise) {
        Native.I
            .protocolVersionFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionToHex(String self, Promise promise) {
        Native.I
            .protocolVersionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionFromHex(String hexStr, Promise promise) {
        Native.I
            .protocolVersionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionToJson(String self, Promise promise) {
        Native.I
            .protocolVersionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionFromJson(String json, Promise promise) {
        Native.I
            .protocolVersionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionMajor(String self, Promise promise) {
        Native.I
            .protocolVersionMajor(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionMinor(String self, Promise promise) {
        Native.I
            .protocolVersionMinor(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolVersionNew(Double major, Double minor, Promise promise) {
        Native.I
            .protocolVersionNew(major.longValue(), minor.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void metadataListToBytes(String self, Promise promise) {
        Native.I
            .metadataListToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListFromBytes(String bytes, Promise promise) {
        Native.I
            .metadataListFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListToHex(String self, Promise promise) {
        Native.I
            .metadataListToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListFromHex(String hexStr, Promise promise) {
        Native.I
            .metadataListFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListNew( Promise promise) {
        Native.I
            .metadataListNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListLen(String self, Promise promise) {
        Native.I
            .metadataListLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListGet(String self, Double index, Promise promise) {
        Native.I
            .metadataListGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataListAdd(String self, String elem, Promise promise) {
        Native.I
            .metadataListAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void transactionMetadatumLabelsToBytes(String self, Promise promise) {
        Native.I
            .transactionMetadatumLabelsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionMetadatumLabelsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsToHex(String self, Promise promise) {
        Native.I
            .transactionMetadatumLabelsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionMetadatumLabelsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsNew( Promise promise) {
        Native.I
            .transactionMetadatumLabelsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsLen(String self, Promise promise) {
        Native.I
            .transactionMetadatumLabelsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsGet(String self, Double index, Promise promise) {
        Native.I
            .transactionMetadatumLabelsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumLabelsAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionMetadatumLabelsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void transactionBodyToBytes(String self, Promise promise) {
        Native.I
            .transactionBodyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionBodyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyToHex(String self, Promise promise) {
        Native.I
            .transactionBodyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionBodyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyToJson(String self, Promise promise) {
        Native.I
            .transactionBodyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFromJson(String json, Promise promise) {
        Native.I
            .transactionBodyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyInputs(String self, Promise promise) {
        Native.I
            .transactionBodyInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyOutputs(String self, Promise promise) {
        Native.I
            .transactionBodyOutputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFee(String self, Promise promise) {
        Native.I
            .transactionBodyFee(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyTtl(String self, Promise promise) {
        Native.I
            .transactionBodyTtl(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyTtlBignum(String self, Promise promise) {
        Native.I
            .transactionBodyTtlBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetTtl(String self, String ttl, Promise promise) {
        Native.I
            .transactionBodySetTtl(new RPtr(self), new RPtr(ttl))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyRemoveTtl(String self, Promise promise) {
        Native.I
            .transactionBodyRemoveTtl(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetCerts(String self, String certs, Promise promise) {
        Native.I
            .transactionBodySetCerts(new RPtr(self), new RPtr(certs))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyCerts(String self, Promise promise) {
        Native.I
            .transactionBodyCerts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetWithdrawals(String self, String withdrawals, Promise promise) {
        Native.I
            .transactionBodySetWithdrawals(new RPtr(self), new RPtr(withdrawals))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyWithdrawals(String self, Promise promise) {
        Native.I
            .transactionBodyWithdrawals(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetUpdate(String self, String update, Promise promise) {
        Native.I
            .transactionBodySetUpdate(new RPtr(self), new RPtr(update))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyUpdate(String self, Promise promise) {
        Native.I
            .transactionBodyUpdate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetAuxiliaryDataHash(String self, String auxiliaryDataHash, Promise promise) {
        Native.I
            .transactionBodySetAuxiliaryDataHash(new RPtr(self), new RPtr(auxiliaryDataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyAuxiliaryDataHash(String self, Promise promise) {
        Native.I
            .transactionBodyAuxiliaryDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetValidityStartInterval(String self, Double validityStartInterval, Promise promise) {
        Native.I
            .transactionBodySetValidityStartInterval(new RPtr(self), validityStartInterval.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetValidityStartIntervalBignum(String self, String validityStartInterval, Promise promise) {
        Native.I
            .transactionBodySetValidityStartIntervalBignum(new RPtr(self), new RPtr(validityStartInterval))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyValidityStartIntervalBignum(String self, Promise promise) {
        Native.I
            .transactionBodyValidityStartIntervalBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyValidityStartInterval(String self, Promise promise) {
        Native.I
            .transactionBodyValidityStartInterval(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetMint(String self, String mint, Promise promise) {
        Native.I
            .transactionBodySetMint(new RPtr(self), new RPtr(mint))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyMint(String self, Promise promise) {
        Native.I
            .transactionBodyMint(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyMultiassets(String self, Promise promise) {
        Native.I
            .transactionBodyMultiassets(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetReferenceInputs(String self, String referenceInputs, Promise promise) {
        Native.I
            .transactionBodySetReferenceInputs(new RPtr(self), new RPtr(referenceInputs))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyReferenceInputs(String self, Promise promise) {
        Native.I
            .transactionBodyReferenceInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetScriptDataHash(String self, String scriptDataHash, Promise promise) {
        Native.I
            .transactionBodySetScriptDataHash(new RPtr(self), new RPtr(scriptDataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyScriptDataHash(String self, Promise promise) {
        Native.I
            .transactionBodyScriptDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetCollateral(String self, String collateral, Promise promise) {
        Native.I
            .transactionBodySetCollateral(new RPtr(self), new RPtr(collateral))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyCollateral(String self, Promise promise) {
        Native.I
            .transactionBodyCollateral(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetRequiredSigners(String self, String requiredSigners, Promise promise) {
        Native.I
            .transactionBodySetRequiredSigners(new RPtr(self), new RPtr(requiredSigners))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyRequiredSigners(String self, Promise promise) {
        Native.I
            .transactionBodyRequiredSigners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetNetworkId(String self, String networkId, Promise promise) {
        Native.I
            .transactionBodySetNetworkId(new RPtr(self), new RPtr(networkId))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyNetworkId(String self, Promise promise) {
        Native.I
            .transactionBodyNetworkId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetCollateralReturn(String self, String collateralReturn, Promise promise) {
        Native.I
            .transactionBodySetCollateralReturn(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyCollateralReturn(String self, Promise promise) {
        Native.I
            .transactionBodyCollateralReturn(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodySetTotalCollateral(String self, String totalCollateral, Promise promise) {
        Native.I
            .transactionBodySetTotalCollateral(new RPtr(self), new RPtr(totalCollateral))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyTotalCollateral(String self, Promise promise) {
        Native.I
            .transactionBodyTotalCollateral(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyNew(String inputs, String outputs, String fee, Promise promise) {
        Native.I
            .transactionBodyNew(new RPtr(inputs), new RPtr(outputs), new RPtr(fee))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyNewWithTtl(String inputs, String outputs, String fee, Double ttl, Promise promise) {
        Native.I
            .transactionBodyNewWithTtl(new RPtr(inputs), new RPtr(outputs), new RPtr(fee), ttl.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionBodyNewTxBody(String inputs, String outputs, String fee, Promise promise) {
        Native.I
            .transactionBodyNewTxBody(new RPtr(inputs), new RPtr(outputs), new RPtr(fee))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void genesisHashFromBytes(String bytes, Promise promise) {
        Native.I
            .genesisHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashToBytes(String self, Promise promise) {
        Native.I
            .genesisHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .genesisHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .genesisHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashToHex(String self, Promise promise) {
        Native.I
            .genesisHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashFromHex(String hex, Promise promise) {
        Native.I
            .genesisHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionInputToBytes(String self, Promise promise) {
        Native.I
            .transactionInputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionInputFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputToHex(String self, Promise promise) {
        Native.I
            .transactionInputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionInputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputToJson(String self, Promise promise) {
        Native.I
            .transactionInputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputFromJson(String json, Promise promise) {
        Native.I
            .transactionInputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputTransactionId(String self, Promise promise) {
        Native.I
            .transactionInputTransactionId(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputIndex(String self, Promise promise) {
        Native.I
            .transactionInputIndex(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputNew(String transactionId, Double index, Promise promise) {
        Native.I
            .transactionInputNew(new RPtr(transactionId), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusScriptToBytes(String self, Promise promise) {
        Native.I
            .plutusScriptToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptFromBytes(String bytes, Promise promise) {
        Native.I
            .plutusScriptFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptToHex(String self, Promise promise) {
        Native.I
            .plutusScriptToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptFromHex(String hexStr, Promise promise) {
        Native.I
            .plutusScriptFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptNew(String bytes, Promise promise) {
        Native.I
            .plutusScriptNew(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptNewV2(String bytes, Promise promise) {
        Native.I
            .plutusScriptNewV2(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptNewWithVersion(String bytes, String language, Promise promise) {
        Native.I
            .plutusScriptNewWithVersion(Base64.encodeToString(bytes), new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptBytes(String self, Promise promise) {
        Native.I
            .plutusScriptBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptFromBytesV2(String bytes, Promise promise) {
        Native.I
            .plutusScriptFromBytesV2(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptFromBytesWithVersion(String bytes, String language, Promise promise) {
        Native.I
            .plutusScriptFromBytesWithVersion(Base64.encodeToString(bytes), new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptFromHexWithVersion(String hexStr, String language, Promise promise) {
        Native.I
            .plutusScriptFromHexWithVersion(hexStr, new RPtr(language))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptHash(String self, Promise promise) {
        Native.I
            .plutusScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptLanguageVersion(String self, Promise promise) {
        Native.I
            .plutusScriptLanguageVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void poolMetadataToBytes(String self, Promise promise) {
        Native.I
            .poolMetadataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataFromBytes(String bytes, Promise promise) {
        Native.I
            .poolMetadataFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataToHex(String self, Promise promise) {
        Native.I
            .poolMetadataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataFromHex(String hexStr, Promise promise) {
        Native.I
            .poolMetadataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataToJson(String self, Promise promise) {
        Native.I
            .poolMetadataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataFromJson(String json, Promise promise) {
        Native.I
            .poolMetadataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataUrl(String self, Promise promise) {
        Native.I
            .poolMetadataUrl(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataPoolMetadataHash(String self, Promise promise) {
        Native.I
            .poolMetadataPoolMetadataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataNew(String url, String poolMetadataHash, Promise promise) {
        Native.I
            .poolMetadataNew(new RPtr(url), new RPtr(poolMetadataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionBuilderAddInputsFrom(String self, String inputs, Double strategy, Promise promise) {
        Native.I
            .transactionBuilderAddInputsFrom(new RPtr(self), new RPtr(inputs), strategy.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetInputs(String self, String inputs, Promise promise) {
        Native.I
            .transactionBuilderSetInputs(new RPtr(self), new RPtr(inputs))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetCollateral(String self, String collateral, Promise promise) {
        Native.I
            .transactionBuilderSetCollateral(new RPtr(self), new RPtr(collateral))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetCollateralReturn(String self, String collateralReturn, Promise promise) {
        Native.I
            .transactionBuilderSetCollateralReturn(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetCollateralReturnAndTotal(String self, String collateralReturn, Promise promise) {
        Native.I
            .transactionBuilderSetCollateralReturnAndTotal(new RPtr(self), new RPtr(collateralReturn))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetTotalCollateral(String self, String totalCollateral, Promise promise) {
        Native.I
            .transactionBuilderSetTotalCollateral(new RPtr(self), new RPtr(totalCollateral))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetTotalCollateralAndReturn(String self, String totalCollateral, String returnAddress, Promise promise) {
        Native.I
            .transactionBuilderSetTotalCollateralAndReturn(new RPtr(self), new RPtr(totalCollateral), new RPtr(returnAddress))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddReferenceInput(String self, String referenceInput, Promise promise) {
        Native.I
            .transactionBuilderAddReferenceInput(new RPtr(self), new RPtr(referenceInput))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddKeyInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddKeyInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddScriptInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddScriptInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddNativeScriptInput(String self, String script, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddNativeScriptInput(new RPtr(self), new RPtr(script), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddPlutusScriptInput(String self, String witness, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddPlutusScriptInput(new RPtr(self), new RPtr(witness), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddBootstrapInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddBootstrapInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderCountMissingInputScripts(String self, Promise promise) {
        Native.I
            .transactionBuilderCountMissingInputScripts(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddRequiredNativeInputScripts(String self, String scripts, Promise promise) {
        Native.I
            .transactionBuilderAddRequiredNativeInputScripts(new RPtr(self), new RPtr(scripts))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddRequiredPlutusInputScripts(String self, String scripts, Promise promise) {
        Native.I
            .transactionBuilderAddRequiredPlutusInputScripts(new RPtr(self), new RPtr(scripts))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetNativeInputScripts(String self, Promise promise) {
        Native.I
            .transactionBuilderGetNativeInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetPlutusInputScripts(String self, Promise promise) {
        Native.I
            .transactionBuilderGetPlutusInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderFeeForInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .transactionBuilderFeeForInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddOutput(String self, String output, Promise promise) {
        Native.I
            .transactionBuilderAddOutput(new RPtr(self), new RPtr(output))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderFeeForOutput(String self, String output, Promise promise) {
        Native.I
            .transactionBuilderFeeForOutput(new RPtr(self), new RPtr(output))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetFee(String self, String fee, Promise promise) {
        Native.I
            .transactionBuilderSetFee(new RPtr(self), new RPtr(fee))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetTtl(String self, Double ttl, Promise promise) {
        Native.I
            .transactionBuilderSetTtl(new RPtr(self), ttl.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetTtlBignum(String self, String ttl, Promise promise) {
        Native.I
            .transactionBuilderSetTtlBignum(new RPtr(self), new RPtr(ttl))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetValidityStartInterval(String self, Double validityStartInterval, Promise promise) {
        Native.I
            .transactionBuilderSetValidityStartInterval(new RPtr(self), validityStartInterval.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetValidityStartIntervalBignum(String self, String validityStartInterval, Promise promise) {
        Native.I
            .transactionBuilderSetValidityStartIntervalBignum(new RPtr(self), new RPtr(validityStartInterval))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetCerts(String self, String certs, Promise promise) {
        Native.I
            .transactionBuilderSetCerts(new RPtr(self), new RPtr(certs))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetWithdrawals(String self, String withdrawals, Promise promise) {
        Native.I
            .transactionBuilderSetWithdrawals(new RPtr(self), new RPtr(withdrawals))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetAuxiliaryData(String self, Promise promise) {
        Native.I
            .transactionBuilderGetAuxiliaryData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetAuxiliaryData(String self, String auxiliaryData, Promise promise) {
        Native.I
            .transactionBuilderSetAuxiliaryData(new RPtr(self), new RPtr(auxiliaryData))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetMetadata(String self, String metadata, Promise promise) {
        Native.I
            .transactionBuilderSetMetadata(new RPtr(self), new RPtr(metadata))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddMetadatum(String self, String key, String val, Promise promise) {
        Native.I
            .transactionBuilderAddMetadatum(new RPtr(self), new RPtr(key), new RPtr(val))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddJsonMetadatum(String self, String key, String val, Promise promise) {
        Native.I
            .transactionBuilderAddJsonMetadatum(new RPtr(self), new RPtr(key), val)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddJsonMetadatumWithSchema(String self, String key, String val, Double schema, Promise promise) {
        Native.I
            .transactionBuilderAddJsonMetadatumWithSchema(new RPtr(self), new RPtr(key), val, schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetMintBuilder(String self, String mintBuilder, Promise promise) {
        Native.I
            .transactionBuilderSetMintBuilder(new RPtr(self), new RPtr(mintBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetMintBuilder(String self, Promise promise) {
        Native.I
            .transactionBuilderGetMintBuilder(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetMint(String self, String mint, String mintScripts, Promise promise) {
        Native.I
            .transactionBuilderSetMint(new RPtr(self), new RPtr(mint), new RPtr(mintScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetMint(String self, Promise promise) {
        Native.I
            .transactionBuilderGetMint(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetMintScripts(String self, Promise promise) {
        Native.I
            .transactionBuilderGetMintScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetMintAsset(String self, String policyScript, String mintAssets, Promise promise) {
        Native.I
            .transactionBuilderSetMintAsset(new RPtr(self), new RPtr(policyScript), new RPtr(mintAssets))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddMintAsset(String self, String policyScript, String assetName, String amount, Promise promise) {
        Native.I
            .transactionBuilderAddMintAsset(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddMintAssetAndOutput(String self, String policyScript, String assetName, String amount, String outputBuilder, String outputCoin, Promise promise) {
        Native.I
            .transactionBuilderAddMintAssetAndOutput(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount), new RPtr(outputBuilder), new RPtr(outputCoin))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddMintAssetAndOutputMinRequiredCoin(String self, String policyScript, String assetName, String amount, String outputBuilder, Promise promise) {
        Native.I
            .transactionBuilderAddMintAssetAndOutputMinRequiredCoin(new RPtr(self), new RPtr(policyScript), new RPtr(assetName), new RPtr(amount), new RPtr(outputBuilder))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderNew(String cfg, Promise promise) {
        Native.I
            .transactionBuilderNew(new RPtr(cfg))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetReferenceInputs(String self, Promise promise) {
        Native.I
            .transactionBuilderGetReferenceInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetExplicitInput(String self, Promise promise) {
        Native.I
            .transactionBuilderGetExplicitInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetImplicitInput(String self, Promise promise) {
        Native.I
            .transactionBuilderGetImplicitInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetTotalInput(String self, Promise promise) {
        Native.I
            .transactionBuilderGetTotalInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetTotalOutput(String self, Promise promise) {
        Native.I
            .transactionBuilderGetTotalOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetExplicitOutput(String self, Promise promise) {
        Native.I
            .transactionBuilderGetExplicitOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetDeposit(String self, Promise promise) {
        Native.I
            .transactionBuilderGetDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetFeeIfSet(String self, Promise promise) {
        Native.I
            .transactionBuilderGetFeeIfSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddChangeIfNeeded(String self, String address, Promise promise) {
        Native.I
            .transactionBuilderAddChangeIfNeeded(new RPtr(self), new RPtr(address))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderCalcScriptDataHash(String self, String costModels, Promise promise) {
        Native.I
            .transactionBuilderCalcScriptDataHash(new RPtr(self), new RPtr(costModels))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetScriptDataHash(String self, String hash, Promise promise) {
        Native.I
            .transactionBuilderSetScriptDataHash(new RPtr(self), new RPtr(hash))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderRemoveScriptDataHash(String self, Promise promise) {
        Native.I
            .transactionBuilderRemoveScriptDataHash(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddRequiredSigner(String self, String key, Promise promise) {
        Native.I
            .transactionBuilderAddRequiredSigner(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderFullSize(String self, Promise promise) {
        Native.I
            .transactionBuilderFullSize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderOutputSizes(String self, Promise promise) {
        Native.I
            .transactionBuilderOutputSizes(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderBuild(String self, Promise promise) {
        Native.I
            .transactionBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderBuildTx(String self, Promise promise) {
        Native.I
            .transactionBuilderBuildTx(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderBuildTxUnsafe(String self, Promise promise) {
        Native.I
            .transactionBuilderBuildTxUnsafe(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderMinFee(String self, Promise promise) {
        Native.I
            .transactionBuilderMinFee(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionOutputsToBytes(String self, Promise promise) {
        Native.I
            .transactionOutputsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionOutputsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsToHex(String self, Promise promise) {
        Native.I
            .transactionOutputsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionOutputsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsToJson(String self, Promise promise) {
        Native.I
            .transactionOutputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsFromJson(String json, Promise promise) {
        Native.I
            .transactionOutputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsNew( Promise promise) {
        Native.I
            .transactionOutputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsLen(String self, Promise promise) {
        Native.I
            .transactionOutputsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsGet(String self, Double index, Promise promise) {
        Native.I
            .transactionOutputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionOutputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void inputsWithScriptWitnessNew( Promise promise) {
        Native.I
            .inputsWithScriptWitnessNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void inputsWithScriptWitnessAdd(String self, String input, Promise promise) {
        Native.I
            .inputsWithScriptWitnessAdd(new RPtr(self), new RPtr(input))
            .pour(promise);
    }

    @ReactMethod
    public final void inputsWithScriptWitnessGet(String self, Double index, Promise promise) {
        Native.I
            .inputsWithScriptWitnessGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void inputsWithScriptWitnessLen(String self, Promise promise) {
        Native.I
            .inputsWithScriptWitnessLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }


    @ReactMethod
    public final void poolRegistrationToBytes(String self, Promise promise) {
        Native.I
            .poolRegistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .poolRegistrationFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationToHex(String self, Promise promise) {
        Native.I
            .poolRegistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .poolRegistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationToJson(String self, Promise promise) {
        Native.I
            .poolRegistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationFromJson(String json, Promise promise) {
        Native.I
            .poolRegistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationPoolParams(String self, Promise promise) {
        Native.I
            .poolRegistrationPoolParams(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRegistrationNew(String poolParams, Promise promise) {
        Native.I
            .poolRegistrationNew(new RPtr(poolParams))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionUnspentOutputToBytes(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionUnspentOutputFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputToHex(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionUnspentOutputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputToJson(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputFromJson(String json, Promise promise) {
        Native.I
            .transactionUnspentOutputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputNew(String input, String output, Promise promise) {
        Native.I
            .transactionUnspentOutputNew(new RPtr(input), new RPtr(output))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputInput(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputOutput(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputOutput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void mintAssetsNew( Promise promise) {
        Native.I
            .mintAssetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAssetsNewFromEntry(String key, String value, Promise promise) {
        Native.I
            .mintAssetsNewFromEntry(new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAssetsLen(String self, Promise promise) {
        Native.I
            .mintAssetsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAssetsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .mintAssetsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAssetsGet(String self, String key, Promise promise) {
        Native.I
            .mintAssetsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAssetsKeys(String self, Promise promise) {
        Native.I
            .mintAssetsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void vkeywitnessToBytes(String self, Promise promise) {
        Native.I
            .vkeywitnessToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessFromBytes(String bytes, Promise promise) {
        Native.I
            .vkeywitnessFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessToHex(String self, Promise promise) {
        Native.I
            .vkeywitnessToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessFromHex(String hexStr, Promise promise) {
        Native.I
            .vkeywitnessFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessToJson(String self, Promise promise) {
        Native.I
            .vkeywitnessToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessFromJson(String json, Promise promise) {
        Native.I
            .vkeywitnessFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessNew(String vkey, String signature, Promise promise) {
        Native.I
            .vkeywitnessNew(new RPtr(vkey), new RPtr(signature))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessVkey(String self, Promise promise) {
        Native.I
            .vkeywitnessVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessSignature(String self, Promise promise) {
        Native.I
            .vkeywitnessSignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void redeemerToBytes(String self, Promise promise) {
        Native.I
            .redeemerToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerFromBytes(String bytes, Promise promise) {
        Native.I
            .redeemerFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerToHex(String self, Promise promise) {
        Native.I
            .redeemerToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerFromHex(String hexStr, Promise promise) {
        Native.I
            .redeemerFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerToJson(String self, Promise promise) {
        Native.I
            .redeemerToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerFromJson(String json, Promise promise) {
        Native.I
            .redeemerFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTag(String self, Promise promise) {
        Native.I
            .redeemerTag(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerIndex(String self, Promise promise) {
        Native.I
            .redeemerIndex(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerData(String self, Promise promise) {
        Native.I
            .redeemerData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerExUnits(String self, Promise promise) {
        Native.I
            .redeemerExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerNew(String tag, String index, String data, String exUnits, Promise promise) {
        Native.I
            .redeemerNew(new RPtr(tag), new RPtr(index), new RPtr(data), new RPtr(exUnits))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void singleHostNameToBytes(String self, Promise promise) {
        Native.I
            .singleHostNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameFromBytes(String bytes, Promise promise) {
        Native.I
            .singleHostNameFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameToHex(String self, Promise promise) {
        Native.I
            .singleHostNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameFromHex(String hexStr, Promise promise) {
        Native.I
            .singleHostNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameToJson(String self, Promise promise) {
        Native.I
            .singleHostNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameFromJson(String json, Promise promise) {
        Native.I
            .singleHostNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNamePort(String self, Promise promise) {
        Native.I
            .singleHostNamePort(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameDnsName(String self, Promise promise) {
        Native.I
            .singleHostNameDnsName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameNew(String dnsName, Promise promise) {
        Native.I
            .singleHostNameNew(new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostNameNewWithPort(Double port, String dnsName, Promise promise) {
        Native.I
            .singleHostNameNewWithPort(port.longValue(), new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void relaysToBytes(String self, Promise promise) {
        Native.I
            .relaysToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void relaysFromBytes(String bytes, Promise promise) {
        Native.I
            .relaysFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysToHex(String self, Promise promise) {
        Native.I
            .relaysToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void relaysFromHex(String hexStr, Promise promise) {
        Native.I
            .relaysFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysToJson(String self, Promise promise) {
        Native.I
            .relaysToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void relaysFromJson(String json, Promise promise) {
        Native.I
            .relaysFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysNew( Promise promise) {
        Native.I
            .relaysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysLen(String self, Promise promise) {
        Native.I
            .relaysLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysGet(String self, Double index, Promise promise) {
        Native.I
            .relaysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relaysAdd(String self, String elem, Promise promise) {
        Native.I
            .relaysAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void costmdlsToBytes(String self, Promise promise) {
        Native.I
            .costmdlsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsFromBytes(String bytes, Promise promise) {
        Native.I
            .costmdlsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsToHex(String self, Promise promise) {
        Native.I
            .costmdlsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsFromHex(String hexStr, Promise promise) {
        Native.I
            .costmdlsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsToJson(String self, Promise promise) {
        Native.I
            .costmdlsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsFromJson(String json, Promise promise) {
        Native.I
            .costmdlsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsNew( Promise promise) {
        Native.I
            .costmdlsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsLen(String self, Promise promise) {
        Native.I
            .costmdlsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .costmdlsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsGet(String self, String key, Promise promise) {
        Native.I
            .costmdlsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsKeys(String self, Promise promise) {
        Native.I
            .costmdlsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costmdlsRetainLanguageVersions(String self, String languages, Promise promise) {
        Native.I
            .costmdlsRetainLanguageVersions(new RPtr(self), new RPtr(languages))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void redeemerTagToBytes(String self, Promise promise) {
        Native.I
            .redeemerTagToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagFromBytes(String bytes, Promise promise) {
        Native.I
            .redeemerTagFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagToHex(String self, Promise promise) {
        Native.I
            .redeemerTagToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagFromHex(String hexStr, Promise promise) {
        Native.I
            .redeemerTagFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagToJson(String self, Promise promise) {
        Native.I
            .redeemerTagToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagFromJson(String json, Promise promise) {
        Native.I
            .redeemerTagFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagNewSpend( Promise promise) {
        Native.I
            .redeemerTagNewSpend()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagNewMint( Promise promise) {
        Native.I
            .redeemerTagNewMint()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagNewCert( Promise promise) {
        Native.I
            .redeemerTagNewCert()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagNewReward( Promise promise) {
        Native.I
            .redeemerTagNewReward()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemerTagKind(String self, Promise promise) {
        Native.I
            .redeemerTagKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }


    @ReactMethod
    public final void scriptDataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptDataHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptDataHashToBytes(String self, Promise promise) {
        Native.I
            .scriptDataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptDataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .scriptDataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptDataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .scriptDataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptDataHashToHex(String self, Promise promise) {
        Native.I
            .scriptDataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptDataHashFromHex(String hex, Promise promise) {
        Native.I
            .scriptDataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void costModelToBytes(String self, Promise promise) {
        Native.I
            .costModelToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void costModelFromBytes(String bytes, Promise promise) {
        Native.I
            .costModelFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelToHex(String self, Promise promise) {
        Native.I
            .costModelToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void costModelFromHex(String hexStr, Promise promise) {
        Native.I
            .costModelFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelToJson(String self, Promise promise) {
        Native.I
            .costModelToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void costModelFromJson(String json, Promise promise) {
        Native.I
            .costModelFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelNew( Promise promise) {
        Native.I
            .costModelNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelSet(String self, Double operation, String cost, Promise promise) {
        Native.I
            .costModelSet(new RPtr(self), operation.longValue(), new RPtr(cost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelGet(String self, Double operation, Promise promise) {
        Native.I
            .costModelGet(new RPtr(self), operation.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void costModelLen(String self, Promise promise) {
        Native.I
            .costModelLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }


    @ReactMethod
    public final void ed25519SignatureToBytes(String self, Promise promise) {
        Native.I
            .ed25519SignatureToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureToBech32(String self, Promise promise) {
        Native.I
            .ed25519SignatureToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureToHex(String self, Promise promise) {
        Native.I
            .ed25519SignatureToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureFromBech32(String bech32Str, Promise promise) {
        Native.I
            .ed25519SignatureFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureFromHex(String input, Promise promise) {
        Native.I
            .ed25519SignatureFromHex(input)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureFromBytes(String bytes, Promise promise) {
        Native.I
            .ed25519SignatureFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void bip32PrivateKeyDerive(String self, Double index, Promise promise) {
        Native.I
            .bip32PrivateKeyDerive(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyFrom_128Xprv(String bytes, Promise promise) {
        Native.I
            .bip32PrivateKeyFrom_128Xprv(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyTo_128Xprv(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyTo_128Xprv(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyGenerateEd25519Bip32( Promise promise) {
        Native.I
            .bip32PrivateKeyGenerateEd25519Bip32()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyToRawKey(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyToRawKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyToPublic(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyToPublic(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .bip32PrivateKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyAsBytes(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .bip32PrivateKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyToBech32(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyFromBip39Entropy(String entropy, String password, Promise promise) {
        Native.I
            .bip32PrivateKeyFromBip39Entropy(Base64.encodeToString(entropy), Base64.encodeToString(password))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyChaincode(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyToHex(String self, Promise promise) {
        Native.I
            .bip32PrivateKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PrivateKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .bip32PrivateKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void vkeywitnessesNew( Promise promise) {
        Native.I
            .vkeywitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesLen(String self, Promise promise) {
        Native.I
            .vkeywitnessesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .vkeywitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .vkeywitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void transactionMetadatumToBytes(String self, Promise promise) {
        Native.I
            .transactionMetadatumToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionMetadatumFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumToHex(String self, Promise promise) {
        Native.I
            .transactionMetadatumToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionMetadatumFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumNewMap(String map, Promise promise) {
        Native.I
            .transactionMetadatumNewMap(new RPtr(map))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumNewList(String list, Promise promise) {
        Native.I
            .transactionMetadatumNewList(new RPtr(list))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumNewInt(String int, Promise promise) {
        Native.I
            .transactionMetadatumNewInt(new RPtr(int))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumNewBytes(String bytes, Promise promise) {
        Native.I
            .transactionMetadatumNewBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumNewText(String text, Promise promise) {
        Native.I
            .transactionMetadatumNewText(text)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumKind(String self, Promise promise) {
        Native.I
            .transactionMetadatumKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumAsMap(String self, Promise promise) {
        Native.I
            .transactionMetadatumAsMap(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumAsList(String self, Promise promise) {
        Native.I
            .transactionMetadatumAsList(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumAsInt(String self, Promise promise) {
        Native.I
            .transactionMetadatumAsInt(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumAsBytes(String self, Promise promise) {
        Native.I
            .transactionMetadatumAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionMetadatumAsText(String self, Promise promise) {
        Native.I
            .transactionMetadatumAsText(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void rewardAddressesToBytes(String self, Promise promise) {
        Native.I
            .rewardAddressesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesFromBytes(String bytes, Promise promise) {
        Native.I
            .rewardAddressesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesToHex(String self, Promise promise) {
        Native.I
            .rewardAddressesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesFromHex(String hexStr, Promise promise) {
        Native.I
            .rewardAddressesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesToJson(String self, Promise promise) {
        Native.I
            .rewardAddressesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesFromJson(String json, Promise promise) {
        Native.I
            .rewardAddressesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesNew( Promise promise) {
        Native.I
            .rewardAddressesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesLen(String self, Promise promise) {
        Native.I
            .rewardAddressesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesGet(String self, Double index, Promise promise) {
        Native.I
            .rewardAddressesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesAdd(String self, String elem, Promise promise) {
        Native.I
            .rewardAddressesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void plutusListToBytes(String self, Promise promise) {
        Native.I
            .plutusListToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListFromBytes(String bytes, Promise promise) {
        Native.I
            .plutusListFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListToHex(String self, Promise promise) {
        Native.I
            .plutusListToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListFromHex(String hexStr, Promise promise) {
        Native.I
            .plutusListFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListNew( Promise promise) {
        Native.I
            .plutusListNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListLen(String self, Promise promise) {
        Native.I
            .plutusListLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListGet(String self, Double index, Promise promise) {
        Native.I
            .plutusListGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusListAdd(String self, String elem, Promise promise) {
        Native.I
            .plutusListAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void transactionHashFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionHashToBytes(String self, Promise promise) {
        Native.I
            .transactionHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .transactionHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .transactionHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionHashToHex(String self, Promise promise) {
        Native.I
            .transactionHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionHashFromHex(String hex, Promise promise) {
        Native.I
            .transactionHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void poolParamsToBytes(String self, Promise promise) {
        Native.I
            .poolParamsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsFromBytes(String bytes, Promise promise) {
        Native.I
            .poolParamsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsToHex(String self, Promise promise) {
        Native.I
            .poolParamsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsFromHex(String hexStr, Promise promise) {
        Native.I
            .poolParamsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsToJson(String self, Promise promise) {
        Native.I
            .poolParamsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsFromJson(String json, Promise promise) {
        Native.I
            .poolParamsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsOperator(String self, Promise promise) {
        Native.I
            .poolParamsOperator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsVrfKeyhash(String self, Promise promise) {
        Native.I
            .poolParamsVrfKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsPledge(String self, Promise promise) {
        Native.I
            .poolParamsPledge(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsCost(String self, Promise promise) {
        Native.I
            .poolParamsCost(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsMargin(String self, Promise promise) {
        Native.I
            .poolParamsMargin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsRewardAccount(String self, Promise promise) {
        Native.I
            .poolParamsRewardAccount(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsPoolOwners(String self, Promise promise) {
        Native.I
            .poolParamsPoolOwners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsRelays(String self, Promise promise) {
        Native.I
            .poolParamsRelays(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsPoolMetadata(String self, Promise promise) {
        Native.I
            .poolParamsPoolMetadata(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsNew(String operator, String vrfKeyhash, String pledge, String cost, String margin, String rewardAccount, String poolOwners, String relays, Promise promise) {
        Native.I
            .poolParamsNew(new RPtr(operator), new RPtr(vrfKeyhash), new RPtr(pledge), new RPtr(cost), new RPtr(margin), new RPtr(rewardAccount), new RPtr(poolOwners), new RPtr(relays))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolParamsNewWithPoolMetadata(String operator, String vrfKeyhash, String pledge, String cost, String margin, String rewardAccount, String poolOwners, String relays, String poolMetadata, Promise promise) {
        Native.I
            .poolParamsNewWithPoolMetadata(new RPtr(operator), new RPtr(vrfKeyhash), new RPtr(pledge), new RPtr(cost), new RPtr(margin), new RPtr(rewardAccount), new RPtr(poolOwners), new RPtr(relays), new RPtr(poolMetadata))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void auxiliaryDataSetNew( Promise promise) {
        Native.I
            .auxiliaryDataSetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetLen(String self, Promise promise) {
        Native.I
            .auxiliaryDataSetLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetInsert(String self, Double txIndex, String data, Promise promise) {
        Native.I
            .auxiliaryDataSetInsert(new RPtr(self), txIndex.longValue(), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetGet(String self, Double txIndex, Promise promise) {
        Native.I
            .auxiliaryDataSetGet(new RPtr(self), txIndex.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetIndices(String self, Promise promise) {
        Native.I
            .auxiliaryDataSetIndices(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void genesisKeyDelegationToBytes(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .genesisKeyDelegationFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationToHex(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .genesisKeyDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationToJson(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationFromJson(String json, Promise promise) {
        Native.I
            .genesisKeyDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationGenesishash(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationGenesishash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationGenesisDelegateHash(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationGenesisDelegateHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationVrfKeyhash(String self, Promise promise) {
        Native.I
            .genesisKeyDelegationVrfKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisKeyDelegationNew(String genesishash, String genesisDelegateHash, String vrfKeyhash, Promise promise) {
        Native.I
            .genesisKeyDelegationNew(new RPtr(genesishash), new RPtr(genesisDelegateHash), new RPtr(vrfKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void uRLToBytes(String self, Promise promise) {
        Native.I
            .uRLToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void uRLFromBytes(String bytes, Promise promise) {
        Native.I
            .uRLFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void uRLToHex(String self, Promise promise) {
        Native.I
            .uRLToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void uRLFromHex(String hexStr, Promise promise) {
        Native.I
            .uRLFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void uRLToJson(String self, Promise promise) {
        Native.I
            .uRLToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void uRLFromJson(String json, Promise promise) {
        Native.I
            .uRLFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void uRLNew(String url, Promise promise) {
        Native.I
            .uRLNew(url)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void uRLUrl(String self, Promise promise) {
        Native.I
            .uRLUrl(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void constrPlutusDataToBytes(String self, Promise promise) {
        Native.I
            .constrPlutusDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataFromBytes(String bytes, Promise promise) {
        Native.I
            .constrPlutusDataFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataToHex(String self, Promise promise) {
        Native.I
            .constrPlutusDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataFromHex(String hexStr, Promise promise) {
        Native.I
            .constrPlutusDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataAlternative(String self, Promise promise) {
        Native.I
            .constrPlutusDataAlternative(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataData(String self, Promise promise) {
        Native.I
            .constrPlutusDataData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void constrPlutusDataNew(String alternative, String data, Promise promise) {
        Native.I
            .constrPlutusDataNew(new RPtr(alternative), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void dNSRecordSRVToBytes(String self, Promise promise) {
        Native.I
            .dNSRecordSRVToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVFromBytes(String bytes, Promise promise) {
        Native.I
            .dNSRecordSRVFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVToHex(String self, Promise promise) {
        Native.I
            .dNSRecordSRVToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVFromHex(String hexStr, Promise promise) {
        Native.I
            .dNSRecordSRVFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVToJson(String self, Promise promise) {
        Native.I
            .dNSRecordSRVToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVFromJson(String json, Promise promise) {
        Native.I
            .dNSRecordSRVFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVNew(String dnsName, Promise promise) {
        Native.I
            .dNSRecordSRVNew(dnsName)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordSRVRecord(String self, Promise promise) {
        Native.I
            .dNSRecordSRVRecord(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void enterpriseAddressNew(Double network, String payment, Promise promise) {
        Native.I
            .enterpriseAddressNew(network.longValue(), new RPtr(payment))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void enterpriseAddressPaymentCred(String self, Promise promise) {
        Native.I
            .enterpriseAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void enterpriseAddressToAddress(String self, Promise promise) {
        Native.I
            .enterpriseAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void enterpriseAddressFromAddress(String addr, Promise promise) {
        Native.I
            .enterpriseAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void blockHashFromBytes(String bytes, Promise promise) {
        Native.I
            .blockHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockHashToBytes(String self, Promise promise) {
        Native.I
            .blockHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void blockHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .blockHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void blockHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .blockHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void blockHashToHex(String self, Promise promise) {
        Native.I
            .blockHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void blockHashFromHex(String hex, Promise promise) {
        Native.I
            .blockHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void vRFKeyHashFromBytes(String bytes, Promise promise) {
        Native.I
            .vRFKeyHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFKeyHashToBytes(String self, Promise promise) {
        Native.I
            .vRFKeyHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFKeyHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .vRFKeyHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFKeyHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .vRFKeyHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFKeyHashToHex(String self, Promise promise) {
        Native.I
            .vRFKeyHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFKeyHashFromHex(String hex, Promise promise) {
        Native.I
            .vRFKeyHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void stakeDelegationToBytes(String self, Promise promise) {
        Native.I
            .stakeDelegationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationFromBytes(String bytes, Promise promise) {
        Native.I
            .stakeDelegationFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationToHex(String self, Promise promise) {
        Native.I
            .stakeDelegationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationFromHex(String hexStr, Promise promise) {
        Native.I
            .stakeDelegationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationToJson(String self, Promise promise) {
        Native.I
            .stakeDelegationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationFromJson(String json, Promise promise) {
        Native.I
            .stakeDelegationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationStakeCredential(String self, Promise promise) {
        Native.I
            .stakeDelegationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationPoolKeyhash(String self, Promise promise) {
        Native.I
            .stakeDelegationPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationNew(String stakeCredential, String poolKeyhash, Promise promise) {
        Native.I
            .stakeDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void mintToBytes(String self, Promise promise) {
        Native.I
            .mintToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void mintFromBytes(String bytes, Promise promise) {
        Native.I
            .mintFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintToHex(String self, Promise promise) {
        Native.I
            .mintToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void mintFromHex(String hexStr, Promise promise) {
        Native.I
            .mintFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintToJson(String self, Promise promise) {
        Native.I
            .mintToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void mintFromJson(String json, Promise promise) {
        Native.I
            .mintFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintNew( Promise promise) {
        Native.I
            .mintNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintNewFromEntry(String key, String value, Promise promise) {
        Native.I
            .mintNewFromEntry(new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintLen(String self, Promise promise) {
        Native.I
            .mintLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void mintInsert(String self, String key, String value, Promise promise) {
        Native.I
            .mintInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintGet(String self, String key, Promise promise) {
        Native.I
            .mintGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintGetAll(String self, String key, Promise promise) {
        Native.I
            .mintGetAll(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintKeys(String self, Promise promise) {
        Native.I
            .mintKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAsPositiveMultiasset(String self, Promise promise) {
        Native.I
            .mintAsPositiveMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintAsNegativeMultiasset(String self, Promise promise) {
        Native.I
            .mintAsNegativeMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void stakeCredentialsToBytes(String self, Promise promise) {
        Native.I
            .stakeCredentialsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsFromBytes(String bytes, Promise promise) {
        Native.I
            .stakeCredentialsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsToHex(String self, Promise promise) {
        Native.I
            .stakeCredentialsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsFromHex(String hexStr, Promise promise) {
        Native.I
            .stakeCredentialsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsToJson(String self, Promise promise) {
        Native.I
            .stakeCredentialsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsFromJson(String json, Promise promise) {
        Native.I
            .stakeCredentialsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsNew( Promise promise) {
        Native.I
            .stakeCredentialsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsLen(String self, Promise promise) {
        Native.I
            .stakeCredentialsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsGet(String self, Double index, Promise promise) {
        Native.I
            .stakeCredentialsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialsAdd(String self, String elem, Promise promise) {
        Native.I
            .stakeCredentialsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void metadataMapToBytes(String self, Promise promise) {
        Native.I
            .metadataMapToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapFromBytes(String bytes, Promise promise) {
        Native.I
            .metadataMapFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapToHex(String self, Promise promise) {
        Native.I
            .metadataMapToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapFromHex(String hexStr, Promise promise) {
        Native.I
            .metadataMapFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapNew( Promise promise) {
        Native.I
            .metadataMapNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapLen(String self, Promise promise) {
        Native.I
            .metadataMapLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapInsert(String self, String key, String value, Promise promise) {
        Native.I
            .metadataMapInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapInsertStr(String self, String key, String value, Promise promise) {
        Native.I
            .metadataMapInsertStr(new RPtr(self), key, new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapInsertI32(String self, Double key, String value, Promise promise) {
        Native.I
            .metadataMapInsertI32(new RPtr(self), key.longValue(), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapGet(String self, String key, Promise promise) {
        Native.I
            .metadataMapGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapGetStr(String self, String key, Promise promise) {
        Native.I
            .metadataMapGetStr(new RPtr(self), key)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapGetI32(String self, Double key, Promise promise) {
        Native.I
            .metadataMapGetI32(new RPtr(self), key.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapHas(String self, String key, Promise promise) {
        Native.I
            .metadataMapHas(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void metadataMapKeys(String self, Promise promise) {
        Native.I
            .metadataMapKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void vRFCertToBytes(String self, Promise promise) {
        Native.I
            .vRFCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertFromBytes(String bytes, Promise promise) {
        Native.I
            .vRFCertFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertToHex(String self, Promise promise) {
        Native.I
            .vRFCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertFromHex(String hexStr, Promise promise) {
        Native.I
            .vRFCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertToJson(String self, Promise promise) {
        Native.I
            .vRFCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertFromJson(String json, Promise promise) {
        Native.I
            .vRFCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertOutput(String self, Promise promise) {
        Native.I
            .vRFCertOutput(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertProof(String self, Promise promise) {
        Native.I
            .vRFCertProof(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFCertNew(String output, String proof, Promise promise) {
        Native.I
            .vRFCertNew(Base64.encodeToString(output), Base64.encodeToString(proof))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void bigNumToBytes(String self, Promise promise) {
        Native.I
            .bigNumToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumFromBytes(String bytes, Promise promise) {
        Native.I
            .bigNumFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumToHex(String self, Promise promise) {
        Native.I
            .bigNumToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumFromHex(String hexStr, Promise promise) {
        Native.I
            .bigNumFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumToJson(String self, Promise promise) {
        Native.I
            .bigNumToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumFromJson(String json, Promise promise) {
        Native.I
            .bigNumFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumFromStr(String string, Promise promise) {
        Native.I
            .bigNumFromStr(string)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumToStr(String self, Promise promise) {
        Native.I
            .bigNumToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumZero( Promise promise) {
        Native.I
            .bigNumZero()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumOne( Promise promise) {
        Native.I
            .bigNumOne()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumIsZero(String self, Promise promise) {
        Native.I
            .bigNumIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumDivFloor(String self, String other, Promise promise) {
        Native.I
            .bigNumDivFloor(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumCheckedMul(String self, String other, Promise promise) {
        Native.I
            .bigNumCheckedMul(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumCheckedAdd(String self, String other, Promise promise) {
        Native.I
            .bigNumCheckedAdd(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumCheckedSub(String self, String other, Promise promise) {
        Native.I
            .bigNumCheckedSub(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumClampedSub(String self, String other, Promise promise) {
        Native.I
            .bigNumClampedSub(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumCompare(String self, String rhsValue, Promise promise) {
        Native.I
            .bigNumCompare(new RPtr(self), new RPtr(rhsValue))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumLessThan(String self, String rhsValue, Promise promise) {
        Native.I
            .bigNumLessThan(new RPtr(self), new RPtr(rhsValue))
            .pour(promise);
    }

    @ReactMethod
    public final void bigNumMax(String a, String b, Promise promise) {
        Native.I
            .bigNumMax(new RPtr(a), new RPtr(b))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void withdrawalsToBytes(String self, Promise promise) {
        Native.I
            .withdrawalsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsFromBytes(String bytes, Promise promise) {
        Native.I
            .withdrawalsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsToHex(String self, Promise promise) {
        Native.I
            .withdrawalsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsFromHex(String hexStr, Promise promise) {
        Native.I
            .withdrawalsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsToJson(String self, Promise promise) {
        Native.I
            .withdrawalsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsFromJson(String json, Promise promise) {
        Native.I
            .withdrawalsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsNew( Promise promise) {
        Native.I
            .withdrawalsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsLen(String self, Promise promise) {
        Native.I
            .withdrawalsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .withdrawalsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsGet(String self, String key, Promise promise) {
        Native.I
            .withdrawalsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsKeys(String self, Promise promise) {
        Native.I
            .withdrawalsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void moveInstantaneousRewardToBytes(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardFromBytes(String bytes, Promise promise) {
        Native.I
            .moveInstantaneousRewardFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardToHex(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardFromHex(String hexStr, Promise promise) {
        Native.I
            .moveInstantaneousRewardFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardToJson(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardFromJson(String json, Promise promise) {
        Native.I
            .moveInstantaneousRewardFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardNewToOtherPot(Double pot, String amount, Promise promise) {
        Native.I
            .moveInstantaneousRewardNewToOtherPot(pot.intValue(), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardNewToStakeCreds(Double pot, String amounts, Promise promise) {
        Native.I
            .moveInstantaneousRewardNewToStakeCreds(pot.intValue(), new RPtr(amounts))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardPot(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardPot(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardKind(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardAsToOtherPot(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardAsToOtherPot(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardAsToStakeCreds(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardAsToStakeCreds(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void ipv6ToBytes(String self, Promise promise) {
        Native.I
            .ipv6ToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6FromBytes(String bytes, Promise promise) {
        Native.I
            .ipv6FromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6ToHex(String self, Promise promise) {
        Native.I
            .ipv6ToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6FromHex(String hexStr, Promise promise) {
        Native.I
            .ipv6FromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6ToJson(String self, Promise promise) {
        Native.I
            .ipv6ToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6FromJson(String json, Promise promise) {
        Native.I
            .ipv6FromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6New(String data, Promise promise) {
        Native.I
            .ipv6New(Base64.encodeToString(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ipv6Ip(String self, Promise promise) {
        Native.I
            .ipv6Ip(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void vkeyToBytes(String self, Promise promise) {
        Native.I
            .vkeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyFromBytes(String bytes, Promise promise) {
        Native.I
            .vkeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyToHex(String self, Promise promise) {
        Native.I
            .vkeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyFromHex(String hexStr, Promise promise) {
        Native.I
            .vkeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyToJson(String self, Promise promise) {
        Native.I
            .vkeyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyFromJson(String json, Promise promise) {
        Native.I
            .vkeyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyNew(String pk, Promise promise) {
        Native.I
            .vkeyNew(new RPtr(pk))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vkeyPublicKey(String self, Promise promise) {
        Native.I
            .vkeyPublicKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionUnspentOutputsToJson(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputsFromJson(String json, Promise promise) {
        Native.I
            .transactionUnspentOutputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputsNew( Promise promise) {
        Native.I
            .transactionUnspentOutputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputsLen(String self, Promise promise) {
        Native.I
            .transactionUnspentOutputsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputsGet(String self, Double index, Promise promise) {
        Native.I
            .transactionUnspentOutputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionUnspentOutputsAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionUnspentOutputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void proposedProtocolParameterUpdatesToBytes(String self, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesFromBytes(String bytes, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesToHex(String self, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesFromHex(String hexStr, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesToJson(String self, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesFromJson(String json, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesNew( Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesLen(String self, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesInsert(String self, String key, String value, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesGet(String self, String key, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void proposedProtocolParameterUpdatesKeys(String self, Promise promise) {
        Native.I
            .proposedProtocolParameterUpdatesKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionOutputAmountBuilderWithValue(String self, String amount, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderWithValue(new RPtr(self), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmountBuilderWithCoin(String self, String coin, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderWithCoin(new RPtr(self), new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmountBuilderWithCoinAndAsset(String self, String coin, String multiasset, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderWithCoinAndAsset(new RPtr(self), new RPtr(coin), new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmountBuilderWithAssetAndMinRequiredCoin(String self, String multiasset, String coinsPerUtxoWord, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderWithAssetAndMinRequiredCoin(new RPtr(self), new RPtr(multiasset), new RPtr(coinsPerUtxoWord))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(String self, String multiasset, String dataCost, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost(new RPtr(self), new RPtr(multiasset), new RPtr(dataCost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmountBuilderBuild(String self, Promise promise) {
        Native.I
            .transactionOutputAmountBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void assetNamesToBytes(String self, Promise promise) {
        Native.I
            .assetNamesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesFromBytes(String bytes, Promise promise) {
        Native.I
            .assetNamesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesToHex(String self, Promise promise) {
        Native.I
            .assetNamesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesFromHex(String hexStr, Promise promise) {
        Native.I
            .assetNamesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesToJson(String self, Promise promise) {
        Native.I
            .assetNamesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesFromJson(String json, Promise promise) {
        Native.I
            .assetNamesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesNew( Promise promise) {
        Native.I
            .assetNamesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesLen(String self, Promise promise) {
        Native.I
            .assetNamesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesGet(String self, Double index, Promise promise) {
        Native.I
            .assetNamesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNamesAdd(String self, String elem, Promise promise) {
        Native.I
            .assetNamesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void generalTransactionMetadataToBytes(String self, Promise promise) {
        Native.I
            .generalTransactionMetadataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataFromBytes(String bytes, Promise promise) {
        Native.I
            .generalTransactionMetadataFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataToHex(String self, Promise promise) {
        Native.I
            .generalTransactionMetadataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataFromHex(String hexStr, Promise promise) {
        Native.I
            .generalTransactionMetadataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataToJson(String self, Promise promise) {
        Native.I
            .generalTransactionMetadataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataFromJson(String json, Promise promise) {
        Native.I
            .generalTransactionMetadataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataNew( Promise promise) {
        Native.I
            .generalTransactionMetadataNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataLen(String self, Promise promise) {
        Native.I
            .generalTransactionMetadataLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataInsert(String self, String key, String value, Promise promise) {
        Native.I
            .generalTransactionMetadataInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataGet(String self, String key, Promise promise) {
        Native.I
            .generalTransactionMetadataGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void generalTransactionMetadataKeys(String self, Promise promise) {
        Native.I
            .generalTransactionMetadataKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionInputsToBytes(String self, Promise promise) {
        Native.I
            .transactionInputsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionInputsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsToHex(String self, Promise promise) {
        Native.I
            .transactionInputsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionInputsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsToJson(String self, Promise promise) {
        Native.I
            .transactionInputsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsFromJson(String json, Promise promise) {
        Native.I
            .transactionInputsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsNew( Promise promise) {
        Native.I
            .transactionInputsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsLen(String self, Promise promise) {
        Native.I
            .transactionInputsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsGet(String self, Double index, Promise promise) {
        Native.I
            .transactionInputsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionInputsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsToOption(String self, Promise promise) {
        Native.I
            .transactionInputsToOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void updateToBytes(String self, Promise promise) {
        Native.I
            .updateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void updateFromBytes(String bytes, Promise promise) {
        Native.I
            .updateFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void updateToHex(String self, Promise promise) {
        Native.I
            .updateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void updateFromHex(String hexStr, Promise promise) {
        Native.I
            .updateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void updateToJson(String self, Promise promise) {
        Native.I
            .updateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void updateFromJson(String json, Promise promise) {
        Native.I
            .updateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void updateProposedProtocolParameterUpdates(String self, Promise promise) {
        Native.I
            .updateProposedProtocolParameterUpdates(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void updateEpoch(String self, Promise promise) {
        Native.I
            .updateEpoch(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void updateNew(String proposedProtocolParameterUpdates, Double epoch, Promise promise) {
        Native.I
            .updateNew(new RPtr(proposedProtocolParameterUpdates), epoch.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void linearFeeConstant(String self, Promise promise) {
        Native.I
            .linearFeeConstant(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void linearFeeCoefficient(String self, Promise promise) {
        Native.I
            .linearFeeCoefficient(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void linearFeeNew(String coefficient, String constant, Promise promise) {
        Native.I
            .linearFeeNew(new RPtr(coefficient), new RPtr(constant))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void stringsNew( Promise promise) {
        Native.I
            .stringsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stringsLen(String self, Promise promise) {
        Native.I
            .stringsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void stringsGet(String self, Double index, Promise promise) {
        Native.I
            .stringsGet(new RPtr(self), index.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void stringsAdd(String self, String elem, Promise promise) {
        Native.I
            .stringsAdd(new RPtr(self), elem)
            .pour(promise);
    }


    @ReactMethod
    public final void timelockStartToBytes(String self, Promise promise) {
        Native.I
            .timelockStartToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartFromBytes(String bytes, Promise promise) {
        Native.I
            .timelockStartFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartToHex(String self, Promise promise) {
        Native.I
            .timelockStartToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartFromHex(String hexStr, Promise promise) {
        Native.I
            .timelockStartFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartToJson(String self, Promise promise) {
        Native.I
            .timelockStartToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartFromJson(String json, Promise promise) {
        Native.I
            .timelockStartFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartSlot(String self, Promise promise) {
        Native.I
            .timelockStartSlot(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartSlotBignum(String self, Promise promise) {
        Native.I
            .timelockStartSlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartNew(Double slot, Promise promise) {
        Native.I
            .timelockStartNew(slot.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockStartNewTimelockstart(String slot, Promise promise) {
        Native.I
            .timelockStartNewTimelockstart(new RPtr(slot))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void ed25519KeyHashesToBytes(String self, Promise promise) {
        Native.I
            .ed25519KeyHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .ed25519KeyHashesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesToHex(String self, Promise promise) {
        Native.I
            .ed25519KeyHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .ed25519KeyHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesToJson(String self, Promise promise) {
        Native.I
            .ed25519KeyHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesFromJson(String json, Promise promise) {
        Native.I
            .ed25519KeyHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesNew( Promise promise) {
        Native.I
            .ed25519KeyHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesLen(String self, Promise promise) {
        Native.I
            .ed25519KeyHashesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesGet(String self, Double index, Promise promise) {
        Native.I
            .ed25519KeyHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .ed25519KeyHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashesToOption(String self, Promise promise) {
        Native.I
            .ed25519KeyHashesToOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void multiAssetToBytes(String self, Promise promise) {
        Native.I
            .multiAssetToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetFromBytes(String bytes, Promise promise) {
        Native.I
            .multiAssetFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetToHex(String self, Promise promise) {
        Native.I
            .multiAssetToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetFromHex(String hexStr, Promise promise) {
        Native.I
            .multiAssetFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetToJson(String self, Promise promise) {
        Native.I
            .multiAssetToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetFromJson(String json, Promise promise) {
        Native.I
            .multiAssetFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetNew( Promise promise) {
        Native.I
            .multiAssetNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetLen(String self, Promise promise) {
        Native.I
            .multiAssetLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetInsert(String self, String policyId, String assets, Promise promise) {
        Native.I
            .multiAssetInsert(new RPtr(self), new RPtr(policyId), new RPtr(assets))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetGet(String self, String policyId, Promise promise) {
        Native.I
            .multiAssetGet(new RPtr(self), new RPtr(policyId))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetSetAsset(String self, String policyId, String assetName, String value, Promise promise) {
        Native.I
            .multiAssetSetAsset(new RPtr(self), new RPtr(policyId), new RPtr(assetName), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetGetAsset(String self, String policyId, String assetName, Promise promise) {
        Native.I
            .multiAssetGetAsset(new RPtr(self), new RPtr(policyId), new RPtr(assetName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetKeys(String self, Promise promise) {
        Native.I
            .multiAssetKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiAssetSub(String self, String rhsMa, Promise promise) {
        Native.I
            .multiAssetSub(new RPtr(self), new RPtr(rhsMa))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void kESSignatureToBytes(String self, Promise promise) {
        Native.I
            .kESSignatureToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void kESSignatureFromBytes(String bytes, Promise promise) {
        Native.I
            .kESSignatureFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void publicKeysNew( Promise promise) {
        Native.I
            .publicKeysNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeysSize(String self, Promise promise) {
        Native.I
            .publicKeysSize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeysGet(String self, Double index, Promise promise) {
        Native.I
            .publicKeysGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeysAdd(String self, String key, Promise promise) {
        Native.I
            .publicKeysAdd(new RPtr(self), new RPtr(key))
            .pour(promise);
    }


    @ReactMethod
    public final void scriptHashesToBytes(String self, Promise promise) {
        Native.I
            .scriptHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptHashesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesToHex(String self, Promise promise) {
        Native.I
            .scriptHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesToJson(String self, Promise promise) {
        Native.I
            .scriptHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesFromJson(String json, Promise promise) {
        Native.I
            .scriptHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesNew( Promise promise) {
        Native.I
            .scriptHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesLen(String self, Promise promise) {
        Native.I
            .scriptHashesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesGet(String self, Double index, Promise promise) {
        Native.I
            .scriptHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .scriptHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void headerToBytes(String self, Promise promise) {
        Native.I
            .headerToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void headerFromBytes(String bytes, Promise promise) {
        Native.I
            .headerFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerToHex(String self, Promise promise) {
        Native.I
            .headerToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerFromHex(String hexStr, Promise promise) {
        Native.I
            .headerFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerToJson(String self, Promise promise) {
        Native.I
            .headerToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerFromJson(String json, Promise promise) {
        Native.I
            .headerFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerHeaderBody(String self, Promise promise) {
        Native.I
            .headerHeaderBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodySignature(String self, Promise promise) {
        Native.I
            .headerBodySignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerNew(String headerBody, String bodySignature, Promise promise) {
        Native.I
            .headerNew(new RPtr(headerBody), new RPtr(bodySignature))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void dNSRecordAorAAAAToBytes(String self, Promise promise) {
        Native.I
            .dNSRecordAorAAAAToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAAFromBytes(String bytes, Promise promise) {
        Native.I
            .dNSRecordAorAAAAFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAAToHex(String self, Promise promise) {
        Native.I
            .dNSRecordAorAAAAToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAAFromHex(String hexStr, Promise promise) {
        Native.I
            .dNSRecordAorAAAAFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAAToJson(String self, Promise promise) {
        Native.I
            .dNSRecordAorAAAAToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAAFromJson(String json, Promise promise) {
        Native.I
            .dNSRecordAorAAAAFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAANew(String dnsName, Promise promise) {
        Native.I
            .dNSRecordAorAAAANew(dnsName)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dNSRecordAorAAAARecord(String self, Promise promise) {
        Native.I
            .dNSRecordAorAAAARecord(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void poolMetadataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .poolMetadataHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataHashToBytes(String self, Promise promise) {
        Native.I
            .poolMetadataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .poolMetadataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .poolMetadataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataHashToHex(String self, Promise promise) {
        Native.I
            .poolMetadataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolMetadataHashFromHex(String hex, Promise promise) {
        Native.I
            .poolMetadataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void inputWithScriptWitnessNewWithNativeScriptWitness(String input, String witness, Promise promise) {
        Native.I
            .inputWithScriptWitnessNewWithNativeScriptWitness(new RPtr(input), new RPtr(witness))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void inputWithScriptWitnessNewWithPlutusWitness(String input, String witness, Promise promise) {
        Native.I
            .inputWithScriptWitnessNewWithPlutusWitness(new RPtr(input), new RPtr(witness))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void inputWithScriptWitnessInput(String self, Promise promise) {
        Native.I
            .inputWithScriptWitnessInput(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusScriptSourceNew(String script, Promise promise) {
        Native.I
            .plutusScriptSourceNew(new RPtr(script))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptSourceNewRefInput(String scriptHash, String input, Promise promise) {
        Native.I
            .plutusScriptSourceNewRefInput(new RPtr(scriptHash), new RPtr(input))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptSourceNewRefInputWithLangVer(String scriptHash, String input, String langVer, Promise promise) {
        Native.I
            .plutusScriptSourceNewRefInputWithLangVer(new RPtr(scriptHash), new RPtr(input), new RPtr(langVer))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusWitnessNew(String script, String datum, String redeemer, Promise promise) {
        Native.I
            .plutusWitnessNew(new RPtr(script), new RPtr(datum), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessNewWithRef(String script, String datum, String redeemer, Promise promise) {
        Native.I
            .plutusWitnessNewWithRef(new RPtr(script), new RPtr(datum), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessNewWithoutDatum(String script, String redeemer, Promise promise) {
        Native.I
            .plutusWitnessNewWithoutDatum(new RPtr(script), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessScript(String self, Promise promise) {
        Native.I
            .plutusWitnessScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessDatum(String self, Promise promise) {
        Native.I
            .plutusWitnessDatum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessRedeemer(String self, Promise promise) {
        Native.I
            .plutusWitnessRedeemer(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void privateKeyToPublic(String self, Promise promise) {
        Native.I
            .privateKeyToPublic(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyGenerateEd25519( Promise promise) {
        Native.I
            .privateKeyGenerateEd25519()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyGenerateEd25519extended( Promise promise) {
        Native.I
            .privateKeyGenerateEd25519extended()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .privateKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyToBech32(String self, Promise promise) {
        Native.I
            .privateKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyAsBytes(String self, Promise promise) {
        Native.I
            .privateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyFromExtendedBytes(String bytes, Promise promise) {
        Native.I
            .privateKeyFromExtendedBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyFromNormalBytes(String bytes, Promise promise) {
        Native.I
            .privateKeyFromNormalBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeySign(String self, String message, Promise promise) {
        Native.I
            .privateKeySign(new RPtr(self), Base64.encodeToString(message))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyToHex(String self, Promise promise) {
        Native.I
            .privateKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void privateKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .privateKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void languageToBytes(String self, Promise promise) {
        Native.I
            .languageToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void languageFromBytes(String bytes, Promise promise) {
        Native.I
            .languageFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languageToHex(String self, Promise promise) {
        Native.I
            .languageToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void languageFromHex(String hexStr, Promise promise) {
        Native.I
            .languageFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languageToJson(String self, Promise promise) {
        Native.I
            .languageToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void languageFromJson(String json, Promise promise) {
        Native.I
            .languageFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languageNewPlutusV1( Promise promise) {
        Native.I
            .languageNewPlutusV1()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languageNewPlutusV2( Promise promise) {
        Native.I
            .languageNewPlutusV2()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languageKind(String self, Promise promise) {
        Native.I
            .languageKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }


    @ReactMethod
    public final void scriptAllToBytes(String self, Promise promise) {
        Native.I
            .scriptAllToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptAllFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllToHex(String self, Promise promise) {
        Native.I
            .scriptAllToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptAllFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllToJson(String self, Promise promise) {
        Native.I
            .scriptAllToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllFromJson(String json, Promise promise) {
        Native.I
            .scriptAllFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllNativeScripts(String self, Promise promise) {
        Native.I
            .scriptAllNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAllNew(String nativeScripts, Promise promise) {
        Native.I
            .scriptAllNew(new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void operationalCertToBytes(String self, Promise promise) {
        Native.I
            .operationalCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertFromBytes(String bytes, Promise promise) {
        Native.I
            .operationalCertFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertToHex(String self, Promise promise) {
        Native.I
            .operationalCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertFromHex(String hexStr, Promise promise) {
        Native.I
            .operationalCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertToJson(String self, Promise promise) {
        Native.I
            .operationalCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertFromJson(String json, Promise promise) {
        Native.I
            .operationalCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertHotVkey(String self, Promise promise) {
        Native.I
            .operationalCertHotVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertSequenceNumber(String self, Promise promise) {
        Native.I
            .operationalCertSequenceNumber(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertKesPeriod(String self, Promise promise) {
        Native.I
            .operationalCertKesPeriod(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertSigma(String self, Promise promise) {
        Native.I
            .operationalCertSigma(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void operationalCertNew(String hotVkey, Double sequenceNumber, Double kesPeriod, String sigma, Promise promise) {
        Native.I
            .operationalCertNew(new RPtr(hotVkey), sequenceNumber.longValue(), kesPeriod.longValue(), new RPtr(sigma))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusWitnessesNew( Promise promise) {
        Native.I
            .plutusWitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessesLen(String self, Promise promise) {
        Native.I
            .plutusWitnessesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .plutusWitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusWitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .plutusWitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void scriptHashFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashToBytes(String self, Promise promise) {
        Native.I
            .scriptHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .scriptHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .scriptHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashToHex(String self, Promise promise) {
        Native.I
            .scriptHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptHashFromHex(String hex, Promise promise) {
        Native.I
            .scriptHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void stakeRegistrationToBytes(String self, Promise promise) {
        Native.I
            .stakeRegistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .stakeRegistrationFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationToHex(String self, Promise promise) {
        Native.I
            .stakeRegistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .stakeRegistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationToJson(String self, Promise promise) {
        Native.I
            .stakeRegistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationFromJson(String json, Promise promise) {
        Native.I
            .stakeRegistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationStakeCredential(String self, Promise promise) {
        Native.I
            .stakeRegistrationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationNew(String stakeCredential, Promise promise) {
        Native.I
            .stakeRegistrationNew(new RPtr(stakeCredential))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionBuilderConfigBuilderNew( Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderFeeAlgo(String self, String feeAlgo, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderFeeAlgo(new RPtr(self), new RPtr(feeAlgo))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderCoinsPerUtxoWord(String self, String coinsPerUtxoWord, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderCoinsPerUtxoWord(new RPtr(self), new RPtr(coinsPerUtxoWord))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderCoinsPerUtxoByte(String self, String coinsPerUtxoByte, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderCoinsPerUtxoByte(new RPtr(self), new RPtr(coinsPerUtxoByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderExUnitPrices(String self, String exUnitPrices, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderExUnitPrices(new RPtr(self), new RPtr(exUnitPrices))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderPoolDeposit(String self, String poolDeposit, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderPoolDeposit(new RPtr(self), new RPtr(poolDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderKeyDeposit(String self, String keyDeposit, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderKeyDeposit(new RPtr(self), new RPtr(keyDeposit))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderMaxValueSize(String self, Double maxValueSize, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderMaxValueSize(new RPtr(self), maxValueSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderMaxTxSize(String self, Double maxTxSize, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderMaxTxSize(new RPtr(self), maxTxSize.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderPreferPureChange(String self, Boolean preferPureChange, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderPreferPureChange(new RPtr(self), preferPureChange)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderConfigBuilderBuild(String self, Promise promise) {
        Native.I
            .transactionBuilderConfigBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void assetsToBytes(String self, Promise promise) {
        Native.I
            .assetsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void assetsFromBytes(String bytes, Promise promise) {
        Native.I
            .assetsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsToHex(String self, Promise promise) {
        Native.I
            .assetsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetsFromHex(String hexStr, Promise promise) {
        Native.I
            .assetsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsToJson(String self, Promise promise) {
        Native.I
            .assetsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetsFromJson(String json, Promise promise) {
        Native.I
            .assetsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsNew( Promise promise) {
        Native.I
            .assetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsLen(String self, Promise promise) {
        Native.I
            .assetsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsInsert(String self, String key, String value, Promise promise) {
        Native.I
            .assetsInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsGet(String self, String key, Promise promise) {
        Native.I
            .assetsGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetsKeys(String self, Promise promise) {
        Native.I
            .assetsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void unitIntervalToBytes(String self, Promise promise) {
        Native.I
            .unitIntervalToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalFromBytes(String bytes, Promise promise) {
        Native.I
            .unitIntervalFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalToHex(String self, Promise promise) {
        Native.I
            .unitIntervalToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalFromHex(String hexStr, Promise promise) {
        Native.I
            .unitIntervalFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalToJson(String self, Promise promise) {
        Native.I
            .unitIntervalToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalFromJson(String json, Promise promise) {
        Native.I
            .unitIntervalFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalNumerator(String self, Promise promise) {
        Native.I
            .unitIntervalNumerator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalDenominator(String self, Promise promise) {
        Native.I
            .unitIntervalDenominator(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalNew(String numerator, String denominator, Promise promise) {
        Native.I
            .unitIntervalNew(new RPtr(numerator), new RPtr(denominator))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void kESVKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .kESVKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void kESVKeyToBytes(String self, Promise promise) {
        Native.I
            .kESVKeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void kESVKeyToBech32(String self, String prefix, Promise promise) {
        Native.I
            .kESVKeyToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void kESVKeyFromBech32(String bechStr, Promise promise) {
        Native.I
            .kESVKeyFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void kESVKeyToHex(String self, Promise promise) {
        Native.I
            .kESVKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void kESVKeyFromHex(String hex, Promise promise) {
        Native.I
            .kESVKeyFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void multiHostNameToBytes(String self, Promise promise) {
        Native.I
            .multiHostNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameFromBytes(String bytes, Promise promise) {
        Native.I
            .multiHostNameFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameToHex(String self, Promise promise) {
        Native.I
            .multiHostNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameFromHex(String hexStr, Promise promise) {
        Native.I
            .multiHostNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameToJson(String self, Promise promise) {
        Native.I
            .multiHostNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameFromJson(String json, Promise promise) {
        Native.I
            .multiHostNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameDnsName(String self, Promise promise) {
        Native.I
            .multiHostNameDnsName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void multiHostNameNew(String dnsName, Promise promise) {
        Native.I
            .multiHostNameNew(new RPtr(dnsName))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void legacyDaedalusPrivateKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .legacyDaedalusPrivateKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void legacyDaedalusPrivateKeyAsBytes(String self, Promise promise) {
        Native.I
            .legacyDaedalusPrivateKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void legacyDaedalusPrivateKeyChaincode(String self, Promise promise) {
        Native.I
            .legacyDaedalusPrivateKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void nonceToBytes(String self, Promise promise) {
        Native.I
            .nonceToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void nonceFromBytes(String bytes, Promise promise) {
        Native.I
            .nonceFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nonceToHex(String self, Promise promise) {
        Native.I
            .nonceToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void nonceFromHex(String hexStr, Promise promise) {
        Native.I
            .nonceFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nonceToJson(String self, Promise promise) {
        Native.I
            .nonceToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void nonceFromJson(String json, Promise promise) {
        Native.I
            .nonceFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nonceNewIdentity( Promise promise) {
        Native.I
            .nonceNewIdentity()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nonceNewFromHash(String hash, Promise promise) {
        Native.I
            .nonceNewFromHash(Base64.encodeToString(hash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nonceGetHash(String self, Promise promise) {
        Native.I
            .nonceGetHash(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void baseAddressNew(Double network, String payment, String stake, Promise promise) {
        Native.I
            .baseAddressNew(network.longValue(), new RPtr(payment), new RPtr(stake))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void baseAddressPaymentCred(String self, Promise promise) {
        Native.I
            .baseAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void baseAddressStakeCred(String self, Promise promise) {
        Native.I
            .baseAddressStakeCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void baseAddressToAddress(String self, Promise promise) {
        Native.I
            .baseAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void baseAddressFromAddress(String addr, Promise promise) {
        Native.I
            .baseAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void exUnitPricesToBytes(String self, Promise promise) {
        Native.I
            .exUnitPricesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesFromBytes(String bytes, Promise promise) {
        Native.I
            .exUnitPricesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesToHex(String self, Promise promise) {
        Native.I
            .exUnitPricesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesFromHex(String hexStr, Promise promise) {
        Native.I
            .exUnitPricesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesToJson(String self, Promise promise) {
        Native.I
            .exUnitPricesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesFromJson(String json, Promise promise) {
        Native.I
            .exUnitPricesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesMemPrice(String self, Promise promise) {
        Native.I
            .exUnitPricesMemPrice(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesStepPrice(String self, Promise promise) {
        Native.I
            .exUnitPricesStepPrice(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitPricesNew(String memPrice, String stepPrice, Promise promise) {
        Native.I
            .exUnitPricesNew(new RPtr(memPrice), new RPtr(stepPrice))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void assetNameToBytes(String self, Promise promise) {
        Native.I
            .assetNameToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameFromBytes(String bytes, Promise promise) {
        Native.I
            .assetNameFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameToHex(String self, Promise promise) {
        Native.I
            .assetNameToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameFromHex(String hexStr, Promise promise) {
        Native.I
            .assetNameFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameToJson(String self, Promise promise) {
        Native.I
            .assetNameToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameFromJson(String json, Promise promise) {
        Native.I
            .assetNameFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameNew(String name, Promise promise) {
        Native.I
            .assetNameNew(Base64.encodeToString(name))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void assetNameName(String self, Promise promise) {
        Native.I
            .assetNameName(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }


    @ReactMethod
    public final void nativeScriptToBytes(String self, Promise promise) {
        Native.I
            .nativeScriptToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptFromBytes(String bytes, Promise promise) {
        Native.I
            .nativeScriptFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptToHex(String self, Promise promise) {
        Native.I
            .nativeScriptToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptFromHex(String hexStr, Promise promise) {
        Native.I
            .nativeScriptFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptToJson(String self, Promise promise) {
        Native.I
            .nativeScriptToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptFromJson(String json, Promise promise) {
        Native.I
            .nativeScriptFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptHash(String self, Promise promise) {
        Native.I
            .nativeScriptHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewScriptPubkey(String scriptPubkey, Promise promise) {
        Native.I
            .nativeScriptNewScriptPubkey(new RPtr(scriptPubkey))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewScriptAll(String scriptAll, Promise promise) {
        Native.I
            .nativeScriptNewScriptAll(new RPtr(scriptAll))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewScriptAny(String scriptAny, Promise promise) {
        Native.I
            .nativeScriptNewScriptAny(new RPtr(scriptAny))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewScriptNOfK(String scriptNOfK, Promise promise) {
        Native.I
            .nativeScriptNewScriptNOfK(new RPtr(scriptNOfK))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewTimelockStart(String timelockStart, Promise promise) {
        Native.I
            .nativeScriptNewTimelockStart(new RPtr(timelockStart))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptNewTimelockExpiry(String timelockExpiry, Promise promise) {
        Native.I
            .nativeScriptNewTimelockExpiry(new RPtr(timelockExpiry))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptKind(String self, Promise promise) {
        Native.I
            .nativeScriptKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsScriptPubkey(String self, Promise promise) {
        Native.I
            .nativeScriptAsScriptPubkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsScriptAll(String self, Promise promise) {
        Native.I
            .nativeScriptAsScriptAll(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsScriptAny(String self, Promise promise) {
        Native.I
            .nativeScriptAsScriptAny(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsScriptNOfK(String self, Promise promise) {
        Native.I
            .nativeScriptAsScriptNOfK(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsTimelockStart(String self, Promise promise) {
        Native.I
            .nativeScriptAsTimelockStart(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptAsTimelockExpiry(String self, Promise promise) {
        Native.I
            .nativeScriptAsTimelockExpiry(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptGetRequiredSigners(String self, Promise promise) {
        Native.I
            .nativeScriptGetRequiredSigners(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void byronAddressToBase58(String self, Promise promise) {
        Native.I
            .byronAddressToBase58(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressToBytes(String self, Promise promise) {
        Native.I
            .byronAddressToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressFromBytes(String bytes, Promise promise) {
        Native.I
            .byronAddressFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressByronProtocolMagic(String self, Promise promise) {
        Native.I
            .byronAddressByronProtocolMagic(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressAttributes(String self, Promise promise) {
        Native.I
            .byronAddressAttributes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressNetworkId(String self, Promise promise) {
        Native.I
            .byronAddressNetworkId(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressFromBase58(String s, Promise promise) {
        Native.I
            .byronAddressFromBase58(s)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressIcarusFromKey(String key, Double protocolMagic, Promise promise) {
        Native.I
            .byronAddressIcarusFromKey(new RPtr(key), protocolMagic.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressIsValid(String s, Promise promise) {
        Native.I
            .byronAddressIsValid(s)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressToAddress(String self, Promise promise) {
        Native.I
            .byronAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void byronAddressFromAddress(String addr, Promise promise) {
        Native.I
            .byronAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void bigIntToBytes(String self, Promise promise) {
        Native.I
            .bigIntToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntFromBytes(String bytes, Promise promise) {
        Native.I
            .bigIntFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntToHex(String self, Promise promise) {
        Native.I
            .bigIntToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntFromHex(String hexStr, Promise promise) {
        Native.I
            .bigIntFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntToJson(String self, Promise promise) {
        Native.I
            .bigIntToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntFromJson(String json, Promise promise) {
        Native.I
            .bigIntFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntIsZero(String self, Promise promise) {
        Native.I
            .bigIntIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntAsU64(String self, Promise promise) {
        Native.I
            .bigIntAsU64(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntAsInt(String self, Promise promise) {
        Native.I
            .bigIntAsInt(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntFromStr(String text, Promise promise) {
        Native.I
            .bigIntFromStr(text)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntToStr(String self, Promise promise) {
        Native.I
            .bigIntToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntAdd(String self, String other, Promise promise) {
        Native.I
            .bigIntAdd(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntMul(String self, String other, Promise promise) {
        Native.I
            .bigIntMul(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntOne( Promise promise) {
        Native.I
            .bigIntOne()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntIncrement(String self, Promise promise) {
        Native.I
            .bigIntIncrement(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bigIntDivCeil(String self, String other, Promise promise) {
        Native.I
            .bigIntDivCeil(new RPtr(self), new RPtr(other))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void pointerNew(Double slot, Double txIndex, Double certIndex, Promise promise) {
        Native.I
            .pointerNew(slot.longValue(), txIndex.longValue(), certIndex.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerNewPointer(String slot, String txIndex, String certIndex, Promise promise) {
        Native.I
            .pointerNewPointer(new RPtr(slot), new RPtr(txIndex), new RPtr(certIndex))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerSlot(String self, Promise promise) {
        Native.I
            .pointerSlot(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerTxIndex(String self, Promise promise) {
        Native.I
            .pointerTxIndex(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerCertIndex(String self, Promise promise) {
        Native.I
            .pointerCertIndex(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerSlotBignum(String self, Promise promise) {
        Native.I
            .pointerSlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerTxIndexBignum(String self, Promise promise) {
        Native.I
            .pointerTxIndexBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerCertIndexBignum(String self, Promise promise) {
        Native.I
            .pointerCertIndexBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void protocolParamUpdateToBytes(String self, Promise promise) {
        Native.I
            .protocolParamUpdateToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateFromBytes(String bytes, Promise promise) {
        Native.I
            .protocolParamUpdateFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateToHex(String self, Promise promise) {
        Native.I
            .protocolParamUpdateToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateFromHex(String hexStr, Promise promise) {
        Native.I
            .protocolParamUpdateFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateToJson(String self, Promise promise) {
        Native.I
            .protocolParamUpdateToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateFromJson(String json, Promise promise) {
        Native.I
            .protocolParamUpdateFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMinfeeA(String self, String minfeeA, Promise promise) {
        Native.I
            .protocolParamUpdateSetMinfeeA(new RPtr(self), new RPtr(minfeeA))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMinfeeA(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMinfeeA(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMinfeeB(String self, String minfeeB, Promise promise) {
        Native.I
            .protocolParamUpdateSetMinfeeB(new RPtr(self), new RPtr(minfeeB))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMinfeeB(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMinfeeB(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxBlockBodySize(String self, Double maxBlockBodySize, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxBlockBodySize(new RPtr(self), maxBlockBodySize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxBlockBodySize(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxBlockBodySize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxTxSize(String self, Double maxTxSize, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxTxSize(new RPtr(self), maxTxSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxTxSize(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxTxSize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxBlockHeaderSize(String self, Double maxBlockHeaderSize, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxBlockHeaderSize(new RPtr(self), maxBlockHeaderSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxBlockHeaderSize(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxBlockHeaderSize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetKeyDeposit(String self, String keyDeposit, Promise promise) {
        Native.I
            .protocolParamUpdateSetKeyDeposit(new RPtr(self), new RPtr(keyDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateKeyDeposit(String self, Promise promise) {
        Native.I
            .protocolParamUpdateKeyDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetPoolDeposit(String self, String poolDeposit, Promise promise) {
        Native.I
            .protocolParamUpdateSetPoolDeposit(new RPtr(self), new RPtr(poolDeposit))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdatePoolDeposit(String self, Promise promise) {
        Native.I
            .protocolParamUpdatePoolDeposit(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxEpoch(String self, Double maxEpoch, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxEpoch(new RPtr(self), maxEpoch.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxEpoch(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxEpoch(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetNOpt(String self, Double nOpt, Promise promise) {
        Native.I
            .protocolParamUpdateSetNOpt(new RPtr(self), nOpt.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateNOpt(String self, Promise promise) {
        Native.I
            .protocolParamUpdateNOpt(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetPoolPledgeInfluence(String self, String poolPledgeInfluence, Promise promise) {
        Native.I
            .protocolParamUpdateSetPoolPledgeInfluence(new RPtr(self), new RPtr(poolPledgeInfluence))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdatePoolPledgeInfluence(String self, Promise promise) {
        Native.I
            .protocolParamUpdatePoolPledgeInfluence(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetExpansionRate(String self, String expansionRate, Promise promise) {
        Native.I
            .protocolParamUpdateSetExpansionRate(new RPtr(self), new RPtr(expansionRate))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateExpansionRate(String self, Promise promise) {
        Native.I
            .protocolParamUpdateExpansionRate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetTreasuryGrowthRate(String self, String treasuryGrowthRate, Promise promise) {
        Native.I
            .protocolParamUpdateSetTreasuryGrowthRate(new RPtr(self), new RPtr(treasuryGrowthRate))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateTreasuryGrowthRate(String self, Promise promise) {
        Native.I
            .protocolParamUpdateTreasuryGrowthRate(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateD(String self, Promise promise) {
        Native.I
            .protocolParamUpdateD(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateExtraEntropy(String self, Promise promise) {
        Native.I
            .protocolParamUpdateExtraEntropy(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetProtocolVersion(String self, String protocolVersion, Promise promise) {
        Native.I
            .protocolParamUpdateSetProtocolVersion(new RPtr(self), new RPtr(protocolVersion))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateProtocolVersion(String self, Promise promise) {
        Native.I
            .protocolParamUpdateProtocolVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMinPoolCost(String self, String minPoolCost, Promise promise) {
        Native.I
            .protocolParamUpdateSetMinPoolCost(new RPtr(self), new RPtr(minPoolCost))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMinPoolCost(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMinPoolCost(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetAdaPerUtxoByte(String self, String adaPerUtxoByte, Promise promise) {
        Native.I
            .protocolParamUpdateSetAdaPerUtxoByte(new RPtr(self), new RPtr(adaPerUtxoByte))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateAdaPerUtxoByte(String self, Promise promise) {
        Native.I
            .protocolParamUpdateAdaPerUtxoByte(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetCostModels(String self, String costModels, Promise promise) {
        Native.I
            .protocolParamUpdateSetCostModels(new RPtr(self), new RPtr(costModels))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateCostModels(String self, Promise promise) {
        Native.I
            .protocolParamUpdateCostModels(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetExecutionCosts(String self, String executionCosts, Promise promise) {
        Native.I
            .protocolParamUpdateSetExecutionCosts(new RPtr(self), new RPtr(executionCosts))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateExecutionCosts(String self, Promise promise) {
        Native.I
            .protocolParamUpdateExecutionCosts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxTxExUnits(String self, String maxTxExUnits, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxTxExUnits(new RPtr(self), new RPtr(maxTxExUnits))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxTxExUnits(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxTxExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxBlockExUnits(String self, String maxBlockExUnits, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxBlockExUnits(new RPtr(self), new RPtr(maxBlockExUnits))
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxBlockExUnits(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxBlockExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxValueSize(String self, Double maxValueSize, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxValueSize(new RPtr(self), maxValueSize.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxValueSize(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxValueSize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetCollateralPercentage(String self, Double collateralPercentage, Promise promise) {
        Native.I
            .protocolParamUpdateSetCollateralPercentage(new RPtr(self), collateralPercentage.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateCollateralPercentage(String self, Promise promise) {
        Native.I
            .protocolParamUpdateCollateralPercentage(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateSetMaxCollateralInputs(String self, Double maxCollateralInputs, Promise promise) {
        Native.I
            .protocolParamUpdateSetMaxCollateralInputs(new RPtr(self), maxCollateralInputs.longValue())
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateMaxCollateralInputs(String self, Promise promise) {
        Native.I
            .protocolParamUpdateMaxCollateralInputs(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void protocolParamUpdateNew( Promise promise) {
        Native.I
            .protocolParamUpdateNew()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void dataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .dataHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dataHashToBytes(String self, Promise promise) {
        Native.I
            .dataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void dataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .dataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void dataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .dataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dataHashToHex(String self, Promise promise) {
        Native.I
            .dataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void dataHashFromHex(String hex, Promise promise) {
        Native.I
            .dataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionOutputToBytes(String self, Promise promise) {
        Native.I
            .transactionOutputToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionOutputFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputToHex(String self, Promise promise) {
        Native.I
            .transactionOutputToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionOutputFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputToJson(String self, Promise promise) {
        Native.I
            .transactionOutputToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputFromJson(String json, Promise promise) {
        Native.I
            .transactionOutputFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAddress(String self, Promise promise) {
        Native.I
            .transactionOutputAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAmount(String self, Promise promise) {
        Native.I
            .transactionOutputAmount(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputDataHash(String self, Promise promise) {
        Native.I
            .transactionOutputDataHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputPlutusData(String self, Promise promise) {
        Native.I
            .transactionOutputPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputScriptRef(String self, Promise promise) {
        Native.I
            .transactionOutputScriptRef(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputSetScriptRef(String self, String scriptRef, Promise promise) {
        Native.I
            .transactionOutputSetScriptRef(new RPtr(self), new RPtr(scriptRef))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputSetPlutusData(String self, String data, Promise promise) {
        Native.I
            .transactionOutputSetPlutusData(new RPtr(self), new RPtr(data))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputSetDataHash(String self, String dataHash, Promise promise) {
        Native.I
            .transactionOutputSetDataHash(new RPtr(self), new RPtr(dataHash))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputHasPlutusData(String self, Promise promise) {
        Native.I
            .transactionOutputHasPlutusData(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputHasDataHash(String self, Promise promise) {
        Native.I
            .transactionOutputHasDataHash(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputHasScriptRef(String self, Promise promise) {
        Native.I
            .transactionOutputHasScriptRef(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputNew(String address, String amount, Promise promise) {
        Native.I
            .transactionOutputNew(new RPtr(address), new RPtr(amount))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void redeemersToBytes(String self, Promise promise) {
        Native.I
            .redeemersToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersFromBytes(String bytes, Promise promise) {
        Native.I
            .redeemersFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersToHex(String self, Promise promise) {
        Native.I
            .redeemersToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersFromHex(String hexStr, Promise promise) {
        Native.I
            .redeemersFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersToJson(String self, Promise promise) {
        Native.I
            .redeemersToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersFromJson(String json, Promise promise) {
        Native.I
            .redeemersFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersNew( Promise promise) {
        Native.I
            .redeemersNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersLen(String self, Promise promise) {
        Native.I
            .redeemersLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersGet(String self, Double index, Promise promise) {
        Native.I
            .redeemersGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersAdd(String self, String elem, Promise promise) {
        Native.I
            .redeemersAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void redeemersTotalExUnits(String self, Promise promise) {
        Native.I
            .redeemersTotalExUnits(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void nativeScriptsNew( Promise promise) {
        Native.I
            .nativeScriptsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptsLen(String self, Promise promise) {
        Native.I
            .nativeScriptsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptsGet(String self, Double index, Promise promise) {
        Native.I
            .nativeScriptsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void nativeScriptsAdd(String self, String elem, Promise promise) {
        Native.I
            .nativeScriptsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void txBuilderConstantsPlutusDefaultCostModels( Promise promise) {
        Native.I
            .txBuilderConstantsPlutusDefaultCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txBuilderConstantsPlutusAlonzoCostModels( Promise promise) {
        Native.I
            .txBuilderConstantsPlutusAlonzoCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txBuilderConstantsPlutusVasilCostModels( Promise promise) {
        Native.I
            .txBuilderConstantsPlutusVasilCostModels()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusMapToBytes(String self, Promise promise) {
        Native.I
            .plutusMapToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapFromBytes(String bytes, Promise promise) {
        Native.I
            .plutusMapFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapToHex(String self, Promise promise) {
        Native.I
            .plutusMapToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapFromHex(String hexStr, Promise promise) {
        Native.I
            .plutusMapFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapNew( Promise promise) {
        Native.I
            .plutusMapNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapLen(String self, Promise promise) {
        Native.I
            .plutusMapLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapInsert(String self, String key, String value, Promise promise) {
        Native.I
            .plutusMapInsert(new RPtr(self), new RPtr(key), new RPtr(value))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapGet(String self, String key, Promise promise) {
        Native.I
            .plutusMapGet(new RPtr(self), new RPtr(key))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusMapKeys(String self, Promise promise) {
        Native.I
            .plutusMapKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void poolRetirementToBytes(String self, Promise promise) {
        Native.I
            .poolRetirementToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementFromBytes(String bytes, Promise promise) {
        Native.I
            .poolRetirementFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementToHex(String self, Promise promise) {
        Native.I
            .poolRetirementToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementFromHex(String hexStr, Promise promise) {
        Native.I
            .poolRetirementFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementToJson(String self, Promise promise) {
        Native.I
            .poolRetirementToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementFromJson(String json, Promise promise) {
        Native.I
            .poolRetirementFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementPoolKeyhash(String self, Promise promise) {
        Native.I
            .poolRetirementPoolKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementEpoch(String self, Promise promise) {
        Native.I
            .poolRetirementEpoch(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void poolRetirementNew(String poolKeyhash, Double epoch, Promise promise) {
        Native.I
            .poolRetirementNew(new RPtr(poolKeyhash), epoch.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void intToBytes(String self, Promise promise) {
        Native.I
            .intToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void intFromBytes(String bytes, Promise promise) {
        Native.I
            .intFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intToHex(String self, Promise promise) {
        Native.I
            .intToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void intFromHex(String hexStr, Promise promise) {
        Native.I
            .intFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intToJson(String self, Promise promise) {
        Native.I
            .intToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void intFromJson(String json, Promise promise) {
        Native.I
            .intFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intNew(String x, Promise promise) {
        Native.I
            .intNew(new RPtr(x))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intNewNegative(String x, Promise promise) {
        Native.I
            .intNewNegative(new RPtr(x))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intNewI32(Double x, Promise promise) {
        Native.I
            .intNewI32(x.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intIsPositive(String self, Promise promise) {
        Native.I
            .intIsPositive(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void intAsPositive(String self, Promise promise) {
        Native.I
            .intAsPositive(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intAsNegative(String self, Promise promise) {
        Native.I
            .intAsNegative(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void intAsI32(String self, Promise promise) {
        Native.I
            .intAsI32(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void intAsI32OrNothing(String self, Promise promise) {
        Native.I
            .intAsI32OrNothing(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void intAsI32OrFail(String self, Promise promise) {
        Native.I
            .intAsI32OrFail(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void intToStr(String self, Promise promise) {
        Native.I
            .intToStr(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void intFromStr(String string, Promise promise) {
        Native.I
            .intFromStr(string)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusScriptsToBytes(String self, Promise promise) {
        Native.I
            .plutusScriptsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsFromBytes(String bytes, Promise promise) {
        Native.I
            .plutusScriptsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsToHex(String self, Promise promise) {
        Native.I
            .plutusScriptsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsFromHex(String hexStr, Promise promise) {
        Native.I
            .plutusScriptsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsToJson(String self, Promise promise) {
        Native.I
            .plutusScriptsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsFromJson(String json, Promise promise) {
        Native.I
            .plutusScriptsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsNew( Promise promise) {
        Native.I
            .plutusScriptsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsLen(String self, Promise promise) {
        Native.I
            .plutusScriptsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsGet(String self, Double index, Promise promise) {
        Native.I
            .plutusScriptsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusScriptsAdd(String self, String elem, Promise promise) {
        Native.I
            .plutusScriptsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void timelockExpiryToBytes(String self, Promise promise) {
        Native.I
            .timelockExpiryToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryFromBytes(String bytes, Promise promise) {
        Native.I
            .timelockExpiryFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryToHex(String self, Promise promise) {
        Native.I
            .timelockExpiryToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryFromHex(String hexStr, Promise promise) {
        Native.I
            .timelockExpiryFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryToJson(String self, Promise promise) {
        Native.I
            .timelockExpiryToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryFromJson(String json, Promise promise) {
        Native.I
            .timelockExpiryFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpirySlot(String self, Promise promise) {
        Native.I
            .timelockExpirySlot(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpirySlotBignum(String self, Promise promise) {
        Native.I
            .timelockExpirySlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryNew(Double slot, Promise promise) {
        Native.I
            .timelockExpiryNew(slot.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void timelockExpiryNewTimelockexpiry(String slot, Promise promise) {
        Native.I
            .timelockExpiryNewTimelockexpiry(new RPtr(slot))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void mintWitnessNewNativeScript(String nativeScript, Promise promise) {
        Native.I
            .mintWitnessNewNativeScript(new RPtr(nativeScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintWitnessNewPlutusScript(String plutusScript, String redeemer, Promise promise) {
        Native.I
            .mintWitnessNewPlutusScript(new RPtr(plutusScript), new RPtr(redeemer))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void stakeCredentialFromKeyhash(String hash, Promise promise) {
        Native.I
            .stakeCredentialFromKeyhash(new RPtr(hash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialFromScripthash(String hash, Promise promise) {
        Native.I
            .stakeCredentialFromScripthash(new RPtr(hash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToKeyhash(String self, Promise promise) {
        Native.I
            .stakeCredentialToKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToScripthash(String self, Promise promise) {
        Native.I
            .stakeCredentialToScripthash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialKind(String self, Promise promise) {
        Native.I
            .stakeCredentialKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToBytes(String self, Promise promise) {
        Native.I
            .stakeCredentialToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialFromBytes(String bytes, Promise promise) {
        Native.I
            .stakeCredentialFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToHex(String self, Promise promise) {
        Native.I
            .stakeCredentialToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialFromHex(String hexStr, Promise promise) {
        Native.I
            .stakeCredentialFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToJson(String self, Promise promise) {
        Native.I
            .stakeCredentialToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialFromJson(String json, Promise promise) {
        Native.I
            .stakeCredentialFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void mintBuilderNew( Promise promise) {
        Native.I
            .mintBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderAddAsset(String self, String mint, String assetName, String amount, Promise promise) {
        Native.I
            .mintBuilderAddAsset(new RPtr(self), new RPtr(mint), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderSetAsset(String self, String mint, String assetName, String amount, Promise promise) {
        Native.I
            .mintBuilderSetAsset(new RPtr(self), new RPtr(mint), new RPtr(assetName), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderBuild(String self, Promise promise) {
        Native.I
            .mintBuilderBuild(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderGetNativeScripts(String self, Promise promise) {
        Native.I
            .mintBuilderGetNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderGetPlutusWitnesses(String self, Promise promise) {
        Native.I
            .mintBuilderGetPlutusWitnesses(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderGetRedeeemers(String self, Promise promise) {
        Native.I
            .mintBuilderGetRedeeemers(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderHasPlutusScripts(String self, Promise promise) {
        Native.I
            .mintBuilderHasPlutusScripts(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void mintBuilderHasNativeScripts(String self, Promise promise) {
        Native.I
            .mintBuilderHasNativeScripts(new RPtr(self))
            .pour(promise);
    }


    @ReactMethod
    public final void transactionWitnessSetsToBytes(String self, Promise promise) {
        Native.I
            .transactionWitnessSetsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionWitnessSetsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsToHex(String self, Promise promise) {
        Native.I
            .transactionWitnessSetsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionWitnessSetsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsToJson(String self, Promise promise) {
        Native.I
            .transactionWitnessSetsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsFromJson(String json, Promise promise) {
        Native.I
            .transactionWitnessSetsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsNew( Promise promise) {
        Native.I
            .transactionWitnessSetsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsLen(String self, Promise promise) {
        Native.I
            .transactionWitnessSetsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsGet(String self, Double index, Promise promise) {
        Native.I
            .transactionWitnessSetsGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetsAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionWitnessSetsAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void languagesNew( Promise promise) {
        Native.I
            .languagesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languagesLen(String self, Promise promise) {
        Native.I
            .languagesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void languagesGet(String self, Double index, Promise promise) {
        Native.I
            .languagesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void languagesAdd(String self, String elem, Promise promise) {
        Native.I
            .languagesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }

    @ReactMethod
    public final void languagesList( Promise promise) {
        Native.I
            .languagesList()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void datumSourceNew(String datum, Promise promise) {
        Native.I
            .datumSourceNew(new RPtr(datum))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void datumSourceNewRefInput(String input, Promise promise) {
        Native.I
            .datumSourceNewRefInput(new RPtr(input))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void stakeDeregistrationToBytes(String self, Promise promise) {
        Native.I
            .stakeDeregistrationToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationFromBytes(String bytes, Promise promise) {
        Native.I
            .stakeDeregistrationFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationToHex(String self, Promise promise) {
        Native.I
            .stakeDeregistrationToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationFromHex(String hexStr, Promise promise) {
        Native.I
            .stakeDeregistrationFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationToJson(String self, Promise promise) {
        Native.I
            .stakeDeregistrationToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationFromJson(String json, Promise promise) {
        Native.I
            .stakeDeregistrationFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationStakeCredential(String self, Promise promise) {
        Native.I
            .stakeDeregistrationStakeCredential(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationNew(String stakeCredential, Promise promise) {
        Native.I
            .stakeDeregistrationNew(new RPtr(stakeCredential))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void txInputsBuilderNew( Promise promise) {
        Native.I
            .txInputsBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddKeyInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddKeyInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddScriptInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddScriptInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddNativeScriptInput(String self, String script, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddNativeScriptInput(new RPtr(self), new RPtr(script), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddPlutusScriptInput(String self, String witness, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddPlutusScriptInput(new RPtr(self), new RPtr(witness), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddBootstrapInput(String self, String hash, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddBootstrapInput(new RPtr(self), new RPtr(hash), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddInput(String self, String address, String input, String amount, Promise promise) {
        Native.I
            .txInputsBuilderAddInput(new RPtr(self), new RPtr(address), new RPtr(input), new RPtr(amount))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderCountMissingInputScripts(String self, Promise promise) {
        Native.I
            .txInputsBuilderCountMissingInputScripts(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddRequiredNativeInputScripts(String self, String scripts, Promise promise) {
        Native.I
            .txInputsBuilderAddRequiredNativeInputScripts(new RPtr(self), new RPtr(scripts))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddRequiredPlutusInputScripts(String self, String scripts, Promise promise) {
        Native.I
            .txInputsBuilderAddRequiredPlutusInputScripts(new RPtr(self), new RPtr(scripts))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddRequiredScriptInputWitnesses(String self, String inputsWithWit, Promise promise) {
        Native.I
            .txInputsBuilderAddRequiredScriptInputWitnesses(new RPtr(self), new RPtr(inputsWithWit))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderGetRefInputs(String self, Promise promise) {
        Native.I
            .txInputsBuilderGetRefInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderGetNativeInputScripts(String self, Promise promise) {
        Native.I
            .txInputsBuilderGetNativeInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderGetPlutusInputScripts(String self, Promise promise) {
        Native.I
            .txInputsBuilderGetPlutusInputScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderLen(String self, Promise promise) {
        Native.I
            .txInputsBuilderLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddRequiredSigner(String self, String key, Promise promise) {
        Native.I
            .txInputsBuilderAddRequiredSigner(new RPtr(self), new RPtr(key))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderAddRequiredSigners(String self, String keys, Promise promise) {
        Native.I
            .txInputsBuilderAddRequiredSigners(new RPtr(self), new RPtr(keys))
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderTotalValue(String self, Promise promise) {
        Native.I
            .txInputsBuilderTotalValue(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderInputs(String self, Promise promise) {
        Native.I
            .txInputsBuilderInputs(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void txInputsBuilderInputsOption(String self, Promise promise) {
        Native.I
            .txInputsBuilderInputsOption(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void valueToBytes(String self, Promise promise) {
        Native.I
            .valueToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void valueFromBytes(String bytes, Promise promise) {
        Native.I
            .valueFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueToHex(String self, Promise promise) {
        Native.I
            .valueToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void valueFromHex(String hexStr, Promise promise) {
        Native.I
            .valueFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueToJson(String self, Promise promise) {
        Native.I
            .valueToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void valueFromJson(String json, Promise promise) {
        Native.I
            .valueFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueNew(String coin, Promise promise) {
        Native.I
            .valueNew(new RPtr(coin))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueNewFromAssets(String multiasset, Promise promise) {
        Native.I
            .valueNewFromAssets(new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueNewWithAssets(String coin, String multiasset, Promise promise) {
        Native.I
            .valueNewWithAssets(new RPtr(coin), new RPtr(multiasset))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueZero( Promise promise) {
        Native.I
            .valueZero()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueIsZero(String self, Promise promise) {
        Native.I
            .valueIsZero(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void valueCoin(String self, Promise promise) {
        Native.I
            .valueCoin(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueSetCoin(String self, String coin, Promise promise) {
        Native.I
            .valueSetCoin(new RPtr(self), new RPtr(coin))
            .pour(promise);
    }

    @ReactMethod
    public final void valueMultiasset(String self, Promise promise) {
        Native.I
            .valueMultiasset(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueSetMultiasset(String self, String multiasset, Promise promise) {
        Native.I
            .valueSetMultiasset(new RPtr(self), new RPtr(multiasset))
            .pour(promise);
    }

    @ReactMethod
    public final void valueCheckedAdd(String self, String rhs, Promise promise) {
        Native.I
            .valueCheckedAdd(new RPtr(self), new RPtr(rhs))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueCheckedSub(String self, String rhsValue, Promise promise) {
        Native.I
            .valueCheckedSub(new RPtr(self), new RPtr(rhsValue))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueClampedSub(String self, String rhsValue, Promise promise) {
        Native.I
            .valueClampedSub(new RPtr(self), new RPtr(rhsValue))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void valueCompare(String self, String rhsValue, Promise promise) {
        Native.I
            .valueCompare(new RPtr(self), new RPtr(rhsValue))
            .map(Long::longValue)
            .pour(promise);
    }


    @ReactMethod
    public final void bip32PublicKeyDerive(String self, Double index, Promise promise) {
        Native.I
            .bip32PublicKeyDerive(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyToRawKey(String self, Promise promise) {
        Native.I
            .bip32PublicKeyToRawKey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .bip32PublicKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyAsBytes(String self, Promise promise) {
        Native.I
            .bip32PublicKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .bip32PublicKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyToBech32(String self, Promise promise) {
        Native.I
            .bip32PublicKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyChaincode(String self, Promise promise) {
        Native.I
            .bip32PublicKeyChaincode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyToHex(String self, Promise promise) {
        Native.I
            .bip32PublicKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .bip32PublicKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void auxiliaryDataToBytes(String self, Promise promise) {
        Native.I
            .auxiliaryDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataFromBytes(String bytes, Promise promise) {
        Native.I
            .auxiliaryDataFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataToHex(String self, Promise promise) {
        Native.I
            .auxiliaryDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataFromHex(String hexStr, Promise promise) {
        Native.I
            .auxiliaryDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataToJson(String self, Promise promise) {
        Native.I
            .auxiliaryDataToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataFromJson(String json, Promise promise) {
        Native.I
            .auxiliaryDataFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataNew( Promise promise) {
        Native.I
            .auxiliaryDataNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataMetadata(String self, Promise promise) {
        Native.I
            .auxiliaryDataMetadata(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetMetadata(String self, String metadata, Promise promise) {
        Native.I
            .auxiliaryDataSetMetadata(new RPtr(self), new RPtr(metadata))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataNativeScripts(String self, Promise promise) {
        Native.I
            .auxiliaryDataNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetNativeScripts(String self, String nativeScripts, Promise promise) {
        Native.I
            .auxiliaryDataSetNativeScripts(new RPtr(self), new RPtr(nativeScripts))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataPlutusScripts(String self, Promise promise) {
        Native.I
            .auxiliaryDataPlutusScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataSetPlutusScripts(String self, String plutusScripts, Promise promise) {
        Native.I
            .auxiliaryDataSetPlutusScripts(new RPtr(self), new RPtr(plutusScripts))
            .pour(promise);
    }


    @ReactMethod
    public final void scriptNOfKToBytes(String self, Promise promise) {
        Native.I
            .scriptNOfKToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptNOfKFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKToHex(String self, Promise promise) {
        Native.I
            .scriptNOfKToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptNOfKFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKToJson(String self, Promise promise) {
        Native.I
            .scriptNOfKToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKFromJson(String json, Promise promise) {
        Native.I
            .scriptNOfKFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKN(String self, Promise promise) {
        Native.I
            .scriptNOfKN(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKNativeScripts(String self, Promise promise) {
        Native.I
            .scriptNOfKNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptNOfKNew(Double n, String nativeScripts, Promise promise) {
        Native.I
            .scriptNOfKNew(n.longValue(), new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void scriptRefToBytes(String self, Promise promise) {
        Native.I
            .scriptRefToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptRefFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefToHex(String self, Promise promise) {
        Native.I
            .scriptRefToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptRefFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefToJson(String self, Promise promise) {
        Native.I
            .scriptRefToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefFromJson(String json, Promise promise) {
        Native.I
            .scriptRefFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefNewNativeScript(String nativeScript, Promise promise) {
        Native.I
            .scriptRefNewNativeScript(new RPtr(nativeScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefNewPlutusScript(String plutusScript, Promise promise) {
        Native.I
            .scriptRefNewPlutusScript(new RPtr(plutusScript))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefIsNativeScript(String self, Promise promise) {
        Native.I
            .scriptRefIsNativeScript(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefIsPlutusScript(String self, Promise promise) {
        Native.I
            .scriptRefIsPlutusScript(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefNativeScript(String self, Promise promise) {
        Native.I
            .scriptRefNativeScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptRefPlutusScript(String self, Promise promise) {
        Native.I
            .scriptRefPlutusScript(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionBodiesToBytes(String self, Promise promise) {
        Native.I
            .transactionBodiesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionBodiesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesToHex(String self, Promise promise) {
        Native.I
            .transactionBodiesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionBodiesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesToJson(String self, Promise promise) {
        Native.I
            .transactionBodiesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesFromJson(String json, Promise promise) {
        Native.I
            .transactionBodiesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesNew( Promise promise) {
        Native.I
            .transactionBodiesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesLen(String self, Promise promise) {
        Native.I
            .transactionBodiesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesGet(String self, Double index, Promise promise) {
        Native.I
            .transactionBodiesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBodiesAdd(String self, String elem, Promise promise) {
        Native.I
            .transactionBodiesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void networkIdToBytes(String self, Promise promise) {
        Native.I
            .networkIdToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdFromBytes(String bytes, Promise promise) {
        Native.I
            .networkIdFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdToHex(String self, Promise promise) {
        Native.I
            .networkIdToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdFromHex(String hexStr, Promise promise) {
        Native.I
            .networkIdFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdToJson(String self, Promise promise) {
        Native.I
            .networkIdToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdFromJson(String json, Promise promise) {
        Native.I
            .networkIdFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdTestnet( Promise promise) {
        Native.I
            .networkIdTestnet()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdMainnet( Promise promise) {
        Native.I
            .networkIdMainnet()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkIdKind(String self, Promise promise) {
        Native.I
            .networkIdKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }


    @ReactMethod
    public final void dataCostNewCoinsPerWord(String coinsPerWord, Promise promise) {
        Native.I
            .dataCostNewCoinsPerWord(new RPtr(coinsPerWord))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dataCostNewCoinsPerByte(String coinsPerByte, Promise promise) {
        Native.I
            .dataCostNewCoinsPerByte(new RPtr(coinsPerByte))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void dataCostCoinsPerByte(String self, Promise promise) {
        Native.I
            .dataCostCoinsPerByte(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void publicKeyFromBech32(String bech32Str, Promise promise) {
        Native.I
            .publicKeyFromBech32(bech32Str)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyToBech32(String self, Promise promise) {
        Native.I
            .publicKeyToBech32(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyAsBytes(String self, Promise promise) {
        Native.I
            .publicKeyAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .publicKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyVerify(String self, String data, String signature, Promise promise) {
        Native.I
            .publicKeyVerify(new RPtr(self), Base64.encodeToString(data), new RPtr(signature))
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyHash(String self, Promise promise) {
        Native.I
            .publicKeyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyToHex(String self, Promise promise) {
        Native.I
            .publicKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void publicKeyFromHex(String hexStr, Promise promise) {
        Native.I
            .publicKeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void genesisHashesToBytes(String self, Promise promise) {
        Native.I
            .genesisHashesToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesFromBytes(String bytes, Promise promise) {
        Native.I
            .genesisHashesFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesToHex(String self, Promise promise) {
        Native.I
            .genesisHashesToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesFromHex(String hexStr, Promise promise) {
        Native.I
            .genesisHashesFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesToJson(String self, Promise promise) {
        Native.I
            .genesisHashesToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesFromJson(String json, Promise promise) {
        Native.I
            .genesisHashesFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesNew( Promise promise) {
        Native.I
            .genesisHashesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesLen(String self, Promise promise) {
        Native.I
            .genesisHashesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesGet(String self, Double index, Promise promise) {
        Native.I
            .genesisHashesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisHashesAdd(String self, String elem, Promise promise) {
        Native.I
            .genesisHashesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void headerBodyToBytes(String self, Promise promise) {
        Native.I
            .headerBodyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyFromBytes(String bytes, Promise promise) {
        Native.I
            .headerBodyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyToHex(String self, Promise promise) {
        Native.I
            .headerBodyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyFromHex(String hexStr, Promise promise) {
        Native.I
            .headerBodyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyToJson(String self, Promise promise) {
        Native.I
            .headerBodyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyFromJson(String json, Promise promise) {
        Native.I
            .headerBodyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyBlockNumber(String self, Promise promise) {
        Native.I
            .headerBodyBlockNumber(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodySlot(String self, Promise promise) {
        Native.I
            .headerBodySlot(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodySlotBignum(String self, Promise promise) {
        Native.I
            .headerBodySlotBignum(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyPrevHash(String self, Promise promise) {
        Native.I
            .headerBodyPrevHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyIssuerVkey(String self, Promise promise) {
        Native.I
            .headerBodyIssuerVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyVrfVkey(String self, Promise promise) {
        Native.I
            .headerBodyVrfVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyHasNonceAndLeaderVrf(String self, Promise promise) {
        Native.I
            .headerBodyHasNonceAndLeaderVrf(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyNonceVrfOrNothing(String self, Promise promise) {
        Native.I
            .headerBodyNonceVrfOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyLeaderVrfOrNothing(String self, Promise promise) {
        Native.I
            .headerBodyLeaderVrfOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyHasVrfResult(String self, Promise promise) {
        Native.I
            .headerBodyHasVrfResult(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyVrfResultOrNothing(String self, Promise promise) {
        Native.I
            .headerBodyVrfResultOrNothing(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyBlockBodySize(String self, Promise promise) {
        Native.I
            .headerBodyBlockBodySize(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyBlockBodyHash(String self, Promise promise) {
        Native.I
            .headerBodyBlockBodyHash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyOperationalCert(String self, Promise promise) {
        Native.I
            .headerBodyOperationalCert(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyProtocolVersion(String self, Promise promise) {
        Native.I
            .headerBodyProtocolVersion(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyNew(Double blockNumber, Double slot, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .headerBodyNew(blockNumber.longValue(), slot.longValue(), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyNewWithPrevHash(Double blockNumber, Double slot, String prevHash, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .headerBodyNewWithPrevHash(blockNumber.longValue(), slot.longValue(), new RPtr(prevHash), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void headerBodyNewHeaderbody(Double blockNumber, String slot, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .headerBodyNewHeaderbody(blockNumber.longValue(), new RPtr(slot), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void headerBodyNewHeaderbodyWithPrevHash(Double blockNumber, String slot, String prevHash, String issuerVkey, String vrfVkey, String vrfResult, Double blockBodySize, String blockBodyHash, String operationalCert, String protocolVersion, Promise promise) {
        Native.I
            .headerBodyNewHeaderbodyWithPrevHash(blockNumber.longValue(), new RPtr(slot), new RPtr(prevHash), new RPtr(issuerVkey), new RPtr(vrfVkey), new RPtr(vrfResult), blockBodySize.longValue(), new RPtr(blockBodyHash), new RPtr(operationalCert), new RPtr(protocolVersion))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void mIRToStakeCredentialsToBytes(String self, Promise promise) {
        Native.I
            .mIRToStakeCredentialsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsFromBytes(String bytes, Promise promise) {
        Native.I
            .mIRToStakeCredentialsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsToHex(String self, Promise promise) {
        Native.I
            .mIRToStakeCredentialsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsFromHex(String hexStr, Promise promise) {
        Native.I
            .mIRToStakeCredentialsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsToJson(String self, Promise promise) {
        Native.I
            .mIRToStakeCredentialsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsFromJson(String json, Promise promise) {
        Native.I
            .mIRToStakeCredentialsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsNew( Promise promise) {
        Native.I
            .mIRToStakeCredentialsNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsLen(String self, Promise promise) {
        Native.I
            .mIRToStakeCredentialsLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsInsert(String self, String cred, String delta, Promise promise) {
        Native.I
            .mIRToStakeCredentialsInsert(new RPtr(self), new RPtr(cred), new RPtr(delta))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsGet(String self, String cred, Promise promise) {
        Native.I
            .mIRToStakeCredentialsGet(new RPtr(self), new RPtr(cred))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void mIRToStakeCredentialsKeys(String self, Promise promise) {
        Native.I
            .mIRToStakeCredentialsKeys(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void singleHostAddrToBytes(String self, Promise promise) {
        Native.I
            .singleHostAddrToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrFromBytes(String bytes, Promise promise) {
        Native.I
            .singleHostAddrFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrToHex(String self, Promise promise) {
        Native.I
            .singleHostAddrToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrFromHex(String hexStr, Promise promise) {
        Native.I
            .singleHostAddrFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrToJson(String self, Promise promise) {
        Native.I
            .singleHostAddrToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrFromJson(String json, Promise promise) {
        Native.I
            .singleHostAddrFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrPort(String self, Promise promise) {
        Native.I
            .singleHostAddrPort(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrIpv4(String self, Promise promise) {
        Native.I
            .singleHostAddrIpv4(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrIpv6(String self, Promise promise) {
        Native.I
            .singleHostAddrIpv6(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNew( Promise promise) {
        Native.I
            .singleHostAddrNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithPort(Double port, Promise promise) {
        Native.I
            .singleHostAddrNewWithPort(port.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithIpv4(String ipv4, Promise promise) {
        Native.I
            .singleHostAddrNewWithIpv4(new RPtr(ipv4))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithPortIpv4(Double port, String ipv4, Promise promise) {
        Native.I
            .singleHostAddrNewWithPortIpv4(port.longValue(), new RPtr(ipv4))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithIpv6(String ipv6, Promise promise) {
        Native.I
            .singleHostAddrNewWithIpv6(new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithPortIpv6(Double port, String ipv6, Promise promise) {
        Native.I
            .singleHostAddrNewWithPortIpv6(port.longValue(), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithIpv4Ipv6(String ipv4, String ipv6, Promise promise) {
        Native.I
            .singleHostAddrNewWithIpv4Ipv6(new RPtr(ipv4), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void singleHostAddrNewWithPortIpv4Ipv6(Double port, String ipv4, String ipv6, Promise promise) {
        Native.I
            .singleHostAddrNewWithPortIpv4Ipv6(port.longValue(), new RPtr(ipv4), new RPtr(ipv6))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void moveInstantaneousRewardsCertToBytes(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertFromBytes(String bytes, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertToHex(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertFromHex(String hexStr, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertToJson(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertFromJson(String json, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertMoveInstantaneousReward(String self, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertMoveInstantaneousReward(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void moveInstantaneousRewardsCertNew(String moveInstantaneousReward, Promise promise) {
        Native.I
            .moveInstantaneousRewardsCertNew(new RPtr(moveInstantaneousReward))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void genesisDelegateHashFromBytes(String bytes, Promise promise) {
        Native.I
            .genesisDelegateHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisDelegateHashToBytes(String self, Promise promise) {
        Native.I
            .genesisDelegateHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisDelegateHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .genesisDelegateHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisDelegateHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .genesisDelegateHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void genesisDelegateHashToHex(String self, Promise promise) {
        Native.I
            .genesisDelegateHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void genesisDelegateHashFromHex(String hex, Promise promise) {
        Native.I
            .genesisDelegateHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionToBytes(String self, Promise promise) {
        Native.I
            .transactionToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionFromBytes(String bytes, Promise promise) {
        Native.I
            .transactionFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionToHex(String self, Promise promise) {
        Native.I
            .transactionToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionFromHex(String hexStr, Promise promise) {
        Native.I
            .transactionFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionToJson(String self, Promise promise) {
        Native.I
            .transactionToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionFromJson(String json, Promise promise) {
        Native.I
            .transactionFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionBody(String self, Promise promise) {
        Native.I
            .transactionBody(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSet(String self, Promise promise) {
        Native.I
            .transactionWitnessSet(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionIsValid(String self, Promise promise) {
        Native.I
            .transactionIsValid(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void transactionAuxiliaryData(String self, Promise promise) {
        Native.I
            .transactionAuxiliaryData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionSetIsValid(String self, Boolean valid, Promise promise) {
        Native.I
            .transactionSetIsValid(new RPtr(self), valid)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionNew(String body, String witnessSet, Promise promise) {
        Native.I
            .transactionNew(new RPtr(body), new RPtr(witnessSet))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionNewWithAuxiliaryData(String body, String witnessSet, String auxiliaryData, Promise promise) {
        Native.I
            .transactionNewWithAuxiliaryData(new RPtr(body), new RPtr(witnessSet), new RPtr(auxiliaryData))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void vRFVKeyFromBytes(String bytes, Promise promise) {
        Native.I
            .vRFVKeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFVKeyToBytes(String self, Promise promise) {
        Native.I
            .vRFVKeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFVKeyToBech32(String self, String prefix, Promise promise) {
        Native.I
            .vRFVKeyToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFVKeyFromBech32(String bechStr, Promise promise) {
        Native.I
            .vRFVKeyFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void vRFVKeyToHex(String self, Promise promise) {
        Native.I
            .vRFVKeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void vRFVKeyFromHex(String hex, Promise promise) {
        Native.I
            .vRFVKeyFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void transactionOutputBuilderNew( Promise promise) {
        Native.I
            .transactionOutputBuilderNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputBuilderWithAddress(String self, String address, Promise promise) {
        Native.I
            .transactionOutputBuilderWithAddress(new RPtr(self), new RPtr(address))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputBuilderWithDataHash(String self, String dataHash, Promise promise) {
        Native.I
            .transactionOutputBuilderWithDataHash(new RPtr(self), new RPtr(dataHash))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputBuilderWithPlutusData(String self, String data, Promise promise) {
        Native.I
            .transactionOutputBuilderWithPlutusData(new RPtr(self), new RPtr(data))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputBuilderWithScriptRef(String self, String scriptRef, Promise promise) {
        Native.I
            .transactionOutputBuilderWithScriptRef(new RPtr(self), new RPtr(scriptRef))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputBuilderNext(String self, Promise promise) {
        Native.I
            .transactionOutputBuilderNext(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void networkInfoNew(Double networkId, Double protocolMagic, Promise promise) {
        Native.I
            .networkInfoNew(networkId.longValue(), protocolMagic.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkInfoNetworkId(String self, Promise promise) {
        Native.I
            .networkInfoNetworkId(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void networkInfoProtocolMagic(String self, Promise promise) {
        Native.I
            .networkInfoProtocolMagic(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void networkInfoTestnet( Promise promise) {
        Native.I
            .networkInfoTestnet()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void networkInfoMainnet( Promise promise) {
        Native.I
            .networkInfoMainnet()
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void ed25519KeyHashFromBytes(String bytes, Promise promise) {
        Native.I
            .ed25519KeyHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashToBytes(String self, Promise promise) {
        Native.I
            .ed25519KeyHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .ed25519KeyHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .ed25519KeyHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashToHex(String self, Promise promise) {
        Native.I
            .ed25519KeyHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashFromHex(String hex, Promise promise) {
        Native.I
            .ed25519KeyHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void bootstrapWitnessToBytes(String self, Promise promise) {
        Native.I
            .bootstrapWitnessToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessFromBytes(String bytes, Promise promise) {
        Native.I
            .bootstrapWitnessFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessToHex(String self, Promise promise) {
        Native.I
            .bootstrapWitnessToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessFromHex(String hexStr, Promise promise) {
        Native.I
            .bootstrapWitnessFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessToJson(String self, Promise promise) {
        Native.I
            .bootstrapWitnessToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessFromJson(String json, Promise promise) {
        Native.I
            .bootstrapWitnessFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessVkey(String self, Promise promise) {
        Native.I
            .bootstrapWitnessVkey(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessSignature(String self, Promise promise) {
        Native.I
            .bootstrapWitnessSignature(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessChainCode(String self, Promise promise) {
        Native.I
            .bootstrapWitnessChainCode(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessAttributes(String self, Promise promise) {
        Native.I
            .bootstrapWitnessAttributes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessNew(String vkey, String signature, String chainCode, String attributes, Promise promise) {
        Native.I
            .bootstrapWitnessNew(new RPtr(vkey), new RPtr(signature), Base64.encodeToString(chainCode), Base64.encodeToString(attributes))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void rewardAddressNew(Double network, String payment, Promise promise) {
        Native.I
            .rewardAddressNew(network.longValue(), new RPtr(payment))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressPaymentCred(String self, Promise promise) {
        Native.I
            .rewardAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressToAddress(String self, Promise promise) {
        Native.I
            .rewardAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressFromAddress(String addr, Promise promise) {
        Native.I
            .rewardAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void auxiliaryDataHashFromBytes(String bytes, Promise promise) {
        Native.I
            .auxiliaryDataHashFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataHashToBytes(String self, Promise promise) {
        Native.I
            .auxiliaryDataHashToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataHashToBech32(String self, String prefix, Promise promise) {
        Native.I
            .auxiliaryDataHashToBech32(new RPtr(self), prefix)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataHashFromBech32(String bechStr, Promise promise) {
        Native.I
            .auxiliaryDataHashFromBech32(bechStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataHashToHex(String self, Promise promise) {
        Native.I
            .auxiliaryDataHashToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void auxiliaryDataHashFromHex(String hex, Promise promise) {
        Native.I
            .auxiliaryDataHashFromHex(hex)
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void bootstrapWitnessesNew( Promise promise) {
        Native.I
            .bootstrapWitnessesNew()
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessesLen(String self, Promise promise) {
        Native.I
            .bootstrapWitnessesLen(new RPtr(self))
            .map(Long::longValue)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessesGet(String self, Double index, Promise promise) {
        Native.I
            .bootstrapWitnessesGet(new RPtr(self), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessesAdd(String self, String elem, Promise promise) {
        Native.I
            .bootstrapWitnessesAdd(new RPtr(self), new RPtr(elem))
            .pour(promise);
    }


    @ReactMethod
    public final void exUnitsToBytes(String self, Promise promise) {
        Native.I
            .exUnitsToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsFromBytes(String bytes, Promise promise) {
        Native.I
            .exUnitsFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsToHex(String self, Promise promise) {
        Native.I
            .exUnitsToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsFromHex(String hexStr, Promise promise) {
        Native.I
            .exUnitsFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsToJson(String self, Promise promise) {
        Native.I
            .exUnitsToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsFromJson(String json, Promise promise) {
        Native.I
            .exUnitsFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsMem(String self, Promise promise) {
        Native.I
            .exUnitsMem(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsSteps(String self, Promise promise) {
        Native.I
            .exUnitsSteps(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void exUnitsNew(String mem, String steps, Promise promise) {
        Native.I
            .exUnitsNew(new RPtr(mem), new RPtr(steps))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void relayToBytes(String self, Promise promise) {
        Native.I
            .relayToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void relayFromBytes(String bytes, Promise promise) {
        Native.I
            .relayFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayToHex(String self, Promise promise) {
        Native.I
            .relayToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void relayFromHex(String hexStr, Promise promise) {
        Native.I
            .relayFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayToJson(String self, Promise promise) {
        Native.I
            .relayToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void relayFromJson(String json, Promise promise) {
        Native.I
            .relayFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayNewSingleHostAddr(String singleHostAddr, Promise promise) {
        Native.I
            .relayNewSingleHostAddr(new RPtr(singleHostAddr))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayNewSingleHostName(String singleHostName, Promise promise) {
        Native.I
            .relayNewSingleHostName(new RPtr(singleHostName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayNewMultiHostName(String multiHostName, Promise promise) {
        Native.I
            .relayNewMultiHostName(new RPtr(multiHostName))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayKind(String self, Promise promise) {
        Native.I
            .relayKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void relayAsSingleHostAddr(String self, Promise promise) {
        Native.I
            .relayAsSingleHostAddr(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayAsSingleHostName(String self, Promise promise) {
        Native.I
            .relayAsSingleHostName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void relayAsMultiHostName(String self, Promise promise) {
        Native.I
            .relayAsMultiHostName(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }



    @ReactMethod
    public final void scriptAnyToBytes(String self, Promise promise) {
        Native.I
            .scriptAnyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptAnyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyToHex(String self, Promise promise) {
        Native.I
            .scriptAnyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptAnyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyToJson(String self, Promise promise) {
        Native.I
            .scriptAnyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyFromJson(String json, Promise promise) {
        Native.I
            .scriptAnyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyNativeScripts(String self, Promise promise) {
        Native.I
            .scriptAnyNativeScripts(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptAnyNew(String nativeScripts, Promise promise) {
        Native.I
            .scriptAnyNew(new RPtr(nativeScripts))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void scriptPubkeyToBytes(String self, Promise promise) {
        Native.I
            .scriptPubkeyToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyFromBytes(String bytes, Promise promise) {
        Native.I
            .scriptPubkeyFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyToHex(String self, Promise promise) {
        Native.I
            .scriptPubkeyToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyFromHex(String hexStr, Promise promise) {
        Native.I
            .scriptPubkeyFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyToJson(String self, Promise promise) {
        Native.I
            .scriptPubkeyToJson(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyFromJson(String json, Promise promise) {
        Native.I
            .scriptPubkeyFromJson(json)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyAddrKeyhash(String self, Promise promise) {
        Native.I
            .scriptPubkeyAddrKeyhash(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void scriptPubkeyNew(String addrKeyhash, Promise promise) {
        Native.I
            .scriptPubkeyNew(new RPtr(addrKeyhash))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void pointerAddressNew(Double network, String payment, String stake, Promise promise) {
        Native.I
            .pointerAddressNew(network.longValue(), new RPtr(payment), new RPtr(stake))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerAddressPaymentCred(String self, Promise promise) {
        Native.I
            .pointerAddressPaymentCred(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerAddressStakePointer(String self, Promise promise) {
        Native.I
            .pointerAddressStakePointer(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerAddressToAddress(String self, Promise promise) {
        Native.I
            .pointerAddressToAddress(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void pointerAddressFromAddress(String addr, Promise promise) {
        Native.I
            .pointerAddressFromAddress(new RPtr(addr))
            .map(RPtr::toJs)
            .pour(promise);
    }


    @ReactMethod
    public final void plutusDataToBytes(String self, Promise promise) {
        Native.I
            .plutusDataToBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataFromBytes(String bytes, Promise promise) {
        Native.I
            .plutusDataFromBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataToHex(String self, Promise promise) {
        Native.I
            .plutusDataToHex(new RPtr(self))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataFromHex(String hexStr, Promise promise) {
        Native.I
            .plutusDataFromHex(hexStr)
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewConstrPlutusData(String constrPlutusData, Promise promise) {
        Native.I
            .plutusDataNewConstrPlutusData(new RPtr(constrPlutusData))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewEmptyConstrPlutusData(String alternative, Promise promise) {
        Native.I
            .plutusDataNewEmptyConstrPlutusData(new RPtr(alternative))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewMap(String map, Promise promise) {
        Native.I
            .plutusDataNewMap(new RPtr(map))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewList(String list, Promise promise) {
        Native.I
            .plutusDataNewList(new RPtr(list))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewInteger(String integer, Promise promise) {
        Native.I
            .plutusDataNewInteger(new RPtr(integer))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataNewBytes(String bytes, Promise promise) {
        Native.I
            .plutusDataNewBytes(Base64.encodeToString(bytes))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataKind(String self, Promise promise) {
        Native.I
            .plutusDataKind(new RPtr(self))
            none.map(Long::intValue)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataAsConstrPlutusData(String self, Promise promise) {
        Native.I
            .plutusDataAsConstrPlutusData(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataAsMap(String self, Promise promise) {
        Native.I
            .plutusDataAsMap(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataAsList(String self, Promise promise) {
        Native.I
            .plutusDataAsList(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataAsInteger(String self, Promise promise) {
        Native.I
            .plutusDataAsInteger(new RPtr(self))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataAsBytes(String self, Promise promise) {
        Native.I
            .plutusDataAsBytes(new RPtr(self))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataToJson(String self, Double schema, Promise promise) {
        Native.I
            .plutusDataToJson(new RPtr(self), schema.intValue())
            .pour(promise);
    }

    @ReactMethod
    public final void plutusDataFromJson(String json, Double schema, Promise promise) {
        Native.I
            .plutusDataFromJson(json, schema.intValue())
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
    public final void calculateExUnitsCeilCost(String exUnits, String exUnitPrices, Promise promise) {
        Native.I
            .calculateExUnitsCeilCost(new RPtr(exUnits), new RPtr(exUnitPrices))
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
    public final void encryptWithPassword(String password, String salt, String nonce, String data, Promise promise) {
        Native.I
            .encryptWithPassword(password, salt, nonce, data)
            .pour(promise);
    }

    @ReactMethod
    public final void decodeMetadatumToJsonStr(String metadatum, Double schema, Promise promise) {
        Native.I
            .decodeMetadatumToJsonStr(new RPtr(metadatum), schema.intValue())
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
    public final void decodeArbitraryBytesFromMetadatum(String metadata, Promise promise) {
        Native.I
            .decodeArbitraryBytesFromMetadatum(new RPtr(metadata))
            .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
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
    public final void encodeJsonStrToNativeScript(String json, String selfXpub, Double schema, Promise promise) {
        Native.I
            .encodeJsonStrToNativeScript(json, selfXpub, schema.intValue())
            .map(RPtr::toJs)
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
    public final void encodeJsonStrToPlutusDatum(String json, Double schema, Promise promise) {
        Native.I
            .encodeJsonStrToPlutusDatum(json, schema.intValue())
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
    public final void hashAuxiliaryData(String auxiliaryData, Promise promise) {
        Native.I
            .hashAuxiliaryData(new RPtr(auxiliaryData))
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
    public final void minAdaForOutput(String output, String dataCost, Promise promise) {
        Native.I
            .minAdaForOutput(new RPtr(output), new RPtr(dataCost))
            .map(RPtr::toJs)
            .pour(promise);
    }

    @ReactMethod
    public final void encodeArbitraryBytesAsMetadatum(String bytes, Promise promise) {
        Native.I
            .encodeArbitraryBytesAsMetadatum(Base64.encodeToString(bytes))
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

}
