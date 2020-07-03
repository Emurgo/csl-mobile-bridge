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

    // Address

    @ReactMethod
    public final void addressFromBytes(String bytes, Promise promise) {
        Native.I
                .addressFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void addressToBytes(String address, Promise promise) {
        Native.I
                .addressToBytes(new RPtr(address))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    // AddrKeyHash

    @ReactMethod
    public final void addrKeyHashFromBytes(String bytes, Promise promise) {
        Native.I
                .addrKeyHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void addrKeyHashToBytes(String addrKeyHash, Promise promise) {
        Native.I
                .addrKeyHashToBytes(new RPtr(addrKeyHash))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    // TransactionHash

    @ReactMethod
    public final void transactionHashFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionHashToBytes(String addrKeyHash, Promise promise) {
        Native.I
                .transactionHashToBytes(new RPtr(addrKeyHash))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    // StakeCredential

    @ReactMethod
    public final void stakeCredentialFromKeyHash(String addrKeyHash, Promise promise) {
        Native.I
                .stakeCredentialFromKeyHash(new RPtr(addrKeyHash))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialToKeyHash(String stakeCredential, Promise promise) {
        Native.I
                .stakeCredentialToKeyHash(new RPtr(stakeCredential))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialKind(String stakeCredential, Promise promise) {
        Native.I
                .stakeCredentialKind(new RPtr(stakeCredential))
                .pour(promise);
    }

    // BaseAddress

    @ReactMethod
    public final void baseAddressNew(Integer network, String payment, String stake, Promise promise) {
        Native.I
                .baseAddressNew(network, new RPtr(payment), new RPtr(stake))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void baseAddressPaymentCred(String baseAddress, Promise promise) {
        Native.I
                .baseAddressPaymentCred(new RPtr(baseAddress))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void baseAddressStakeCred(String baseAddress, Promise promise) {
        Native.I
                .baseAddressStakeCred(new RPtr(baseAddress))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // UnitInterval

    @ReactMethod
    public final void unitIntervalFromBytes(String bytes, Promise promise) {
        Native.I
                .unitIntervalFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);

    @ReactMethod
    public final void unitIntervalToBytes(String unitInterval, Promise promise) {
        Native.I
                .unitIntervalToBytes(new RPtr(unitInterval))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);

    @ReactMethod
    public final void unitIntervalNew(Double index0, Double index1, Promise promise) {
        Native.I
                .unitIntervalNew(index0.longValue(), index1.longValue())
                .map(RPtr::toJs)
                .pour(promise);

    // TransactionInput

    @ReactMethod
    public final void transactionInputFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionInputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputToBytes(String transactionInput, Promise promise) {
        Native.I
                .transactionInputToBytes(new RPtr(transactionInput))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    public final void transactionInputNew(String transactionId, Double index, Promise promise) {
        Native.I
                .transactionInputNew(new RPtr(transactionId), index.longValue())
                .map(RPtr::toJs)
                .pour(promise);
    }

    // TransactionOutput

    @ReactMethod
    public final void transactionOutputFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionOutputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputToBytes(String transactionOutput, Promise promise) {
        Native.I
                .transactionOutputToBytes(new RPtr(transactionOutput))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputNew(String address, Double amount, Promise promise) {
        Native.I
                .transactionOutputNew(new RPtr(address), amount.longValue())
                .map(RPtr::toJs)
                .pour(promise);
    }

}
