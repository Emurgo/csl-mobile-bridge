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

    // Utils

    @ReactMethod
    public final void makeIcarusBootstrapWitness(String txBodyHash, String addr, String key, Promise promise) {
        Native.I
                .makeIcarusBootstrapWitness(new RPtr(txBodyHash), new RPtr(addr), new RPtr(key))
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

    // BigNum

    @ReactMethod
    public final void bigNumFromStr(String string, Promise promise) {
        Native.I
                .bigNumFromStr(string)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bigNumToStr(String bigNum, Promise promise) {
        Native.I
                .bigNumToStr(new RPtr(bigNum))
                .pour(promise);
    }

    // Bip32PrivateKey

@ReactMethod
public final void bip32PrivateKeyDerive(String bip32PrivateKey, Double index, Promise promise) {
    Native.I
            .bip32PrivateKeyDerive(new RPtr(bip32PrivateKey), index.longValue())
            .map(RPtr::toJs)
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyGenerateEd25519Bip32(Promise promise) {
    Native.I
            .bip32PrivateKeyGenerateEd25519Bip32()
            .map(RPtr::toJs)
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyToRawKey(String bip32PrivateKey, Promise promise) {
    Native.I
            .bip32PrivateKeyToRawKey(new RPtr(bip32PrivateKey))
            .map(RPtr::toJs)
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyToPublic(String bip32PrivateKey, Promise promise) {
    Native.I
            .bip32PrivateKeyToPublic(new RPtr(bip32PrivateKey))
            .map(RPtr::toJs)
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyFromBytes(String bytes, Promise promise) {
    Native.I
            .bip32PrivateKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyAsBytes(String bip32PrivateKey, Promise promise) {
    Native.I
            .bip32PrivateKeyAsBytes(new RPtr(bip32PrivateKey))
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
public final void bip32PrivateKeyToBech32(String bip32PrivateKey, Promise promise) {
    Native.I
            .bip32PrivateKeyToBech32(new RPtr(bip32PrivateKey))
            .pour(promise);
}

@ReactMethod
public final void bip32PrivateKeyFromBip39Entropy(String entropy, String password, Promise promise) {
    Native.I
            .bip32PrivateKeyFromBip39Entropy(Base64.decode(entropy, Base64.DEFAULT), Base64.decode(password, Base64.DEFAULT))
            .map(RPtr::toJs)
            .pour(promise);
}

    // ByronAddress

    @ReactMethod
    public final void byronAddressToBase58(String byronAddress, Promise promise) {
        Native.I
                .byronAddressToBase58(new RPtr(byronAddress))
                .pour(promise);
    }

    @ReactMethod
    public final void byronAddressFromBase58(String string, Promise promise) {
        Native.I
                .byronAddressFromBase58(string)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void byronAddressIsValid(String string, Promise promise) {
        Native.I
                .byronAddressIsValid(string)
                .pour(promise);
    }

    @ReactMethod
    public final void byronAddressFromAddress(String address, Promise promise) {
        Native.I
                .byronAddressFromAddress(new RPtr(address))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Address

    @ReactMethod
    public final void addressToBytes(String address, Promise promise) {
        Native.I
                .addressToBytes(new RPtr(address))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void addressFromBytes(String bytes, Promise promise) {
        Native.I
                .addressFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void addressToBech32(String address, Promise promise) {
        Native.I
                .addressToBech32(new RPtr(address))
                .pour(promise);
    }

    @ReactMethod
    public final void addressFromBech32(String string, Promise promise) {
        Native.I
                .addressFromBech32(string)
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Ed25519KeyHash

    @ReactMethod
    public final void ed25519KeyHashToBytes(String ed25519KeyHash, Promise promise) {
        Native.I
                .ed25519KeyHashToBytes(new RPtr(ed25519KeyHash))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void ed25519KeyHashFromBytes(String bytes, Promise promise) {
        Native.I
                .ed25519KeyHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // TransactionHash

    @ReactMethod
    public final void transactionHashToBytes(String transactionHash, Promise promise) {
        Native.I
                .transactionHashToBytes(new RPtr(transactionHash))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionHashFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // StakeCredential

    @ReactMethod
    public final void stakeCredentialFromKeyHash(String keyHash, Promise promise) {
        Native.I
                .stakeCredentialFromKeyHash(new RPtr(keyHash))
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

    @ReactMethod
    public final void stakeCredentialToBytes(String stakeCredential, Promise promise) {
        Native.I
                .stakeCredentialToBytes(new RPtr(stakeCredential))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void stakeCredentialFromBytes(String bytes, Promise promise) {
        Native.I
                .stakeCredentialFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
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

    @ReactMethod
    public final void baseAddressFromAddress(String address, Promise promise) {
        Native.I
                .baseAddressFromAddress(new RPtr(address))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // UnitInterval

    @ReactMethod
    public final void unitIntervalToBytes(String unitInterval, Promise promise) {
        Native.I
                .unitIntervalToBytes(new RPtr(unitInterval))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void unitIntervalFromBytes(String bytes, Promise promise) {
        Native.I
                .unitIntervalFromBytes(Base64.decode(bytes, Base64.DEFAULT))
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

    // TransactionInput

    @ReactMethod
    public final void transactionInputToBytes(String transactionInput, Promise promise) {
        Native.I
                .transactionInputToBytes(new RPtr(transactionInput))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionInputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputTransactionId(String transactionInput, Promise promise) {
        Native.I
                .transactionInputTransactionId(new RPtr(transactionInput))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputIndex(String transactionInput, Promise promise) {
        Native.I
                .transactionInputIndex(new RPtr(transactionInput))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputNew(String transactionId, Double index, Promise promise) {
        Native.I
                .transactionInputNew(new RPtr(transactionId), index.longValue())
                .map(RPtr::toJs)
                .pour(promise);
    }

    // TransactionOutput

    @ReactMethod
    public final void transactionOutputToBytes(String transactionOutput, Promise promise) {
        Native.I
                .transactionOutputToBytes(new RPtr(transactionOutput))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionOutputFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputNew(String address, String amount, Promise promise) {
        Native.I
                .transactionOutputNew(new RPtr(address), new RPtr(amount))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // LinearFee

    @ReactMethod
    public final void linearFeeCoefficient(String linearFee, Promise promise) {
        Native.I
                .linearFeeCoefficient(new RPtr(linearFee))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void linearFeeConstant(String linearFee, Promise promise) {
        Native.I
                .linearFeeConstant(new RPtr(linearFee))
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

    // Vkeywitnesses

    @ReactMethod
    public final void vkeywitnessesNew(Promise promise) {
        Native.I
                .vkeywitnessesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesLen(String vkwitnesses, Promise promise) {
        Native.I
                .vkeywitnessesLen(new RPtr(vkwitnesses))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesAdd(String vkwitnesses, String item, Promise promise) {
        Native.I
                .vkeywitnessesAdd(new RPtr(vkwitnesses), new RPtr(item))
                .pour(promise);
    }

    // BootstrapWitnesses

    @ReactMethod
    public final void bootstrapWitnessesNew(Promise promise) {
        Native.I
                .bootstrapWitnessesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessesLen(String witnesses, Promise promise) {
        Native.I
                .bootstrapWitnessesLen(new RPtr(witnesses))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessesAdd(String witnesses, String item, Promise promise) {
        Native.I
                .bootstrapWitnessesAdd(new RPtr(witnesses), new RPtr(item))
                .pour(promise);
    }

    // TransactionWitnessSet

    @ReactMethod
    public final void transactionWitnessSetNew(Promise promise) {
        Native.I
                .transactionWitnessSetNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetVkeys(String witnessSet, String vkeys, Promise promise) {
        Native.I
                .transactionWitnessSetSetVkeys(new RPtr(witnessSet), new RPtr(vkeys))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionWitnessSetSetBootstraps(String witnessSet, String bootstraps, Promise promise) {
        Native.I
                .transactionWitnessSetSetBootstraps(new RPtr(witnessSet), new RPtr(bootstraps))
                .pour(promise);
    }

    // TransactionBody

    @ReactMethod
    public final void transactionBodyToBytes(String transactionBody, Promise promise) {
        Native.I
                .transactionBodyToBytes(new RPtr(transactionBody))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionBodyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Transaction

    @ReactMethod
    public final void transactionBody(String tx, Promise promise) {
        Native.I
                .transactionBody(new RPtr(tx))
                .map(RPtr::toJs)
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
    public final void transactionToBytes(String transaction, Promise promise) {
        Native.I
                .transactionToBytes(new RPtr(transaction))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionFromBytes(String bytes, Promise promise) {
        Native.I
                .transactionFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // TransactionBuilder

    @ReactMethod
    public final void transactionBuilderAddKeyInput(String txBuilder, String hash, String input, String amount, Promise promise) {
        Native.I
                .transactionBuilderAddKeyInput(new RPtr(txBuilder), new RPtr(hash), new RPtr(input), new RPtr(amount))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddBootstrapInput(String txBuilder, String hash, String input, String amount, Promise promise) {
        Native.I
                .transactionBuilderAddBootstrapInput(new RPtr(txBuilder), new RPtr(hash), new RPtr(input), new RPtr(amount))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddOutput(String txBuilder, String output, Promise promise) {
        Native.I
                .transactionBuilderAddOutput(new RPtr(txBuilder), new RPtr(output))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetFee(String txBuilder, String fee, Promise promise) {
        Native.I
                .transactionBuilderSetFee(new RPtr(txBuilder), new RPtr(fee))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetTtl(String txBuilder, Double ttl, Promise promise) {
        Native.I
                .transactionBuilderSetTtl(new RPtr(txBuilder), ttl.longValue())
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderNew(String linearFee, String minimumUtxoVal, String poolDeposit, String keyDeposit, Promise promise) {
        Native.I
                .transactionBuilderNew(new RPtr(linearFee), new RPtr(minimumUtxoVal), new RPtr(poolDeposit), new RPtr(keyDeposit))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetExplicitInput(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderGetExplicitInput(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetImplicitInput(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderGetImplicitInput(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetExplicitOutput(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderGetExplicitOutput(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderAddChangeIfNeeded(String txBuilder, String address, Promise promise) {
        Native.I
                .transactionBuilderAddChangeIfNeeded(new RPtr(txBuilder), new RPtr(address))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderBuild(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderBuild(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderEstimateFee(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderEstimateFee(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

}
