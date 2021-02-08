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

    @ReactMethod
    public final void hashTransaction(String txBody, Promise promise) {
        Native.I
                .hashTransaction(new RPtr(txBody))
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

    @ReactMethod
    public final void bigNumCheckedAdd(String bigNumPtr, String otherPtr, Promise promise) {
        Native.I
                .bigNumCheckedAdd(new RPtr(bigNumPtr), new RPtr(otherPtr))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bigNumCheckedSub(String bigNumPtr, String otherPtr, Promise promise) {
        Native.I
                .bigNumCheckedSub(new RPtr(bigNumPtr), new RPtr(otherPtr))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // AssetName

    @ReactMethod
    public final void assetNameNew(String bytes, Promise promise) {
        Native.I
                .assetNameNew(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void assetNameToBytes(String assetName, Promise promise) {
        Native.I
                .assetNameToBytes(new RPtr(assetName))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void assetNameFromBytes(String bytes, Promise promise) {
        Native.I
                .assetNameFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // AssetNames

    // @ReactMethod
    // public final void assetNamesToBytes(String assetNames, Promise promise) {
    //     Native.I
    //             .assetNamesToBytes(new RPtr(assetNames))
    //             .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
    //             .pour(promise);
    // }
    //
    // @ReactMethod
    // public final void assetNamesFromBytes(String bytes, Promise promise) {
    //     Native.I
    //             .assetNamesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
    //             .map(RPtr::toJs)
    //             .pour(promise);
    // }

    @ReactMethod
    public final void assetNamesNew(Promise promise) {
        Native.I
                .assetNamesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void assetNamesLen(String assetNames, Promise promise) {
        Native.I
                .assetNamesLen(new RPtr(assetNames))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void assetNamesGet(String assetNames, Integer index, Promise promise) {
        Native.I
                .assetNamesGet(new RPtr(assetNames), index)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void assetNamesAdd(String assetNames, String item, Promise promise) {
        Native.I
                .assetNamesAdd(new RPtr(assetNames), new RPtr(item))
                .pour(promise);
    }

    // PublicKey

    @ReactMethod
    public final void publicKeyFromBech32(String bech32, Promise promise) {
        Native.I.publicKeyFromBech32(bech32)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void publicKeyToBech32(String pubPtr, Promise promise) {
        Native.I
                .publicKeyToBech32(new RPtr(pubPtr))
                .pour(promise);
    }

    @ReactMethod
    public final void publicKeyFromBytes(String bytes, Promise promise) {
        Native.I
                .publicKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void publicKeyAsBytes(String pubPtr, Promise promise) {
        Native.I
                .publicKeyAsBytes(new RPtr(pubPtr))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    // @ReactMethod
    // public final void publicKeyVerify(String pubPtr, String data, String signature, Promise promise) {
    //     Native.I
    //             .publicKeyVerify(new RPtr(pubPtr), Base64.decode(data, Base64.DEFAULT), new RPtr(signature))
    //             .pour(promise);
    // }

    @ReactMethod
    public final void publicKeyHash(String pubPtr, Promise promise) {
        Native.I
                .publicKeyHash(new RPtr(pubPtr))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // PrivateKey

    @ReactMethod
    public final void privateKeyToPublic(String prvPtr, Promise promise) {
        Native.I
                .privateKeyToPublic(new RPtr(prvPtr))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void privateKeyAsBytes(String prvPtr, Promise promise) {
        Native.I
                .privateKeyAsBytes(new RPtr(prvPtr))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void privateKeyFromExtendedBytes(String bytes, Promise promise) {
        Native.I
                .privateKeyFromExtendedBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Bip32PublicKey

    @ReactMethod
    public final void bip32PublicKeyDerive(String bip32PublicKey, Double index, Promise promise) {
        Native.I
                .bip32PublicKeyDerive(new RPtr(bip32PublicKey), index.longValue())
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyToRawKey(String bip32PublicKey, Promise promise) {
        Native.I
                .bip32PublicKeyToRawKey(new RPtr(bip32PublicKey))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyFromBytes(String bytes, Promise promise) {
        Native.I
                .bip32PublicKeyFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyAsBytes(String bip32PublicKey, Promise promise) {
        Native.I
                .bip32PublicKeyAsBytes(new RPtr(bip32PublicKey))
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
    public final void bip32PublicKeyToBech32(String bip32PublicKey, Promise promise) {
        Native.I
                .bip32PublicKeyToBech32(new RPtr(bip32PublicKey))
                .pour(promise);
    }

    @ReactMethod
    public final void bip32PublicKeyChaincode(String bip32PublicKey, Promise promise) {
        Native.I
                .bip32PublicKeyChaincode(new RPtr(bip32PublicKey))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
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

    @ReactMethod
    public final void byronAddressToAddress(String byronAddress, Promise promise) {
        Native.I
                .byronAddressToAddress(new RPtr(byronAddress))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void byronAddressByronProtocolMagic(String byronAddress, Promise promise) {
        Native.I
                .byronAddressByronProtocolMagic(new RPtr(byronAddress))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void byronAddressAttributes(String byronAddress, Promise promise) {
        Native.I
                .byronAddressAttributes(new RPtr(byronAddress))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
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
    public final void addressToBech32WithPrefix(String address, String prefix, Promise promise) {
        Native.I
                .addressToBech32WithPrefix(new RPtr(address), prefix)
                .pour(promise);
    }

    @ReactMethod
    public final void addressFromBech32(String string, Promise promise) {
        Native.I
                .addressFromBech32(string)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void addressNetworkId(String address, Promise promise) {
        Native.I
                .addressNetworkId(new RPtr(address))
                .pour(promise);
    }

    // Ed25519Signature

    @ReactMethod
    public final void ed25519SignatureToBytes(String ed25519Signature, Promise promise) {
        Native.I
                .ed25519SignatureToBytes(new RPtr(ed25519Signature))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void ed25519SignatureFromBytes(String bytes, Promise promise) {
        Native.I
                .ed25519SignatureFromBytes(Base64.decode(bytes, Base64.DEFAULT))
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

    // ScriptHash

    @ReactMethod
    public final void scriptHashToBytes(String scriptHash, Promise promise) {
        Native.I
                .scriptHashToBytes(new RPtr(scriptHash))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashFromBytes(String bytes, Promise promise) {
        Native.I
                .scriptHashFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // ScriptHashes

    @ReactMethod
    public final void scriptHashesToBytes(String scriptHashes, Promise promise) {
        Native.I
                .scriptHashesToBytes(new RPtr(scriptHashes))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesFromBytes(String bytes, Promise promise) {
        Native.I
                .scriptHashesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesNew(Promise promise) {
        Native.I
                .scriptHashesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesLen(String scriptHashes, Promise promise) {
        Native.I
                .scriptHashesLen(new RPtr(scriptHashes))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesGet(String scriptHashes, Integer index, Promise promise) {
        Native.I
                .scriptHashesGet(new RPtr(scriptHashes), index)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void scriptHashesAdd(String scriptHashes, String item, Promise promise) {
        Native.I
                .scriptHashesAdd(new RPtr(scriptHashes), new RPtr(item))
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
    public final void stakeCredentialFromScriptHash(String scriptHash, Promise promise) {
        Native.I
                .stakeCredentialFromScriptHash(new RPtr(scriptHash))
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
    public final void stakeCredentialToScriptHash(String stakeCredential, Promise promise) {
        Native.I
                .stakeCredentialToScriptHash(new RPtr(stakeCredential))
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

    // StakeRegistration

    @ReactMethod
    public final void stakeRegistrationNew(String stakeCredential, Promise promise) {
        Native.I
                .stakeRegistrationNew(new RPtr(stakeCredential))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationStakeCredential(String stakeRegistration, Promise promise) {
        Native.I
                .stakeRegistrationStakeCredential(new RPtr(stakeRegistration))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationToBytes(String stakeRegistration, Promise promise) {
        Native.I
                .stakeRegistrationToBytes(new RPtr(stakeRegistration))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void stakeRegistrationFromBytes(String bytes, Promise promise) {
        Native.I
                .stakeRegistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // StakeDeregistration

    @ReactMethod
    public final void stakeDeregistrationNew(String stakeCredential, Promise promise) {
        Native.I
                .stakeDeregistrationNew(new RPtr(stakeCredential))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationStakeCredential(String stakeDeregistration, Promise promise) {
        Native.I
                .stakeDeregistrationStakeCredential(new RPtr(stakeDeregistration))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationToBytes(String stakeDeregistration, Promise promise) {
        Native.I
                .stakeDeregistrationToBytes(new RPtr(stakeDeregistration))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDeregistrationFromBytes(String bytes, Promise promise) {
        Native.I
                .stakeDeregistrationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // StakeDelegation

    @ReactMethod
    public final void stakeDelegationNew(String stakeCredential, String poolKeyhash, Promise promise) {
        Native.I
                .stakeDelegationNew(new RPtr(stakeCredential), new RPtr(poolKeyhash))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationStakeCredential(String stakeDelegation, Promise promise) {
        Native.I
                .stakeDelegationStakeCredential(new RPtr(stakeDelegation))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationPoolKeyhash(String poolKeyHash, Promise promise) {
        Native.I
                .stakeDelegationPoolKeyhash(new RPtr(poolKeyHash))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationToBytes(String stakeDelegation, Promise promise) {
        Native.I
                .stakeDelegationToBytes(new RPtr(stakeDelegation))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void stakeDelegationFromBytes(String bytes, Promise promise) {
        Native.I
                .stakeDelegationFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Certificate

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
    public final void certificateAsStakeRegistration(String certificate, Promise promise) {
        Native.I
                .certificateAsStakeRegistration(new RPtr(certificate))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificateAsStakeDeregistration(String certificate, Promise promise) {
        Native.I
                .certificateAsStakeDeregistration(new RPtr(certificate))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificateAsStakeDelegation(String certificate, Promise promise) {
        Native.I
                .certificateAsStakeDelegation(new RPtr(certificate))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificateToBytes(String certificate, Promise promise) {
        Native.I
                .certificateToBytes(new RPtr(certificate))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void certificateFromBytes(String bytes, Promise promise) {
        Native.I
                .certificateFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Certificates

    @ReactMethod
    public final void certificatesToBytes(String certificates, Promise promise) {
        Native.I
                .certificatesToBytes(new RPtr(certificates))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void certificatesFromBytes(String bytes, Promise promise) {
        Native.I
                .certificatesFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificatesNew(Promise promise) {
        Native.I
                .certificatesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificatesLen(String certificates, Promise promise) {
        Native.I
                .certificatesLen(new RPtr(certificates))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void certificatesGet(String certificates, Integer index, Promise promise) {
        Native.I
                .certificatesGet(new RPtr(certificates), index)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void certificatesAdd(String certificates, String item, Promise promise) {
        Native.I
                .certificatesAdd(new RPtr(certificates), new RPtr(item))
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
    public final void baseAddressToAddress(String baseAddress, Promise promise) {
        Native.I
                .baseAddressToAddress(new RPtr(baseAddress))
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

    // RewardAddress

    @ReactMethod
    public final void rewardAddressNew(Integer network, String payment, Promise promise) {
        Native.I
                .rewardAddressNew(network, new RPtr(payment))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressPaymentCred(String rewardAddress, Promise promise) {
        Native.I
                .rewardAddressPaymentCred(new RPtr(rewardAddress))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressToAddress(String rewardAddress, Promise promise) {
        Native.I
                .rewardAddressToAddress(new RPtr(rewardAddress))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressFromAddress(String address, Promise promise) {
        Native.I
                .rewardAddressFromAddress(new RPtr(address))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // RewardAddresses

    @ReactMethod
    public final void rewardAddressesNew(Promise promise) {
        Native.I
                .rewardAddressesNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesLen(String rewardAddresses, Promise promise) {
        Native.I
                .rewardAddressesLen(new RPtr(rewardAddresses))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesGet(String rewardAddresses, Integer index, Promise promise) {
        Native.I
                .rewardAddressesGet(new RPtr(rewardAddresses), index)
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void rewardAddressesAdd(String rewardAddresses, String item, Promise promise) {
        Native.I
                .rewardAddressesAdd(new RPtr(rewardAddresses), new RPtr(item))
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

    // TransactionInputs

    @ReactMethod
    public final void transactionInputsLen(String transactionInputs, Promise promise) {
        Native.I
                .transactionInputsLen(new RPtr(transactionInputs))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionInputsGet(String transactionInputs, Integer index, Promise promise) {
        Native.I
                .transactionInputsGet(new RPtr(transactionInputs), index)
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

    @ReactMethod
    public final void transactionOutputAmount(String transactionOutput, Promise promise) {
        Native.I
                .transactionOutputAmount(new RPtr(transactionOutput))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputAddress(String transactionOutput, Promise promise) {
        Native.I
                .transactionOutputAddress(new RPtr(transactionOutput))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // TransactionOutputs

    @ReactMethod
    public final void transactionOutputsLen(String transactionOutputs, Promise promise) {
        Native.I
                .transactionOutputsLen(new RPtr(transactionOutputs))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionOutputsGet(String transactionOutputs, Integer index, Promise promise) {
        Native.I
                .transactionOutputsGet(new RPtr(transactionOutputs), index)
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

    // Vkey

    @ReactMethod
    public final void vkeyNew(String publicKey, Promise promise) {
        Native.I
                .vkeyNew(new RPtr(publicKey))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Vkeywitness

    @ReactMethod
    public final void vkeywitnessToBytes(String vkeywitness, Promise promise) {
        Native.I
                .vkeywitnessToBytes(new RPtr(vkeywitness))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessFromBytes(String bytes, Promise promise) {
        Native.I
                .vkeywitnessFromBytes(Base64.decode(bytes, Base64.DEFAULT))
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
    public final void vkeywitnessSignature(String vkeywitness, Promise promise) {
        Native.I
                .vkeywitnessSignature(new RPtr(vkeywitness))
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
    public final void vkeywitnessesLen(String vkeywitnesses, Promise promise) {
        Native.I
                .vkeywitnessesLen(new RPtr(vkeywitnesses))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void vkeywitnessesAdd(String vkeywitnesses, String item, Promise promise) {
        Native.I
                .vkeywitnessesAdd(new RPtr(vkeywitnesses), new RPtr(item))
                .pour(promise);
    }

    // BootstrapWitness

    @ReactMethod
    public final void bootstrapWitnessToBytes(String bootstrapWitness, Promise promise) {
        Native.I
                .bootstrapWitnessToBytes(new RPtr(bootstrapWitness))
                .map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))
                .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessFromBytes(String bytes, Promise promise) {
        Native.I
                .bootstrapWitnessFromBytes(Base64.decode(bytes, Base64.DEFAULT))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void bootstrapWitnessNew(String vkey, String signature, String chainCode, String attributes, Promise promise) {
        Native.I
                .bootstrapWitnessNew(new RPtr(vkey), new RPtr(signature), Base64.decode(chainCode, Base64.DEFAULT), Base64.decode(attributes, Base64.DEFAULT))
                .map(RPtr::toJs)
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

    @ReactMethod
    public final void transactionBodyOutputs(String txBody, Promise promise) {
        Native.I
                .transactionBodyOutputs(new RPtr(txBody))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyInputs(String txBody, Promise promise) {
        Native.I
                .transactionBodyInputs(new RPtr(txBody))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyFee(String txBody, Promise promise) {
        Native.I
                .transactionBodyFee(new RPtr(txBody))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyTtl(String txBody, Promise promise) {
        Native.I
                .transactionBodyTtl(new RPtr(txBody))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyCerts(String txBody, Promise promise) {
        Native.I
                .transactionBodyCerts(new RPtr(txBody))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBodyWithdrawals(String txBody, Promise promise) {
        Native.I
                .transactionBodyWithdrawals(new RPtr(txBody))
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
    public final void transactionBuilderFeeForOutput(String txBuilder, String output, Promise promise) {
        Native.I
                .transactionBuilderFeeForOutput(new RPtr(txBuilder), new RPtr(output))
                .map(RPtr::toJs)
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
    public final void transactionBuilderSetCerts(String txBuilder, String certs, Promise promise) {
        Native.I
                .transactionBuilderSetCerts(new RPtr(txBuilder), new RPtr(certs))
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderSetWithdrawals(String txBuilder, String withdrawals, Promise promise) {
        Native.I
                .transactionBuilderSetWithdrawals(new RPtr(txBuilder), new RPtr(withdrawals))
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
    public final void transactionBuilderGetDeposit(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderGetDeposit(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void transactionBuilderGetFeeIfSet(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderGetFeeIfSet(new RPtr(txBuilder))
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
    public final void transactionBuilderMinFee(String txBuilder, Promise promise) {
        Native.I
                .transactionBuilderMinFee(new RPtr(txBuilder))
                .map(RPtr::toJs)
                .pour(promise);
    }

    // Vkeywitnesses

    @ReactMethod
    public final void withdrawalsNew(Promise promise) {
        Native.I
                .withdrawalsNew()
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsLen(String withdrawals, Promise promise) {
        Native.I
                .withdrawalsLen(new RPtr(withdrawals))
                .map(Long::intValue)
                .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsInsert(String withdrawals, String key, String value, Promise promise) {
        Native.I
                .withdrawalsInsert(new RPtr(withdrawals), new RPtr(key), new RPtr(value))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsGet(String withdrawals, String key, Promise promise) {
        Native.I
                .withdrawalsGet(new RPtr(withdrawals), new RPtr(key))
                .map(RPtr::toJs)
                .pour(promise);
    }

    @ReactMethod
    public final void withdrawalsKeys(String withdrawals, Promise promise) {
        Native.I
                .withdrawalsKeys(new RPtr(withdrawals))
                .map(RPtr::toJs)
                .pour(promise);
    }

}
