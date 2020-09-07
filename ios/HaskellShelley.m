#import "HaskellShelley.h"
#import "NSString+RPtr.h"
#import "NSData+DataPtr.h"
#import "SafeOperation.h"
#import <react_native_haskell_shelley.h>


@implementation HaskellShelley

RCT_EXPORT_MODULE()

// Utils

RCT_EXPORT_METHOD(makeIcarusBootstrapWitness:(nonnull NSString *)txBodyHashPtr withAddr:(nonnull NSString *)addrPtr andKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBodyHash = [[params objectAtIndex:0] rPtr];
        RPtr addr = [[params objectAtIndex:1] rPtr];
        RPtr key = [[params objectAtIndex:2] rPtr];
        RPtr result;
        return utils_make_icarus_bootstrap_witness(txBodyHash, addr, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txBodyHashPtr, addrPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(makeVkeyWitness:(nonnull NSString *)txBodyHashPtr withSk:(nonnull NSString *)skPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBodyHash = [[params objectAtIndex:0] rPtr];
        RPtr sk = [[params objectAtIndex:1] rPtr];
        RPtr result;
        return utils_make_vkey_witness(txBodyHash, sk, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txBodyHashPtr, skPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(hashTransaction:(nonnull NSString *)txBodyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* txBodyPtr, CharPtr* error) {
        RPtr txBody = [txBodyPtr rPtr];
        RPtr result;
        return utils_hash_transaction(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:txBodyPtr andResolve:resolve orReject:reject];
}

// BigNum

RCT_EXPORT_METHOD(bigNumFromStr:(nonnull NSString *)string withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* string, CharPtr* error) {
        RPtr result;
        return big_num_from_str([string charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:string andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumToStr:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        CharPtr result;
        return big_num_to_str([ptr rPtr], &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCheckedAdd:(nonnull NSString *)ptr1 other:(nonnull NSString *)ptr2 withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray<NSString*>* ptrs, CharPtr* error) {
        RPtr result;
        return big_num_checked_add([[ptrs objectAtIndex:0] rPtr],
                                 [[ptrs objectAtIndex:1] rPtr],
                                 &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[ptr1, ptr2] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCheckedSub:(nonnull NSString *)ptr1 other:(nonnull NSString *)ptr2 withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray<NSString*>* ptrs, CharPtr* error) {
        RPtr result;
        return big_num_checked_sub([[ptrs objectAtIndex:0] rPtr],
                                 [[ptrs objectAtIndex:1] rPtr],
                                 &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[ptr1, ptr2] andResolve:resolve orReject:reject];
}

// PrivateKey

RCT_EXPORT_METHOD(privateKeyToPublic: (nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        return private_key_to_public([ptr rPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyAsBytes:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        DataPtr result;
        return private_key_as_bytes([ptr rPtr], &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyFromExtendedBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return private_key_from_extended_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// PublicKey

RCT_EXPORT_METHOD(publicKeyFromBech32:(nonnull NSString *)bech32_str withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* string, CharPtr* error) {
        RPtr result;
        return public_key_from_bech32([string charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32_str andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyToBech32:(nonnull NSString *)publicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* publicKeyPtr, CharPtr* error) {
        CharPtr result;
        RPtr publicKey = [publicKeyPtr rPtr];
        return public_key_to_bech32(publicKey, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:publicKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return public_key_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyAsBytes:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        DataPtr result;
        return public_key_as_bytes([ptr rPtr], &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// TODO: publicKeyVerify

RCT_EXPORT_METHOD(publicKeyHash:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr publicKey = [ptr rPtr];
        return public_key_hash(publicKey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// Bip32PublicKey

RCT_EXPORT_METHOD(bip32PublicKeyDerive:(nonnull NSString *)bip32PublicKeyPtr withIndex:(nonnull NSNumber *)index withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr bip32PublicKey = [[params objectAtIndex:0] rPtr];
        int64_t index = [[params objectAtIndex:1] longLongValue];
        return bip32_public_key_derive(bip32PublicKey, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bip32PublicKeyPtr, index] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyToRawKey:(nonnull NSString *)bip32PublicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PublicKeyPtr, CharPtr* error) {
        RPtr result;
        RPtr bip32PublicKey = [bip32PublicKeyPtr rPtr];
        return bip32_public_key_to_raw_key(bip32PublicKey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bip32PublicKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return bip32_public_key_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyAsBytes:(nonnull NSString *)bip32PublicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PublicKeyPtr, CharPtr* error) {
        DataPtr result;
        RPtr bip32PublicKey = [bip32PublicKeyPtr rPtr];
        return bip32_public_key_as_bytes(bip32PublicKey, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:bip32PublicKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyFromBech32:(nonnull NSString *)bech32Str withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32Str, CharPtr* error) {
        RPtr result;
        return bip32_public_key_from_bech32([bech32Str charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32Str andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyToBech32:(nonnull NSString *)bip32PublicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PublicKeyPtr, CharPtr* error) {
        CharPtr result;
        RPtr bip32PublicKey = [bip32PublicKeyPtr rPtr];
        return bip32_public_key_to_bech32(bip32PublicKey, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:bip32PublicKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyChaincode:(nonnull NSString *)bip32PublicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PublicKeyPtr, CharPtr* error) {
        CharPtr result;
        RPtr bip32PublicKey = [bip32PublicKeyPtr rPtr];
        return bip32_public_key_chaincode(bip32PublicKey, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:bip32PublicKeyPtr andResolve:resolve orReject:reject];
}

// Bip32PrivateKey

RCT_EXPORT_METHOD(bip32PrivateKeyDerive:(nonnull NSString *)bip32PrivateKeyPtr withIndex:(nonnull NSNumber *)index withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr bip32PrivateKey = [[params objectAtIndex:0] rPtr];
        int64_t index = [[params objectAtIndex:1] longLongValue];
        return bip_32_private_key_derive(bip32PrivateKey, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bip32PrivateKeyPtr, index] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyGenerateEd25519Bip32:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return bip_32_private_key_generate_ed25519_bip32(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToRawKey:(nonnull NSString *)bip32PrivateKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PrivateKeyPtr, CharPtr* error) {
        RPtr result;
        RPtr bip32PrivateKey = [bip32PrivateKeyPtr rPtr];
        return bip_32_private_key_to_raw_key(bip32PrivateKey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bip32PrivateKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToPublic:(nonnull NSString *)bip32PrivateKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PrivateKeyPtr, CharPtr* error) {
        RPtr result;
        RPtr bip32PrivateKey = [bip32PrivateKeyPtr rPtr];
        return bip_32_private_key_to_public(bip32PrivateKey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bip32PrivateKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return bip_32_private_key_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyAsBytes:(nonnull NSString *)bip32PrivateKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PrivateKeyPtr, CharPtr* error) {
        DataPtr result;
        RPtr bip32PrivateKey = [bip32PrivateKeyPtr rPtr];
        return bip_32_private_key_as_bytes(bip32PrivateKey, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:bip32PrivateKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBech32:(nonnull NSString *)bech32Str withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32Str, CharPtr* error) {
        RPtr result;
        return bip_32_private_key_from_bech32([bech32Str charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32Str andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToBech32:(nonnull NSString *)bip32PrivateKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bip32PrivateKeyPtr, CharPtr* error) {
        CharPtr result;
        RPtr bip32PrivateKey = [bip32PrivateKeyPtr rPtr];
        return bip_32_private_key_to_bech32(bip32PrivateKey, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:bip32PrivateKeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBip39Entropy:(nonnull NSString *)entropy withPassword:(nonnull NSString *)password withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* entropy = [NSData fromBase64:[params objectAtIndex:0]];
        NSData* password = [NSData fromBase64:[params objectAtIndex:1]];
        return bip_32_private_key_from_bip39_entropy(
                                                     (uint8_t*)entropy.bytes, entropy.length,
                                                     (uint8_t*)password.bytes, password.length,
                                                     &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[entropy, password] andResolve:resolve orReject:reject];
}

// ByronAddress

RCT_EXPORT_METHOD(byronAddressToBase58:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        CharPtr result;
        return byron_address_to_base58([ptr rPtr], &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressFromBase58:(nonnull NSString *)string withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* string, CharPtr* error) {
        RPtr result;
        return byron_address_from_base58([string charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:string andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressIsValid:(nonnull NSString *)string  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* string, CharPtr* error) {
        BOOL result;
        return byron_address_is_valid([string charPtr], &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:string andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressToAddress:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr byronAddr = [ptr rPtr];
        return byron_address_to_address(byronAddr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr rPtr];
        return byron_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressAttributes:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        CharPtr result;
        RPtr byronAddr = [ptr rPtr];
        return byron_address_attributes(byronAddr, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// Address

RCT_EXPORT_METHOD(addressToBytes:(nonnull NSString *)addressPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addressPtr, CharPtr* error) {
        DataPtr result;
        RPtr address = [addressPtr rPtr];
        return address_to_bytes(address, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:addressPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return address_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToBech32:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        CharPtr result;
        return address_to_bech32([ptr rPtr], &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToBech32WithPrefix:(nonnull NSString *)ptr withPrefix:(nonnull NSString *)prefix withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
      RPtr rptr = [[params objectAtIndex:0] rPtr];
      CharPtr prefixChars = [[params objectAtIndex:1] charPtr];
        CharPtr result;
        return address_to_bech32_with_prefix(rptr, prefixChars, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[ptr, prefix] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressFromBech32:(nonnull NSString *)string withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* string, CharPtr* error) {
        RPtr result;
        return address_from_bech32([string charPtr], &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:string andResolve:resolve orReject:reject];
}

// Ed25519Signature

RCT_EXPORT_METHOD(ed25519SignatureToBytes:(nonnull NSString *)signaturePtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* signaturePtr, CharPtr* error) {
        DataPtr result;
        RPtr signature = [signaturePtr rPtr];
        return ed25519_signature_to_bytes(signature, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:signaturePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return ed25519_signature_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// Ed25519KeyHash

RCT_EXPORT_METHOD(ed25519KeyHashToBytes:(nonnull NSString *)keyHashPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* keyHashPtr, CharPtr* error) {
        DataPtr result;
        RPtr keyHash = [keyHashPtr rPtr];
        return ed25519_key_hash_to_bytes(keyHash, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:keyHashPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return ed25519_key_hash_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// TransactionHash

RCT_EXPORT_METHOD(transactionHashToBytes:(nonnull NSString *)txHashPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* txHashPtr, CharPtr* error) {
        DataPtr result;
        RPtr txHash = [txHashPtr rPtr];
        return transaction_hash_to_bytes(txHash, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:txHashPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return transaction_hash_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// StakeCredential

RCT_EXPORT_METHOD(stakeCredentialFromKeyHash:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr keyhash = [ptr rPtr];
        return stake_credential_from_keyhash(keyhash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToKeyHash:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeCredential = [ptr rPtr];
        return stake_credential_to_keyhash(stakeCredential, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialKind:(nonnull NSString *)stakeCredentialPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* stakeCredentialPtr, CharPtr* error) {
        uint8_t result;
        RPtr stakeCredential = [stakeCredentialPtr rPtr];
        return stake_credential_to_kind(stakeCredential, &result, error)
            ? [NSNumber numberWithInt:result]
            : nil;
    }] exec:stakeCredentialPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToBytes:(nonnull NSString *)stakeCredentialPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeCredentialPtr, CharPtr* error) {
        DataPtr result;
        RPtr stakeCredential = [stakeCredentialPtr rPtr];
        return stake_credential_to_bytes(stakeCredential, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:stakeCredentialPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return stake_credential_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// StakeRegistration

RCT_EXPORT_METHOD(stakeRegistrationNew:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeCred = [ptr rPtr];
        return stake_registration_new(stakeCred, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationStakeCredential:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeRegistration = [ptr rPtr];
        return stake_registration_stake_credential(stakeRegistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeRegistrationToBytes:(nonnull NSString *)stakeRegistrationPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeRegistrationPtr, CharPtr* error) {
        DataPtr result;
        RPtr stakeRegistration = [stakeRegistrationPtr rPtr];
        return stake_registration_to_bytes(stakeRegistration, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:stakeRegistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return stake_registration_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// StakeDeregistration

RCT_EXPORT_METHOD(stakeDeregistrationNew:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeCred = [ptr rPtr];
        return stake_deregistration_new(stakeCred, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationStakeCredential:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeDeregistration = [ptr rPtr];
        return stake_deregistration_stake_credential(stakeDeregistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeDeregistrationToBytes:(nonnull NSString *)stakeDeregistrationPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeDeregistrationPtr, CharPtr* error) {
        DataPtr result;
        RPtr stakeDeregistration = [stakeDeregistrationPtr rPtr];
        return stake_deregistration_to_bytes(stakeDeregistration, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:stakeDeregistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return stake_deregistration_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// StakeDelegation

RCT_EXPORT_METHOD(stakeDelegationNew:(nonnull NSString *)stakeCredPtr withPoolKeyhash:(nonnull NSString *)poolKeyhashPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr stakeCred = [[params objectAtIndex:0] rPtr];
        RPtr poolKeyhash = [[params objectAtIndex:1] rPtr];
        return stake_delegation_new(stakeCred, poolKeyhash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[stakeCredPtr, poolKeyhashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationStakeCredential:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeDelegation = [ptr rPtr];
        return stake_delegation_stake_credential(stakeDelegation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationPoolKeyhash:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeDelegation = [ptr rPtr];
        return stake_delegation_pool_keyhash(stakeDelegation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationToBytes:(nonnull NSString *)stakeDeregistrationPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeDeregistrationPtr, CharPtr* error) {
        DataPtr result;
        RPtr stakeDeregistration = [stakeDeregistrationPtr rPtr];
        return stake_delegation_to_bytes(stakeDeregistration, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:stakeDeregistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return stake_delegation_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// Certificate

RCT_EXPORT_METHOD(certificateNewStakeRegistration:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeRegistration = [ptr rPtr];
        return certificate_new_stake_registration(stakeRegistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewStakeDeregistration:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeDeregistration = [ptr rPtr];
        return certificate_new_stake_deregistration(stakeDeregistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewStakeDelegation:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr stakeDelegation = [ptr rPtr];
        return certificate_new_stake_delegation(stakeDelegation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateToBytes:(nonnull NSString *)certificatePtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* certificatePtr, CharPtr* error) {
        DataPtr result;
        RPtr certificate = [certificatePtr rPtr];
        return certificate_to_bytes(certificate, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:certificatePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return certificate_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// Certificates

RCT_EXPORT_METHOD(certificatesToBytes:(nonnull NSString *)certificatesPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* certificatesPtr, CharPtr* error) {
        DataPtr result;
        RPtr certificates = [certificatesPtr rPtr];
        return certificates_to_bytes(certificates, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:certificatesPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return certificates_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return certificates_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesLen:(nonnull NSString *)certificatesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* certificatesPtr, CharPtr* error) {
        uintptr_t result;
        RPtr certificates = [certificatesPtr rPtr];
        return certificates_len(certificates, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:certificatesPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesAdd:(nonnull NSString *)certificatesPtr withItem:(nonnull NSString *)item withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr certificates = [[params objectAtIndex:0] rPtr];
        RPtr item = [[params objectAtIndex:1] rPtr];
        certificates_add(&certificates, item, error);
        return nil;
    }] exec:@[certificatesPtr, item] andResolve:resolve orReject:reject];
}

// BaseAddress

RCT_EXPORT_METHOD(baseAddressNew:(nonnull NSNumber *)network withPaymentCredential:(nonnull NSString *)payment andStakeCredential:(nonnull NSString *)stake withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        uintptr_t network = [[params objectAtIndex:0] unsignedIntegerValue];
        RPtr payment = [[params objectAtIndex:1] rPtr];
        RPtr stake = [[params objectAtIndex:2] rPtr];
        return base_address_new(network, payment, stake, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[network, payment, stake] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressPaymentCred:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr baseAddress = [ptr rPtr];
        return base_address_payment_cred(baseAddress, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressStakeCred:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr baseAddress = [ptr rPtr];
        return base_address_stake_cred(baseAddress, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressToAddress:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr baseAddress = [ptr rPtr];
        return base_address_to_address(baseAddress, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr rPtr];
        return base_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}

// RewardAddress

RCT_EXPORT_METHOD(rewardAddressNew:(nonnull NSNumber *)network withPaymentCredential:(nonnull NSString *)payment withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        uintptr_t network = [[params objectAtIndex:0] unsignedIntegerValue];
        RPtr payment = [[params objectAtIndex:1] rPtr];
        return reward_address_new(network, payment, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[network, payment] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressPaymentCred:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr rewardAddress = [ptr rPtr];
        return reward_address_payment_cred(rewardAddress, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressToAddress:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr rewardAddress = [ptr rPtr];
        return reward_address_to_address(rewardAddress, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr rPtr];
        return reward_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}

// UnitInterval

RCT_EXPORT_METHOD(unitIntervalToBytes:(nonnull NSString *)unitIntervalPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* unitIntervalPtr, CharPtr* error) {
        DataPtr result;
        RPtr unitInterval = [unitIntervalPtr rPtr];
        return unit_interval_to_bytes(unitInterval, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:unitIntervalPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return unit_interval_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalNew:(nonnull NSString *)numeratorPtr withDenominator:(nonnull NSString *)denominatorPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr numerator = [[params objectAtIndex:0] rPtr];
        RPtr denominator = [[params objectAtIndex:1] rPtr];
        return unit_interval_new(numerator, denominator, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[numeratorPtr, denominatorPtr] andResolve:resolve orReject:reject];
}

// TransactionInput

RCT_EXPORT_METHOD(transactionInputToBytes:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        DataPtr result;
        RPtr txInput = [ptr rPtr];
        return transaction_input_to_bytes(txInput, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return transaction_input_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputTransactionId:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txInput = [ptr rPtr];
        return transaction_input_transaction_id(txInput, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputIndex:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* ptr, CharPtr* error) {
        uint32_t result;
        RPtr txInput = [ptr rPtr];
        return transaction_input_index(txInput, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputNew:(nonnull NSString *)transactionIdPtr withTransactionIndex:(nonnull NSNumber *)index withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr transactionIdPtr = [[params objectAtIndex:0] rPtr];
        // note: this is a bad conversion (unsigned long -> unsigned int)
        uint32_t index = [[params objectAtIndex:1] unsignedIntegerValue];
        return transaction_input_new(transactionIdPtr, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[transactionIdPtr, index] andResolve:resolve orReject:reject];
}

// TransactionInputs

RCT_EXPORT_METHOD(transactionInputsLen:(nonnull NSString *)txInputsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* txInputsPtr, CharPtr* error) {
        uintptr_t result;
        RPtr txInputs = [txInputsPtr rPtr];
        return transaction_inputs_len(txInputs, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:txInputsPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsGet:(nonnull NSString *)txInputsPtr withIndex:(nonnull NSNumber *)index withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txInputs = [[params objectAtIndex:0] rPtr];
        uintptr_t index = [[params objectAtIndex:1] unsignedIntegerValue];
        return transaction_inputs_get(txInputs, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txInputsPtr, index] andResolve:resolve orReject:reject];
}

// TransactionOutput

RCT_EXPORT_METHOD(transactionOutputToBytes:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        DataPtr result;
        RPtr rptr = [ptr rPtr];
        return transaction_output_to_bytes(rptr, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return transaction_output_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputNew:(nonnull NSString *)addressPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr address = [[params objectAtIndex:0] rPtr];
        RPtr amount = [[params objectAtIndex:1] rPtr];
        return transaction_output_new(address, amount, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[addressPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmount:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txOutput = [ptr rPtr];
        return transaction_output_amount(txOutput, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAddress:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txOutput = [ptr rPtr];
        return transaction_output_address(txOutput, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}


// TransactionOutputs

RCT_EXPORT_METHOD(transactionOutputsLen:(nonnull NSString *)txOutputsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* txOutputsPtr, CharPtr* error) {
        uintptr_t result;
        RPtr txOutputs = [txOutputsPtr rPtr];
        return transaction_outputs_len(txOutputs, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:txOutputsPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsGet:(nonnull NSString *)txOutputsPtr withIndex:(nonnull NSNumber *)index withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txOutputs = [[params objectAtIndex:0] rPtr];
        uintptr_t index = [[params objectAtIndex:1] unsignedIntegerValue];
        return transaction_outputs_get(txOutputs, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txOutputsPtr, index] andResolve:resolve orReject:reject];
}

// LinearFee

RCT_EXPORT_METHOD(linearFeeCoefficient:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr linearFee = [ptr rPtr];
        return linear_fee_coefficient(linearFee, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(linearFeeConstant:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr linearFee = [ptr rPtr];
        return linear_fee_constant(linearFee, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(linearFeeNew:(nonnull NSString *)coefficientPtr withConstant:(nonnull NSString *)constantPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr coeff = [[params objectAtIndex:0] rPtr];
        RPtr constant = [[params objectAtIndex:1] rPtr];
        return linear_fee_new(coeff, constant, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[coefficientPtr, constantPtr] andResolve:resolve orReject:reject];
}

// Vkey

RCT_EXPORT_METHOD(vkeyNew:(nonnull NSString *)publicKeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* publicKeyPtr, CharPtr* error) {
        RPtr result;
        RPtr publicKey = [publicKeyPtr rPtr];
        return vkey_new(publicKey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:publicKeyPtr andResolve:resolve orReject:reject];
}

// Vkeywitness

RCT_EXPORT_METHOD(vkeywitnessNew:(nonnull NSString *)vkeyPtr withSignature:(nonnull NSString *)signaturePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr vkey = [[params objectAtIndex:0] rPtr];
        RPtr signature = [[params objectAtIndex:1] rPtr];
        return vkeywitness_new(vkey, signature, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[vkeyPtr, signaturePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessSignature:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr vkeywit = [ptr rPtr];
        return vkeywitness_signature(vkeywit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// Vkeywitnesses

RCT_EXPORT_METHOD(vkeywitnessesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return vkeywitnesses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesLen:(nonnull NSString *)witnessesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* witnessesPtr, CharPtr* error) {
        uintptr_t result;
        RPtr witnesses = [witnessesPtr rPtr];
        return vkeywitnesses_len(witnesses, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:witnessesPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesAdd:(nonnull NSString *)witnessesPtr withItem:(nonnull NSString *)itemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr witnesses = [[params objectAtIndex:0] rPtr];
        RPtr item = [[params objectAtIndex:1] rPtr];
        vkeywitnesses_add(&witnesses, item, error);
        return nil;
    }] exec:@[witnessesPtr, itemPtr] andResolve:resolve orReject:reject];
}

// BootstrapWitness

RCT_EXPORT_METHOD(bootstrapWitnessNew:(nonnull NSString *)vkeyPtr withSignature:(nonnull NSString *)signaturePtr withChainCode:(nonnull NSString *)chainCodeStr withAttributes:(nonnull NSString *)attributesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr vkey = [[params objectAtIndex:0] rPtr];
        RPtr signature = [[params objectAtIndex:1] rPtr];
        NSData* chainCode = [NSData fromBase64:[params objectAtIndex:2]];
        NSData* attributes = [NSData fromBase64:[params objectAtIndex:3]];
        return bootstrap_witness_new(vkey, signature, (uint8_t*)chainCode.bytes, chainCode.length, (uint8_t*)attributes.bytes, attributes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[vkeyPtr, signaturePtr, chainCodeStr, attributesStr] andResolve:resolve orReject:reject];
}


// BootstrapWitnesses

RCT_EXPORT_METHOD(bootstrapWitnessesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return bootstrap_witnesses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessesLen:(nonnull NSString *)witnessesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* witnessesPtr, CharPtr* error) {
        uintptr_t result;
        RPtr witnesses = [witnessesPtr rPtr];
        return bootstrap_witnesses_len(witnesses, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:witnessesPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessesAdd:(nonnull NSString *)witnessesPtr withItem:(nonnull NSString *)item withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr witnesses = [[params objectAtIndex:0] rPtr];
        RPtr item = [[params objectAtIndex:1] rPtr];
        bootstrap_witnesses_add(&witnesses, item, error);
        return nil;
    }] exec:@[witnessesPtr, item] andResolve:resolve orReject:reject];
}

// TransactionWitnessSet

RCT_EXPORT_METHOD(transactionWitnessSetNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_witness_set_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetVkeys:(nonnull NSString *)witnessSetPtr withVkeys:(nonnull NSString *)vkeysPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr witnessSet = [[params objectAtIndex:0] rPtr];
        RPtr vkeys = [[params objectAtIndex:1] rPtr];
        transaction_witness_set_set_vkeys(witnessSet, vkeys, error);
        return nil;
    }] exec:@[witnessSetPtr, vkeysPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetBootstraps:(nonnull NSString *)witnessSetPtr withBootstraps:(nonnull NSString *)bootstrapsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr witnessSet = [[params objectAtIndex:0] rPtr];
        RPtr bootstraps = [[params objectAtIndex:1] rPtr];
        transaction_witness_set_set_bootstraps(witnessSet, bootstraps, error);
        return nil;
    }] exec:@[witnessSetPtr, bootstrapsPtr] andResolve:resolve orReject:reject];
}

// TransactionBody

RCT_EXPORT_METHOD(transactionBodyToBytes:(nonnull NSString *)txBodyPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* txBodyPtr, CharPtr* error) {
        DataPtr result;
        RPtr txBody = [txBodyPtr rPtr];
        return transaction_body_to_bytes(txBody, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:txBodyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return transaction_body_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyInputs:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_inputs(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyOutputs:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_outputs(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFee:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_fee(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyTtl:(nonnull NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* ptr, CharPtr* error) {
        uint32_t result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_ttl(txBody, &result, error)
            ? [NSNumber numberWithInt:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyWithdrawals:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_withdrawals(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyCerts:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [ptr rPtr];
        return transaction_body_certs(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// Transaction

RCT_EXPORT_METHOD(transactionBody:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr tx = [ptr rPtr];
        return transaction_body(tx, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionNew:(nonnull NSString *)bodyPtr withWitnessSet:(nonnull NSString *)witnessSetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr body = [[params objectAtIndex:0] rPtr];
        RPtr witnesses = [[params objectAtIndex:1] rPtr];
        return transaction_new(body, witnesses, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bodyPtr, witnessSetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionNewWithMetadata:(nonnull NSString *)bodyPtr withWitnessSet:(nonnull NSString *)witnessSetPtr andMetadata:(nonnull NSString *)metadataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr body = [[params objectAtIndex:0] rPtr];
        RPtr witnesses = [[params objectAtIndex:1] rPtr];
        RPtr metadata = [[params objectAtIndex:2] rPtr];
        return transaction_new_with_metadata(body, witnesses, &metadata, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bodyPtr, witnessSetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionToBytes:(nonnull NSString *)txPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* txPtr, CharPtr* error) {
        DataPtr result;
        RPtr tx = [txPtr rPtr];
        return transaction_to_bytes(tx, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:txPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return transaction_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesStr andResolve:resolve orReject:reject];
}

// TransactionBuilder

RCT_EXPORT_METHOD(transactionBuilderAddKeyInput:(nonnull NSString *)txBuilderPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr andAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr hash = [[params objectAtIndex:1] rPtr];
        RPtr input = [[params objectAtIndex:2] rPtr];
        RPtr amount = [[params objectAtIndex:3] rPtr];
        transaction_builder_add_key_input(txBuilder, hash, input, amount, error);
        return nil;
    }] exec:@[txBuilderPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddBootstrapInput:(nonnull NSString *)txBuilderPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr andAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr hash = [[params objectAtIndex:1] rPtr];
        RPtr input = [[params objectAtIndex:2] rPtr];
        RPtr amount = [[params objectAtIndex:3] rPtr];
        transaction_builder_add_bootstrap_input(txBuilder, hash, input, amount, error);
        return nil;
    }] exec:@[txBuilderPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddOutput:(nonnull NSString *)txBuilderPtr withOutput:(nonnull NSString *)outputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr output = [[params objectAtIndex:1] rPtr];
        transaction_builder_add_output(txBuilder, output, error);
        return nil;
    }] exec:@[txBuilderPtr, outputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetFee:(nonnull NSString *)txBuilderPtr withFee:(nonnull NSString *)feePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr fee = [[params objectAtIndex:1] rPtr];
        transaction_builder_set_fee(txBuilder, fee, error);
        return nil;
    }] exec:@[txBuilderPtr, feePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetTtl:(nonnull NSString *)txBuilderPtr withTtl:(nonnull NSNumber *)ttl withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        uint32_t ttlU32 = [[params objectAtIndex:1] unsignedIntegerValue];
        transaction_builder_set_ttl(txBuilder, ttlU32, error);
        return nil;
    }] exec:@[txBuilderPtr, ttl] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetCerts:(nonnull NSString *)txBuilderPtr withCerts:(nonnull NSString *)certsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr certs = [[params objectAtIndex:1] rPtr];
        transaction_builder_set_certs(txBuilder, certs, error);
        return nil;
    }] exec:@[txBuilderPtr, certsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetWithdrawals:(nonnull NSString *)txBuilderPtr withWithdrawals:(nonnull NSString *)withdrawalsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr withdrawals = [[params objectAtIndex:1] rPtr];
        transaction_builder_set_withdrawals(txBuilder, withdrawals, error);
        return nil;
    }] exec:@[txBuilderPtr, withdrawalsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderNew:(nonnull NSString *)linearFeePtr withMinUtxoVal:(nonnull NSString *)minimumUtxoValPtr withPoolDeposit:(nonnull NSString *)poolDepositPtr andKeyDeposit:(nonnull NSString *)keyDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr linearFee = [[params objectAtIndex:0] rPtr];
        RPtr minUtxoVal = [[params objectAtIndex:1] rPtr];
        RPtr poolDeposit = [[params objectAtIndex:2] rPtr];
        RPtr keyDeposit = [[params objectAtIndex:3] rPtr];
        return transaction_builder_new(linearFee, minUtxoVal, poolDeposit, keyDeposit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[linearFeePtr, minimumUtxoValPtr, poolDepositPtr, keyDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetExplicitInput:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_get_explicit_input(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetImplicitInput:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_get_implicit_input(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetExplicitOutput:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_get_explicit_output(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetDeposit:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_get_deposit(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetFeeIfSet:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_get_fee_if_set(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddChangeIfNeeded:(nonnull NSString *)ptr withAddress:(nonnull NSString *)addressPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr txBuilder = [[params objectAtIndex:0] rPtr];
        RPtr address = [[params objectAtIndex:1] rPtr];
        BOOL result;
        return transaction_builder_add_change_if_needed(txBuilder, address, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:@[ptr, addressPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderBuild:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_build(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderMinFee:(nonnull NSString *)ptr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ptr, CharPtr* error) {
        RPtr result;
        RPtr txBuilder = [ptr rPtr];
        return transaction_builder_min_fee(txBuilder, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ptr andResolve:resolve orReject:reject];
}

// Withdrawals

RCT_EXPORT_METHOD(withdrawalsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return withdrawals_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsLen:(nonnull NSString *)withdrawalsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* withdrawalsPtr, CharPtr* error) {
        uintptr_t result;
        RPtr withdrawals = [withdrawalsPtr rPtr];
        return withdrawals_len(withdrawals, &result, error)
            ? [NSNumber numberWithUnsignedLong:result]
            : nil;
    }] exec:withdrawalsPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsInsert:(nonnull NSString *)withdrawalsPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr withdrawals = [[params objectAtIndex:0] rPtr];
        RPtr key = [[params objectAtIndex:1] rPtr];
        RPtr value = [[params objectAtIndex:2] rPtr];
        return withdrawals_insert(withdrawals, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[withdrawalsPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsGet:(nonnull NSString *)withdrawalsPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr withdrawals = [[params objectAtIndex:0] rPtr];
        RPtr key = [[params objectAtIndex:1] rPtr];
        return withdrawals_get(withdrawals, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[withdrawalsPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsKeys:(nonnull NSString *)withdrawalsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* withdrawalsPtr, CharPtr* error) {
        RPtr result;
        RPtr withdrawals = [withdrawalsPtr rPtr];
        return withdrawals_keys(withdrawals, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:withdrawalsPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ptrFree:(NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    RPtr rPtr = [ptr rPtr];
    rptr_free(&rPtr);
    resolve(nil);
}

+ (void)initialize
{
    if (self == [HaskellShelley class]) {
        init_haskell_shelley_library();
    }
}

@end
