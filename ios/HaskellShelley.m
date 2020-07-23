#import "HaskellShelley.h"
#import "NSString+RPtr.h"
#import "NSData+DataPtr.h"
#import "SafeOperation.h"
#import <react_native_haskell_shelley.h>


@implementation HaskellShelley

RCT_EXPORT_MODULE()

// BigNumber

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
        uint32_t index = [[params objectAtIndex:1] unsignedIntegerValue];
        return transaction_input_new(transactionIdPtr, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[transactionIdPtr, index] andResolve:resolve orReject:reject];
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

+ (void)initialize
{
    if (self == [HaskellShelley class]) {
        init_haskell_shelley_library();
    }
}

@end
