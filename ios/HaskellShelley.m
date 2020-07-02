#import "HaskellShelley.h"
#import "NSString+RPtr.h"
#import "NSData+DataPtr.h"
#import "SafeOperation.h"
#import <react_native_haskell_shelley.h>


@implementation HaskellShelley

RCT_EXPORT_MODULE()

// address

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

// AddrKeyHash

RCT_EXPORT_METHOD(addrKeyHashToBytes:(nonnull NSString *)keyHashPtr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* keyHashPtr, CharPtr* error) {
        DataPtr result;
        RPtr keyHash = [keyHashPtr rPtr];
        return addr_key_hash_to_bytes(keyHash, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:keyHashPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addrKeyHashFromBytes:(nonnull NSString *)bytesStr  withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesStr, CharPtr* error) {
        RPtr result;
        NSData* data = [NSData fromBase64:bytesStr];
        return addr_key_hash_from_bytes((uint8_t*)data.bytes, data.length, &result, error)
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

+ (void)initialize
{
    if (self == [HaskellShelley class]) {
        init_haskell_shelley_library();
    }
}

@end
