#import "HaskellShelley.h"
#import "NSString+RPtr.h"
#import "NSData+DataPtr.h"
#import "SafeOperation.h"
#import <react_native_haskell_shelley.h>


@implementation HaskellShelley

RCT_EXPORT_MODULE()

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

RCT_EXPORT_METHOD(addressFromBytes:(nonnull NSString *)dataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dataVal, CharPtr* error) {
        RPtr result;
        NSData* dataData = [NSData fromBase64:dataVal];
        return address_from_bytes((uint8_t*)dataData.bytes, dataData.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dataVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return address_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return address_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return address_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return address_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return address_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return address_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressToBech32WithPrefix:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return address_to_bech32_with_prefix(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(addressFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return address_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(addressNetworkId:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return address_network_id(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(assetNameToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_name_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return asset_name_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_name_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return asset_name_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_name_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return asset_name_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameNew:(nonnull NSString *)nameVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* nameVal, CharPtr* error) {
        RPtr result;
        NSData* dataName = [NSData fromBase64:nameVal];
        return asset_name_new((uint8_t*)dataName.bytes, dataName.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nameVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNameName:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_name_name(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(assetNamesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_names_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return asset_names_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_names_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return asset_names_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return asset_names_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return asset_names_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return asset_names_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return asset_names_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return asset_names_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetNamesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        asset_names_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(assetsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return assets_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return assets_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return assets_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return assets_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return assets_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return assets_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return assets_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return assets_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return assets_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return assets_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(assetsKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return assets_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(auxiliaryDataToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return auxiliary_data_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return auxiliary_data_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return auxiliary_data_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return auxiliary_data_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataMetadata:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_metadata(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetMetadata:(nonnull NSString *)selfPtr withMetadata:(nonnull NSString *)metadataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr metadata = [[params objectAtIndex:1]  rPtr];
        auxiliary_data_set_metadata(self, metadata, error);
        return nil;
    }] exec:@[selfPtr, metadataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetNativeScripts:(nonnull NSString *)selfPtr withNativeScripts:(nonnull NSString *)nativeScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr nativeScripts = [[params objectAtIndex:1]  rPtr];
        auxiliary_data_set_native_scripts(self, nativeScripts, error);
        return nil;
    }] exec:@[selfPtr, nativeScriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataPlutusScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_plutus_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetPlutusScripts:(nonnull NSString *)selfPtr withPlutusScripts:(nonnull NSString *)plutusScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr plutusScripts = [[params objectAtIndex:1]  rPtr];
        auxiliary_data_set_plutus_scripts(self, plutusScripts, error);
        return nil;
    }] exec:@[selfPtr, plutusScriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataPreferAlonzoFormat:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_prefer_alonzo_format(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetPreferAlonzoFormat:(nonnull NSString *)selfPtr withPrefer:(nonnull NSNumber *)preferVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        BOOL prefer = [[params objectAtIndex:1]  boolValue];
        auxiliary_data_set_prefer_alonzo_format(self, prefer, error);
        return nil;
    }] exec:@[selfPtr, preferVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(auxiliaryDataHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return auxiliary_data_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return auxiliary_data_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return auxiliary_data_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return auxiliary_data_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(auxiliaryDataSetNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return auxiliary_data_set_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_set_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetInsert:(nonnull NSString *)selfPtr withTxIndex:(nonnull NSNumber *)txIndexVal withData:(nonnull NSString *)dataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t txIndex = [[params objectAtIndex:1]  longLongValue];
        RPtr data = [[params objectAtIndex:2]  rPtr];
        return auxiliary_data_set_insert(self, txIndex, data, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, txIndexVal, dataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetGet:(nonnull NSString *)selfPtr withTxIndex:(nonnull NSNumber *)txIndexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t txIndex = [[params objectAtIndex:1]  longLongValue];
        return auxiliary_data_set_get(self, txIndex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, txIndexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(auxiliaryDataSetIndices:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return auxiliary_data_set_indices(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(baseAddressNew:(nonnull NSNumber *)networkVal withPayment:(nonnull NSString *)paymentPtr withStake:(nonnull NSString *)stakePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t network = [[params objectAtIndex:0]  longLongValue];
        RPtr payment = [[params objectAtIndex:1]  rPtr];
        RPtr stake = [[params objectAtIndex:2]  rPtr];
        return base_address_new(network, payment, stake, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[networkVal, paymentPtr, stakePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressPaymentCred:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return base_address_payment_cred(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressStakeCred:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return base_address_stake_cred(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressToAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return base_address_to_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(baseAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr  rPtr];
        return base_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bigIntToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return big_int_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return big_int_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return big_int_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntIsZero:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return big_int_is_zero(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntAsU64:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_as_u64(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntAsInt:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_as_int(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntFromStr:(nonnull NSString *)textVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* textVal, CharPtr* error) {
        RPtr result;
        CharPtr text = [textVal  charPtr];
        return big_int_from_str(text, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:textVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntToStr:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_to_str(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntAdd:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_int_add(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntMul:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_int_mul(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntOne:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return big_int_one(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntIncrement:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_int_increment(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigIntDivCeil:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_int_div_ceil(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bigNumToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_num_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return big_num_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_num_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return big_num_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_num_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return big_num_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumFromStr:(nonnull NSString *)stringVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stringVal, CharPtr* error) {
        RPtr result;
        CharPtr string = [stringVal  charPtr];
        return big_num_from_str(string, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stringVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumToStr:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return big_num_to_str(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumZero:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return big_num_zero(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumOne:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return big_num_one(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumIsZero:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return big_num_is_zero(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumDivFloor:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_num_div_floor(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCheckedMul:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_num_checked_mul(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCheckedAdd:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_num_checked_add(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCheckedSub:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_num_checked_sub(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumClampedSub:(nonnull NSString *)selfPtr withOther:(nonnull NSString *)otherPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr other = [[params objectAtIndex:1]  rPtr];
        return big_num_clamped_sub(self, other, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, otherPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumCompare:(nonnull NSString *)selfPtr withRhsValue:(nonnull NSString *)rhsValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsValue = [[params objectAtIndex:1]  rPtr];
        return big_num_compare(self, rhsValue, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, rhsValuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumLessThan:(nonnull NSString *)selfPtr withRhsValue:(nonnull NSString *)rhsValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        BOOL result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsValue = [[params objectAtIndex:1]  rPtr];
        return big_num_less_than(self, rhsValue, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:@[selfPtr, rhsValuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumMaxValue:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return big_num_max_value(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bigNumMax:(nonnull NSString *)aPtr withB:(nonnull NSString *)bPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr a = [[params objectAtIndex:0]  rPtr];
        RPtr b = [[params objectAtIndex:1]  rPtr];
        return big_num_max(a, b, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[aPtr, bPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bip32PrivateKeyDerive:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return bip32_private_key_derive(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFrom_128Xprv:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return bip32_private_key_from_128_xprv((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyTo_128Xprv:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_to_128_xprv(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyGenerateEd25519Bip32:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return bip32_private_key_generate_ed25519_bip32(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToRawKey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_to_raw_key(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToPublic:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_to_public(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return bip32_private_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBech32:(nonnull NSString *)bech32StrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32StrVal, CharPtr* error) {
        RPtr result;
        CharPtr bech32Str = [bech32StrVal  charPtr];
        return bip32_private_key_from_bech32(bech32Str, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32StrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromBip39Entropy:(nonnull NSString *)entropyVal withPassword:(nonnull NSString *)passwordVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataEntropy = [NSData fromBase64:[params objectAtIndex:0]];
        NSData* dataPassword = [NSData fromBase64:[params objectAtIndex:1]];
        return bip32_private_key_from_bip39_entropy((uint8_t*)dataEntropy.bytes, dataEntropy.length, (uint8_t*)dataPassword.bytes, dataPassword.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[entropyVal, passwordVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyChaincode:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_chaincode(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_private_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PrivateKeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return bip32_private_key_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bip32PublicKeyDerive:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return bip32_public_key_derive(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyToRawKey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_public_key_to_raw_key(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return bip32_public_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_public_key_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyFromBech32:(nonnull NSString *)bech32StrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32StrVal, CharPtr* error) {
        RPtr result;
        CharPtr bech32Str = [bech32StrVal  charPtr];
        return bip32_public_key_from_bech32(bech32Str, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32StrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_public_key_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyChaincode:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_public_key_chaincode(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bip32_public_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bip32PublicKeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return bip32_public_key_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(blockToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return block_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return block_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return block_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHeader:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_header(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockTransactionBodies:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_transaction_bodies(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockTransactionWitnessSets:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_transaction_witness_sets(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockAuxiliaryDataSet:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_auxiliary_data_set(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockInvalidTransactions:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_invalid_transactions(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockNew:(nonnull NSString *)headerPtr withTransactionBodies:(nonnull NSString *)transactionBodiesPtr withTransactionWitnessSets:(nonnull NSString *)transactionWitnessSetsPtr withAuxiliaryDataSet:(nonnull NSString *)auxiliaryDataSetPtr withInvalidTransactions:(nonnull NSString *)invalidTransactionsVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr header = [[params objectAtIndex:0]  rPtr];
        RPtr transactionBodies = [[params objectAtIndex:1]  rPtr];
        RPtr transactionWitnessSets = [[params objectAtIndex:2]  rPtr];
        RPtr auxiliaryDataSet = [[params objectAtIndex:3]  rPtr];
        CharPtr invalidTransactions = [[params objectAtIndex:4]  charPtr];
        return block_new(header, transactionBodies, transactionWitnessSets, auxiliaryDataSet, invalidTransactions, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[headerPtr, transactionBodiesPtr, transactionWitnessSetsPtr, auxiliaryDataSetPtr, invalidTransactionsVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(blockHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return block_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return block_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return block_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return block_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(blockHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return block_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bootstrapWitnessToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return bootstrap_witness_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return bootstrap_witness_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return bootstrap_witness_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessVkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_vkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessSignature:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_signature(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessChainCode:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_chain_code(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessAttributes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witness_attributes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessNew:(nonnull NSString *)vkeyPtr withSignature:(nonnull NSString *)signaturePtr withChainCode:(nonnull NSString *)chainCodeVal withAttributes:(nonnull NSString *)attributesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr vkey = [[params objectAtIndex:0]  rPtr];
        RPtr signature = [[params objectAtIndex:1]  rPtr];
        NSData* dataChainCode = [NSData fromBase64:[params objectAtIndex:2]];
        NSData* dataAttributes = [NSData fromBase64:[params objectAtIndex:3]];
        return bootstrap_witness_new(vkey, signature, (uint8_t*)dataChainCode.bytes, dataChainCode.length, (uint8_t*)dataAttributes.bytes, dataAttributes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[vkeyPtr, signaturePtr, chainCodeVal, attributesVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(bootstrapWitnessesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return bootstrap_witnesses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return bootstrap_witnesses_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return bootstrap_witnesses_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(bootstrapWitnessesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        bootstrap_witnesses_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(byronAddressToBase58:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_to_base58(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return byron_address_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressByronProtocolMagic:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_byron_protocol_magic(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressAttributes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_attributes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressNetworkId:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_network_id(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressFromBase58:(nonnull NSString *)sVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* sVal, CharPtr* error) {
        RPtr result;
        CharPtr s = [sVal  charPtr];
        return byron_address_from_base58(s, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:sVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressIcarusFromKey:(nonnull NSString *)keyPtr withProtocolMagic:(nonnull NSNumber *)protocolMagicVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr key = [[params objectAtIndex:0]  rPtr];
        int64_t protocolMagic = [[params objectAtIndex:1]  longLongValue];
        return byron_address_icarus_from_key(key, protocolMagic, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[keyPtr, protocolMagicVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressIsValid:(nonnull NSString *)sVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* sVal, CharPtr* error) {
        BOOL result;
        CharPtr s = [sVal  charPtr];
        return byron_address_is_valid(s, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:sVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressToAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return byron_address_to_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(byronAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr  rPtr];
        return byron_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(certificateToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return certificate_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return certificate_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return certificate_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewStakeRegistration:(nonnull NSString *)stakeRegistrationPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeRegistrationPtr, CharPtr* error) {
        RPtr result;
        RPtr stakeRegistration = [stakeRegistrationPtr  rPtr];
        return certificate_new_stake_registration(stakeRegistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stakeRegistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewStakeDeregistration:(nonnull NSString *)stakeDeregistrationPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeDeregistrationPtr, CharPtr* error) {
        RPtr result;
        RPtr stakeDeregistration = [stakeDeregistrationPtr  rPtr];
        return certificate_new_stake_deregistration(stakeDeregistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stakeDeregistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewStakeDelegation:(nonnull NSString *)stakeDelegationPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeDelegationPtr, CharPtr* error) {
        RPtr result;
        RPtr stakeDelegation = [stakeDelegationPtr  rPtr];
        return certificate_new_stake_delegation(stakeDelegation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stakeDelegationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewPoolRegistration:(nonnull NSString *)poolRegistrationPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* poolRegistrationPtr, CharPtr* error) {
        RPtr result;
        RPtr poolRegistration = [poolRegistrationPtr  rPtr];
        return certificate_new_pool_registration(poolRegistration, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:poolRegistrationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewPoolRetirement:(nonnull NSString *)poolRetirementPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* poolRetirementPtr, CharPtr* error) {
        RPtr result;
        RPtr poolRetirement = [poolRetirementPtr  rPtr];
        return certificate_new_pool_retirement(poolRetirement, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:poolRetirementPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewGenesisKeyDelegation:(nonnull NSString *)genesisKeyDelegationPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* genesisKeyDelegationPtr, CharPtr* error) {
        RPtr result;
        RPtr genesisKeyDelegation = [genesisKeyDelegationPtr  rPtr];
        return certificate_new_genesis_key_delegation(genesisKeyDelegation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:genesisKeyDelegationPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateNewMoveInstantaneousRewardsCert:(nonnull NSString *)moveInstantaneousRewardsCertPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* moveInstantaneousRewardsCertPtr, CharPtr* error) {
        RPtr result;
        RPtr moveInstantaneousRewardsCert = [moveInstantaneousRewardsCertPtr  rPtr];
        return certificate_new_move_instantaneous_rewards_cert(moveInstantaneousRewardsCert, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:moveInstantaneousRewardsCertPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return certificate_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsStakeRegistration:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_stake_registration(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsStakeDeregistration:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_stake_deregistration(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsStakeDelegation:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_stake_delegation(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsPoolRegistration:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_pool_registration(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsPoolRetirement:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_pool_retirement(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsGenesisKeyDelegation:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_genesis_key_delegation(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificateAsMoveInstantaneousRewardsCert:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificate_as_move_instantaneous_rewards_cert(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(certificatesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificates_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return certificates_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificates_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return certificates_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return certificates_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return certificates_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
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

RCT_EXPORT_METHOD(certificatesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return certificates_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return certificates_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(certificatesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        certificates_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(constrPlutusDataToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return constr_plutus_data_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return constr_plutus_data_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return constr_plutus_data_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return constr_plutus_data_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataAlternative:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return constr_plutus_data_alternative(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return constr_plutus_data_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(constrPlutusDataNew:(nonnull NSString *)alternativePtr withData:(nonnull NSString *)dataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr alternative = [[params objectAtIndex:0]  rPtr];
        RPtr data = [[params objectAtIndex:1]  rPtr];
        return constr_plutus_data_new(alternative, data, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[alternativePtr, dataPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(costModelToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return cost_model_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return cost_model_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return cost_model_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return cost_model_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return cost_model_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return cost_model_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return cost_model_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelSet:(nonnull NSString *)selfPtr withOperation:(nonnull NSNumber *)operationVal withCost:(nonnull NSString *)costPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t operation = [[params objectAtIndex:1]  longLongValue];
        RPtr cost = [[params objectAtIndex:2]  rPtr];
        return cost_model_set(self, operation, cost, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, operationVal, costPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelGet:(nonnull NSString *)selfPtr withOperation:(nonnull NSNumber *)operationVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t operation = [[params objectAtIndex:1]  longLongValue];
        return cost_model_get(self, operation, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, operationVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costModelLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return cost_model_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(costmdlsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return costmdls_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return costmdls_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return costmdls_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return costmdls_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return costmdls_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return costmdls_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return costmdls_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return costmdls_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return costmdls_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return costmdls_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return costmdls_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(costmdlsRetainLanguageVersions:(nonnull NSString *)selfPtr withLanguages:(nonnull NSString *)languagesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr languages = [[params objectAtIndex:1]  rPtr];
        return costmdls_retain_language_versions(self, languages, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, languagesPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(dNSRecordAorAAAAToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_aor_a_a_a_a_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAAFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return d_n_s_record_aor_a_a_a_a_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAAToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_aor_a_a_a_a_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAAFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return d_n_s_record_aor_a_a_a_a_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAAToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_aor_a_a_a_a_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAAFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return d_n_s_record_aor_a_a_a_a_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAANew:(nonnull NSString *)dnsNameVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dnsNameVal, CharPtr* error) {
        RPtr result;
        CharPtr dnsName = [dnsNameVal  charPtr];
        return d_n_s_record_aor_a_a_a_a_new(dnsName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dnsNameVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordAorAAAARecord:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_aor_a_a_a_a_record(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(dNSRecordSRVToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_s_r_v_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return d_n_s_record_s_r_v_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_s_r_v_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return d_n_s_record_s_r_v_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_s_r_v_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return d_n_s_record_s_r_v_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVNew:(nonnull NSString *)dnsNameVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dnsNameVal, CharPtr* error) {
        RPtr result;
        CharPtr dnsName = [dnsNameVal  charPtr];
        return d_n_s_record_s_r_v_new(dnsName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dnsNameVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dNSRecordSRVRecord:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return d_n_s_record_s_r_v_record(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(dataCostNewCoinsPerWord:(nonnull NSString *)coinsPerWordPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* coinsPerWordPtr, CharPtr* error) {
        RPtr result;
        RPtr coinsPerWord = [coinsPerWordPtr  rPtr];
        return data_cost_new_coins_per_word(coinsPerWord, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:coinsPerWordPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataCostNewCoinsPerByte:(nonnull NSString *)coinsPerBytePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* coinsPerBytePtr, CharPtr* error) {
        RPtr result;
        RPtr coinsPerByte = [coinsPerBytePtr  rPtr];
        return data_cost_new_coins_per_byte(coinsPerByte, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:coinsPerBytePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataCostCoinsPerByte:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return data_cost_coins_per_byte(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(dataHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return data_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return data_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return data_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return data_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return data_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(dataHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return data_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(datumSourceNew:(nonnull NSString *)datumPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* datumPtr, CharPtr* error) {
        RPtr result;
        RPtr datum = [datumPtr  rPtr];
        return datum_source_new(datum, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:datumPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(datumSourceNewRefInput:(nonnull NSString *)inputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* inputPtr, CharPtr* error) {
        RPtr result;
        RPtr input = [inputPtr  rPtr];
        return datum_source_new_ref_input(input, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:inputPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(ed25519KeyHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ed25519_key_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return ed25519_key_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return ed25519_key_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return ed25519_key_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(ed25519KeyHashesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hashes_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ed25519_key_hashes_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hashes_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return ed25519_key_hashes_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hashes_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return ed25519_key_hashes_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return ed25519_key_hashes_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hashes_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return ed25519_key_hashes_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        ed25519_key_hashes_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519KeyHashesToOption:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_key_hashes_to_option(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(ed25519SignatureToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_signature_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_signature_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ed25519_signature_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureFromBech32:(nonnull NSString *)bech32StrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32StrVal, CharPtr* error) {
        RPtr result;
        CharPtr bech32Str = [bech32StrVal  charPtr];
        return ed25519_signature_from_bech32(bech32Str, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32StrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureFromHex:(nonnull NSString *)inputVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* inputVal, CharPtr* error) {
        RPtr result;
        CharPtr input = [inputVal  charPtr];
        return ed25519_signature_from_hex(input, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:inputVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ed25519SignatureFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ed25519_signature_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(enterpriseAddressNew:(nonnull NSNumber *)networkVal withPayment:(nonnull NSString *)paymentPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t network = [[params objectAtIndex:0]  longLongValue];
        RPtr payment = [[params objectAtIndex:1]  rPtr];
        return enterprise_address_new(network, payment, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[networkVal, paymentPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(enterpriseAddressPaymentCred:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return enterprise_address_payment_cred(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(enterpriseAddressToAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return enterprise_address_to_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(enterpriseAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr  rPtr];
        return enterprise_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(exUnitPricesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_unit_prices_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ex_unit_prices_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_unit_prices_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return ex_unit_prices_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_unit_prices_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return ex_unit_prices_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesMemPrice:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_unit_prices_mem_price(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesStepPrice:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_unit_prices_step_price(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitPricesNew:(nonnull NSString *)memPricePtr withStepPrice:(nonnull NSString *)stepPricePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr memPrice = [[params objectAtIndex:0]  rPtr];
        RPtr stepPrice = [[params objectAtIndex:1]  rPtr];
        return ex_unit_prices_new(memPrice, stepPrice, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[memPricePtr, stepPricePtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(exUnitsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_units_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ex_units_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_units_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return ex_units_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_units_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return ex_units_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsMem:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_units_mem(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsSteps:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return ex_units_steps(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(exUnitsNew:(nonnull NSString *)memPtr withSteps:(nonnull NSString *)stepsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr mem = [[params objectAtIndex:0]  rPtr];
        RPtr steps = [[params objectAtIndex:1]  rPtr];
        return ex_units_new(mem, steps, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[memPtr, stepsPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(fixedTransactionToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return fixed_transaction_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return fixed_transaction_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionNew:(nonnull NSString *)rawBodyVal withRawWitnessSet:(nonnull NSString *)rawWitnessSetVal withIsValid:(nonnull NSNumber *)isValidVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataRawBody = [NSData fromBase64:[params objectAtIndex:0]];
        NSData* dataRawWitnessSet = [NSData fromBase64:[params objectAtIndex:1]];
        BOOL isValid = [[params objectAtIndex:2]  boolValue];
        return fixed_transaction_new((uint8_t*)dataRawBody.bytes, dataRawBody.length, (uint8_t*)dataRawWitnessSet.bytes, dataRawWitnessSet.length, isValid, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[rawBodyVal, rawWitnessSetVal, isValidVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionNewWithAuxiliary:(nonnull NSString *)rawBodyVal withRawWitnessSet:(nonnull NSString *)rawWitnessSetVal withRawAuxiliaryData:(nonnull NSString *)rawAuxiliaryDataVal withIsValid:(nonnull NSNumber *)isValidVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataRawBody = [NSData fromBase64:[params objectAtIndex:0]];
        NSData* dataRawWitnessSet = [NSData fromBase64:[params objectAtIndex:1]];
        NSData* dataRawAuxiliaryData = [NSData fromBase64:[params objectAtIndex:2]];
        BOOL isValid = [[params objectAtIndex:3]  boolValue];
        return fixed_transaction_new_with_auxiliary((uint8_t*)dataRawBody.bytes, dataRawBody.length, (uint8_t*)dataRawWitnessSet.bytes, dataRawWitnessSet.length, (uint8_t*)dataRawAuxiliaryData.bytes, dataRawAuxiliaryData.length, isValid, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[rawBodyVal, rawWitnessSetVal, rawAuxiliaryDataVal, isValidVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionBody:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_body(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionRawBody:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_raw_body(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionSetBody:(nonnull NSString *)selfPtr withRawBody:(nonnull NSString *)rawBodyVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        NSData* dataRawBody = [NSData fromBase64:[params objectAtIndex:1]];
        fixed_transaction_set_body(self, (uint8_t*)dataRawBody.bytes, dataRawBody.length, error);
        return nil;
    }] exec:@[selfPtr, rawBodyVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionSetWitnessSet:(nonnull NSString *)selfPtr withRawWitnessSet:(nonnull NSString *)rawWitnessSetVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        NSData* dataRawWitnessSet = [NSData fromBase64:[params objectAtIndex:1]];
        fixed_transaction_set_witness_set(self, (uint8_t*)dataRawWitnessSet.bytes, dataRawWitnessSet.length, error);
        return nil;
    }] exec:@[selfPtr, rawWitnessSetVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionWitnessSet:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_witness_set(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionRawWitnessSet:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_raw_witness_set(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionSetIsValid:(nonnull NSString *)selfPtr withValid:(nonnull NSNumber *)validVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        BOOL valid = [[params objectAtIndex:1]  boolValue];
        fixed_transaction_set_is_valid(self, valid, error);
        return nil;
    }] exec:@[selfPtr, validVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionIsValid:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_is_valid(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionSetAuxiliaryData:(nonnull NSString *)selfPtr withRawAuxiliaryData:(nonnull NSString *)rawAuxiliaryDataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        NSData* dataRawAuxiliaryData = [NSData fromBase64:[params objectAtIndex:1]];
        fixed_transaction_set_auxiliary_data(self, (uint8_t*)dataRawAuxiliaryData.bytes, dataRawAuxiliaryData.length, error);
        return nil;
    }] exec:@[selfPtr, rawAuxiliaryDataVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionAuxiliaryData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_auxiliary_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(fixedTransactionRawAuxiliaryData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return fixed_transaction_raw_auxiliary_data(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(generalTransactionMetadataToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return general_transaction_metadata_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return general_transaction_metadata_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return general_transaction_metadata_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return general_transaction_metadata_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return general_transaction_metadata_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return general_transaction_metadata_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return general_transaction_metadata_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return general_transaction_metadata_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return general_transaction_metadata_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return general_transaction_metadata_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(generalTransactionMetadataKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return general_transaction_metadata_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(genesisDelegateHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return genesis_delegate_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisDelegateHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_delegate_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisDelegateHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return genesis_delegate_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisDelegateHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return genesis_delegate_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisDelegateHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_delegate_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisDelegateHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return genesis_delegate_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(genesisHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return genesis_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return genesis_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return genesis_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return genesis_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(genesisHashesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hashes_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return genesis_hashes_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hashes_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return genesis_hashes_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hashes_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return genesis_hashes_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return genesis_hashes_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return genesis_hashes_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return genesis_hashes_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisHashesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        genesis_hashes_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(genesisKeyDelegationToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return genesis_key_delegation_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return genesis_key_delegation_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return genesis_key_delegation_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationGenesishash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_genesishash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationGenesisDelegateHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_genesis_delegate_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationVrfKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return genesis_key_delegation_vrf_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(genesisKeyDelegationNew:(nonnull NSString *)genesishashPtr withGenesisDelegateHash:(nonnull NSString *)genesisDelegateHashPtr withVrfKeyhash:(nonnull NSString *)vrfKeyhashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr genesishash = [[params objectAtIndex:0]  rPtr];
        RPtr genesisDelegateHash = [[params objectAtIndex:1]  rPtr];
        RPtr vrfKeyhash = [[params objectAtIndex:2]  rPtr];
        return genesis_key_delegation_new(genesishash, genesisDelegateHash, vrfKeyhash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[genesishashPtr, genesisDelegateHashPtr, vrfKeyhashPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(headerToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return header_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return header_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return header_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerHeaderBody:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_header_body(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodySignature:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_signature(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerNew:(nonnull NSString *)headerBodyPtr withBodySignature:(nonnull NSString *)bodySignaturePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr headerBody = [[params objectAtIndex:0]  rPtr];
        RPtr bodySignature = [[params objectAtIndex:1]  rPtr];
        return header_new(headerBody, bodySignature, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[headerBodyPtr, bodySignaturePtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(headerBodyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return header_body_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return header_body_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return header_body_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyBlockNumber:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return header_body_block_number(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodySlot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return header_body_slot(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodySlotBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_slot_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyPrevHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_prev_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyIssuerVkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_issuer_vkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyVrfVkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_vrf_vkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyHasNonceAndLeaderVrf:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return header_body_has_nonce_and_leader_vrf(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyNonceVrfOrNothing:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_nonce_vrf_or_nothing(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyLeaderVrfOrNothing:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_leader_vrf_or_nothing(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyHasVrfResult:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return header_body_has_vrf_result(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyVrfResultOrNothing:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_vrf_result_or_nothing(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyBlockBodySize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return header_body_block_body_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyBlockBodyHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_block_body_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyOperationalCert:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_operational_cert(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyProtocolVersion:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return header_body_protocol_version(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyNew:(nonnull NSNumber *)blockNumberVal withSlot:(nonnull NSNumber *)slotVal withIssuerVkey:(nonnull NSString *)issuerVkeyPtr withVrfVkey:(nonnull NSString *)vrfVkeyPtr withVrfResult:(nonnull NSString *)vrfResultPtr withBlockBodySize:(nonnull NSNumber *)blockBodySizeVal withBlockBodyHash:(nonnull NSString *)blockBodyHashPtr withOperationalCert:(nonnull NSString *)operationalCertPtr withProtocolVersion:(nonnull NSString *)protocolVersionPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t blockNumber = [[params objectAtIndex:0]  longLongValue];
        int64_t slot = [[params objectAtIndex:1]  longLongValue];
        RPtr issuerVkey = [[params objectAtIndex:2]  rPtr];
        RPtr vrfVkey = [[params objectAtIndex:3]  rPtr];
        RPtr vrfResult = [[params objectAtIndex:4]  rPtr];
        int64_t blockBodySize = [[params objectAtIndex:5]  longLongValue];
        RPtr blockBodyHash = [[params objectAtIndex:6]  rPtr];
        RPtr operationalCert = [[params objectAtIndex:7]  rPtr];
        RPtr protocolVersion = [[params objectAtIndex:8]  rPtr];
        return header_body_new(blockNumber, slot, issuerVkey, vrfVkey, vrfResult, blockBodySize, blockBodyHash, operationalCert, protocolVersion, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[blockNumberVal, slotVal, issuerVkeyPtr, vrfVkeyPtr, vrfResultPtr, blockBodySizeVal, blockBodyHashPtr, operationalCertPtr, protocolVersionPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyNewWithPrevHash:(nonnull NSNumber *)blockNumberVal withSlot:(nonnull NSNumber *)slotVal withPrevHash:(nonnull NSString *)prevHashPtr withIssuerVkey:(nonnull NSString *)issuerVkeyPtr withVrfVkey:(nonnull NSString *)vrfVkeyPtr withVrfResult:(nonnull NSString *)vrfResultPtr withBlockBodySize:(nonnull NSNumber *)blockBodySizeVal withBlockBodyHash:(nonnull NSString *)blockBodyHashPtr withOperationalCert:(nonnull NSString *)operationalCertPtr withProtocolVersion:(nonnull NSString *)protocolVersionPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t blockNumber = [[params objectAtIndex:0]  longLongValue];
        int64_t slot = [[params objectAtIndex:1]  longLongValue];
        RPtr prevHash = [[params objectAtIndex:2]  rPtr];
        RPtr issuerVkey = [[params objectAtIndex:3]  rPtr];
        RPtr vrfVkey = [[params objectAtIndex:4]  rPtr];
        RPtr vrfResult = [[params objectAtIndex:5]  rPtr];
        int64_t blockBodySize = [[params objectAtIndex:6]  longLongValue];
        RPtr blockBodyHash = [[params objectAtIndex:7]  rPtr];
        RPtr operationalCert = [[params objectAtIndex:8]  rPtr];
        RPtr protocolVersion = [[params objectAtIndex:9]  rPtr];
        return header_body_new_with_prev_hash(blockNumber, slot, prevHash, issuerVkey, vrfVkey, vrfResult, blockBodySize, blockBodyHash, operationalCert, protocolVersion, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[blockNumberVal, slotVal, prevHashPtr, issuerVkeyPtr, vrfVkeyPtr, vrfResultPtr, blockBodySizeVal, blockBodyHashPtr, operationalCertPtr, protocolVersionPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(headerBodyNewHeaderbody:(nonnull NSNumber *)blockNumberVal withSlot:(nonnull NSString *)slotPtr withIssuerVkey:(nonnull NSString *)issuerVkeyPtr withVrfVkey:(nonnull NSString *)vrfVkeyPtr withVrfResult:(nonnull NSString *)vrfResultPtr withBlockBodySize:(nonnull NSNumber *)blockBodySizeVal withBlockBodyHash:(nonnull NSString *)blockBodyHashPtr withOperationalCert:(nonnull NSString *)operationalCertPtr withProtocolVersion:(nonnull NSString *)protocolVersionPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t blockNumber = [[params objectAtIndex:0]  longLongValue];
        RPtr slot = [[params objectAtIndex:1]  rPtr];
        RPtr issuerVkey = [[params objectAtIndex:2]  rPtr];
        RPtr vrfVkey = [[params objectAtIndex:3]  rPtr];
        RPtr vrfResult = [[params objectAtIndex:4]  rPtr];
        int64_t blockBodySize = [[params objectAtIndex:5]  longLongValue];
        RPtr blockBodyHash = [[params objectAtIndex:6]  rPtr];
        RPtr operationalCert = [[params objectAtIndex:7]  rPtr];
        RPtr protocolVersion = [[params objectAtIndex:8]  rPtr];
        return header_body_new_headerbody(blockNumber, slot, issuerVkey, vrfVkey, vrfResult, blockBodySize, blockBodyHash, operationalCert, protocolVersion, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[blockNumberVal, slotPtr, issuerVkeyPtr, vrfVkeyPtr, vrfResultPtr, blockBodySizeVal, blockBodyHashPtr, operationalCertPtr, protocolVersionPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(headerBodyNewHeaderbodyWithPrevHash:(nonnull NSNumber *)blockNumberVal withSlot:(nonnull NSString *)slotPtr withPrevHash:(nonnull NSString *)prevHashPtr withIssuerVkey:(nonnull NSString *)issuerVkeyPtr withVrfVkey:(nonnull NSString *)vrfVkeyPtr withVrfResult:(nonnull NSString *)vrfResultPtr withBlockBodySize:(nonnull NSNumber *)blockBodySizeVal withBlockBodyHash:(nonnull NSString *)blockBodyHashPtr withOperationalCert:(nonnull NSString *)operationalCertPtr withProtocolVersion:(nonnull NSString *)protocolVersionPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t blockNumber = [[params objectAtIndex:0]  longLongValue];
        RPtr slot = [[params objectAtIndex:1]  rPtr];
        RPtr prevHash = [[params objectAtIndex:2]  rPtr];
        RPtr issuerVkey = [[params objectAtIndex:3]  rPtr];
        RPtr vrfVkey = [[params objectAtIndex:4]  rPtr];
        RPtr vrfResult = [[params objectAtIndex:5]  rPtr];
        int64_t blockBodySize = [[params objectAtIndex:6]  longLongValue];
        RPtr blockBodyHash = [[params objectAtIndex:7]  rPtr];
        RPtr operationalCert = [[params objectAtIndex:8]  rPtr];
        RPtr protocolVersion = [[params objectAtIndex:9]  rPtr];
        return header_body_new_headerbody_with_prev_hash(blockNumber, slot, prevHash, issuerVkey, vrfVkey, vrfResult, blockBodySize, blockBodyHash, operationalCert, protocolVersion, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[blockNumberVal, slotPtr, prevHashPtr, issuerVkeyPtr, vrfVkeyPtr, vrfResultPtr, blockBodySizeVal, blockBodyHashPtr, operationalCertPtr, protocolVersionPtr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(inputWithScriptWitnessNewWithNativeScriptWitness:(nonnull NSString *)inputPtr withWitness:(nonnull NSString *)witnessPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr input = [[params objectAtIndex:0]  rPtr];
        RPtr witness = [[params objectAtIndex:1]  rPtr];
        return input_with_script_witness_new_with_native_script_witness(input, witness, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputPtr, witnessPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(inputWithScriptWitnessNewWithPlutusWitness:(nonnull NSString *)inputPtr withWitness:(nonnull NSString *)witnessPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr input = [[params objectAtIndex:0]  rPtr];
        RPtr witness = [[params objectAtIndex:1]  rPtr];
        return input_with_script_witness_new_with_plutus_witness(input, witness, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputPtr, witnessPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(inputWithScriptWitnessInput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return input_with_script_witness_input(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(inputsWithScriptWitnessNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return inputs_with_script_witness_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(inputsWithScriptWitnessAdd:(nonnull NSString *)selfPtr withInput:(nonnull NSString *)inputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr input = [[params objectAtIndex:1]  rPtr];
        inputs_with_script_witness_add(self, input, error);
        return nil;
    }] exec:@[selfPtr, inputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(inputsWithScriptWitnessGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return inputs_with_script_witness_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(inputsWithScriptWitnessLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return inputs_with_script_witness_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(intToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return int_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return int_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return int_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intNew:(nonnull NSString *)xPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* xPtr, CharPtr* error) {
        RPtr result;
        RPtr x = [xPtr  rPtr];
        return int_new(x, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:xPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intNewNegative:(nonnull NSString *)xPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* xPtr, CharPtr* error) {
        RPtr result;
        RPtr x = [xPtr  rPtr];
        return int_new_negative(x, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:xPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intNewI32:(nonnull NSNumber *)xVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSNumber* xVal, CharPtr* error) {
        RPtr result;
        int64_t x = [xVal  longLongValue];
        return int_new_i32(x, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:xVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intIsPositive:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return int_is_positive(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intAsPositive:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_as_positive(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intAsNegative:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_as_negative(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intAsI32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return int_as_i32(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intAsI32OrNothing:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return int_as_i32_or_nothing(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intAsI32OrFail:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return int_as_i32_or_fail(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intToStr:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return int_to_str(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(intFromStr:(nonnull NSString *)stringVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stringVal, CharPtr* error) {
        RPtr result;
        CharPtr string = [stringVal  charPtr];
        return int_from_str(string, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stringVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(ipv4ToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv4_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4FromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ipv4_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4ToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv4_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4FromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return ipv4_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4ToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv4_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4FromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return ipv4_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4New:(nonnull NSString *)dataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dataVal, CharPtr* error) {
        RPtr result;
        NSData* dataData = [NSData fromBase64:dataVal];
        return ipv4_new((uint8_t*)dataData.bytes, dataData.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dataVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv4Ip:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv4_ip(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(ipv6ToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv6_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6FromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return ipv6_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6ToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv6_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6FromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return ipv6_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6ToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv6_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6FromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return ipv6_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6New:(nonnull NSString *)dataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dataVal, CharPtr* error) {
        RPtr result;
        NSData* dataData = [NSData fromBase64:dataVal];
        return ipv6_new((uint8_t*)dataData.bytes, dataData.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dataVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(ipv6Ip:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return ipv6_ip(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(kESSignatureToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return k_e_s_signature_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESSignatureFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return k_e_s_signature_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(kESVKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return k_e_s_v_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESVKeyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return k_e_s_v_key_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESVKeyToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return k_e_s_v_key_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESVKeyFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return k_e_s_v_key_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESVKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return k_e_s_v_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(kESVKeyFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return k_e_s_v_key_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(languageToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return language_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return language_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return language_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return language_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return language_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return language_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageNewPlutusV1:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return language_new_plutus_v1(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageNewPlutusV2:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return language_new_plutus_v2(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languageKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return language_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(languagesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return languages_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languagesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return languages_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languagesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return languages_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languagesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        languages_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(languagesList:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return languages_list(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(legacyDaedalusPrivateKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return legacy_daedalus_private_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(legacyDaedalusPrivateKeyAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return legacy_daedalus_private_key_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(legacyDaedalusPrivateKeyChaincode:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return legacy_daedalus_private_key_chaincode(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(linearFeeConstant:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return linear_fee_constant(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(linearFeeCoefficient:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return linear_fee_coefficient(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(linearFeeNew:(nonnull NSString *)coefficientPtr withConstant:(nonnull NSString *)constantPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr coefficient = [[params objectAtIndex:0]  rPtr];
        RPtr constant = [[params objectAtIndex:1]  rPtr];
        return linear_fee_new(coefficient, constant, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[coefficientPtr, constantPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(mIRToStakeCredentialsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return m_i_r_to_stake_credentials_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return m_i_r_to_stake_credentials_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return m_i_r_to_stake_credentials_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return m_i_r_to_stake_credentials_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return m_i_r_to_stake_credentials_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return m_i_r_to_stake_credentials_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return m_i_r_to_stake_credentials_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return m_i_r_to_stake_credentials_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsInsert:(nonnull NSString *)selfPtr withCred:(nonnull NSString *)credPtr withDelta:(nonnull NSString *)deltaPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr cred = [[params objectAtIndex:1]  rPtr];
        RPtr delta = [[params objectAtIndex:2]  rPtr];
        return m_i_r_to_stake_credentials_insert(self, cred, delta, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, credPtr, deltaPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsGet:(nonnull NSString *)selfPtr withCred:(nonnull NSString *)credPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr cred = [[params objectAtIndex:1]  rPtr];
        return m_i_r_to_stake_credentials_get(self, cred, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, credPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mIRToStakeCredentialsKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return m_i_r_to_stake_credentials_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(metadataListToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return metadata_list_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return metadata_list_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return metadata_list_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return metadata_list_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return metadata_list_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return metadata_list_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return metadata_list_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataListAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        metadata_list_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(metadataMapToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return metadata_map_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return metadata_map_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return metadata_map_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return metadata_map_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return metadata_map_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return metadata_map_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return metadata_map_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapInsertStr:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyVal withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr key = [[params objectAtIndex:1]  charPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return metadata_map_insert_str(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyVal, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapInsertI32:(nonnull NSString *)selfPtr withKey:(nonnull NSNumber *)keyVal withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t key = [[params objectAtIndex:1]  longLongValue];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return metadata_map_insert_i32(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyVal, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return metadata_map_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapGetStr:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr key = [[params objectAtIndex:1]  charPtr];
        return metadata_map_get_str(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapGetI32:(nonnull NSString *)selfPtr withKey:(nonnull NSNumber *)keyVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t key = [[params objectAtIndex:1]  longLongValue];
        return metadata_map_get_i32(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapHas:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        BOOL result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return metadata_map_has(self, key, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(metadataMapKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return metadata_map_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(mintToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return mint_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return mint_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return mint_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return mint_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintNewFromEntry:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr key = [[params objectAtIndex:0]  rPtr];
        RPtr value = [[params objectAtIndex:1]  rPtr];
        return mint_new_from_entry(key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return mint_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return mint_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return mint_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintGetAll:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return mint_get_all(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAsPositiveMultiasset:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_as_positive_multiasset(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAsNegativeMultiasset:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_as_negative_multiasset(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(mintAssetsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return mint_assets_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAssetsNewFromEntry:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr key = [[params objectAtIndex:0]  rPtr];
        RPtr value = [[params objectAtIndex:1]  rPtr];
        return mint_assets_new_from_entry(key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAssetsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return mint_assets_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAssetsInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return mint_assets_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAssetsGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return mint_assets_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintAssetsKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_assets_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(mintBuilderNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return mint_builder_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderAddAsset:(nonnull NSString *)selfPtr withMint:(nonnull NSString *)mintPtr withAssetName:(nonnull NSString *)assetNamePtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr mint = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        mint_builder_add_asset(self, mint, assetName, amount, error);
        return nil;
    }] exec:@[selfPtr, mintPtr, assetNamePtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderSetAsset:(nonnull NSString *)selfPtr withMint:(nonnull NSString *)mintPtr withAssetName:(nonnull NSString *)assetNamePtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr mint = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        mint_builder_set_asset(self, mint, assetName, amount, error);
        return nil;
    }] exec:@[selfPtr, mintPtr, assetNamePtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderBuild:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_build(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderGetNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_get_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderGetPlutusWitnesses:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_get_plutus_witnesses(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderGetRefInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_get_ref_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderGetRedeeemers:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_get_redeeemers(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderHasPlutusScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_has_plutus_scripts(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintBuilderHasNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return mint_builder_has_native_scripts(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(mintWitnessNewNativeScript:(nonnull NSString *)nativeScriptPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* nativeScriptPtr, CharPtr* error) {
        RPtr result;
        RPtr nativeScript = [nativeScriptPtr  rPtr];
        return mint_witness_new_native_script(nativeScript, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nativeScriptPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(mintWitnessNewPlutusScript:(nonnull NSString *)plutusScriptPtr withRedeemer:(nonnull NSString *)redeemerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr plutusScript = [[params objectAtIndex:0]  rPtr];
        RPtr redeemer = [[params objectAtIndex:1]  rPtr];
        return mint_witness_new_plutus_script(plutusScript, redeemer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[plutusScriptPtr, redeemerPtr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(moveInstantaneousRewardToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return move_instantaneous_reward_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return move_instantaneous_reward_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return move_instantaneous_reward_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardNewToOtherPot:(nonnull NSNumber *)potVal withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int32_t pot = [[params objectAtIndex:0]  integerValue];
        RPtr amount = [[params objectAtIndex:1]  rPtr];
        return move_instantaneous_reward_new_to_other_pot(pot, amount, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[potVal, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardNewToStakeCreds:(nonnull NSNumber *)potVal withAmounts:(nonnull NSString *)amountsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int32_t pot = [[params objectAtIndex:0]  integerValue];
        RPtr amounts = [[params objectAtIndex:1]  rPtr];
        return move_instantaneous_reward_new_to_stake_creds(pot, amounts, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[potVal, amountsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardPot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_pot(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardAsToOtherPot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_as_to_other_pot(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardAsToStakeCreds:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_reward_as_to_stake_creds(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(moveInstantaneousRewardsCertToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_rewards_cert_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return move_instantaneous_rewards_cert_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_rewards_cert_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return move_instantaneous_rewards_cert_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_rewards_cert_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return move_instantaneous_rewards_cert_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertMoveInstantaneousReward:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return move_instantaneous_rewards_cert_move_instantaneous_reward(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(moveInstantaneousRewardsCertNew:(nonnull NSString *)moveInstantaneousRewardPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* moveInstantaneousRewardPtr, CharPtr* error) {
        RPtr result;
        RPtr moveInstantaneousReward = [moveInstantaneousRewardPtr  rPtr];
        return move_instantaneous_rewards_cert_new(moveInstantaneousReward, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:moveInstantaneousRewardPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(multiAssetToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_asset_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return multi_asset_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_asset_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return multi_asset_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_asset_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return multi_asset_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return multi_asset_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return multi_asset_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetInsert:(nonnull NSString *)selfPtr withPolicyId:(nonnull NSString *)policyIdPtr withAssets:(nonnull NSString *)assetsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyId = [[params objectAtIndex:1]  rPtr];
        RPtr assets = [[params objectAtIndex:2]  rPtr];
        return multi_asset_insert(self, policyId, assets, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, policyIdPtr, assetsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetGet:(nonnull NSString *)selfPtr withPolicyId:(nonnull NSString *)policyIdPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyId = [[params objectAtIndex:1]  rPtr];
        return multi_asset_get(self, policyId, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, policyIdPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetSetAsset:(nonnull NSString *)selfPtr withPolicyId:(nonnull NSString *)policyIdPtr withAssetName:(nonnull NSString *)assetNamePtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyId = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr value = [[params objectAtIndex:3]  rPtr];
        return multi_asset_set_asset(self, policyId, assetName, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, policyIdPtr, assetNamePtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetGetAsset:(nonnull NSString *)selfPtr withPolicyId:(nonnull NSString *)policyIdPtr withAssetName:(nonnull NSString *)assetNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyId = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        return multi_asset_get_asset(self, policyId, assetName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, policyIdPtr, assetNamePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_asset_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiAssetSub:(nonnull NSString *)selfPtr withRhsMa:(nonnull NSString *)rhsMaPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsMa = [[params objectAtIndex:1]  rPtr];
        return multi_asset_sub(self, rhsMa, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, rhsMaPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(multiHostNameToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_host_name_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return multi_host_name_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_host_name_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return multi_host_name_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_host_name_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return multi_host_name_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameDnsName:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return multi_host_name_dns_name(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(multiHostNameNew:(nonnull NSString *)dnsNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dnsNamePtr, CharPtr* error) {
        RPtr result;
        RPtr dnsName = [dnsNamePtr  rPtr];
        return multi_host_name_new(dnsName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dnsNamePtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(nativeScriptToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return native_script_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return native_script_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return native_script_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewScriptPubkey:(nonnull NSString *)scriptPubkeyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* scriptPubkeyPtr, CharPtr* error) {
        RPtr result;
        RPtr scriptPubkey = [scriptPubkeyPtr  rPtr];
        return native_script_new_script_pubkey(scriptPubkey, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:scriptPubkeyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewScriptAll:(nonnull NSString *)scriptAllPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* scriptAllPtr, CharPtr* error) {
        RPtr result;
        RPtr scriptAll = [scriptAllPtr  rPtr];
        return native_script_new_script_all(scriptAll, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:scriptAllPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewScriptAny:(nonnull NSString *)scriptAnyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* scriptAnyPtr, CharPtr* error) {
        RPtr result;
        RPtr scriptAny = [scriptAnyPtr  rPtr];
        return native_script_new_script_any(scriptAny, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:scriptAnyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewScriptNOfK:(nonnull NSString *)scriptNOfKPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* scriptNOfKPtr, CharPtr* error) {
        RPtr result;
        RPtr scriptNOfK = [scriptNOfKPtr  rPtr];
        return native_script_new_script_n_of_k(scriptNOfK, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:scriptNOfKPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewTimelockStart:(nonnull NSString *)timelockStartPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* timelockStartPtr, CharPtr* error) {
        RPtr result;
        RPtr timelockStart = [timelockStartPtr  rPtr];
        return native_script_new_timelock_start(timelockStart, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:timelockStartPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptNewTimelockExpiry:(nonnull NSString *)timelockExpiryPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* timelockExpiryPtr, CharPtr* error) {
        RPtr result;
        RPtr timelockExpiry = [timelockExpiryPtr  rPtr];
        return native_script_new_timelock_expiry(timelockExpiry, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:timelockExpiryPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return native_script_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsScriptPubkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_script_pubkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsScriptAll:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_script_all(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsScriptAny:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_script_any(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsScriptNOfK:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_script_n_of_k(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsTimelockStart:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_timelock_start(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptAsTimelockExpiry:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_as_timelock_expiry(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptGetRequiredSigners:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return native_script_get_required_signers(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(nativeScriptsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return native_scripts_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return native_scripts_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return native_scripts_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nativeScriptsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        native_scripts_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(networkIdToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return network_id_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return network_id_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return network_id_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return network_id_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return network_id_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return network_id_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdTestnet:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_id_testnet(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdMainnet:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_id_mainnet(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkIdKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return network_id_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(networkInfoNew:(nonnull NSNumber *)networkIdVal withProtocolMagic:(nonnull NSNumber *)protocolMagicVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t networkId = [[params objectAtIndex:0]  longLongValue];
        int64_t protocolMagic = [[params objectAtIndex:1]  longLongValue];
        return network_info_new(networkId, protocolMagic, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[networkIdVal, protocolMagicVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoNetworkId:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return network_info_network_id(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoProtocolMagic:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return network_info_protocol_magic(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoTestnetPreview:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_info_testnet_preview(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoTestnetPreprod:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_info_testnet_preprod(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoTestnet:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_info_testnet(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(networkInfoMainnet:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return network_info_mainnet(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(nonceToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return nonce_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return nonce_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return nonce_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return nonce_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return nonce_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return nonce_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceNewIdentity:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return nonce_new_identity(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceNewFromHash:(nonnull NSString *)hashVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hashVal, CharPtr* error) {
        RPtr result;
        NSData* dataHash = [NSData fromBase64:hashVal];
        return nonce_new_from_hash((uint8_t*)dataHash.bytes, dataHash.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hashVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(nonceGetHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return nonce_get_hash(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(operationalCertToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return operational_cert_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return operational_cert_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return operational_cert_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertHotVkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_hot_vkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertSequenceNumber:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_sequence_number(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertKesPeriod:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_kes_period(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertSigma:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return operational_cert_sigma(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(operationalCertNew:(nonnull NSString *)hotVkeyPtr withSequenceNumber:(nonnull NSNumber *)sequenceNumberVal withKesPeriod:(nonnull NSNumber *)kesPeriodVal withSigma:(nonnull NSString *)sigmaPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr hotVkey = [[params objectAtIndex:0]  rPtr];
        int64_t sequenceNumber = [[params objectAtIndex:1]  longLongValue];
        int64_t kesPeriod = [[params objectAtIndex:2]  longLongValue];
        RPtr sigma = [[params objectAtIndex:3]  rPtr];
        return operational_cert_new(hotVkey, sequenceNumber, kesPeriod, sigma, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[hotVkeyPtr, sequenceNumberVal, kesPeriodVal, sigmaPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusDataToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_data_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return plutus_data_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewConstrPlutusData:(nonnull NSString *)constrPlutusDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* constrPlutusDataPtr, CharPtr* error) {
        RPtr result;
        RPtr constrPlutusData = [constrPlutusDataPtr  rPtr];
        return plutus_data_new_constr_plutus_data(constrPlutusData, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:constrPlutusDataPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewEmptyConstrPlutusData:(nonnull NSString *)alternativePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* alternativePtr, CharPtr* error) {
        RPtr result;
        RPtr alternative = [alternativePtr  rPtr];
        return plutus_data_new_empty_constr_plutus_data(alternative, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:alternativePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewMap:(nonnull NSString *)mapPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* mapPtr, CharPtr* error) {
        RPtr result;
        RPtr map = [mapPtr  rPtr];
        return plutus_data_new_map(map, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:mapPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewList:(nonnull NSString *)listPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* listPtr, CharPtr* error) {
        RPtr result;
        RPtr list = [listPtr  rPtr];
        return plutus_data_new_list(list, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:listPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewInteger:(nonnull NSString *)integerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* integerPtr, CharPtr* error) {
        RPtr result;
        RPtr integer = [integerPtr  rPtr];
        return plutus_data_new_integer(integer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:integerPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataNewBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_data_new_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataAsConstrPlutusData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_as_constr_plutus_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataAsMap:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_as_map(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataAsList:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_as_list(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataAsInteger:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_as_integer(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_data_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataToJson:(nonnull NSString *)selfPtr withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return plutus_data_to_json(self, schema, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusDataFromJson:(nonnull NSString *)jsonVal withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        CharPtr json = [[params objectAtIndex:0]  charPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return plutus_data_from_json(json, schema, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[jsonVal, schemaVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusListToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_list_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_list_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_list_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return plutus_list_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return plutus_list_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return plutus_list_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return plutus_list_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusListAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        plutus_list_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusMapToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_map_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_map_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_map_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return plutus_map_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return plutus_map_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return plutus_map_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return plutus_map_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return plutus_map_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusMapKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_map_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusScriptToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_script_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_script_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_script_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return plutus_script_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptNew:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_script_new((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptNewV2:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_script_new_v2((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptNewWithVersion:(nonnull NSString *)bytesVal withLanguage:(nonnull NSString *)languagePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:[params objectAtIndex:0]];
        RPtr language = [[params objectAtIndex:1]  rPtr];
        return plutus_script_new_with_version((uint8_t*)dataBytes.bytes, dataBytes.length, language, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bytesVal, languagePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_script_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptFromBytesV2:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_script_from_bytes_v2((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptFromBytesWithVersion:(nonnull NSString *)bytesVal withLanguage:(nonnull NSString *)languagePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:[params objectAtIndex:0]];
        RPtr language = [[params objectAtIndex:1]  rPtr];
        return plutus_script_from_bytes_with_version((uint8_t*)dataBytes.bytes, dataBytes.length, language, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bytesVal, languagePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptFromHexWithVersion:(nonnull NSString *)hexStrVal withLanguage:(nonnull NSString *)languagePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [[params objectAtIndex:0]  charPtr];
        RPtr language = [[params objectAtIndex:1]  rPtr];
        return plutus_script_from_hex_with_version(hexStr, language, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[hexStrVal, languagePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_script_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptLanguageVersion:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_script_language_version(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusScriptSourceNew:(nonnull NSString *)scriptPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* scriptPtr, CharPtr* error) {
        RPtr result;
        RPtr script = [scriptPtr  rPtr];
        return plutus_script_source_new(script, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:scriptPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptSourceNewRefInput:(nonnull NSString *)scriptHashPtr withInput:(nonnull NSString *)inputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr scriptHash = [[params objectAtIndex:0]  rPtr];
        RPtr input = [[params objectAtIndex:1]  rPtr];
        return plutus_script_source_new_ref_input(scriptHash, input, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptHashPtr, inputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptSourceNewRefInputWithLangVer:(nonnull NSString *)scriptHashPtr withInput:(nonnull NSString *)inputPtr withLangVer:(nonnull NSString *)langVerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr scriptHash = [[params objectAtIndex:0]  rPtr];
        RPtr input = [[params objectAtIndex:1]  rPtr];
        RPtr langVer = [[params objectAtIndex:2]  rPtr];
        return plutus_script_source_new_ref_input_with_lang_ver(scriptHash, input, langVer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptHashPtr, inputPtr, langVerPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusScriptsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_scripts_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return plutus_scripts_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_scripts_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return plutus_scripts_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_scripts_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return plutus_scripts_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return plutus_scripts_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return plutus_scripts_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return plutus_scripts_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusScriptsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        plutus_scripts_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusWitnessNew:(nonnull NSString *)scriptPtr withDatum:(nonnull NSString *)datumPtr withRedeemer:(nonnull NSString *)redeemerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr script = [[params objectAtIndex:0]  rPtr];
        RPtr datum = [[params objectAtIndex:1]  rPtr];
        RPtr redeemer = [[params objectAtIndex:2]  rPtr];
        return plutus_witness_new(script, datum, redeemer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptPtr, datumPtr, redeemerPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessNewWithRef:(nonnull NSString *)scriptPtr withDatum:(nonnull NSString *)datumPtr withRedeemer:(nonnull NSString *)redeemerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr script = [[params objectAtIndex:0]  rPtr];
        RPtr datum = [[params objectAtIndex:1]  rPtr];
        RPtr redeemer = [[params objectAtIndex:2]  rPtr];
        return plutus_witness_new_with_ref(script, datum, redeemer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptPtr, datumPtr, redeemerPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessNewWithoutDatum:(nonnull NSString *)scriptPtr withRedeemer:(nonnull NSString *)redeemerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr script = [[params objectAtIndex:0]  rPtr];
        RPtr redeemer = [[params objectAtIndex:1]  rPtr];
        return plutus_witness_new_without_datum(script, redeemer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptPtr, redeemerPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessNewWithRefWithoutDatum:(nonnull NSString *)scriptPtr withRedeemer:(nonnull NSString *)redeemerPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr script = [[params objectAtIndex:0]  rPtr];
        RPtr redeemer = [[params objectAtIndex:1]  rPtr];
        return plutus_witness_new_with_ref_without_datum(script, redeemer, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[scriptPtr, redeemerPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessScript:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_witness_script(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessDatum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_witness_datum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessRedeemer:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return plutus_witness_redeemer(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(plutusWitnessesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return plutus_witnesses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return plutus_witnesses_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return plutus_witnesses_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(plutusWitnessesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        plutus_witnesses_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(pointerNew:(nonnull NSNumber *)slotVal withTxIndex:(nonnull NSNumber *)txIndexVal withCertIndex:(nonnull NSNumber *)certIndexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t slot = [[params objectAtIndex:0]  longLongValue];
        int64_t txIndex = [[params objectAtIndex:1]  longLongValue];
        int64_t certIndex = [[params objectAtIndex:2]  longLongValue];
        return pointer_new(slot, txIndex, certIndex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[slotVal, txIndexVal, certIndexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerNewPointer:(nonnull NSString *)slotPtr withTxIndex:(nonnull NSString *)txIndexPtr withCertIndex:(nonnull NSString *)certIndexPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr slot = [[params objectAtIndex:0]  rPtr];
        RPtr txIndex = [[params objectAtIndex:1]  rPtr];
        RPtr certIndex = [[params objectAtIndex:2]  rPtr];
        return pointer_new_pointer(slot, txIndex, certIndex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[slotPtr, txIndexPtr, certIndexPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerSlot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return pointer_slot(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerTxIndex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return pointer_tx_index(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerCertIndex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return pointer_cert_index(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerSlotBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_slot_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerTxIndexBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_tx_index_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerCertIndexBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_cert_index_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(pointerAddressNew:(nonnull NSNumber *)networkVal withPayment:(nonnull NSString *)paymentPtr withStake:(nonnull NSString *)stakePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t network = [[params objectAtIndex:0]  longLongValue];
        RPtr payment = [[params objectAtIndex:1]  rPtr];
        RPtr stake = [[params objectAtIndex:2]  rPtr];
        return pointer_address_new(network, payment, stake, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[networkVal, paymentPtr, stakePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerAddressPaymentCred:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_address_payment_cred(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerAddressStakePointer:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_address_stake_pointer(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerAddressToAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pointer_address_to_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(pointerAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr  rPtr];
        return pointer_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(poolMetadataToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return pool_metadata_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return pool_metadata_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return pool_metadata_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataUrl:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_url(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataPoolMetadataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_pool_metadata_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataNew:(nonnull NSString *)urlPtr withPoolMetadataHash:(nonnull NSString *)poolMetadataHashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr url = [[params objectAtIndex:0]  rPtr];
        RPtr poolMetadataHash = [[params objectAtIndex:1]  rPtr];
        return pool_metadata_new(url, poolMetadataHash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[urlPtr, poolMetadataHashPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(poolMetadataHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return pool_metadata_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return pool_metadata_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return pool_metadata_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_metadata_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolMetadataHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return pool_metadata_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(poolParamsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return pool_params_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return pool_params_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return pool_params_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsOperator:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_operator(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsVrfKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_vrf_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsPledge:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_pledge(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsCost:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_cost(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsMargin:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_margin(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsRewardAccount:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_reward_account(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsPoolOwners:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_pool_owners(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsRelays:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_relays(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsPoolMetadata:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_params_pool_metadata(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsNew:(nonnull NSString *)operatorPtr withVrfKeyhash:(nonnull NSString *)vrfKeyhashPtr withPledge:(nonnull NSString *)pledgePtr withCost:(nonnull NSString *)costPtr withMargin:(nonnull NSString *)marginPtr withRewardAccount:(nonnull NSString *)rewardAccountPtr withPoolOwners:(nonnull NSString *)poolOwnersPtr withRelays:(nonnull NSString *)relaysPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr operator = [[params objectAtIndex:0]  rPtr];
        RPtr vrfKeyhash = [[params objectAtIndex:1]  rPtr];
        RPtr pledge = [[params objectAtIndex:2]  rPtr];
        RPtr cost = [[params objectAtIndex:3]  rPtr];
        RPtr margin = [[params objectAtIndex:4]  rPtr];
        RPtr rewardAccount = [[params objectAtIndex:5]  rPtr];
        RPtr poolOwners = [[params objectAtIndex:6]  rPtr];
        RPtr relays = [[params objectAtIndex:7]  rPtr];
        return pool_params_new(operator, vrfKeyhash, pledge, cost, margin, rewardAccount, poolOwners, relays, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[operatorPtr, vrfKeyhashPtr, pledgePtr, costPtr, marginPtr, rewardAccountPtr, poolOwnersPtr, relaysPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolParamsNewWithPoolMetadata:(nonnull NSString *)operatorPtr withVrfKeyhash:(nonnull NSString *)vrfKeyhashPtr withPledge:(nonnull NSString *)pledgePtr withCost:(nonnull NSString *)costPtr withMargin:(nonnull NSString *)marginPtr withRewardAccount:(nonnull NSString *)rewardAccountPtr withPoolOwners:(nonnull NSString *)poolOwnersPtr withRelays:(nonnull NSString *)relaysPtr withPoolMetadata:(nonnull NSString *)poolMetadataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr operator = [[params objectAtIndex:0]  rPtr];
        RPtr vrfKeyhash = [[params objectAtIndex:1]  rPtr];
        RPtr pledge = [[params objectAtIndex:2]  rPtr];
        RPtr cost = [[params objectAtIndex:3]  rPtr];
        RPtr margin = [[params objectAtIndex:4]  rPtr];
        RPtr rewardAccount = [[params objectAtIndex:5]  rPtr];
        RPtr poolOwners = [[params objectAtIndex:6]  rPtr];
        RPtr relays = [[params objectAtIndex:7]  rPtr];
        RPtr poolMetadata = [[params objectAtIndex:8]  rPtr];
        return pool_params_new_with_pool_metadata(operator, vrfKeyhash, pledge, cost, margin, rewardAccount, poolOwners, relays, poolMetadata, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[operatorPtr, vrfKeyhashPtr, pledgePtr, costPtr, marginPtr, rewardAccountPtr, poolOwnersPtr, relaysPtr, poolMetadataPtr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(poolRegistrationToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_registration_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return pool_registration_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_registration_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return pool_registration_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_registration_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return pool_registration_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationPoolParams:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_registration_pool_params(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRegistrationNew:(nonnull NSString *)poolParamsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* poolParamsPtr, CharPtr* error) {
        RPtr result;
        RPtr poolParams = [poolParamsPtr  rPtr];
        return pool_registration_new(poolParams, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:poolParamsPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(poolRetirementToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_retirement_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return pool_retirement_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_retirement_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return pool_retirement_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_retirement_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return pool_retirement_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementPoolKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return pool_retirement_pool_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementEpoch:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return pool_retirement_epoch(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(poolRetirementNew:(nonnull NSString *)poolKeyhashPtr withEpoch:(nonnull NSNumber *)epochVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr poolKeyhash = [[params objectAtIndex:0]  rPtr];
        int64_t epoch = [[params objectAtIndex:1]  longLongValue];
        return pool_retirement_new(poolKeyhash, epoch, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[poolKeyhashPtr, epochVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(privateKeyToPublic:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return private_key_to_public(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyGenerateEd25519:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return private_key_generate_ed25519(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyGenerateEd25519extended:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return private_key_generate_ed25519extended(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyFromBech32:(nonnull NSString *)bech32StrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32StrVal, CharPtr* error) {
        RPtr result;
        CharPtr bech32Str = [bech32StrVal  charPtr];
        return private_key_from_bech32(bech32Str, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32StrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return private_key_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return private_key_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyFromExtendedBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return private_key_from_extended_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyFromNormalBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return private_key_from_normal_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeySign:(nonnull NSString *)selfPtr withMessage:(nonnull NSString *)messageVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        NSData* dataMessage = [NSData fromBase64:[params objectAtIndex:1]];
        return private_key_sign(self, (uint8_t*)dataMessage.bytes, dataMessage.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, messageVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return private_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(privateKeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return private_key_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return proposed_protocol_parameter_updates_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return proposed_protocol_parameter_updates_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return proposed_protocol_parameter_updates_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return proposed_protocol_parameter_updates_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return proposed_protocol_parameter_updates_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return proposed_protocol_parameter_updates_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return proposed_protocol_parameter_updates_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return proposed_protocol_parameter_updates_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return proposed_protocol_parameter_updates_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return proposed_protocol_parameter_updates_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(proposedProtocolParameterUpdatesKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return proposed_protocol_parameter_updates_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(protocolParamUpdateToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return protocol_param_update_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return protocol_param_update_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return protocol_param_update_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMinfeeA:(nonnull NSString *)selfPtr withMinfeeA:(nonnull NSString *)minfeeAPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr minfeeA = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_minfee_a(self, minfeeA, error);
        return nil;
    }] exec:@[selfPtr, minfeeAPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMinfeeA:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_minfee_a(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMinfeeB:(nonnull NSString *)selfPtr withMinfeeB:(nonnull NSString *)minfeeBPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr minfeeB = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_minfee_b(self, minfeeB, error);
        return nil;
    }] exec:@[selfPtr, minfeeBPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMinfeeB:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_minfee_b(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxBlockBodySize:(nonnull NSString *)selfPtr withMaxBlockBodySize:(nonnull NSNumber *)maxBlockBodySizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxBlockBodySize = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_block_body_size(self, maxBlockBodySize, error);
        return nil;
    }] exec:@[selfPtr, maxBlockBodySizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxBlockBodySize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_block_body_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxTxSize:(nonnull NSString *)selfPtr withMaxTxSize:(nonnull NSNumber *)maxTxSizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxTxSize = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_tx_size(self, maxTxSize, error);
        return nil;
    }] exec:@[selfPtr, maxTxSizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxTxSize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_tx_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxBlockHeaderSize:(nonnull NSString *)selfPtr withMaxBlockHeaderSize:(nonnull NSNumber *)maxBlockHeaderSizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxBlockHeaderSize = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_block_header_size(self, maxBlockHeaderSize, error);
        return nil;
    }] exec:@[selfPtr, maxBlockHeaderSizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxBlockHeaderSize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_block_header_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetKeyDeposit:(nonnull NSString *)selfPtr withKeyDeposit:(nonnull NSString *)keyDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr keyDeposit = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_key_deposit(self, keyDeposit, error);
        return nil;
    }] exec:@[selfPtr, keyDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateKeyDeposit:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_key_deposit(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetPoolDeposit:(nonnull NSString *)selfPtr withPoolDeposit:(nonnull NSString *)poolDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr poolDeposit = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_pool_deposit(self, poolDeposit, error);
        return nil;
    }] exec:@[selfPtr, poolDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdatePoolDeposit:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_pool_deposit(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxEpoch:(nonnull NSString *)selfPtr withMaxEpoch:(nonnull NSNumber *)maxEpochVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxEpoch = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_epoch(self, maxEpoch, error);
        return nil;
    }] exec:@[selfPtr, maxEpochVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxEpoch:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_epoch(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetNOpt:(nonnull NSString *)selfPtr withNOpt:(nonnull NSNumber *)nOptVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t nOpt = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_n_opt(self, nOpt, error);
        return nil;
    }] exec:@[selfPtr, nOptVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateNOpt:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_n_opt(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetPoolPledgeInfluence:(nonnull NSString *)selfPtr withPoolPledgeInfluence:(nonnull NSString *)poolPledgeInfluencePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr poolPledgeInfluence = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_pool_pledge_influence(self, poolPledgeInfluence, error);
        return nil;
    }] exec:@[selfPtr, poolPledgeInfluencePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdatePoolPledgeInfluence:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_pool_pledge_influence(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetExpansionRate:(nonnull NSString *)selfPtr withExpansionRate:(nonnull NSString *)expansionRatePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr expansionRate = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_expansion_rate(self, expansionRate, error);
        return nil;
    }] exec:@[selfPtr, expansionRatePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateExpansionRate:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_expansion_rate(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetTreasuryGrowthRate:(nonnull NSString *)selfPtr withTreasuryGrowthRate:(nonnull NSString *)treasuryGrowthRatePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr treasuryGrowthRate = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_treasury_growth_rate(self, treasuryGrowthRate, error);
        return nil;
    }] exec:@[selfPtr, treasuryGrowthRatePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateTreasuryGrowthRate:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_treasury_growth_rate(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateD:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_d(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateExtraEntropy:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_extra_entropy(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetProtocolVersion:(nonnull NSString *)selfPtr withProtocolVersion:(nonnull NSString *)protocolVersionPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr protocolVersion = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_protocol_version(self, protocolVersion, error);
        return nil;
    }] exec:@[selfPtr, protocolVersionPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateProtocolVersion:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_protocol_version(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMinPoolCost:(nonnull NSString *)selfPtr withMinPoolCost:(nonnull NSString *)minPoolCostPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr minPoolCost = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_min_pool_cost(self, minPoolCost, error);
        return nil;
    }] exec:@[selfPtr, minPoolCostPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMinPoolCost:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_min_pool_cost(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetAdaPerUtxoByte:(nonnull NSString *)selfPtr withAdaPerUtxoByte:(nonnull NSString *)adaPerUtxoBytePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr adaPerUtxoByte = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_ada_per_utxo_byte(self, adaPerUtxoByte, error);
        return nil;
    }] exec:@[selfPtr, adaPerUtxoBytePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateAdaPerUtxoByte:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_ada_per_utxo_byte(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetCostModels:(nonnull NSString *)selfPtr withCostModels:(nonnull NSString *)costModelsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr costModels = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_cost_models(self, costModels, error);
        return nil;
    }] exec:@[selfPtr, costModelsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateCostModels:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_cost_models(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetExecutionCosts:(nonnull NSString *)selfPtr withExecutionCosts:(nonnull NSString *)executionCostsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr executionCosts = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_execution_costs(self, executionCosts, error);
        return nil;
    }] exec:@[selfPtr, executionCostsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateExecutionCosts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_execution_costs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxTxExUnits:(nonnull NSString *)selfPtr withMaxTxExUnits:(nonnull NSString *)maxTxExUnitsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr maxTxExUnits = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_max_tx_ex_units(self, maxTxExUnits, error);
        return nil;
    }] exec:@[selfPtr, maxTxExUnitsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxTxExUnits:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_tx_ex_units(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxBlockExUnits:(nonnull NSString *)selfPtr withMaxBlockExUnits:(nonnull NSString *)maxBlockExUnitsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr maxBlockExUnits = [[params objectAtIndex:1]  rPtr];
        protocol_param_update_set_max_block_ex_units(self, maxBlockExUnits, error);
        return nil;
    }] exec:@[selfPtr, maxBlockExUnitsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxBlockExUnits:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_block_ex_units(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxValueSize:(nonnull NSString *)selfPtr withMaxValueSize:(nonnull NSNumber *)maxValueSizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxValueSize = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_value_size(self, maxValueSize, error);
        return nil;
    }] exec:@[selfPtr, maxValueSizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxValueSize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_value_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetCollateralPercentage:(nonnull NSString *)selfPtr withCollateralPercentage:(nonnull NSNumber *)collateralPercentageVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t collateralPercentage = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_collateral_percentage(self, collateralPercentage, error);
        return nil;
    }] exec:@[selfPtr, collateralPercentageVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateCollateralPercentage:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_collateral_percentage(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateSetMaxCollateralInputs:(nonnull NSString *)selfPtr withMaxCollateralInputs:(nonnull NSNumber *)maxCollateralInputsVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxCollateralInputs = [[params objectAtIndex:1]  longLongValue];
        protocol_param_update_set_max_collateral_inputs(self, maxCollateralInputs, error);
        return nil;
    }] exec:@[selfPtr, maxCollateralInputsVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateMaxCollateralInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_param_update_max_collateral_inputs(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolParamUpdateNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return protocol_param_update_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(protocolVersionToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_version_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return protocol_version_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_version_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return protocol_version_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return protocol_version_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return protocol_version_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionMajor:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_version_major(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionMinor:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return protocol_version_minor(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(protocolVersionNew:(nonnull NSNumber *)majorVal withMinor:(nonnull NSNumber *)minorVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t major = [[params objectAtIndex:0]  longLongValue];
        int64_t minor = [[params objectAtIndex:1]  longLongValue];
        return protocol_version_new(major, minor, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[majorVal, minorVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(publicKeyFromBech32:(nonnull NSString *)bech32StrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bech32StrVal, CharPtr* error) {
        RPtr result;
        CharPtr bech32Str = [bech32StrVal  charPtr];
        return public_key_from_bech32(bech32Str, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bech32StrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyToBech32:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return public_key_to_bech32(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return public_key_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return public_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyVerify:(nonnull NSString *)selfPtr withData:(nonnull NSString *)dataVal withSignature:(nonnull NSString *)signaturePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        BOOL result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        NSData* dataData = [NSData fromBase64:[params objectAtIndex:1]];
        RPtr signature = [[params objectAtIndex:2]  rPtr];
        return public_key_verify(self, (uint8_t*)dataData.bytes, dataData.length, signature, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:@[selfPtr, dataVal, signaturePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return public_key_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return public_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return public_key_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(publicKeysNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return public_keys_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeysSize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return public_keys_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeysGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return public_keys_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(publicKeysAdd:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        public_keys_add(self, key, error);
        return nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(redeemerToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return redeemer_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return redeemer_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return redeemer_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTag:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_tag(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerIndex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_index(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerExUnits:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_ex_units(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerNew:(nonnull NSString *)tagPtr withIndex:(nonnull NSString *)indexPtr withData:(nonnull NSString *)dataPtr withExUnits:(nonnull NSString *)exUnitsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr tag = [[params objectAtIndex:0]  rPtr];
        RPtr index = [[params objectAtIndex:1]  rPtr];
        RPtr data = [[params objectAtIndex:2]  rPtr];
        RPtr exUnits = [[params objectAtIndex:3]  rPtr];
        return redeemer_new(tag, index, data, exUnits, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[tagPtr, indexPtr, dataPtr, exUnitsPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(redeemerTagToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_tag_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return redeemer_tag_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_tag_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return redeemer_tag_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_tag_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return redeemer_tag_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagNewSpend:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return redeemer_tag_new_spend(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagNewMint:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return redeemer_tag_new_mint(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagNewCert:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return redeemer_tag_new_cert(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagNewReward:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return redeemer_tag_new_reward(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemerTagKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return redeemer_tag_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(redeemersToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemers_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return redeemers_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemers_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return redeemers_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemers_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return redeemers_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return redeemers_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return redeemers_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return redeemers_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        redeemers_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(redeemersTotalExUnits:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return redeemers_total_ex_units(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(relayToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return relay_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return relay_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return relay_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayNewSingleHostAddr:(nonnull NSString *)singleHostAddrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* singleHostAddrPtr, CharPtr* error) {
        RPtr result;
        RPtr singleHostAddr = [singleHostAddrPtr  rPtr];
        return relay_new_single_host_addr(singleHostAddr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:singleHostAddrPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayNewSingleHostName:(nonnull NSString *)singleHostNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* singleHostNamePtr, CharPtr* error) {
        RPtr result;
        RPtr singleHostName = [singleHostNamePtr  rPtr];
        return relay_new_single_host_name(singleHostName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:singleHostNamePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayNewMultiHostName:(nonnull NSString *)multiHostNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* multiHostNamePtr, CharPtr* error) {
        RPtr result;
        RPtr multiHostName = [multiHostNamePtr  rPtr];
        return relay_new_multi_host_name(multiHostName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:multiHostNamePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return relay_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayAsSingleHostAddr:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_as_single_host_addr(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayAsSingleHostName:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_as_single_host_name(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relayAsMultiHostName:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return relay_as_multi_host_name(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(relaysToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relays_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return relays_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relays_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return relays_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return relays_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return relays_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return relays_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return relays_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return relays_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(relaysAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        relays_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(rewardAddressNew:(nonnull NSNumber *)networkVal withPayment:(nonnull NSString *)paymentPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t network = [[params objectAtIndex:0]  longLongValue];
        RPtr payment = [[params objectAtIndex:1]  rPtr];
        return reward_address_new(network, payment, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[networkVal, paymentPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressPaymentCred:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return reward_address_payment_cred(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressToAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return reward_address_to_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressFromAddress:(nonnull NSString *)addrPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrPtr, CharPtr* error) {
        RPtr result;
        RPtr addr = [addrPtr  rPtr];
        return reward_address_from_address(addr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(rewardAddressesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return reward_addresses_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return reward_addresses_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return reward_addresses_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return reward_addresses_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return reward_addresses_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return reward_addresses_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return reward_addresses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return reward_addresses_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return reward_addresses_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(rewardAddressesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        reward_addresses_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptAllToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_all_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_all_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_all_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_all_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_all_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_all_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_all_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAllNew:(nonnull NSString *)nativeScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* nativeScriptsPtr, CharPtr* error) {
        RPtr result;
        RPtr nativeScripts = [nativeScriptsPtr  rPtr];
        return script_all_new(nativeScripts, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nativeScriptsPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptAnyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_any_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_any_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_any_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_any_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_any_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_any_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_any_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptAnyNew:(nonnull NSString *)nativeScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* nativeScriptsPtr, CharPtr* error) {
        RPtr result;
        RPtr nativeScripts = [nativeScriptsPtr  rPtr];
        return script_any_new(nativeScripts, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nativeScriptsPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptDataHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_data_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptDataHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_data_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptDataHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return script_data_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptDataHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return script_data_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptDataHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_data_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptDataHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return script_data_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return script_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return script_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return script_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptHashesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_hashes_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_hashes_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_hashes_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_hashes_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_hashes_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_hashes_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return script_hashes_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return script_hashes_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return script_hashes_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptHashesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        script_hashes_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptNOfKToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_n_of_k_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_n_of_k_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_n_of_k_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_n_of_k_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_n_of_k_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_n_of_k_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKN:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return script_n_of_k_n(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_n_of_k_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptNOfKNew:(nonnull NSNumber *)nVal withNativeScripts:(nonnull NSString *)nativeScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t n = [[params objectAtIndex:0]  longLongValue];
        RPtr nativeScripts = [[params objectAtIndex:1]  rPtr];
        return script_n_of_k_new(n, nativeScripts, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[nVal, nativeScriptsPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptPubkeyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_pubkey_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_pubkey_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_pubkey_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_pubkey_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_pubkey_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_pubkey_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyAddrKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_pubkey_addr_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptPubkeyNew:(nonnull NSString *)addrKeyhashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* addrKeyhashPtr, CharPtr* error) {
        RPtr result;
        RPtr addrKeyhash = [addrKeyhashPtr  rPtr];
        return script_pubkey_new(addrKeyhash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:addrKeyhashPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(scriptRefToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return script_ref_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return script_ref_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return script_ref_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefNewNativeScript:(nonnull NSString *)nativeScriptPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* nativeScriptPtr, CharPtr* error) {
        RPtr result;
        RPtr nativeScript = [nativeScriptPtr  rPtr];
        return script_ref_new_native_script(nativeScript, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nativeScriptPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefNewPlutusScript:(nonnull NSString *)plutusScriptPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* plutusScriptPtr, CharPtr* error) {
        RPtr result;
        RPtr plutusScript = [plutusScriptPtr  rPtr];
        return script_ref_new_plutus_script(plutusScript, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:plutusScriptPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefIsNativeScript:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_is_native_script(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefIsPlutusScript:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_is_plutus_script(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefNativeScript:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_native_script(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(scriptRefPlutusScript:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return script_ref_plutus_script(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(singleHostAddrToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return single_host_addr_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return single_host_addr_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return single_host_addr_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrPort:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_port(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrIpv4:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_ipv4(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrIpv6:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_addr_ipv6(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return single_host_addr_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithPort:(nonnull NSNumber *)portVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSNumber* portVal, CharPtr* error) {
        RPtr result;
        int64_t port = [portVal  longLongValue];
        return single_host_addr_new_with_port(port, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:portVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithIpv4:(nonnull NSString *)ipv4Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ipv4Ptr, CharPtr* error) {
        RPtr result;
        RPtr ipv4 = [ipv4Ptr  rPtr];
        return single_host_addr_new_with_ipv4(ipv4, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ipv4Ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithPortIpv4:(nonnull NSNumber *)portVal withIpv4:(nonnull NSString *)ipv4Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t port = [[params objectAtIndex:0]  longLongValue];
        RPtr ipv4 = [[params objectAtIndex:1]  rPtr];
        return single_host_addr_new_with_port_ipv4(port, ipv4, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[portVal, ipv4Ptr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithIpv6:(nonnull NSString *)ipv6Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* ipv6Ptr, CharPtr* error) {
        RPtr result;
        RPtr ipv6 = [ipv6Ptr  rPtr];
        return single_host_addr_new_with_ipv6(ipv6, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:ipv6Ptr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithPortIpv6:(nonnull NSNumber *)portVal withIpv6:(nonnull NSString *)ipv6Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t port = [[params objectAtIndex:0]  longLongValue];
        RPtr ipv6 = [[params objectAtIndex:1]  rPtr];
        return single_host_addr_new_with_port_ipv6(port, ipv6, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[portVal, ipv6Ptr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithIpv4Ipv6:(nonnull NSString *)ipv4Ptr withIpv6:(nonnull NSString *)ipv6Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr ipv4 = [[params objectAtIndex:0]  rPtr];
        RPtr ipv6 = [[params objectAtIndex:1]  rPtr];
        return single_host_addr_new_with_ipv4_ipv6(ipv4, ipv6, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[ipv4Ptr, ipv6Ptr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostAddrNewWithPortIpv4Ipv6:(nonnull NSNumber *)portVal withIpv4:(nonnull NSString *)ipv4Ptr withIpv6:(nonnull NSString *)ipv6Ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t port = [[params objectAtIndex:0]  longLongValue];
        RPtr ipv4 = [[params objectAtIndex:1]  rPtr];
        RPtr ipv6 = [[params objectAtIndex:2]  rPtr];
        return single_host_addr_new_with_port_ipv4_ipv6(port, ipv4, ipv6, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[portVal, ipv4Ptr, ipv6Ptr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(singleHostNameToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_name_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return single_host_name_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_name_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return single_host_name_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_name_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return single_host_name_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNamePort:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return single_host_name_port(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameDnsName:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return single_host_name_dns_name(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameNew:(nonnull NSString *)dnsNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* dnsNamePtr, CharPtr* error) {
        RPtr result;
        RPtr dnsName = [dnsNamePtr  rPtr];
        return single_host_name_new(dnsName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:dnsNamePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(singleHostNameNewWithPort:(nonnull NSNumber *)portVal withDnsName:(nonnull NSString *)dnsNamePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        int64_t port = [[params objectAtIndex:0]  longLongValue];
        RPtr dnsName = [[params objectAtIndex:1]  rPtr];
        return single_host_name_new_with_port(port, dnsName, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[portVal, dnsNamePtr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(stakeCredentialFromKeyhash:(nonnull NSString *)hashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hashPtr, CharPtr* error) {
        RPtr result;
        RPtr hash = [hashPtr  rPtr];
        return stake_credential_from_keyhash(hash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hashPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialFromScripthash:(nonnull NSString *)hashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hashPtr, CharPtr* error) {
        RPtr result;
        RPtr hash = [hashPtr  rPtr];
        return stake_credential_from_scripthash(hash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hashPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_to_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToScripthash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_to_scripthash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return stake_credential_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return stake_credential_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credential_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return stake_credential_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeCredentialsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credentials_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return stake_credentials_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credentials_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return stake_credentials_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_credentials_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return stake_credentials_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return stake_credentials_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return stake_credentials_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return stake_credentials_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeCredentialsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        stake_credentials_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeDelegationToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_delegation_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return stake_delegation_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_delegation_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return stake_delegation_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_delegation_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return stake_delegation_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationStakeCredential:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_delegation_stake_credential(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationPoolKeyhash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_delegation_pool_keyhash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDelegationNew:(nonnull NSString *)stakeCredentialPtr withPoolKeyhash:(nonnull NSString *)poolKeyhashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr stakeCredential = [[params objectAtIndex:0]  rPtr];
        RPtr poolKeyhash = [[params objectAtIndex:1]  rPtr];
        return stake_delegation_new(stakeCredential, poolKeyhash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[stakeCredentialPtr, poolKeyhashPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeDeregistrationToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_deregistration_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return stake_deregistration_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_deregistration_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return stake_deregistration_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_deregistration_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return stake_deregistration_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationStakeCredential:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_deregistration_stake_credential(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeDeregistrationNew:(nonnull NSString *)stakeCredentialPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeCredentialPtr, CharPtr* error) {
        RPtr result;
        RPtr stakeCredential = [stakeCredentialPtr  rPtr];
        return stake_deregistration_new(stakeCredential, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stakeCredentialPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stakeRegistrationToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_registration_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return stake_registration_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_registration_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return stake_registration_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_registration_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return stake_registration_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationStakeCredential:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return stake_registration_stake_credential(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stakeRegistrationNew:(nonnull NSString *)stakeCredentialPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* stakeCredentialPtr, CharPtr* error) {
        RPtr result;
        RPtr stakeCredential = [stakeCredentialPtr  rPtr];
        return stake_registration_new(stakeCredential, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:stakeCredentialPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(stringsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return strings_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stringsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return strings_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stringsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return strings_get(self, index, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(stringsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr elem = [[params objectAtIndex:1]  charPtr];
        strings_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(timelockExpiryToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_expiry_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return timelock_expiry_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_expiry_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return timelock_expiry_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_expiry_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return timelock_expiry_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpirySlot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return timelock_expiry_slot(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpirySlotBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_expiry_slot_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryNew:(nonnull NSNumber *)slotVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSNumber* slotVal, CharPtr* error) {
        RPtr result;
        int64_t slot = [slotVal  longLongValue];
        return timelock_expiry_new(slot, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:slotVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockExpiryNewTimelockexpiry:(nonnull NSString *)slotPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* slotPtr, CharPtr* error) {
        RPtr result;
        RPtr slot = [slotPtr  rPtr];
        return timelock_expiry_new_timelockexpiry(slot, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:slotPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(timelockStartToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_start_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return timelock_start_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_start_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return timelock_start_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_start_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return timelock_start_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartSlot:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return timelock_start_slot(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartSlotBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return timelock_start_slot_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartNew:(nonnull NSNumber *)slotVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSNumber* slotVal, CharPtr* error) {
        RPtr result;
        int64_t slot = [slotVal  longLongValue];
        return timelock_start_new(slot, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:slotVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(timelockStartNewTimelockstart:(nonnull NSString *)slotPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* slotPtr, CharPtr* error) {
        RPtr result;
        RPtr slot = [slotPtr  rPtr];
        return timelock_start_new_timelockstart(slot, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:slotPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBody:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSet:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionIsValid:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return transaction_is_valid(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionAuxiliaryData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_auxiliary_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionSetIsValid:(nonnull NSString *)selfPtr withValid:(nonnull NSNumber *)validVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        BOOL valid = [[params objectAtIndex:1]  boolValue];
        transaction_set_is_valid(self, valid, error);
        return nil;
    }] exec:@[selfPtr, validVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionNew:(nonnull NSString *)bodyPtr withWitnessSet:(nonnull NSString *)witnessSetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr body = [[params objectAtIndex:0]  rPtr];
        RPtr witnessSet = [[params objectAtIndex:1]  rPtr];
        return transaction_new(body, witnessSet, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bodyPtr, witnessSetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionNewWithAuxiliaryData:(nonnull NSString *)bodyPtr withWitnessSet:(nonnull NSString *)witnessSetPtr withAuxiliaryData:(nonnull NSString *)auxiliaryDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr body = [[params objectAtIndex:0]  rPtr];
        RPtr witnessSet = [[params objectAtIndex:1]  rPtr];
        RPtr auxiliaryData = [[params objectAtIndex:2]  rPtr];
        return transaction_new_with_auxiliary_data(body, witnessSet, auxiliaryData, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[bodyPtr, witnessSetPtr, auxiliaryDataPtr] andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(transactionBatchLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_batch_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBatchGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_batch_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionBatchListLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_batch_list_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBatchListGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_batch_list_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionBodiesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_bodies_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_bodies_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_bodies_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_bodies_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_bodies_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_bodies_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_bodies_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_bodies_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_bodies_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodiesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_bodies_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionBodyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_body_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_body_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_body_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyOutputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_outputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyFee:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_fee(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyTtl:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_ttl(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyTtlBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_ttl_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetTtl:(nonnull NSString *)selfPtr withTtl:(nonnull NSString *)ttlPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr ttl = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_ttl(self, ttl, error);
        return nil;
    }] exec:@[selfPtr, ttlPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyRemoveTtl:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr self = [selfPtr  rPtr];
        transaction_body_remove_ttl(self, error);
        return nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetCerts:(nonnull NSString *)selfPtr withCerts:(nonnull NSString *)certsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr certs = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_certs(self, certs, error);
        return nil;
    }] exec:@[selfPtr, certsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyCerts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_certs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetWithdrawals:(nonnull NSString *)selfPtr withWithdrawals:(nonnull NSString *)withdrawalsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr withdrawals = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_withdrawals(self, withdrawals, error);
        return nil;
    }] exec:@[selfPtr, withdrawalsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyWithdrawals:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_withdrawals(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetUpdate:(nonnull NSString *)selfPtr withUpdate:(nonnull NSString *)updatePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr update = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_update(self, update, error);
        return nil;
    }] exec:@[selfPtr, updatePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyUpdate:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_update(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetAuxiliaryDataHash:(nonnull NSString *)selfPtr withAuxiliaryDataHash:(nonnull NSString *)auxiliaryDataHashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr auxiliaryDataHash = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_auxiliary_data_hash(self, auxiliaryDataHash, error);
        return nil;
    }] exec:@[selfPtr, auxiliaryDataHashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyAuxiliaryDataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_auxiliary_data_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetValidityStartInterval:(nonnull NSString *)selfPtr withValidityStartInterval:(nonnull NSNumber *)validityStartIntervalVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t validityStartInterval = [[params objectAtIndex:1]  longLongValue];
        transaction_body_set_validity_start_interval(self, validityStartInterval, error);
        return nil;
    }] exec:@[selfPtr, validityStartIntervalVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetValidityStartIntervalBignum:(nonnull NSString *)selfPtr withValidityStartInterval:(nonnull NSString *)validityStartIntervalPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr validityStartInterval = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_validity_start_interval_bignum(self, validityStartInterval, error);
        return nil;
    }] exec:@[selfPtr, validityStartIntervalPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyValidityStartIntervalBignum:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_validity_start_interval_bignum(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyValidityStartInterval:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_validity_start_interval(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetMint:(nonnull NSString *)selfPtr withMint:(nonnull NSString *)mintPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr mint = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_mint(self, mint, error);
        return nil;
    }] exec:@[selfPtr, mintPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyMint:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_mint(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyMultiassets:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_multiassets(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetReferenceInputs:(nonnull NSString *)selfPtr withReferenceInputs:(nonnull NSString *)referenceInputsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr referenceInputs = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_reference_inputs(self, referenceInputs, error);
        return nil;
    }] exec:@[selfPtr, referenceInputsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyReferenceInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_reference_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetScriptDataHash:(nonnull NSString *)selfPtr withScriptDataHash:(nonnull NSString *)scriptDataHashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scriptDataHash = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_script_data_hash(self, scriptDataHash, error);
        return nil;
    }] exec:@[selfPtr, scriptDataHashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyScriptDataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_script_data_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetCollateral:(nonnull NSString *)selfPtr withCollateral:(nonnull NSString *)collateralPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr collateral = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_collateral(self, collateral, error);
        return nil;
    }] exec:@[selfPtr, collateralPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyCollateral:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_collateral(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetRequiredSigners:(nonnull NSString *)selfPtr withRequiredSigners:(nonnull NSString *)requiredSignersPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr requiredSigners = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_required_signers(self, requiredSigners, error);
        return nil;
    }] exec:@[selfPtr, requiredSignersPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyRequiredSigners:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_required_signers(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetNetworkId:(nonnull NSString *)selfPtr withNetworkId:(nonnull NSString *)networkIdPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr networkId = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_network_id(self, networkId, error);
        return nil;
    }] exec:@[selfPtr, networkIdPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyNetworkId:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_network_id(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetCollateralReturn:(nonnull NSString *)selfPtr withCollateralReturn:(nonnull NSString *)collateralReturnPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr collateralReturn = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_collateral_return(self, collateralReturn, error);
        return nil;
    }] exec:@[selfPtr, collateralReturnPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyCollateralReturn:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_collateral_return(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodySetTotalCollateral:(nonnull NSString *)selfPtr withTotalCollateral:(nonnull NSString *)totalCollateralPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr totalCollateral = [[params objectAtIndex:1]  rPtr];
        transaction_body_set_total_collateral(self, totalCollateral, error);
        return nil;
    }] exec:@[selfPtr, totalCollateralPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyTotalCollateral:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_body_total_collateral(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyNew:(nonnull NSString *)inputsPtr withOutputs:(nonnull NSString *)outputsPtr withFee:(nonnull NSString *)feePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr inputs = [[params objectAtIndex:0]  rPtr];
        RPtr outputs = [[params objectAtIndex:1]  rPtr];
        RPtr fee = [[params objectAtIndex:2]  rPtr];
        return transaction_body_new(inputs, outputs, fee, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputsPtr, outputsPtr, feePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBodyNewWithTtl:(nonnull NSString *)inputsPtr withOutputs:(nonnull NSString *)outputsPtr withFee:(nonnull NSString *)feePtr withTtl:(nonnull NSNumber *)ttlVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr inputs = [[params objectAtIndex:0]  rPtr];
        RPtr outputs = [[params objectAtIndex:1]  rPtr];
        RPtr fee = [[params objectAtIndex:2]  rPtr];
        int64_t ttl = [[params objectAtIndex:3]  longLongValue];
        return transaction_body_new_with_ttl(inputs, outputs, fee, ttl, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputsPtr, outputsPtr, feePtr, ttlVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionBodyNewTxBody:(nonnull NSString *)inputsPtr withOutputs:(nonnull NSString *)outputsPtr withFee:(nonnull NSString *)feePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr inputs = [[params objectAtIndex:0]  rPtr];
        RPtr outputs = [[params objectAtIndex:1]  rPtr];
        RPtr fee = [[params objectAtIndex:2]  rPtr];
        return transaction_body_new_tx_body(inputs, outputs, fee, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputsPtr, outputsPtr, feePtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionBuilderAddInputsFrom:(nonnull NSString *)selfPtr withInputs:(nonnull NSString *)inputsPtr withStrategy:(nonnull NSNumber *)strategyVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr inputs = [[params objectAtIndex:1]  rPtr];
        int32_t strategy = [[params objectAtIndex:2]  integerValue];
        transaction_builder_add_inputs_from(self, inputs, strategy, error);
        return nil;
    }] exec:@[selfPtr, inputsPtr, strategyVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetInputs:(nonnull NSString *)selfPtr withInputs:(nonnull NSString *)inputsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr inputs = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_inputs(self, inputs, error);
        return nil;
    }] exec:@[selfPtr, inputsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetCollateral:(nonnull NSString *)selfPtr withCollateral:(nonnull NSString *)collateralPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr collateral = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_collateral(self, collateral, error);
        return nil;
    }] exec:@[selfPtr, collateralPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetCollateralReturn:(nonnull NSString *)selfPtr withCollateralReturn:(nonnull NSString *)collateralReturnPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr collateralReturn = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_collateral_return(self, collateralReturn, error);
        return nil;
    }] exec:@[selfPtr, collateralReturnPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetCollateralReturnAndTotal:(nonnull NSString *)selfPtr withCollateralReturn:(nonnull NSString *)collateralReturnPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr collateralReturn = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_collateral_return_and_total(self, collateralReturn, error);
        return nil;
    }] exec:@[selfPtr, collateralReturnPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetTotalCollateral:(nonnull NSString *)selfPtr withTotalCollateral:(nonnull NSString *)totalCollateralPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr totalCollateral = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_total_collateral(self, totalCollateral, error);
        return nil;
    }] exec:@[selfPtr, totalCollateralPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetTotalCollateralAndReturn:(nonnull NSString *)selfPtr withTotalCollateral:(nonnull NSString *)totalCollateralPtr withReturnAddress:(nonnull NSString *)returnAddressPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr totalCollateral = [[params objectAtIndex:1]  rPtr];
        RPtr returnAddress = [[params objectAtIndex:2]  rPtr];
        transaction_builder_set_total_collateral_and_return(self, totalCollateral, returnAddress, error);
        return nil;
    }] exec:@[selfPtr, totalCollateralPtr, returnAddressPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddReferenceInput:(nonnull NSString *)selfPtr withReferenceInput:(nonnull NSString *)referenceInputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr referenceInput = [[params objectAtIndex:1]  rPtr];
        transaction_builder_add_reference_input(self, referenceInput, error);
        return nil;
    }] exec:@[selfPtr, referenceInputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddKeyInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_key_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddScriptInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_script_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddNativeScriptInput:(nonnull NSString *)selfPtr withScript:(nonnull NSString *)scriptPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr script = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_native_script_input(self, script, input, amount, error);
        return nil;
    }] exec:@[selfPtr, scriptPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddPlutusScriptInput:(nonnull NSString *)selfPtr withWitness:(nonnull NSString *)witnessPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr witness = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_plutus_script_input(self, witness, input, amount, error);
        return nil;
    }] exec:@[selfPtr, witnessPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddBootstrapInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_bootstrap_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddInput:(nonnull NSString *)selfPtr withAddress:(nonnull NSString *)addressPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr address = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_input(self, address, input, amount, error);
        return nil;
    }] exec:@[selfPtr, addressPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderCountMissingInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_count_missing_input_scripts(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddRequiredNativeInputScripts:(nonnull NSString *)selfPtr withScripts:(nonnull NSString *)scriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scripts = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_add_required_native_input_scripts(self, scripts, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, scriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddRequiredPlutusInputScripts:(nonnull NSString *)selfPtr withScripts:(nonnull NSString *)scriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scripts = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_add_required_plutus_input_scripts(self, scripts, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, scriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetNativeInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_native_input_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetPlutusInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_plutus_input_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderFeeForInput:(nonnull NSString *)selfPtr withAddress:(nonnull NSString *)addressPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr address = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        return transaction_builder_fee_for_input(self, address, input, amount, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, addressPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddOutput:(nonnull NSString *)selfPtr withOutput:(nonnull NSString *)outputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr output = [[params objectAtIndex:1]  rPtr];
        transaction_builder_add_output(self, output, error);
        return nil;
    }] exec:@[selfPtr, outputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderFeeForOutput:(nonnull NSString *)selfPtr withOutput:(nonnull NSString *)outputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr output = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_fee_for_output(self, output, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, outputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetFee:(nonnull NSString *)selfPtr withFee:(nonnull NSString *)feePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr fee = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_fee(self, fee, error);
        return nil;
    }] exec:@[selfPtr, feePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetTtl:(nonnull NSString *)selfPtr withTtl:(nonnull NSNumber *)ttlVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t ttl = [[params objectAtIndex:1]  longLongValue];
        transaction_builder_set_ttl(self, ttl, error);
        return nil;
    }] exec:@[selfPtr, ttlVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetTtlBignum:(nonnull NSString *)selfPtr withTtl:(nonnull NSString *)ttlPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr ttl = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_ttl_bignum(self, ttl, error);
        return nil;
    }] exec:@[selfPtr, ttlPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetValidityStartInterval:(nonnull NSString *)selfPtr withValidityStartInterval:(nonnull NSNumber *)validityStartIntervalVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t validityStartInterval = [[params objectAtIndex:1]  longLongValue];
        transaction_builder_set_validity_start_interval(self, validityStartInterval, error);
        return nil;
    }] exec:@[selfPtr, validityStartIntervalVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetValidityStartIntervalBignum:(nonnull NSString *)selfPtr withValidityStartInterval:(nonnull NSString *)validityStartIntervalPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr validityStartInterval = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_validity_start_interval_bignum(self, validityStartInterval, error);
        return nil;
    }] exec:@[selfPtr, validityStartIntervalPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetCerts:(nonnull NSString *)selfPtr withCerts:(nonnull NSString *)certsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr certs = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_certs(self, certs, error);
        return nil;
    }] exec:@[selfPtr, certsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetWithdrawals:(nonnull NSString *)selfPtr withWithdrawals:(nonnull NSString *)withdrawalsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr withdrawals = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_withdrawals(self, withdrawals, error);
        return nil;
    }] exec:@[selfPtr, withdrawalsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetAuxiliaryData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_auxiliary_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetAuxiliaryData:(nonnull NSString *)selfPtr withAuxiliaryData:(nonnull NSString *)auxiliaryDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr auxiliaryData = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_auxiliary_data(self, auxiliaryData, error);
        return nil;
    }] exec:@[selfPtr, auxiliaryDataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetMetadata:(nonnull NSString *)selfPtr withMetadata:(nonnull NSString *)metadataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr metadata = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_metadata(self, metadata, error);
        return nil;
    }] exec:@[selfPtr, metadataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddMetadatum:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withVal:(nonnull NSString *)valPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr val = [[params objectAtIndex:2]  rPtr];
        transaction_builder_add_metadatum(self, key, val, error);
        return nil;
    }] exec:@[selfPtr, keyPtr, valPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddJsonMetadatum:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withVal:(nonnull NSString *)valVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        CharPtr val = [[params objectAtIndex:2]  charPtr];
        transaction_builder_add_json_metadatum(self, key, val, error);
        return nil;
    }] exec:@[selfPtr, keyPtr, valVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddJsonMetadatumWithSchema:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withVal:(nonnull NSString *)valVal withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        CharPtr val = [[params objectAtIndex:2]  charPtr];
        int32_t schema = [[params objectAtIndex:3]  integerValue];
        transaction_builder_add_json_metadatum_with_schema(self, key, val, schema, error);
        return nil;
    }] exec:@[selfPtr, keyPtr, valVal, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetMintBuilder:(nonnull NSString *)selfPtr withMintBuilder:(nonnull NSString *)mintBuilderPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr mintBuilder = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_mint_builder(self, mintBuilder, error);
        return nil;
    }] exec:@[selfPtr, mintBuilderPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetMintBuilder:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_mint_builder(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetMint:(nonnull NSString *)selfPtr withMint:(nonnull NSString *)mintPtr withMintScripts:(nonnull NSString *)mintScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr mint = [[params objectAtIndex:1]  rPtr];
        RPtr mintScripts = [[params objectAtIndex:2]  rPtr];
        transaction_builder_set_mint(self, mint, mintScripts, error);
        return nil;
    }] exec:@[selfPtr, mintPtr, mintScriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetMint:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_mint(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetMintScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_mint_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetMintAsset:(nonnull NSString *)selfPtr withPolicyScript:(nonnull NSString *)policyScriptPtr withMintAssets:(nonnull NSString *)mintAssetsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyScript = [[params objectAtIndex:1]  rPtr];
        RPtr mintAssets = [[params objectAtIndex:2]  rPtr];
        transaction_builder_set_mint_asset(self, policyScript, mintAssets, error);
        return nil;
    }] exec:@[selfPtr, policyScriptPtr, mintAssetsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddMintAsset:(nonnull NSString *)selfPtr withPolicyScript:(nonnull NSString *)policyScriptPtr withAssetName:(nonnull NSString *)assetNamePtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyScript = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        transaction_builder_add_mint_asset(self, policyScript, assetName, amount, error);
        return nil;
    }] exec:@[selfPtr, policyScriptPtr, assetNamePtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddMintAssetAndOutput:(nonnull NSString *)selfPtr withPolicyScript:(nonnull NSString *)policyScriptPtr withAssetName:(nonnull NSString *)assetNamePtr withAmount:(nonnull NSString *)amountPtr withOutputBuilder:(nonnull NSString *)outputBuilderPtr withOutputCoin:(nonnull NSString *)outputCoinPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyScript = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        RPtr outputBuilder = [[params objectAtIndex:4]  rPtr];
        RPtr outputCoin = [[params objectAtIndex:5]  rPtr];
        transaction_builder_add_mint_asset_and_output(self, policyScript, assetName, amount, outputBuilder, outputCoin, error);
        return nil;
    }] exec:@[selfPtr, policyScriptPtr, assetNamePtr, amountPtr, outputBuilderPtr, outputCoinPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddMintAssetAndOutputMinRequiredCoin:(nonnull NSString *)selfPtr withPolicyScript:(nonnull NSString *)policyScriptPtr withAssetName:(nonnull NSString *)assetNamePtr withAmount:(nonnull NSString *)amountPtr withOutputBuilder:(nonnull NSString *)outputBuilderPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr policyScript = [[params objectAtIndex:1]  rPtr];
        RPtr assetName = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        RPtr outputBuilder = [[params objectAtIndex:4]  rPtr];
        transaction_builder_add_mint_asset_and_output_min_required_coin(self, policyScript, assetName, amount, outputBuilder, error);
        return nil;
    }] exec:@[selfPtr, policyScriptPtr, assetNamePtr, amountPtr, outputBuilderPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderNew:(nonnull NSString *)cfgPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* cfgPtr, CharPtr* error) {
        RPtr result;
        RPtr cfg = [cfgPtr  rPtr];
        return transaction_builder_new(cfg, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:cfgPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetReferenceInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_reference_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetExplicitInput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_explicit_input(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetImplicitInput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_implicit_input(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetTotalInput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_total_input(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetTotalOutput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_total_output(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetExplicitOutput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_explicit_output(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetDeposit:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_deposit(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderGetFeeIfSet:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_get_fee_if_set(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddChangeIfNeeded:(nonnull NSString *)selfPtr withAddress:(nonnull NSString *)addressPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        BOOL result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr address = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_add_change_if_needed(self, address, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:@[selfPtr, addressPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderCalcScriptDataHash:(nonnull NSString *)selfPtr withCostModels:(nonnull NSString *)costModelsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr costModels = [[params objectAtIndex:1]  rPtr];
        transaction_builder_calc_script_data_hash(self, costModels, error);
        return nil;
    }] exec:@[selfPtr, costModelsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderSetScriptDataHash:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        transaction_builder_set_script_data_hash(self, hash, error);
        return nil;
    }] exec:@[selfPtr, hashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderRemoveScriptDataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr self = [selfPtr  rPtr];
        transaction_builder_remove_script_data_hash(self, error);
        return nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderAddRequiredSigner:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        transaction_builder_add_required_signer(self, key, error);
        return nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderFullSize:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_full_size(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderOutputSizes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_output_sizes(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderBuild:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_build(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderBuildTx:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_build_tx(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderBuildTxUnsafe:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_build_tx_unsafe(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderMinFee:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_min_fee(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}



RCT_EXPORT_METHOD(transactionBuilderConfigBuilderNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_builder_config_builder_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderFeeAlgo:(nonnull NSString *)selfPtr withFeeAlgo:(nonnull NSString *)feeAlgoPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr feeAlgo = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_fee_algo(self, feeAlgo, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, feeAlgoPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderCoinsPerUtxoWord:(nonnull NSString *)selfPtr withCoinsPerUtxoWord:(nonnull NSString *)coinsPerUtxoWordPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr coinsPerUtxoWord = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_coins_per_utxo_word(self, coinsPerUtxoWord, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, coinsPerUtxoWordPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderCoinsPerUtxoByte:(nonnull NSString *)selfPtr withCoinsPerUtxoByte:(nonnull NSString *)coinsPerUtxoBytePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr coinsPerUtxoByte = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_coins_per_utxo_byte(self, coinsPerUtxoByte, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, coinsPerUtxoBytePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderExUnitPrices:(nonnull NSString *)selfPtr withExUnitPrices:(nonnull NSString *)exUnitPricesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr exUnitPrices = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_ex_unit_prices(self, exUnitPrices, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, exUnitPricesPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderPoolDeposit:(nonnull NSString *)selfPtr withPoolDeposit:(nonnull NSString *)poolDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr poolDeposit = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_pool_deposit(self, poolDeposit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, poolDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderKeyDeposit:(nonnull NSString *)selfPtr withKeyDeposit:(nonnull NSString *)keyDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr keyDeposit = [[params objectAtIndex:1]  rPtr];
        return transaction_builder_config_builder_key_deposit(self, keyDeposit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderMaxValueSize:(nonnull NSString *)selfPtr withMaxValueSize:(nonnull NSNumber *)maxValueSizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxValueSize = [[params objectAtIndex:1]  longLongValue];
        return transaction_builder_config_builder_max_value_size(self, maxValueSize, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, maxValueSizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderMaxTxSize:(nonnull NSString *)selfPtr withMaxTxSize:(nonnull NSNumber *)maxTxSizeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t maxTxSize = [[params objectAtIndex:1]  longLongValue];
        return transaction_builder_config_builder_max_tx_size(self, maxTxSize, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, maxTxSizeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderPreferPureChange:(nonnull NSString *)selfPtr withPreferPureChange:(nonnull NSNumber *)preferPureChangeVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        BOOL preferPureChange = [[params objectAtIndex:1]  boolValue];
        return transaction_builder_config_builder_prefer_pure_change(self, preferPureChange, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, preferPureChangeVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionBuilderConfigBuilderBuild:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_builder_config_builder_build(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return transaction_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return transaction_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return transaction_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionInputToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_input_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_input_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_input_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_input_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_input_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_input_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputTransactionId:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_input_transaction_id(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputIndex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_input_index(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputNew:(nonnull NSString *)transactionIdPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr transactionId = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_input_new(transactionId, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[transactionIdPtr, indexVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionInputsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_inputs_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_inputs_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_inputs_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_inputs_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_inputs_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_inputs_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_inputs_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_inputs_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_inputs_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_inputs_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionInputsToOption:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_inputs_to_option(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionMetadatumToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_metadatum_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_metadatum_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumNewMap:(nonnull NSString *)mapPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* mapPtr, CharPtr* error) {
        RPtr result;
        RPtr map = [mapPtr  rPtr];
        return transaction_metadatum_new_map(map, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:mapPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumNewList:(nonnull NSString *)listPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* listPtr, CharPtr* error) {
        RPtr result;
        RPtr list = [listPtr  rPtr];
        return transaction_metadatum_new_list(list, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:listPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumNewInt:(nonnull NSString *)intValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* intValuePtr, CharPtr* error) {
        RPtr result;
        RPtr intValue = [intValuePtr  rPtr];
        return transaction_metadatum_new_int(intValue, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:intValuePtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumNewBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_metadatum_new_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumNewText:(nonnull NSString *)textVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* textVal, CharPtr* error) {
        RPtr result;
        CharPtr text = [textVal  charPtr];
        return transaction_metadatum_new_text(text, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:textVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumKind:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int32_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_kind(self, &result, error)
            ? [NSNumber numberWithLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumAsMap:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_as_map(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumAsList:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_as_list(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumAsInt:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_as_int(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumAsBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_as_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumAsText:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_as_text(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionMetadatumLabelsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_labels_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_metadatum_labels_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_labels_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_metadatum_labels_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_metadatum_labels_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_metadatum_labels_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_metadatum_labels_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionMetadatumLabelsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_metadatum_labels_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionOutputToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_output_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_output_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_output_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAddress:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_address(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmount:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_amount(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputDataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_data_hash(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputPlutusData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_plutus_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputScriptRef:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_script_ref(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputSetScriptRef:(nonnull NSString *)selfPtr withScriptRef:(nonnull NSString *)scriptRefPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scriptRef = [[params objectAtIndex:1]  rPtr];
        transaction_output_set_script_ref(self, scriptRef, error);
        return nil;
    }] exec:@[selfPtr, scriptRefPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputSetPlutusData:(nonnull NSString *)selfPtr withData:(nonnull NSString *)dataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr data = [[params objectAtIndex:1]  rPtr];
        transaction_output_set_plutus_data(self, data, error);
        return nil;
    }] exec:@[selfPtr, dataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputSetDataHash:(nonnull NSString *)selfPtr withDataHash:(nonnull NSString *)dataHashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr dataHash = [[params objectAtIndex:1]  rPtr];
        transaction_output_set_data_hash(self, dataHash, error);
        return nil;
    }] exec:@[selfPtr, dataHashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputHasPlutusData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_has_plutus_data(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputHasDataHash:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_has_data_hash(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputHasScriptRef:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_has_script_ref(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputNew:(nonnull NSString *)addressPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr address = [[params objectAtIndex:0]  rPtr];
        RPtr amount = [[params objectAtIndex:1]  rPtr];
        return transaction_output_new(address, amount, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[addressPtr, amountPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionOutputAmountBuilderWithValue:(nonnull NSString *)selfPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr amount = [[params objectAtIndex:1]  rPtr];
        return transaction_output_amount_builder_with_value(self, amount, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmountBuilderWithCoin:(nonnull NSString *)selfPtr withCoin:(nonnull NSString *)coinPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr coin = [[params objectAtIndex:1]  rPtr];
        return transaction_output_amount_builder_with_coin(self, coin, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, coinPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmountBuilderWithCoinAndAsset:(nonnull NSString *)selfPtr withCoin:(nonnull NSString *)coinPtr withMultiasset:(nonnull NSString *)multiassetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr coin = [[params objectAtIndex:1]  rPtr];
        RPtr multiasset = [[params objectAtIndex:2]  rPtr];
        return transaction_output_amount_builder_with_coin_and_asset(self, coin, multiasset, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, coinPtr, multiassetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmountBuilderWithAssetAndMinRequiredCoin:(nonnull NSString *)selfPtr withMultiasset:(nonnull NSString *)multiassetPtr withCoinsPerUtxoWord:(nonnull NSString *)coinsPerUtxoWordPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr multiasset = [[params objectAtIndex:1]  rPtr];
        RPtr coinsPerUtxoWord = [[params objectAtIndex:2]  rPtr];
        return transaction_output_amount_builder_with_asset_and_min_required_coin(self, multiasset, coinsPerUtxoWord, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, multiassetPtr, coinsPerUtxoWordPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmountBuilderWithAssetAndMinRequiredCoinByUtxoCost:(nonnull NSString *)selfPtr withMultiasset:(nonnull NSString *)multiassetPtr withDataCost:(nonnull NSString *)dataCostPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr multiasset = [[params objectAtIndex:1]  rPtr];
        RPtr dataCost = [[params objectAtIndex:2]  rPtr];
        return transaction_output_amount_builder_with_asset_and_min_required_coin_by_utxo_cost(self, multiasset, dataCost, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, multiassetPtr, dataCostPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputAmountBuilderBuild:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_amount_builder_build(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionOutputBuilderNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_output_builder_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputBuilderWithAddress:(nonnull NSString *)selfPtr withAddress:(nonnull NSString *)addressPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr address = [[params objectAtIndex:1]  rPtr];
        return transaction_output_builder_with_address(self, address, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, addressPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputBuilderWithDataHash:(nonnull NSString *)selfPtr withDataHash:(nonnull NSString *)dataHashPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr dataHash = [[params objectAtIndex:1]  rPtr];
        return transaction_output_builder_with_data_hash(self, dataHash, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, dataHashPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputBuilderWithPlutusData:(nonnull NSString *)selfPtr withData:(nonnull NSString *)dataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr data = [[params objectAtIndex:1]  rPtr];
        return transaction_output_builder_with_plutus_data(self, data, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, dataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputBuilderWithScriptRef:(nonnull NSString *)selfPtr withScriptRef:(nonnull NSString *)scriptRefPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scriptRef = [[params objectAtIndex:1]  rPtr];
        return transaction_output_builder_with_script_ref(self, scriptRef, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, scriptRefPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputBuilderNext:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_output_builder_next(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionOutputsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_outputs_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_outputs_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_outputs_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_outputs_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_outputs_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_outputs_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_outputs_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_outputs_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_outputs_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionOutputsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_outputs_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionUnspentOutputToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_output_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_unspent_output_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_output_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_unspent_output_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_output_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_unspent_output_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputNew:(nonnull NSString *)inputPtr withOutput:(nonnull NSString *)outputPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr input = [[params objectAtIndex:0]  rPtr];
        RPtr output = [[params objectAtIndex:1]  rPtr];
        return transaction_unspent_output_new(input, output, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[inputPtr, outputPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputInput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_output_input(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputOutput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_output_output(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionUnspentOutputsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_outputs_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_unspent_outputs_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_unspent_outputs_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_unspent_outputs_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_unspent_outputs_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionUnspentOutputsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_unspent_outputs_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionWitnessSetToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_witness_set_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_witness_set_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_witness_set_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetVkeys:(nonnull NSString *)selfPtr withVkeys:(nonnull NSString *)vkeysPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr vkeys = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_vkeys(self, vkeys, error);
        return nil;
    }] exec:@[selfPtr, vkeysPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetVkeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_vkeys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetNativeScripts:(nonnull NSString *)selfPtr withNativeScripts:(nonnull NSString *)nativeScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr nativeScripts = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_native_scripts(self, nativeScripts, error);
        return nil;
    }] exec:@[selfPtr, nativeScriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetNativeScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_native_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetBootstraps:(nonnull NSString *)selfPtr withBootstraps:(nonnull NSString *)bootstrapsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr bootstraps = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_bootstraps(self, bootstraps, error);
        return nil;
    }] exec:@[selfPtr, bootstrapsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetBootstraps:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_bootstraps(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetPlutusScripts:(nonnull NSString *)selfPtr withPlutusScripts:(nonnull NSString *)plutusScriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr plutusScripts = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_plutus_scripts(self, plutusScripts, error);
        return nil;
    }] exec:@[selfPtr, plutusScriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetPlutusScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_plutus_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetPlutusData:(nonnull NSString *)selfPtr withPlutusData:(nonnull NSString *)plutusDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr plutusData = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_plutus_data(self, plutusData, error);
        return nil;
    }] exec:@[selfPtr, plutusDataPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetPlutusData:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_plutus_data(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetSetRedeemers:(nonnull NSString *)selfPtr withRedeemers:(nonnull NSString *)redeemersPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr redeemers = [[params objectAtIndex:1]  rPtr];
        transaction_witness_set_set_redeemers(self, redeemers, error);
        return nil;
    }] exec:@[selfPtr, redeemersPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetRedeemers:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_set_redeemers(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_witness_set_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(transactionWitnessSetsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_sets_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return transaction_witness_sets_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_sets_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return transaction_witness_sets_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_sets_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return transaction_witness_sets_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return transaction_witness_sets_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return transaction_witness_sets_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return transaction_witness_sets_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(transactionWitnessSetsAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        transaction_witness_sets_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(txBuilderConstantsPlutusDefaultCostModels:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return tx_builder_constants_plutus_default_cost_models(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txBuilderConstantsPlutusAlonzoCostModels:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return tx_builder_constants_plutus_alonzo_cost_models(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txBuilderConstantsPlutusVasilCostModels:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return tx_builder_constants_plutus_vasil_cost_models(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(txInputsBuilderNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return tx_inputs_builder_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddKeyInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_key_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddScriptInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_script_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddNativeScriptInput:(nonnull NSString *)selfPtr withScript:(nonnull NSString *)scriptPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr script = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_native_script_input(self, script, input, amount, error);
        return nil;
    }] exec:@[selfPtr, scriptPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddPlutusScriptInput:(nonnull NSString *)selfPtr withWitness:(nonnull NSString *)witnessPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr witness = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_plutus_script_input(self, witness, input, amount, error);
        return nil;
    }] exec:@[selfPtr, witnessPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddBootstrapInput:(nonnull NSString *)selfPtr withHash:(nonnull NSString *)hashPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr hash = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_bootstrap_input(self, hash, input, amount, error);
        return nil;
    }] exec:@[selfPtr, hashPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddInput:(nonnull NSString *)selfPtr withAddress:(nonnull NSString *)addressPtr withInput:(nonnull NSString *)inputPtr withAmount:(nonnull NSString *)amountPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr address = [[params objectAtIndex:1]  rPtr];
        RPtr input = [[params objectAtIndex:2]  rPtr];
        RPtr amount = [[params objectAtIndex:3]  rPtr];
        tx_inputs_builder_add_input(self, address, input, amount, error);
        return nil;
    }] exec:@[selfPtr, addressPtr, inputPtr, amountPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderCountMissingInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_count_missing_input_scripts(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddRequiredNativeInputScripts:(nonnull NSString *)selfPtr withScripts:(nonnull NSString *)scriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scripts = [[params objectAtIndex:1]  rPtr];
        return tx_inputs_builder_add_required_native_input_scripts(self, scripts, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, scriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddRequiredPlutusInputScripts:(nonnull NSString *)selfPtr withScripts:(nonnull NSString *)scriptsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr scripts = [[params objectAtIndex:1]  rPtr];
        return tx_inputs_builder_add_required_plutus_input_scripts(self, scripts, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, scriptsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddRequiredScriptInputWitnesses:(nonnull NSString *)selfPtr withInputsWithWit:(nonnull NSString *)inputsWithWitPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr inputsWithWit = [[params objectAtIndex:1]  rPtr];
        return tx_inputs_builder_add_required_script_input_witnesses(self, inputsWithWit, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, inputsWithWitPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderGetRefInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_get_ref_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderGetNativeInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_get_native_input_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderGetPlutusInputScripts:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_get_plutus_input_scripts(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddRequiredSigner:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        tx_inputs_builder_add_required_signer(self, key, error);
        return nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderAddRequiredSigners:(nonnull NSString *)selfPtr withKeys:(nonnull NSString *)keysPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr keys = [[params objectAtIndex:1]  rPtr];
        tx_inputs_builder_add_required_signers(self, keys, error);
        return nil;
    }] exec:@[selfPtr, keysPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderTotalValue:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_total_value(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderInputs:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_inputs(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(txInputsBuilderInputsOption:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return tx_inputs_builder_inputs_option(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(uRLToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return u_r_l_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return u_r_l_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return u_r_l_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return u_r_l_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return u_r_l_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return u_r_l_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLNew:(nonnull NSString *)urlVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* urlVal, CharPtr* error) {
        RPtr result;
        CharPtr url = [urlVal  charPtr];
        return u_r_l_new(url, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:urlVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(uRLUrl:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return u_r_l_url(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(unitIntervalToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return unit_interval_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return unit_interval_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return unit_interval_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return unit_interval_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return unit_interval_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return unit_interval_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalNumerator:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return unit_interval_numerator(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalDenominator:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return unit_interval_denominator(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(unitIntervalNew:(nonnull NSString *)numeratorPtr withDenominator:(nonnull NSString *)denominatorPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr numerator = [[params objectAtIndex:0]  rPtr];
        RPtr denominator = [[params objectAtIndex:1]  rPtr];
        return unit_interval_new(numerator, denominator, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[numeratorPtr, denominatorPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(updateToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return update_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return update_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return update_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return update_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return update_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return update_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateProposedProtocolParameterUpdates:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return update_proposed_protocol_parameter_updates(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateEpoch:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return update_epoch(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(updateNew:(nonnull NSString *)proposedProtocolParameterUpdatesPtr withEpoch:(nonnull NSNumber *)epochVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr proposedProtocolParameterUpdates = [[params objectAtIndex:0]  rPtr];
        int64_t epoch = [[params objectAtIndex:1]  longLongValue];
        return update_new(proposedProtocolParameterUpdates, epoch, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[proposedProtocolParameterUpdatesPtr, epochVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vRFCertToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_cert_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return v_r_f_cert_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_cert_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return v_r_f_cert_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_cert_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return v_r_f_cert_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertOutput:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_cert_output(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertProof:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_cert_proof(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFCertNew:(nonnull NSString *)outputVal withProof:(nonnull NSString *)proofVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        NSData* dataOutput = [NSData fromBase64:[params objectAtIndex:0]];
        NSData* dataProof = [NSData fromBase64:[params objectAtIndex:1]];
        return v_r_f_cert_new((uint8_t*)dataOutput.bytes, dataOutput.length, (uint8_t*)dataProof.bytes, dataProof.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[outputVal, proofVal] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vRFKeyHashFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return v_r_f_key_hash_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFKeyHashToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_key_hash_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFKeyHashToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return v_r_f_key_hash_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFKeyHashFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return v_r_f_key_hash_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFKeyHashToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_key_hash_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFKeyHashFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return v_r_f_key_hash_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vRFVKeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return v_r_f_v_key_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFVKeyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_v_key_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFVKeyToBech32:(nonnull NSString *)selfPtr withPrefix:(nonnull NSString *)prefixVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        CharPtr prefix = [[params objectAtIndex:1]  charPtr];
        return v_r_f_v_key_to_bech32(self, prefix, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[selfPtr, prefixVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFVKeyFromBech32:(nonnull NSString *)bechStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bechStrVal, CharPtr* error) {
        RPtr result;
        CharPtr bechStr = [bechStrVal  charPtr];
        return v_r_f_v_key_from_bech32(bechStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bechStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFVKeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return v_r_f_v_key_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vRFVKeyFromHex:(nonnull NSString *)hexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexVal, CharPtr* error) {
        RPtr result;
        CharPtr hex = [hexVal  charPtr];
        return v_r_f_v_key_from_hex(hex, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexVal andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(valueToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return value_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return value_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return value_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return value_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return value_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return value_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueNew:(nonnull NSString *)coinPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* coinPtr, CharPtr* error) {
        RPtr result;
        RPtr coin = [coinPtr  rPtr];
        return value_new(coin, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:coinPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueNewFromAssets:(nonnull NSString *)multiassetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* multiassetPtr, CharPtr* error) {
        RPtr result;
        RPtr multiasset = [multiassetPtr  rPtr];
        return value_new_from_assets(multiasset, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:multiassetPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueNewWithAssets:(nonnull NSString *)coinPtr withMultiasset:(nonnull NSString *)multiassetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr coin = [[params objectAtIndex:0]  rPtr];
        RPtr multiasset = [[params objectAtIndex:1]  rPtr];
        return value_new_with_assets(coin, multiasset, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[coinPtr, multiassetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueZero:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return value_zero(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueIsZero:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        BOOL result;
        RPtr self = [selfPtr  rPtr];
        return value_is_zero(self, &result, error)
            ? [NSNumber numberWithBool:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueCoin:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return value_coin(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueSetCoin:(nonnull NSString *)selfPtr withCoin:(nonnull NSString *)coinPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr coin = [[params objectAtIndex:1]  rPtr];
        value_set_coin(self, coin, error);
        return nil;
    }] exec:@[selfPtr, coinPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueMultiasset:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return value_multiasset(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueSetMultiasset:(nonnull NSString *)selfPtr withMultiasset:(nonnull NSString *)multiassetPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr multiasset = [[params objectAtIndex:1]  rPtr];
        value_set_multiasset(self, multiasset, error);
        return nil;
    }] exec:@[selfPtr, multiassetPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueCheckedAdd:(nonnull NSString *)selfPtr withRhs:(nonnull NSString *)rhsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhs = [[params objectAtIndex:1]  rPtr];
        return value_checked_add(self, rhs, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, rhsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueCheckedSub:(nonnull NSString *)selfPtr withRhsValue:(nonnull NSString *)rhsValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsValue = [[params objectAtIndex:1]  rPtr];
        return value_checked_sub(self, rhsValue, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, rhsValuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueClampedSub:(nonnull NSString *)selfPtr withRhsValue:(nonnull NSString *)rhsValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsValue = [[params objectAtIndex:1]  rPtr];
        return value_clamped_sub(self, rhsValue, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, rhsValuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(valueCompare:(nonnull NSString *)selfPtr withRhsValue:(nonnull NSString *)rhsValuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSArray* params, CharPtr* error) {
        int64_t result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr rhsValue = [[params objectAtIndex:1]  rPtr];
        return value_compare(self, rhsValue, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:@[selfPtr, rhsValuePtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vkeyToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkey_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return vkey_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkey_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return vkey_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkey_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return vkey_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyNew:(nonnull NSString *)pkPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* pkPtr, CharPtr* error) {
        RPtr result;
        RPtr pk = [pkPtr  rPtr];
        return vkey_new(pk, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:pkPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeyPublicKey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkey_public_key(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vkeysNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return vkeys_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeysLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return vkeys_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeysGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return vkeys_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeysAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        vkeys_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vkeywitnessToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitness_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return vkeywitness_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitness_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return vkeywitness_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitness_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return vkeywitness_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessNew:(nonnull NSString *)vkeyPtr withSignature:(nonnull NSString *)signaturePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr vkey = [[params objectAtIndex:0]  rPtr];
        RPtr signature = [[params objectAtIndex:1]  rPtr];
        return vkeywitness_new(vkey, signature, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[vkeyPtr, signaturePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessVkey:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitness_vkey(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessSignature:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitness_signature(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(vkeywitnessesToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitnesses_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return vkeywitnesses_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitnesses_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return vkeywitnesses_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitnesses_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return vkeywitnesses_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return vkeywitnesses_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return vkeywitnesses_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesGet:(nonnull NSString *)selfPtr withIndex:(nonnull NSNumber *)indexVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        int64_t index = [[params objectAtIndex:1]  longLongValue];
        return vkeywitnesses_get(self, index, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, indexVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(vkeywitnessesAdd:(nonnull NSString *)selfPtr withElem:(nonnull NSString *)elemPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr elem = [[params objectAtIndex:1]  rPtr];
        vkeywitnesses_add(self, elem, error);
        return nil;
    }] exec:@[selfPtr, elemPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(withdrawalsToBytes:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return withdrawals_to_bytes(self, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsFromBytes:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return withdrawals_from_bytes((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsToHex:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return withdrawals_to_hex(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsFromHex:(nonnull NSString *)hexStrVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* hexStrVal, CharPtr* error) {
        RPtr result;
        CharPtr hexStr = [hexStrVal  charPtr];
        return withdrawals_from_hex(hexStr, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:hexStrVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsToJson:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        CharPtr result;
        RPtr self = [selfPtr  rPtr];
        return withdrawals_to_json(self, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsFromJson:(nonnull NSString *)jsonVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* jsonVal, CharPtr* error) {
        RPtr result;
        CharPtr json = [jsonVal  charPtr];
        return withdrawals_from_json(json, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:jsonVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsNew:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(id _void, CharPtr* error) {
        RPtr result;
        return withdrawals_new(&result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:nil andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsLen:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSNumber*(NSString* selfPtr, CharPtr* error) {
        int64_t result;
        RPtr self = [selfPtr  rPtr];
        return withdrawals_len(self, &result, error)
            ? [NSNumber numberWithLongLong:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsInsert:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withValue:(nonnull NSString *)valuePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        RPtr value = [[params objectAtIndex:2]  rPtr];
        return withdrawals_insert(self, key, value, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr, valuePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsGet:(nonnull NSString *)selfPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr self = [[params objectAtIndex:0]  rPtr];
        RPtr key = [[params objectAtIndex:1]  rPtr];
        return withdrawals_get(self, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[selfPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(withdrawalsKeys:(nonnull NSString *)selfPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* selfPtr, CharPtr* error) {
        RPtr result;
        RPtr self = [selfPtr  rPtr];
        return withdrawals_keys(self, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:selfPtr andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(calculateExUnitsCeilCost:(nonnull NSString *)exUnitsPtr withExUnitPrices:(nonnull NSString *)exUnitPricesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr exUnits = [[params objectAtIndex:0]  rPtr];
        RPtr exUnitPrices = [[params objectAtIndex:1]  rPtr];
        return calculate_ex_units_ceil_cost(exUnits, exUnitPrices, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[exUnitsPtr, exUnitPricesPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(createSendAll:(nonnull NSString *)addressPtr withUtxos:(nonnull NSString *)utxosPtr withConfig:(nonnull NSString *)configPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr address = [[params objectAtIndex:0]  rPtr];
        RPtr utxos = [[params objectAtIndex:1]  rPtr];
        RPtr config = [[params objectAtIndex:2]  rPtr];
        return create_send_all(address, utxos, config, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[addressPtr, utxosPtr, configPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(decodeArbitraryBytesFromMetadatum:(nonnull NSString *)metadataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* metadataPtr, CharPtr* error) {
        CharPtr result;
        RPtr metadata = [metadataPtr  rPtr];
        return decode_arbitrary_bytes_from_metadatum(metadata, &result, error)
            ? [[NSData fromDataPtr:&result] base64]
            : nil;
    }] exec:metadataPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(decodeMetadatumToJsonStr:(nonnull NSString *)metadatumPtr withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr metadatum = [[params objectAtIndex:0]  rPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return decode_metadatum_to_json_str(metadatum, schema, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[metadatumPtr, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(decodePlutusDatumToJsonStr:(nonnull NSString *)datumPtr withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        RPtr datum = [[params objectAtIndex:0]  rPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return decode_plutus_datum_to_json_str(datum, schema, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[datumPtr, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(decryptWithPassword:(nonnull NSString *)passwordVal withData:(nonnull NSString *)dataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        CharPtr password = [[params objectAtIndex:0]  charPtr];
        CharPtr data = [[params objectAtIndex:1]  charPtr];
        return decrypt_with_password(password, data, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[passwordVal, dataVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(encodeArbitraryBytesAsMetadatum:(nonnull NSString *)bytesVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* bytesVal, CharPtr* error) {
        RPtr result;
        NSData* dataBytes = [NSData fromBase64:bytesVal];
        return encode_arbitrary_bytes_as_metadatum((uint8_t*)dataBytes.bytes, dataBytes.length, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:bytesVal andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(encodeJsonStrToMetadatum:(nonnull NSString *)jsonVal withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        CharPtr json = [[params objectAtIndex:0]  charPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return encode_json_str_to_metadatum(json, schema, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[jsonVal, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(encodeJsonStrToNativeScript:(nonnull NSString *)jsonVal withSelfXpub:(nonnull NSString *)selfXpubVal withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        CharPtr json = [[params objectAtIndex:0]  charPtr];
        CharPtr selfXpub = [[params objectAtIndex:1]  charPtr];
        int32_t schema = [[params objectAtIndex:2]  integerValue];
        return encode_json_str_to_native_script(json, selfXpub, schema, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[jsonVal, selfXpubVal, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(encodeJsonStrToPlutusDatum:(nonnull NSString *)jsonVal withSchema:(nonnull NSNumber *)schemaVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        CharPtr json = [[params objectAtIndex:0]  charPtr];
        int32_t schema = [[params objectAtIndex:1]  integerValue];
        return encode_json_str_to_plutus_datum(json, schema, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[jsonVal, schemaVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(encryptWithPassword:(nonnull NSString *)passwordVal withSalt:(nonnull NSString *)saltVal withNonce:(nonnull NSString *)nonceVal withData:(nonnull NSString *)dataVal withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        CharPtr result;
        CharPtr password = [[params objectAtIndex:0]  charPtr];
        CharPtr salt = [[params objectAtIndex:1]  charPtr];
        CharPtr nonce = [[params objectAtIndex:2]  charPtr];
        CharPtr data = [[params objectAtIndex:3]  charPtr];
        return encrypt_with_password(password, salt, nonce, data, &result, error)
            ? [NSString stringFromCharPtr:&result]
            : nil;
    }] exec:@[passwordVal, saltVal, nonceVal, dataVal] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(getDeposit:(nonnull NSString *)txbodyPtr withPoolDeposit:(nonnull NSString *)poolDepositPtr withKeyDeposit:(nonnull NSString *)keyDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txbody = [[params objectAtIndex:0]  rPtr];
        RPtr poolDeposit = [[params objectAtIndex:1]  rPtr];
        RPtr keyDeposit = [[params objectAtIndex:2]  rPtr];
        return get_deposit(txbody, poolDeposit, keyDeposit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txbodyPtr, poolDepositPtr, keyDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(getImplicitInput:(nonnull NSString *)txbodyPtr withPoolDeposit:(nonnull NSString *)poolDepositPtr withKeyDeposit:(nonnull NSString *)keyDepositPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txbody = [[params objectAtIndex:0]  rPtr];
        RPtr poolDeposit = [[params objectAtIndex:1]  rPtr];
        RPtr keyDeposit = [[params objectAtIndex:2]  rPtr];
        return get_implicit_input(txbody, poolDeposit, keyDeposit, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txbodyPtr, poolDepositPtr, keyDepositPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(hashAuxiliaryData:(nonnull NSString *)auxiliaryDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* auxiliaryDataPtr, CharPtr* error) {
        RPtr result;
        RPtr auxiliaryData = [auxiliaryDataPtr  rPtr];
        return hash_auxiliary_data(auxiliaryData, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:auxiliaryDataPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(hashPlutusData:(nonnull NSString *)plutusDataPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* plutusDataPtr, CharPtr* error) {
        RPtr result;
        RPtr plutusData = [plutusDataPtr  rPtr];
        return hash_plutus_data(plutusData, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:plutusDataPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(hashScriptData:(nonnull NSString *)redeemersPtr withCostModels:(nonnull NSString *)costModelsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr redeemers = [[params objectAtIndex:0]  rPtr];
        RPtr costModels = [[params objectAtIndex:1]  rPtr];
        return hash_script_data(redeemers, costModels, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[redeemersPtr, costModelsPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(hashScriptDataWithDatums:(nonnull NSString *)redeemersPtr withCostModels:(nonnull NSString *)costModelsPtr withDatums:(nonnull NSString *)datumsPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr redeemers = [[params objectAtIndex:0]  rPtr];
        RPtr costModels = [[params objectAtIndex:1]  rPtr];
        RPtr datums = [[params objectAtIndex:2]  rPtr];
        return hash_script_data_with_datums(redeemers, costModels, datums, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[redeemersPtr, costModelsPtr, datumsPtr] andResolve:resolve orReject:reject];
}


RCT_EXPORT_METHOD(hashTransaction:(nonnull NSString *)txBodyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSString* txBodyPtr, CharPtr* error) {
        RPtr result;
        RPtr txBody = [txBodyPtr  rPtr];
        return hash_transaction(txBody, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:txBodyPtr andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(makeDaedalusBootstrapWitness:(nonnull NSString *)txBodyHashPtr withAddr:(nonnull NSString *)addrPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txBodyHash = [[params objectAtIndex:0]  rPtr];
        RPtr addr = [[params objectAtIndex:1]  rPtr];
        RPtr key = [[params objectAtIndex:2]  rPtr];
        return make_daedalus_bootstrap_witness(txBodyHash, addr, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txBodyHashPtr, addrPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(makeIcarusBootstrapWitness:(nonnull NSString *)txBodyHashPtr withAddr:(nonnull NSString *)addrPtr withKey:(nonnull NSString *)keyPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txBodyHash = [[params objectAtIndex:0]  rPtr];
        RPtr addr = [[params objectAtIndex:1]  rPtr];
        RPtr key = [[params objectAtIndex:2]  rPtr];
        return make_icarus_bootstrap_witness(txBodyHash, addr, key, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txBodyHashPtr, addrPtr, keyPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(makeVkeyWitness:(nonnull NSString *)txBodyHashPtr withSk:(nonnull NSString *)skPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr txBodyHash = [[params objectAtIndex:0]  rPtr];
        RPtr sk = [[params objectAtIndex:1]  rPtr];
        return make_vkey_witness(txBodyHash, sk, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txBodyHashPtr, skPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(minAdaForOutput:(nonnull NSString *)outputPtr withDataCost:(nonnull NSString *)dataCostPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr output = [[params objectAtIndex:0]  rPtr];
        RPtr dataCost = [[params objectAtIndex:1]  rPtr];
        return min_ada_for_output(output, dataCost, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[outputPtr, dataCostPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(minAdaRequired:(nonnull NSString *)assetsPtr withHasDataHash:(nonnull NSNumber *)hasDataHashVal withCoinsPerUtxoWord:(nonnull NSString *)coinsPerUtxoWordPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr assets = [[params objectAtIndex:0]  rPtr];
        BOOL hasDataHash = [[params objectAtIndex:1]  boolValue];
        RPtr coinsPerUtxoWord = [[params objectAtIndex:2]  rPtr];
        return min_ada_required(assets, hasDataHash, coinsPerUtxoWord, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[assetsPtr, hasDataHashVal, coinsPerUtxoWordPtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(minFee:(nonnull NSString *)txPtr withLinearFee:(nonnull NSString *)linearFeePtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr tx = [[params objectAtIndex:0]  rPtr];
        RPtr linearFee = [[params objectAtIndex:1]  rPtr];
        return min_fee(tx, linearFee, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txPtr, linearFeePtr] andResolve:resolve orReject:reject];
}

RCT_EXPORT_METHOD(minScriptFee:(nonnull NSString *)txPtr withExUnitPrices:(nonnull NSString *)exUnitPricesPtr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)
{
    [[CSafeOperation new:^NSString*(NSArray* params, CharPtr* error) {
        RPtr result;
        RPtr tx = [[params objectAtIndex:0]  rPtr];
        RPtr exUnitPrices = [[params objectAtIndex:1]  rPtr];
        return min_script_fee(tx, exUnitPrices, &result, error)
            ? [NSString stringFromPtr:result]
            : nil;
    }] exec:@[txPtr, exUnitPricesPtr] andResolve:resolve orReject:reject];
}

@end
