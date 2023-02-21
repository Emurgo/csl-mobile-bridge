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

@end
