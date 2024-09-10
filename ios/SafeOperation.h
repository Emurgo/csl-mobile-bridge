//
//  SafeOperation.h
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import <react_native_haskell_shelley.h>

NS_ASSUME_NONNULL_BEGIN

//#define CHECK_NON_NULL_OR_CERROR(var, error, name) if (var == NULL) {\
//    error = copy_string([[NSString stringWithFormat:@"Empty parameter: \"%s\"", name] UTF8String]);\
//    return nil;\
//}
//
//#define CHECK_HAS_LENGTH_OR_CERROR(var, error, name) if (var == NULL || [var length] <= 0) {\
//    error = copy_string([[NSString stringWithFormat:@"Empty parameter: \"%s\"", name] UTF8String]);\
//    return nil;\
//}

@interface NSError (Rust)

+ (NSError *)rustError:(NSString *)description;

@end

@interface CSLBaseSafeOperation<In, Out> : NSObject

- (Out)exec:(In)param error:(NSError **)error;

- (void)exec:(_Nullable In)param andResolve:(RCTPromiseResolveBlock)resolve orReject:(RCTPromiseRejectBlock)reject;

@end

@interface CSLSafeOperation<In, Out> : CSLBaseSafeOperation<In, Out>

+ (CSLBaseSafeOperation<In, Out> *)new:(Out(^)(In param, NSError** error))cb;

- (CSLSafeOperation<In, Out> *)initWithCallback:(Out(^)(In param, NSError** error))cb;

@end

@interface CSLCSafeOperation<In, Out> : CSLSafeOperation<In, Out>

+ (CSLBaseSafeOperation *)new:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

- (CSLCSafeOperation *)initWithCallback:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

@end

@interface CSLSafeOperationCombined<In1, Out1, Out2> : CSLBaseSafeOperation<In1, Out2>

+ (CSLBaseSafeOperation<In1, Out2>* )combine:(CSLBaseSafeOperation<In1, Out1> *)op1
                                    with:(CSLBaseSafeOperation<Out1, Out2> *)op2;

- (CSLSafeOperationCombined<In1, Out1, Out2> *)init:(CSLBaseSafeOperation<In1, Out1> *)op1
                                                and:(CSLBaseSafeOperation<Out1, Out2> *)op2;

@end

NS_ASSUME_NONNULL_END
