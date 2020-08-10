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

@interface EMBaseSafeOperation<In, Out> : NSObject

- (Out)exec:(In)param error:(NSError **)error;

- (void)exec:(_Nullable In)param andResolve:(RCTPromiseResolveBlock)resolve orReject:(RCTPromiseRejectBlock)reject;

@end

@interface EMSafeOperation<In, Out> : EMBaseSafeOperation<In, Out>

+ (EMBaseSafeOperation<In, Out> *)new:(Out(^)(In param, NSError** error))cb;

- (SafeOperation<In, Out> *)initWithCallback:(Out(^)(In param, NSError** error))cb;

@end

@interface EMCSafeOperation<In, Out> : EMSafeOperation<In, Out>

+ (EMBaseSafeOperation *)new:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

- (EMCSafeOperation *)initWithCallback:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

@end

@interface EMSafeOperationCombined<In1, Out1, Out2> : EMBaseSafeOperation<In1, Out2>

+ (EMBaseSafeOperation<In1, Out2>* )combine:(EMBaseSafeOperation<In1, Out1> *)op1
                                    with:(EMBaseSafeOperation<Out1, Out2> *)op2;

- (EMSafeOperationCombined<In1, Out1, Out2> *)init:(EMBaseSafeOperation<In1, Out1> *)op1
                                                and:(EMBaseSafeOperation<Out1, Out2> *)op2;

@end

NS_ASSUME_NONNULL_END
