//
//  SafeOperation.h
//

#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import <csl_mobile_bridge.h>

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

@interface BaseSafeOperation<In, Out> : NSObject

- (Out)exec:(In)param error:(NSError **)error;

- (void)exec:(_Nullable In)param andResolve:(RCTPromiseResolveBlock)resolve orReject:(RCTPromiseRejectBlock)reject;

@end

@interface SafeOperation<In, Out> : BaseSafeOperation<In, Out>

+ (BaseSafeOperation<In, Out> *)new:(Out(^)(In param, NSError** error))cb;

- (SafeOperation<In, Out> *)initWithCallback:(Out(^)(In param, NSError** error))cb;

@end

@interface CSafeOperation<In, Out> : SafeOperation<In, Out>

+ (BaseSafeOperation *)new:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

- (CSafeOperation *)initWithCallback:(Out(^)(In param, CharPtr _Nullable* _Nonnull error))cb;

@end

@interface SafeOperationCombined<In1, Out1, Out2> : BaseSafeOperation<In1, Out2>

+ (BaseSafeOperation<In1, Out2>* )combine:(BaseSafeOperation<In1, Out1> *)op1
                                    with:(BaseSafeOperation<Out1, Out2> *)op2;

- (SafeOperationCombined<In1, Out1, Out2> *)init:(BaseSafeOperation<In1, Out1> *)op1
                                                and:(BaseSafeOperation<Out1, Out2> *)op2;

@end

NS_ASSUME_NONNULL_END
