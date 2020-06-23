//
//  SafeOperation.m
//

#import "SafeOperation.h"
#import "NSString+RPtr.h"

@implementation BaseSafeOperation

- (void)exec:(_Nullable id)param andResolve:(RCTPromiseResolveBlock)resolve orReject:(RCTPromiseRejectBlock)reject {
    @try {
        NSError* error = nil;
        id result = [self exec:param error:&error];
        if (error != nil) {
            reject([NSString stringWithFormat:@"%li", (long)[error code]],
                   [error localizedDescription],
                   error);
        } else {
            resolve(result);
        }
    }
    @catch (NSException* e) {
        NSError* error = [NSError errorWithDomain:[e name] code:0 userInfo:[e userInfo]];
        reject(@"0", [e reason], error);
    }
}

- (id)exec:(id)param error:(NSError **)error {
    NSAssert(NO, @"Reload");
    return nil;
}

@end

@interface SafeOperation<In, Out> (/* Private */)

@property (copy) Out (^callback)(In param, NSError** error);

@end

@implementation SafeOperation

+ (BaseSafeOperation *)new:(_Nullable id (^)(_Nullable id param, NSError** error))cb {
    return [[SafeOperation alloc] initWithCallback: cb];
}

- (SafeOperation *)initWithCallback:(_Nullable id(^)(_Nullable id param, NSError** error))cb {
    if (self = [super init]) {
        self.callback = cb;
    }
    return self;
}

- (id)exec:(id)param error:(NSError **)error {
    return self.callback(param, error);
}

@end

@implementation CSafeOperation

+ (BaseSafeOperation *)new:(_Nullable id(^)(_Nullable id param, CharPtr _Nullable* _Nonnull error))cb {
    return [[CSafeOperation alloc] initWithCallback:cb];
}

- (CSafeOperation *)initWithCallback:(_Nullable id(^)(_Nullable id param, CharPtr _Nullable* _Nonnull error))cb {
    return [super initWithCallback:^_Nullable id(_Nullable id param, NSError **error) {
        CharPtr cError = NULL;
        id result = cb(param, &cError);
        if (cError != NULL && result == nil) {
            *error = [NSError rustError:[NSString stringFromCharPtr:&cError]];
        }
        return result;
    }];
}

@end

@interface SafeOperationCombined (/* Private */)

@property (strong) SafeOperation* op1;
@property (strong) SafeOperation* op2;

@end

@implementation SafeOperationCombined

+ (BaseSafeOperation* )combine:(SafeOperation *)op1 with:(SafeOperation *)op2 {
    return [[self alloc] init:op1 and: op2];
}

- (SafeOperationCombined* )init:(SafeOperation *)op1 and:(SafeOperation *)op2 {
    if (self = [super init]) {
        self.op1 = op1;
        self.op2 = op2;
    }
    return self;
}

- (id)exec:(id)param error:(NSError **)error {
    id result = [self.op1 exec:param error:error];
    if (*error == nil) {
        result = [self.op2 exec:result error:error];
    }
    return result;
}

@end

@implementation NSError (Rust)

+ (NSError *)rustError:(NSString *)description {
    return [NSError errorWithDomain:@"HaskellShelleyLibs.Rust"
                              code: 0
                          userInfo: @{NSLocalizedDescriptionKey: description}];
}

@end
