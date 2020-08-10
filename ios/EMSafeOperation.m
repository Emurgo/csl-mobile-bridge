//
//  EMSafeOperation.m
//

#import "EMSafeOperation.h"
#import "NSString+RPtr.h"

@implementation EMBaseSafeOperation

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

@interface EMSafeOperation<In, Out> (/* Private */)

@property (copy) Out (^callback)(In param, NSError** error);

@end

@implementation EMSafeOperation

+ (EMBaseSafeOperation *)new:(_Nullable id (^)(_Nullable id param, NSError** error))cb {
    return [[EMSafeOperation alloc] initWithCallback: cb];
}

- (EMSafeOperation *)initWithCallback:(_Nullable id(^)(_Nullable id param, NSError** error))cb {
    if (self = [super init]) {
        self.callback = cb;
    }
    return self;
}

- (id)exec:(id)param error:(NSError **)error {
    return self.callback(param, error);
}

@end

@implementation EMCSafeOperation

+ (EMBaseSafeOperation *)new:(_Nullable id(^)(_Nullable id param, CharPtr _Nullable* _Nonnull error))cb {
    return [[EMCSafeOperation alloc] initWithCallback:cb];
}

- (EMCSafeOperation *)initWithCallback:(_Nullable id(^)(_Nullable id param, CharPtr _Nullable* _Nonnull error))cb {
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

@interface EMSafeOperationCombined (/* Private */)

@property (strong) EMSafeOperation* op1;
@property (strong) EMSafeOperation* op2;

@end

@implementation EMSafeOperationCombined

+ (EMBaseSafeOperation* )combine:(EMSafeOperation *)op1 with:(EMSafeOperation *)op2 {
    return [[self alloc] init:op1 and: op2];
}

- (EMSafeOperationCombined* )init:(EMSafeOperation *)op1 and:(EMSafeOperation *)op2 {
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
