//
//  NSData+DataPtr.h
//
//  Created by Ostap Danylovych on 24.10.2019.
//

#import <Foundation/Foundation.h>
#import <react_native_haskell_shelley.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (DataPtr)

+ (NSData *)fromDataPtr:(DataPtr *)ptr;

+ (NSData *)fromBase64:(NSString *)base64Encoded;

- (NSString *)base64;

@end

NS_ASSUME_NONNULL_END
