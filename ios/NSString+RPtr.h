//
//  NSString+RPtr.h
//
//  Created by Yehor Popovych on 10/24/19.
//

#import <Foundation/Foundation.h>
#import <csl_mobile_bridge.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSString (RPtr)

+ (NSString *)stringFromPtr:(RPtr)ptr;

+ (NSString *)stringFromCharPtr:(CharPtr _Nonnull * _Nonnull)ptr;

- (CharPtr)charPtr;

- (RPtr)rPtr;

@end

NS_ASSUME_NONNULL_END
