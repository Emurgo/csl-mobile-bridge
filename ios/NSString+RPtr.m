//
//  NSString+RPtr.m
//
//  Created by Yehor Popovych on 10/24/19.
//

#import "NSString+RPtr.h"

@implementation NSString (RPtr)

+ (NSString *)stringFromPtr:(RPtr)ptr {
    char buf[17];
    snprintf(buf, 17, "%"PRIxPTR, rptr_into_usize(ptr));
    return [NSString stringWithUTF8String:buf];
}

+ (NSString *)stringFromCharPtr:(CharPtr *)ptr {
    NSString* str = [NSString stringWithUTF8String:*ptr];
    charptr_free(ptr);
    return str;
}

- (CharPtr)charPtr {
    return [self UTF8String];
}

- (RPtr)rPtr {
    uintptr_t ptr = 0;
    sscanf([self UTF8String], "%"SCNxPTR, &ptr);
    return rptr_from_usize(ptr);
}

@end
