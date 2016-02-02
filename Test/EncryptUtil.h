//
//  EncryptUtil.h
//  Test
//
//  Created by admin on 16/2/2.
//  Copyright © 2016年 AlezJi. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface EncryptUtil : NSObject
//最基础的MD5加密
+ (NSString *)md5:(NSString *)string;
+ (NSString *)getMd5_32Bit_String:(NSString *)srcString;


//DES加密解密
+(NSString*) encryptUseDES:(NSString *)clearText key:(NSString *)key;
+(NSString*) decryptUseDES:(NSString*)cipherText key:(NSString*)key;


//RSA加密
+ (NSString *)encryptByRSAString:(NSString *)str publicKey:(NSString *)pubKey;
+ (NSString *)encryptByRSAData:(NSData *)data publicKey:(NSString *)pubKey;


@end
