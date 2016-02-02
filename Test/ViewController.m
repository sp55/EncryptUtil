//
//  ViewController.m
//  Test
//
//  Created by admin on 16/2/2.
//  Copyright © 2016年 AlezJi. All rights reserved.
//

#import "ViewController.h"
#import "EncryptUtil.h"


#define RSAPUBLICKEY @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4QVQ+n54HCCFMHuGikTD0GMDxHgB8utMoszl955dcl6ax5YOMTa1z4Ib815/PGbRCBDv0vsG9jeGKY1pe9Qj3KHxJKiicJr3KV1R1vmzv1JdcRNTFVb6I9/awbJTNnTOvl8JZNm8QomdHlrQk8u3vP/Xdj217Mk4I4mTGDK1WFwIDAQAB\n-----END PUBLIC KEY-----"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];


    NSLog(@"MD5==%@",[EncryptUtil md5:@"Hello"]);
    NSLog(@"MD5==%@",[EncryptUtil getMd5_32Bit_String:@"Hello"]);
    NSLog(@"**********************************************");
    NSLog(@"DES-encrypt==%@",[EncryptUtil encryptUseDES:@"Hello" key:@"c"]);
    NSLog(@"DES-descrypt==%@",[EncryptUtil decryptUseDES:[EncryptUtil encryptUseDES:@"Hello" key:@"c"] key:@"c"]);
    NSLog(@"**********************************************");
    NSLog(@"RSA==%@",[EncryptUtil encryptByRSAString:@"Hello" publicKey:RSAPUBLICKEY]);
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
