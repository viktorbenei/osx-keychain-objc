//
//  main.m
//  osx-keychain
//
//  Created by Viktor Benei on 22/01/16.
//  Copyright © 2016 bitrise. All rights reserved.
//

#import <Foundation/Foundation.h>


//
// Search OSStatus codes: http://www.osstatus.com/
// Full list can be found in SecItem.h
//


void performExport(CFTypeRef itemRef) {
    //
    
    CFDataRef exportedData;
    SecItemImportExportKeyParameters params;
    params.passphrase = (__bridge CFStringRef)@"";
    //
    //    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    //    params.flags = 0;
    //    params.alertTitle = NULL;
    //    params.alertPrompt = NULL;
    //    params.accessRef = NULL;
    // These two values are for import
    params.keyUsage = NULL;
    params.keyAttributes = NULL;
    //
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.alertTitle = 0;
    params.alertPrompt = 0;
    
    
    NSLog(@"params: %@", params.passphrase);
    OSStatus ret = SecItemExport(itemRef,
                                 kSecFormatPKCS12,
                                 kSecItemPemArmour, /* Use kSecItemPemArmour to add PEM armor */
                                 &params,
                                 &exportedData);
    NSLog(@"params: %@", params.passphrase);
    
    if(ret != errSecSuccess)
    {
        NSLog(@"SecItemExport: error: %d", ret);
        return;
    }
    /* exportedData now contains your PKCS12 data */
    NSData *finalData = nil;
    finalData = CFBridgingRelease(exportedData);
//    NSLog(@"finalData: %@", finalData);
    
    NSError *error = nil;
    NSString *path = @"./test-123.p12";
    [finalData writeToFile:path options:NSDataWritingAtomic error:&error];
    NSLog(@"Write returned error: %@", [error localizedDescription]);
}

static void PrintItem(const void *value, void *context) {
    CFDictionaryRef dict = value;

//    NSLog(@"--> %@", dict);
    
    CFStringRef labl = CFDictionaryGetValue(dict, @"labl");
    
    if ([(__bridge id)labl isEqualToString:@"iPhone Developer: Viktor Benei (F82R82XD37)"]) {
        CFTypeRef relRef = CFDictionaryGetValue(dict, @"v_Ref");
        NSLog(@"--> %@", relRef);
        NSLog(@"--> DATA: %@", dict);
    
        performExport(relRef);
    }
}

void doExport1() {
//    NSString *searchFor = @"iPhone Developer: Viktor Benei (F82R82XD37)";
//    NSString *searchFor = @"Viktor Benei";
    
    
    
    NSDictionary *queryDict = @{
                                (__bridge id)kSecClass: (__bridge NSString *)kSecClassIdentity,
//                                (__bridge id)kSecClass: (__bridge NSString *)kSecClassCertificate,
                                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
//                                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
                                (__bridge id)kSecReturnAttributes: @YES,
                                (__bridge id)kSecReturnRef: @YES,
//                                (__bridge id)kSecAttrLabel: searchFor,
//                                (__bridge id)kSecAttrApplicationLabel: searchFor,
                                };
    CFTypeRef itemRef;
    OSStatus sanityCheck = noErr;
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryDict, &itemRef);
    if (sanityCheck != errSecSuccess) {
//        publicKeyBits = CFBridgingRelease(result);
        NSLog(@"SecItemCopyMatching: error: %d", sanityCheck);
        return;
    }
    
    CFArrayRef identitiesArrRef = (CFArrayRef)itemRef;
//    NSLog(@"%@", (__bridge id)result);
    
    // do something with the result
//    CFRange range = CFRangeMake(0, CFArrayGetCount(result));
//    CFArrayApplyFunction(result, range, PrintItem, nil);
    
    CFIndex identitiesCount = CFArrayGetCount(identitiesArrRef);
    NSLog(@"identitiesCount: %d", identitiesCount);
    for (CFIndex i = identitiesCount-1; i > 0; i--) {
        CFTypeRef aIdentityRef = CFArrayGetValueAtIndex(identitiesArrRef, i);
        NSLog(@"aIdentityRef: %@", aIdentityRef);
        CFDictionaryRef aIdentityDictRef = (CFDictionaryRef)aIdentityRef;
        NSLog(@"aIdentityDictRef: %@", aIdentityDictRef);
//        CFStringRef ts = CFSTR("hi");
    }
    
//    performExport(result);

    
    
//    //
//    // Private Key
//    NSDictionary *queryDict = @{
//                                (__bridge id)kSecClass: (__bridge NSString *)kSecClassKey,
//                                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
//                                (__bridge id)kSecReturnRef: @YES,
//                                (__bridge id)kSecAttrLabel: @"Viktor Benei",
//                                };
//    CFTypeRef itemRef;
//    OSStatus sanityCheck = noErr;
//    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryDict, &itemRef);
//    if (sanityCheck != errSecSuccess) {
//        //        publicKeyBits = CFBridgingRelease(result);
//        NSLog(@"SecItemCopyMatching: error: %d", sanityCheck);
//        return;
//    }

    
    
//    //
//    SecKeychainAttribute labelAttr;
//    labelAttr.tag = kSecLabelItemAttr;
//    labelAttr.length = (UInt32)[searchFor length];
//    labelAttr.data = (void *)[searchFor UTF8String];
//    
//    SecKeychainAttributeList searchList;
//    searchList.count = 1;
//    searchList.attr = &labelAttr;
//    
//    SecKeychainSearchRef searchRef = 0;
//    OSStatus status = SecKeychainSearchCreateFromAttributes(
//                                                            NULL, // Search all kechains
//                                                            CSSM_DL_DB_RECORD_ANY,
//                                                            &searchList,
//                                                            &searchRef);
//    if(status != errSecSuccess)
//    {
//        NSLog(@"SecKeychainSearchCreateFromAttributes: error: %d", status);
//        return;
//    }
//    
//    CFTypeRef itemRef;
//    status = SecKeychainSearchCopyNext(searchRef, &itemRef);
//    
//    if(status != noErr)
//    {
//        NSLog(@"SecKeychainSearchCopyNext: error: %d", status);
//        return;
//    }

    
    
    
    
    
    NSLog(@"-- DONE [OK] --");
}

void doExport2() {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  nil];
    
    NSArray *secItemClasses = [NSArray arrayWithObjects:
//                               (__bridge id)kSecClassGenericPassword,
//                               (__bridge id)kSecClassInternetPassword,
                               (__bridge id)kSecClassCertificate,
                               (__bridge id)kSecClassKey,
                               (__bridge id)kSecClassIdentity,
                               nil];
    
    for (id secItemClass in secItemClasses) {
        NSLog(@"---> %@", secItemClass);
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFTypeRef result = NULL;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        NSLog(@"%@", (__bridge id)result);
        if (result != NULL) CFRelease(result);
    }
}


void doExport3() {
    NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnRef,
                                  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                  nil];
    
    NSArray *secItemClasses = [NSArray arrayWithObjects:
                               (__bridge id)kSecClassIdentity,
                               nil];
    
    for (id secItemClass in secItemClasses) {
        NSLog(@"---> %@", secItemClass);
        [query setObject:secItemClass forKey:(__bridge id)kSecClass];
        
        CFArrayRef result = nil;
        SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&result);
        NSLog(@"%@", (__bridge id)result);
        
        // do something with the result
        CFRange range = CFRangeMake(0, CFArrayGetCount(result));
        CFArrayApplyFunction(result, range, PrintItem, nil);
        
//        performExport(result);
        
        if (result != NULL) CFRelease(result);
    }
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
        doExport1();
//        doExport2();
//        doExport3();
    }
    return 0;
}
