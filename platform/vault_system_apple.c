#include "../core/vault/system_internal.h"
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
static bc_status status_map(OSStatus status) {
    if(status==errSecSuccess||status==errSecItemNotFound)return BC_OK;
    if(status==errSecMissingEntitlement||status==errSecNotAvailable||status==errSecNoDefaultKeychain)return BC_UNSUPPORTED;
    if(status==errSecInteractionNotAllowed)return BC_BUSY;
    if(status==errSecAuthFailed||status==errSecUserCanceled)return BC_AUTHENTICATION_FAILED;
    return BC_IO_ERROR;
}
static CFMutableDictionaryRef query(const char *reference, int mode, int legacy) {
    CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    if(!q)return NULL;
    CFStringRef account=CFStringCreateWithCString(NULL,reference,kCFStringEncodingUTF8);
    if(!account){CFRelease(q);return NULL;}
    CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
    CFDictionarySetValue(q,kSecAttrService,legacy?CFSTR("org.bcontrol.vault-key"):CFSTR("work.permutation.shelfview.vault-key"));
    CFDictionarySetValue(q,kSecAttrAccount,account);CFRelease(account);
    CFDictionarySetValue(q,kSecAttrSynchronizable,mode==0?kCFBooleanTrue:kCFBooleanFalse);
    if(mode<2)CFDictionarySetValue(q,kSecUseDataProtectionKeychain,kCFBooleanTrue);
    return q;
}
static bc_status read_mode(const char *reference, int mode, int legacy, uint8_t key[32], int *found) {
    CFMutableDictionaryRef q=query(reference,mode,legacy);if(!q)return BC_NO_MEMORY;
    CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
    CFTypeRef result=NULL;OSStatus status=SecItemCopyMatching(q,&result);CFRelease(q);
    bc_status code=status_map(status);
    if(status==errSecSuccess){
        if(!result||CFGetTypeID(result)!=CFDataGetTypeID()||CFDataGetLength((CFDataRef)result)!=32)code=BC_PROTOCOL_ERROR;
        else{memcpy(key,CFDataGetBytePtr((CFDataRef)result),32);*found=1;}
    }
    if(result)CFRelease(result);
    return code;
}
bc_status vault_system_read(const char reference[65], int legacy, uint8_t key[32], int *found, uint32_t *flags) {
    bc_status previous=BC_UNSUPPORTED;
    for(int mode=0;mode<3;++mode){
        bc_status status=read_mode(reference,mode,legacy,key,found);
        if(status==BC_OK&&*found){*flags=mode==0?BC_VAULT_KEY_ROAMING_ELIGIBLE:BC_VAULT_KEY_LOCAL;return BC_OK;}
        if(status!=BC_OK&&status!=BC_UNSUPPORTED)return status;
        if(status==BC_OK)previous=BC_OK;
    }
    return previous;
}
static bc_status store_mode(const char *reference, const uint8_t key[32], int mode) {
    CFMutableDictionaryRef q=query(reference,mode,0);if(!q)return BC_NO_MEMORY;
    CFMutableDictionaryRef values=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDataRef data=CFDataCreate(NULL,key,32);
    if(!values||!data){if(values)CFRelease(values);if(data)CFRelease(data);CFRelease(q);return BC_NO_MEMORY;}
    CFDictionarySetValue(values,kSecValueData,data);
    CFDictionarySetValue(values,kSecAttrAccessible,mode==0?kSecAttrAccessibleWhenUnlocked:kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    OSStatus status=SecItemUpdate(q,values);
    if(status==errSecItemNotFound){
        CFDictionarySetValue(q,kSecValueData,data);
        CFDictionarySetValue(q,kSecAttrAccessible,mode==0?kSecAttrAccessibleWhenUnlocked:kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
        status=SecItemAdd(q,NULL);
    }
    CFRelease(data);CFRelease(values);CFRelease(q);return status_map(status);
}
bc_status vault_system_store(const char reference[65], const uint8_t key[32], int roaming, uint32_t *flags) {
    for(int mode=roaming?0:1;mode<3;++mode){
        bc_status status=store_mode(reference,key,mode);
        if(status==BC_OK){*flags=mode==0?BC_VAULT_KEY_ROAMING_ELIGIBLE:BC_VAULT_KEY_LOCAL;return BC_OK;}
        if(status!=BC_UNSUPPORTED)return status;
    }
    return BC_UNSUPPORTED;
}
bc_status vault_system_delete(const char reference[65], int legacy) {
    bc_status result=BC_OK;
    for(int mode=0;mode<3;++mode){
        CFMutableDictionaryRef q=query(reference,mode,legacy);if(!q)return BC_NO_MEMORY;
        bc_status status=status_map(SecItemDelete(q));CFRelease(q);
        if(status!=BC_OK&&status!=BC_UNSUPPORTED)result=status;
    }
    return result;
}
