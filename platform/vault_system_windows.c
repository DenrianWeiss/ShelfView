#include "../core/vault/system_internal.h"
#include <windows.h>
#include <wincred.h>
#include <string.h>
#include <wchar.h>
static void target(const char *reference, int legacy, WCHAR out[128]) {
    const WCHAR *prefix=legacy?L"bControl/Vault/":L"work.permutation.shelfview/Vault/";size_t n=wcslen(prefix);
    memcpy(out,prefix,n*sizeof(*out));for(unsigned i=0;i<65;++i)out[n+i]=(WCHAR)reference[i];
}
static bc_status error_status(DWORD error) {
    return error==ERROR_NOT_FOUND?BC_OK:error==ERROR_NO_SUCH_LOGON_SESSION?BC_UNSUPPORTED:
        error==ERROR_ACCESS_DENIED?BC_AUTHENTICATION_FAILED:BC_IO_ERROR;
}
bc_status vault_system_read(const char reference[65], int legacy, uint8_t key[32], int *found, uint32_t *flags) {
    WCHAR name[128];target(reference,legacy,name);PCREDENTIALW credential=NULL;
    if(!CredReadW(name,CRED_TYPE_GENERIC,0,&credential))return error_status(GetLastError());
    bc_status status=BC_OK;
    if(!credential||credential->CredentialBlobSize!=32||!credential->CredentialBlob)status=BC_PROTOCOL_ERROR;
    else{memcpy(key,credential->CredentialBlob,32);*found=1;*flags=credential->Persist==CRED_PERSIST_ENTERPRISE?BC_VAULT_KEY_ROAMING_ELIGIBLE:BC_VAULT_KEY_LOCAL;}
    if(credential){
        if(credential->CredentialBlob&&credential->CredentialBlobSize<=CRED_MAX_CREDENTIAL_BLOB_SIZE)
            SecureZeroMemory(credential->CredentialBlob,credential->CredentialBlobSize);
        CredFree(credential);
    }
    return status;
}
bc_status vault_system_store(const char reference[65], const uint8_t key[32], int roaming, uint32_t *flags) {
    DWORD supported[CRED_TYPE_MAXIMUM]={0};
    if(!CredGetSessionTypes(CRED_TYPE_MAXIMUM,supported))return error_status(GetLastError());
    DWORD persistence=roaming&&supported[CRED_TYPE_GENERIC]>=CRED_PERSIST_ENTERPRISE?CRED_PERSIST_ENTERPRISE:CRED_PERSIST_LOCAL_MACHINE;
    if(supported[CRED_TYPE_GENERIC]<persistence)return BC_UNSUPPORTED;
    WCHAR name[128];target(reference,0,name);
    CREDENTIALW credential={0};credential.Type=CRED_TYPE_GENERIC;credential.TargetName=name;credential.UserName=L"Vault";
    credential.CredentialBlobSize=32;credential.CredentialBlob=(LPBYTE)key;credential.Persist=persistence;
    if(!CredWriteW(&credential,0))return error_status(GetLastError());
    *flags=persistence==CRED_PERSIST_ENTERPRISE?BC_VAULT_KEY_ROAMING_ELIGIBLE:BC_VAULT_KEY_LOCAL;return BC_OK;
}
bc_status vault_system_delete(const char reference[65], int legacy) {
    WCHAR name[128];target(reference,legacy,name);return CredDeleteW(name,CRED_TYPE_GENERIC,0)?BC_OK:error_status(GetLastError());
}
