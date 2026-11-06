#include "media_internal.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char fold(char c) { return c>='A'&&c<='Z'?(char)(c+32):c; }
static int hex(char c) {
    c=fold(c);return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;
}
static int ipv6(const char *s,size_t n,uint16_t words[8]) {
    size_t at=0;unsigned count=0;int gap=-1;
    memset(words,0,16);
    if(n>=2&&s[0]==':'&&s[1]==':'){gap=0;at=2;}
    while(at<n){
        size_t start=at;unsigned value=0,digits=0;
        while(at<n&&hex(s[at])>=0){value=value*16+(unsigned)hex(s[at++]);if(++digits>4)return 0;}
        if(at<n&&s[at]=='.'){
            at=start;if(count>6)return 0;unsigned bytes[4];
            for(unsigned i=0;i<4;++i){value=0;digits=0;
                while(at<n&&s[at]>='0'&&s[at]<='9'){value=value*10+(unsigned)(s[at++]-'0');if(++digits>3)return 0;}
                if(!digits||value>255)return 0;
                bytes[i]=value;
                if(i<3){if(at>=n||s[at++]!='.')return 0;}else if(at!=n)return 0;
            }
            words[count++]=(uint16_t)((bytes[0]<<8)|bytes[1]);words[count++]=(uint16_t)((bytes[2]<<8)|bytes[3]);break;
        }
        if(!digits||count>=8)return 0;
        words[count++]=(uint16_t)value;
        if(at==n)break;
        if(s[at++]!=':')return 0;
        if(at<n&&s[at]==':'){if(gap>=0)return 0;gap=(int)count;++at;}
        else if(at==n)return 0;
    }
    if(gap<0)return count==8;
    if(count>=8)return 0;
    unsigned tail=count-(unsigned)gap;memmove(words+8-tail,words+gap,tail*sizeof(*words));
    memset(words+gap,0,(8-count)*sizeof(*words));return 1;
}
static void ipv6_text(const uint16_t words[8],char text[48]) {
    unsigned best=8,length=0;
    for(unsigned i=0;i<8;){if(words[i]){++i;continue;}unsigned start=i;while(i<8&&!words[i])++i;if(i-start>length){best=start;length=i-start;}}
    if(length<2)best=8;
    size_t used=0;
    for(unsigned i=0;i<8;){
        if(i==best){text[used++]=':';text[used++]=':';i+=length;continue;}
        if(used&&text[used-1]!=':')text[used++]=':';
        used+=(size_t)snprintf(text+used,48-used,"%x",(unsigned)words[i++]);
    }
    text[used]=0;
}
static int add(bc_vault_media_scope *scope,const char *origin,bc_string username) {
    unsigned char digest[32];unsigned length=0;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return 0;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)&&EVP_DigestUpdate(ctx,origin,strlen(origin))&&
        EVP_DigestUpdate(ctx,"",1)&&EVP_DigestUpdate(ctx,username.data,(size_t)username.length)&&EVP_DigestFinal_ex(ctx,digest,&length);
    EVP_MD_CTX_free(ctx);if(!ok||length!=32){OPENSSL_cleanse(digest,sizeof(digest));return 0;}
    char id[77];memcpy(id,"state:media:",12);static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i){id[12+i*2]=digits[digest[i]>>4];id[13+i*2]=digits[digest[i]&15];}id[76]=0;
    OPENSSL_cleanse(digest,sizeof(digest));
    for(unsigned i=0;i<scope->count;++i)if(!strcmp(id,scope->ids[i]))return 1;
    if(scope->count>=VAULT_MEDIA_ALIASES)return 0;
    memcpy(scope->ids[scope->count++],id,sizeof(id));return 1;
}
static int add_host(bc_vault_media_scope *scope,const char *scheme,const char *host,unsigned port,int brackets,bc_string username) {
    char origin[2100];int n=snprintf(origin,sizeof(origin),brackets?"%s://[%s]:%u":"%s://%s:%u",scheme,host,port);
    if(n<0||(size_t)n>=sizeof(origin))return 0;
    int ok=add(scope,origin,username);OPENSSL_cleanse(origin,sizeof(origin));return ok;
}
bc_status bc_vault_media_scope_create(bc_string address,bc_string username,bc_vault_media_scope **out) {
    if(!out)return BC_INVALID_ARGUMENT;
    *out=NULL;
    if(!address.data||!address.length||address.length>2048||username.length>1024||(!username.data&&username.length)||
       memchr(address.data,0,(size_t)address.length)||(username.length&&memchr(username.data,0,(size_t)username.length)))return BC_INVALID_ARGUMENT;
    char text[2049];for(size_t i=0;i<(size_t)address.length;++i){unsigned char c=(unsigned char)address.data[i];if(c<=32||c>=127)return BC_INVALID_ARGUMENT;text[i]=fold((char)c);}text[address.length]=0;
    bc_vault_media_scope *scope=calloc(1,sizeof(*scope));if(!scope)return BC_NO_MEMORY;
    char *authority=strstr(text,"://");
    if(!authority){
        /* Earlier bare-host records used their exact spelling. */
        memcpy(text,address.data,(size_t)address.length);
        if(!add(scope,text,username)){free(scope);return BC_NO_MEMORY;}
        *out=scope;return BC_OK;
    }
    *authority=0;authority+=3;
    unsigned port=!strcmp(text,"https")?443:!strcmp(text,"http")?80:!strcmp(text,"ipmi")?623:0;
    if(!port){free(scope);return BC_INVALID_ARGUMENT;}
    char *end=strchr(authority,'/');if(end)*end=0;
    if(!*authority||strpbrk(authority,"@?#\\")){free(scope);return BC_INVALID_ARGUMENT;}
    int bracket=*authority=='[';char *host=authority,*port_text=NULL;
    if(bracket){host=authority+1;end=strchr(host,']');if(!end||end==host){free(scope);return BC_INVALID_ARGUMENT;}*end=0;
        if(end[1]){if(end[1]!=':'){free(scope);return BC_INVALID_ARGUMENT;}port_text=end+2;}}
    else {end=strchr(host,':');if(end){*end=0;port_text=end+1;}if(!*host){free(scope);return BC_INVALID_ARGUMENT;}}
    if(port_text){port=0;size_t n=strlen(port_text);if(!n||n>5){free(scope);return BC_INVALID_ARGUMENT;}
        for(size_t i=0;i<n;++i){if(port_text[i]<'0'||port_text[i]>'9'){free(scope);return BC_INVALID_ARGUMENT;}port=port*10+(unsigned)(port_text[i]-'0');}
        if(!port||port>65535){free(scope);return BC_INVALID_ARGUMENT;}}
    char canonical[48];uint16_t words[8];
    if(bracket){if(!ipv6(host,strlen(host),words)){free(scope);return BC_INVALID_ARGUMENT;}ipv6_text(words,canonical);}
    int ok=add_host(scope,text,bracket?canonical:host,port,bracket,username)&&add_host(scope,text,host,port,bracket,username);
    if(bracket){ok=ok&&add_host(scope,text,host,port,0,username)&&add_host(scope,text,canonical,port,0,username);
        if(!words[0]&&!words[1]&&!words[2]&&!words[3]&&!words[4]&&words[5]==65535){
            char mapped[48];snprintf(mapped,sizeof(mapped),"::ffff:%u.%u.%u.%u",(unsigned)(words[6]>>8),(unsigned)(words[6]&255),(unsigned)(words[7]>>8),(unsigned)(words[7]&255));
            ok=ok&&add_host(scope,text,mapped,port,1,username);}}
    if(!strcmp(text,"ipmi")&&!port_text)ok=ok&&add_host(scope,text,host,80,bracket,username);
    OPENSSL_cleanse(text,sizeof(text));if(!ok){free(scope);return BC_NO_MEMORY;}*out=scope;return BC_OK;
}
bc_string bc_vault_media_scope_id(const bc_vault_media_scope *scope) {return scope&&scope->count?(bc_string){scope->ids[0],76}:(bc_string){0};}
void bc_vault_media_scope_destroy(bc_vault_media_scope *scope){if(scope){OPENSSL_cleanse(scope,sizeof(*scope));free(scope);}}
