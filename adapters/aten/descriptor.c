#include "bcontrol/aten.h"
#include "launch_xml.h"
#include <string.h>
typedef struct {
    bc_aten_launch launch;
    char main_class[96], argument[4097], jar[1025], version[65];
    char args[22][1025], os[33], arch[33], property_name[65], property_value[17];
    uint32_t property_depth, property_name_size, property_value_size;
    uint32_t os_size, arch_size, resources_depth, native;
    uint32_t class_size, argument_size, jar_size, version_size, codebase_size;
    uint32_t app_depth, arg_depth, apps, arguments, capture, jar_depth;
} document;
static bc_status argument(document *d) {
    if(d->arguments>=22 || strlen(d->argument)>=sizeof(d->args[0]))return BC_PROTOCOL_ERROR;
    strcpy(d->args[d->arguments++],d->argument);
    return BC_OK;
}
static bc_status decode(document *d) {
    uint32_t offset=d->arguments==22?10:0;
    if(d->arguments!=8 && d->arguments!=10 && d->arguments!=22)return BC_PROTOCOL_ERROR;
    for(uint32_t i=0;i<d->arguments-offset;++i) {
        const char *p=d->args[offset+i];uint32_t n=0;
        if(i<3) {
            size_t size=strlen(p),limit=i?23:255;
            if(!size || size>limit)return BC_PROTOCOL_ERROR;
            for(size_t j=0;j<size;++j)if((unsigned char)p[j]<33 || (unsigned char)p[j]>126 ||
                (!i && strchr("/@?#\\",p[j])))return BC_PROTOCOL_ERROR;
            strcpy(i==0?d->launch.host:i==1?d->launch.username:d->launch.password,p);
        } else if(i==4 || i==5 || i>=8) {
            uint32_t flag=i==8 || i==11;
            if(bc_launch_number(p,flag?1:65535,&n)!=BC_OK || (!flag && !n))return BC_PROTOCOL_ERROR;
            if(i==4)d->launch.port=n;
            if(i==5)d->launch.media_port=n;
            if(i==8)d->launch.tls=n;
            if(i==9)d->launch.tls_port=n;
            if(i==10)d->launch.media_tls_port=n;
            if(i==11)d->launch.media_enabled=n;
        }
    }
    if(offset && (!d->launch.jar_path[0] || strcmp(d->args[1],d->launch.jar_path)))return BC_PROTOCOL_ERROR;
    if(!offset)d->launch.media_enabled=1;
    return BC_OK;
}

static bc_status event(void *user,enum bc_launch_xml_event kind,uint32_t depth,const char *name,const char *data) {
    document *d=user;
    switch(kind) {
    case BC_XML_START:
        if(d->arg_depth || (depth==1 && strcmp(name,"jnlp")))return BC_PROTOCOL_ERROR;
        if(!strcmp(name,"resources")) {
            if(depth!=2)return BC_PROTOCOL_ERROR;
            d->resources_depth=depth;d->os_size=d->arch_size=0;d->os[0]=d->arch[0]=0;
        } else if(!strcmp(name,"property")) {
            d->property_depth=depth;d->property_name_size=d->property_value_size=0;
            d->property_name[0]=d->property_value[0]=0;
        } else if(!strcmp(name,"application-desc")) {
            if(depth!=2 || ++d->apps!=1)return BC_PROTOCOL_ERROR;
            d->app_depth=depth;
        } else if(!strcmp(name,"argument")) {
            if(!d->app_depth || depth!=d->app_depth+1)return BC_PROTOCOL_ERROR;
            d->arg_depth=depth;d->argument_size=0;d->argument[0]=0;
        } else if(!strcmp(name,"jar") || !strcmp(name,"nativelib")) {
            d->native=!strcmp(name,"nativelib");
            d->jar_depth=depth;d->jar_size=d->version_size=0;d->jar[0]=d->version[0]=0;
        }
        break;
    case BC_XML_ATTRIBUTE:
        d->capture=depth==1 && !strcmp(name,"codebase")?8:d->app_depth==depth && !strcmp(name,"main-class")?1:
            d->jar_depth==depth && !strcmp(name,"href")?2:d->jar_depth==depth && !strcmp(name,"version")?3:d->resources_depth==depth && !strcmp(name,"os")?4:
            d->resources_depth==depth && !strcmp(name,"arch")?5:
            d->property_depth==depth && !strcmp(name,"name")?6:d->property_depth==depth && !strcmp(name,"value")?7:0;
        break;
    case BC_XML_ATTRIBUTE_VALUE:
        if(d->capture==8)return bc_launch_append(d->launch.codebase,&d->codebase_size,sizeof(d->launch.codebase),data);
        if(d->capture==1)return bc_launch_append(d->main_class,&d->class_size,sizeof(d->main_class),data);
        if(d->capture==2)return bc_launch_append(d->jar,&d->jar_size,sizeof(d->jar),data);
        if(d->capture==3)return bc_launch_append(d->version,&d->version_size,sizeof(d->version),data);
        if(d->capture==4)return bc_launch_append(d->os,&d->os_size,sizeof(d->os),data);
        if(d->capture==6)return bc_launch_append(d->property_name,&d->property_name_size,sizeof(d->property_name),data);
        if(d->capture==7)return bc_launch_append(d->property_value,&d->property_value_size,sizeof(d->property_value),data);
        if(d->capture==5)return bc_launch_append(d->arch,&d->arch_size,sizeof(d->arch),data);
        break;
    case BC_XML_ATTRIBUTE_END:d->capture=0;break;
    case BC_XML_CONTENT:
        if(d->arg_depth)return bc_launch_append(d->argument,&d->argument_size,sizeof(d->argument),data);
        break;
    case BC_XML_END:
        if(d->arg_depth==depth) {d->arg_depth=0;bc_status status=argument(d);if(status!=BC_OK)return status;}
        if(d->app_depth==depth)d->app_depth=0;
        if(d->jar_depth==depth) {
            const char *base=strrchr(d->jar,'/');base=base?base+1:d->jar;
            if(d->native && !strcmp(d->os,"Linux") && (!strcmp(d->arch,"amd64") || !strcmp(d->arch,"x86_64"))) {
                if(d->launch.native_path[0] && strcmp(d->launch.native_path,d->jar))return BC_UNSUPPORTED;
                strcpy(d->launch.native_path,d->jar);
            }
            if(!d->native && (!strcmp(base,"iKVM.jar") || !strncmp(base,"iKVM__V",7))) {
                if(d->launch.jar_path[0] && strcmp(d->launch.jar_path,d->jar))return BC_PROTOCOL_ERROR;
                strcpy(d->launch.jar_path,d->jar);
                if(!d->version_size && !strncmp(base,"iKVM__V",7)) {
                    size_t n=strlen(base+7);
                    if(n<=4 || strcmp(base+7+n-4,".jar") || n-4>=sizeof(d->version))return BC_PROTOCOL_ERROR;
                    memcpy(d->version,base+7,n-4);d->version[n-4]=0;d->version_size=(uint32_t)n-4;
                }
                if(d->launch.viewer_version[0] && strcmp(d->launch.viewer_version,d->version))return BC_PROTOCOL_ERROR;
                for(uint32_t i=0;i<d->version_size;++i)if(!strchr("0123456789.xXabcdefABCDEF-_",d->version[i]))return BC_PROTOCOL_ERROR;
                strcpy(d->launch.viewer_version,d->version);
            }
        }
        if(d->jar_depth==depth)d->jar_depth=0;
        if(d->resources_depth==depth)d->resources_depth=0;
        if(d->property_depth==depth) {
            if(!strcmp(d->property_name,"jnlp.packEnabled")) {
                if(strcmp(d->property_value,"true") && strcmp(d->property_value,"false"))return BC_PROTOCOL_ERROR;
                d->launch.pack_enabled=!strcmp(d->property_value,"true");
            }
            d->property_depth=0;
        }
        break;
    }
    return BC_OK;
}
bc_status bc_aten_launch_parse(const uint8_t *data,uint32_t length,bc_aten_launch *out) {
    if(!out)return BC_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));document d={0};
    bc_status status=bc_launch_xml_parse(data,length,event,&d);
    if(status==BC_OK && strcmp(d.main_class,"tw.com.aten.ikvm.KVMMain"))status=BC_UNSUPPORTED;
    if(status==BC_OK && d.apps!=1)status=BC_PROTOCOL_ERROR;
    if(status==BC_OK)status=decode(&d);
    if(status==BC_OK) {d.launch.struct_size=sizeof(d.launch);*out=d.launch;}
    volatile unsigned char *p=(volatile unsigned char *)&d;for(size_t i=0;i<sizeof(d);++i)p[i]=0;
    return status;
}
