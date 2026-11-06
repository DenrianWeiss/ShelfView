#include "sensor_compat_internal.h"
#include <stdlib.h>
#include <string.h>
struct bc_sensor_compat { char *json;size_t size;char links[2][1025]; };
bc_status bc_sensor_compat_create(bc_bytes body,bc_sensor_compat **out){
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!body.data||!body.length||body.length>1024u*1024u)return BC_INVALID_ARGUMENT;
    yyjson_doc *input=yyjson_read((const char *)body.data,(size_t)body.length,0);
    if(!input||!yyjson_is_obj(yyjson_doc_get_root(input))){if(input)yyjson_doc_free(input);return BC_PROTOCOL_ERROR;}
    yyjson_mut_doc *doc=yyjson_doc_mut_copy(input,NULL);yyjson_doc_free(input);if(!doc)return BC_NO_MEMORY;
    bc_sensor_compat *view=calloc(1,sizeof(*view));if(!view){yyjson_mut_doc_free(doc);return BC_NO_MEMORY;}
    bc_status status=bc_huawei_sensor_normalize(doc,yyjson_mut_doc_get_root(doc),view->links);
    if(status==BC_OK){view->json=yyjson_mut_write(doc,0,&view->size);if(!view->json)status=BC_NO_MEMORY;}
    yyjson_mut_doc_free(doc);if(status!=BC_OK){bc_sensor_compat_destroy(view);return status;}
    *out=view;return BC_OK;
}
bc_bytes bc_sensor_compat_json(const bc_sensor_compat *view){return view?(bc_bytes){(const uint8_t *)view->json,view->size}:(bc_bytes){NULL,0};}
bc_string bc_sensor_compat_link(const bc_sensor_compat *view,uint32_t kind){
    if(!view||kind<1||kind>2)return(bc_string){NULL,0};
    const char *value=view->links[kind-1];return(bc_string){value,strlen(value)};
}
void bc_sensor_compat_destroy(bc_sensor_compat *view){if(!view)return;free(view->json);free(view);}
int bc_redfish_logout_response_succeeded(uint32_t http,bc_bytes body){
    if(http!=200||!body.data||!body.length||body.length>1024u*1024u)return 0;
    yyjson_doc *doc=yyjson_read((const char *)body.data,(size_t)body.length,0);if(!doc)return 0;
    yyjson_val *root=yyjson_doc_get_root(doc),*error=yyjson_obj_get(root,"error"),*messages=yyjson_obj_get(error,"@Message.ExtendedInfo");
    size_t count=yyjson_arr_size(messages);int success=yyjson_is_obj(root)&&yyjson_is_obj(error)&&count>0&&count<=16;
    size_t index,max;yyjson_val *message;
    yyjson_arr_foreach(messages,index,max,message){const char *id=yyjson_get_str(yyjson_obj_get(message,"MessageId"));size_t n=id?strlen(id):0;if(n<9||strcmp(id+n-8,".Success"))success=0;}
    yyjson_doc_free(doc);return success;
}
