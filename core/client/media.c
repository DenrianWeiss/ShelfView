#define _POSIX_C_SOURCE 200809L
#include "internal.h"

static void redfish_done(bc_redfish_operation *op,const bc_redfish_result *result,void *user){(void)op;(void)result;(void)user;}
static void pause_ms(void) {
#ifdef _WIN32
    Sleep(10);
#else
    struct timespec duration={0,10000000};nanosleep(&duration,NULL);
#endif
}
static bc_status media_resource(bc_console_client *s,const char *path,bc_redfish_operation **out) {
    bc_redfish_options options={sizeof(options),BC_ABI_VERSION,client_remaining(s),32};
    bc_status status=bc_redfish_get_virtual_media(s->endpoint,str(path),&options,redfish_done,NULL,out);
    if(status==BC_OK) {
        while(!bc_redfish_result_get(*out)) {
            if(!client_remaining(s)||(!s->closing&&client_cancelled(s))){bc_redfish_cancel(*out);return client_cancelled(s)?BC_CANCELLED:BC_TIMEOUT;}
            status=bc_context_poll(s->context,10);if(status!=BC_OK)return status;
            if(s->media && s->links[0]) {status=client_pump(s,0,1);if(status!=BC_OK&&status!=BC_TIMEOUT)return status;}
        }
        status=bc_redfish_result_get(*out)->status;
    }
    return status;
}
static bc_status find_media(bc_console_client *s) {
    bc_redfish_collection_options options={sizeof(options),BC_ABI_VERSION,client_remaining(s),32};
    bc_redfish_operation *op=NULL;
    bc_status status=bc_redfish_discover_managers(s->endpoint,&options,redfish_done,NULL,&op);
    if(status==BC_OK)status=client_wait_redfish(s,op);
    const bc_redfish_collection_info *info=bc_redfish_collection_info_get(op);
    char managers[32][1025];uint32_t count=0;
    if(status==BC_OK&&(!info||info->member_count>32))status=BC_LIMIT_EXCEEDED;
    if(status==BC_OK)for(uint32_t i=0;i<info->member_count;++i){if(info->members[i].length>1024){status=BC_LIMIT_EXCEEDED;break;}memcpy(managers[i],info->members[i].data,(size_t)info->members[i].length);managers[i][info->members[i].length]=0;++count;}
    bc_redfish_release(op);if(status!=BC_OK)return status;
    uint32_t matches=0;
    for(uint32_t i=0;i<count;++i) {
        options.request_timeout_ms=client_remaining(s);op=NULL;
        status=bc_redfish_discover_virtual_media(s->endpoint,str(managers[i]),&options,redfish_done,NULL,&op);
        if(status==BC_OK)status=client_wait_redfish(s,op);
        info=bc_redfish_collection_info_get(op);
        char paths[32][1025];uint32_t n=0;
        if(status==BC_OK&&(!info||info->member_count>32))status=BC_LIMIT_EXCEEDED;
        if(status==BC_OK)for(uint32_t j=0;j<info->member_count;++j){if(info->members[j].length>1024){status=BC_LIMIT_EXCEEDED;break;}memcpy(paths[j],info->members[j].data,(size_t)info->members[j].length);paths[j][info->members[j].length]=0;++n;}
        bc_redfish_release(op);if(status!=BC_OK)return status;
        for(uint32_t j=0;j<n;++j) {
            op=NULL;status=media_resource(s,paths[j],&op);
            const bc_redfish_virtual_media_info *device=bc_redfish_virtual_media_info_get(op);
            if(status==BC_OK&&device)for(uint32_t k=0;k<device->media_type_count;++k){bc_string type=device->media_types[k];if((type.length==2&&!memcmp(type.data,"CD",2))||(type.length==3&&!memcmp(type.data,"DVD",3))){++matches;snprintf(s->media_uri,sizeof(s->media_uri),"%s",paths[j]);break;}}
            bc_redfish_release(op);if(status!=BC_OK)return status;
        }
    }
    return matches==1?BC_OK:BC_UNSUPPORTED;
}
bc_status client_media_readback(bc_console_client *s,int expected) {
    bc_status status=BC_OK;
    if(!s->media_uri[0])status=find_media(s);
    if(status!=BC_OK)return status;
    do {
        bc_redfish_operation *op=NULL;status=media_resource(s,s->media_uri,&op);
        const bc_redfish_virtual_media_info *info=bc_redfish_virtual_media_info_get(op);
        if(status==BC_OK&&info&&(info->flags&BC_REDFISH_VM_INSERTED_PRESENT)) {
            int inserted=(info->flags&BC_REDFISH_VM_INSERTED)!=0;
            if(expected<0){status=inserted?BC_BUSY:BC_OK;bc_redfish_release(op);return status;}
            if(inserted==expected){bc_media_session_observe_mount(s->media,inserted);bc_redfish_release(op);return BC_OK;}
        } else if(status==BC_OK&&expected<0)status=BC_UNSUPPORTED;
        bc_redfish_release(op);
        if(status!=BC_OK)return status;
        pause_ms();
    }while(client_remaining(s));
    return BC_TIMEOUT;
}
/* Parent requests are executed by its existing I/O lane. */
static bc_status parent_control(bc_console_client *s,uint32_t control) {
    bc_console_client *parent=s->parent;
    mutex_lock(&parent->mutex);parent->pending_controls|=control;mutex_unlock(&parent->mutex);
    while(client_remaining(s)&&(s->closing||!client_cancelled(s))) {
        mutex_lock(&parent->mutex);uint32_t pending=parent->pending_controls&control;bc_status status=parent->media_status;uint32_t state=parent->info.state;mutex_unlock(&parent->mutex);
        if(!pending)return status;
        if(state!=BC_CLIENT_ACTIVE)return BC_SHUTTING_DOWN;
        pause_ms();
    }
    return client_cancelled(s)?BC_CANCELLED:BC_TIMEOUT;
}
bc_status bc_console_client_media_create(bc_console_client *parent,const bc_console_client_options *configuration,bc_console_client **out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!parent||!configuration||configuration->struct_size!=sizeof(*configuration)||!configuration->source||configuration->source->struct_size!=sizeof(bc_media_source)||!configuration->source->read)return BC_INVALID_ARGUMENT;
    mutex_lock(&parent->mutex);
    if(parent->info.state!=BC_CLIENT_ACTIVE||parent->media_children){mutex_unlock(&parent->mutex);return BC_BUSY;}
    if (parent->irmc && !(parent->published.flags & BC_CLIENT_LOCAL_MEDIA)) {
        mutex_unlock(&parent->mutex);
        return BC_UNSUPPORTED;
    }
    ++parent->media_children;mutex_unlock(&parent->mutex);
    bc_console_client_options options=parent->options;options.service=BC_CLIENT_MEDIA;options.source=configuration->source;options.user=configuration->user;options.cancelled=configuration->cancelled;options.confirm=configuration->confirm;options.submit=NULL;if(configuration->timeout_ms)options.timeout_ms=configuration->timeout_ms;
    bc_console_client *child=NULL;bc_status status=bc_console_client_create(&options,&child);
    if(status!=BC_OK){mutex_lock(&parent->mutex);--parent->media_children;mutex_unlock(&parent->mutex);return status;}
    child->parent=parent;child->protocol=parent->protocol;child->port=parent->port;child->media_parameters=parent->media_parameters;
    child->generation=parent->generation;
    child->irmc = parent->irmc;
    if (child->irmc) child->mega = parent->mega;
    child->host=client_copy(str(parent->host),255);child->origin=client_copy(str(parent->origin),8192);
    if(parent->cookie)client_cookie(child,str(parent->cookie));
    child->deadline=bc_monotonic_ms()+child->options.timeout_ms;
    if(parent->protocol==BC_CONSOLE_PROTOCOL_IDRAC||parent->protocol==BC_CONSOLE_PROTOCOL_ILO||parent->lenovo_remote[0]) {
        /* These media realms deliberately authenticate their own HTTP owner. */
        child->parent=NULL;mutex_lock(&parent->mutex);--parent->media_children;mutex_unlock(&parent->mutex);
        free(child->host);child->host=NULL;free(child->origin);child->origin=NULL;
    }
    if(child->parent)child->info.flags|=BC_CLIENT_DEPENDENT;child->published=child->info;
    *out=child;return BC_OK;
}
bc_status client_parent_media_start(bc_console_client *s) {
    if (s->irmc) {
        bc_status status = bc_media_offer_from_token(BC_CONSOLE_PROTOCOL_MEGARAC, 0, str(s->mega.token), &s->offer);
        return status == BC_OK ? client_url(s, "tls", s->mega.port, "", &s->urls[0]) : status;
    }
    mutex_lock(&s->parent->mutex);s->parent->offer_requested=1;mutex_unlock(&s->parent->mutex);
    bc_status status=parent_control(s,BC_CONSOLE_CONTROL_MEDIA_ENABLE);
    if(status!=BC_OK)return status;
    while(client_remaining(s)) {
        mutex_lock(&s->parent->mutex);s->offer=s->parent->offer;s->parent->offer=NULL;mutex_unlock(&s->parent->mutex);
        if(s->offer)break;
        if(client_cancelled(s))return BC_CANCELLED;pause_ms();
    }
    if(!s->offer)return BC_TIMEOUT;
    if(s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI){bc_media_offer_info info={sizeof(info),0,0};status=bc_media_offer_info_get(s->offer,&info);if(status==BC_OK)status=client_url(s,"wss",info.port,"/websocket",&s->urls[0]);}
    else {int websocket=(s->media_parameters.flags&BC_MEGARAC_MEDIA_WEBSOCKET)!=0;status=client_url(s,websocket?"wss":(s->media_parameters.secure?"tls":"tcp"),websocket?s->port:s->media_parameters.port,websocket?"/cd-server":"",&s->urls[0]);}
    return status;
}
bc_status client_parent_media_attached(bc_console_client *s) {
    if (!s->parent || s->protocol != BC_CONSOLE_PROTOCOL_MEGARAC) return BC_OK;
    if (s->irmc) s->irmc_media_announced = 1;
    return parent_control(s, BC_CONSOLE_CONTROL_SOURCE_ATTACH);
}
bc_status client_irmc_media_detach(bc_console_client *s) {
    if (!s->parent || !s->irmc_media_announced) return BC_OK;
    bc_status status = parent_control(s, BC_CONSOLE_CONTROL_SOURCE_DETACH);
    if (status == BC_OK) s->irmc_media_announced = 0;
    return status;
}
void client_parent_media_close(bc_console_client *s) {
    if(!s->parent)return;
    uint64_t saved=s->deadline;s->deadline=bc_monotonic_ms()+1000;
    if(!s->irmc&&s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC){parent_control(s,BC_CONSOLE_CONTROL_SOURCE_DETACH);parent_control(s,BC_CONSOLE_CONTROL_MEDIA_DISABLE);}
    s->deadline=saved;
    mutex_lock(&s->parent->mutex);--s->parent->media_children;mutex_unlock(&s->parent->mutex);s->parent=NULL;
}


bc_status client_irmc_media_tunnel(bc_console_client *s) {
    uint8_t data[1024];
    uint32_t length = 0;
    bc_status status = bc_megarac_tunnel_request(&s->mega, BC_MEGARAC_TUNNEL_CD, data, sizeof(data), &length);
    if (status == BC_OK) status = bc_irmc_send(s->links[0], data, length);
    memset(data, 0, sizeof(data));
    length = 0;
    while (status == BC_OK && length < 255) {
        uint32_t remaining = client_remaining(s);
        if (!remaining || client_cancelled(s)) return client_cancelled(s) ? BC_CANCELLED : BC_TIMEOUT;
        uint32_t received = 0;
        status = client_receive(s, data + length, 1, &received, remaining < 200 ? remaining : 200);
        if (status == BC_TIMEOUT) { status = BC_OK; continue; }
        if (status != BC_OK) return status;
        if (received != 1) return BC_PROTOCOL_ERROR;
        uint32_t consumed = 0;
        status = bc_megarac_tunnel_status_line(data, ++length, &consumed);
        if (status != BC_BUSY) return status;
        status = BC_OK;
    }
    return status == BC_OK ? BC_LIMIT_EXCEEDED : status;
}
