#define _POSIX_C_SOURCE 200809L
#include "internal.h"
#include "bcontrol/decode_provider.h"
#include "bcontrol/huawei_session.h"
#include <limits.h>
#include <openssl/rand.h>

static void wipe_free(char *p) { if (p) { volatile char *w=p; size_t n=strlen(p); while(n--) *w++=0; free(p); } }
static bc_status enqueue_output(bc_console_client *s, uint32_t channel, const uint8_t *bytes, uint32_t size) {
    if (size > CLIENT_BYTES) return BC_LIMIT_EXCEEDED;
    client_message *message = malloc(sizeof(*message)+(size_t)size);
    if (!message) return BC_NO_MEMORY;
    message->next=NULL; message->channel=channel; message->size=size;
    if(size) memcpy(message->data,bytes,size);
    mutex_lock(&s->mutex);
    if(s->output_count>=CLIENT_MESSAGES || size>CLIENT_BYTES-s->output_bytes) {
        mutex_unlock(&s->mutex); memset(message->data,0,size); free(message); return BC_LIMIT_EXCEEDED;
    }
    if(s->output_tail) s->output_tail->next=message; else s->output_head=message;
    s->output_tail=message; ++s->output_count; s->output_bytes+=size;
    mutex_unlock(&s->mutex); return BC_OK;
}
bc_status client_emit(void *user,const uint8_t *bytes,uint32_t size) { return enqueue_output(user,0,bytes,size); }
bc_status client_receive(void *user,uint8_t *bytes,uint32_t capacity,uint32_t *size,uint32_t timeout) {
    bc_console_client *s=user;
    return bc_kvm_transport_recv(s->links[0],bytes,capacity,size,timeout);
}
static uint8_t leds(void *user) {
    bc_console_client *s=user; mutex_lock(&s->mutex); uint8_t result=(uint8_t)s->keyboard_leds; mutex_unlock(&s->mutex); return result;
}
void client_publish_protocol(bc_console_client *s) {
    bc_console_info info={0}; info.struct_size=sizeof(info);
    if(bc_console_session_info_get(s->console,&info)!=BC_OK) return;
    mutex_lock(&s->mutex);
    if(info.flags & BC_CONSOLE_INFO_PROFILE_VALID) s->info.profile=info.profile;
    if(info.flags & BC_CONSOLE_INFO_FAILURE_VALID) s->info.failure=info.failure;
    if(info.flags & BC_CONSOLE_INFO_LEDS_VALID) s->keyboard_leds=info.keyboard_leds;
    if(info.flags & BC_CONSOLE_INFO_FAILED) { s->info.state=BC_CLIENT_FAILED; s->info.status=info.failure.status ? info.failure.status : BC_PROTOCOL_ERROR; }
    mutex_unlock(&s->mutex);
}
static bc_status collect_channel_output(bc_console_client *s,uint32_t channel) {
    uint8_t bytes[8192];
    uint32_t count = 0;
    bc_status status;
    do {
        count = 0;
        status = bc_console_session_output(s->console, channel, bytes, sizeof(bytes), &count);
        if (status == BC_UNSUPPORTED) status = BC_OK;
        else if (status == BC_OK && count) status = enqueue_output(s, channel, bytes, count);
    } while (status == BC_OK && (s->irmc || s->protocol == BC_CONSOLE_PROTOCOL_AVOCENT) && count);
    memset(bytes, 0, sizeof(bytes));
    return status;
}
static bc_status collect_output(bc_console_client *s,uint32_t channel) {
    bc_status status = collect_channel_output(s, channel);
    if (status == BC_OK && s->protocol == BC_CONSOLE_PROTOCOL_AVOCENT)
        status = collect_channel_output(s, 1u - channel);
    return status;
}
bc_status client_drain(bc_console_client *s) {
    for(;;) {
        mutex_lock(&s->mutex); client_message *message=s->output_head;
        if(message) { s->output_head=message->next; if(!s->output_head)s->output_tail=NULL; --s->output_count; s->output_bytes-=message->size; }
        mutex_unlock(&s->mutex); if(!message) return BC_OK;
        bc_status status = s->irmc ? bc_irmc_send(s->links[message->channel], message->data, message->size) :
            bc_kvm_transport_send(s->links[message->channel], message->data, message->size);
        memset(message->data,0,message->size); free(message); if(status!=BC_OK) return status;
    }
}
static bc_status network_send(void *user,const uint8_t *bytes,uint32_t size) {
    return bc_kvm_transport_send(((bc_console_client *)user)->links[0],bytes,size);
}
bc_status client_network_open(bc_console_client *s,const char *url,const char *subprotocol,bc_kvm_transport **out) {
    bc_kvm_transport_options options={0}; options.struct_size=sizeof(options); options.abi_version=BC_ABI_VERSION;
    options.url=str(url); options.ca_file=str(s->ca_file); options.cert_policy=s->options.cert_policy;
    options.tls_min=s->options.tls_min; options.tls_max=s->options.tls_max; options.timeout_ms=client_remaining(s);
    if(!options.timeout_ms || client_cancelled(s)) return client_cancelled(s)?BC_CANCELLED:BC_TIMEOUT;
    options.subprotocols=str(subprotocol);
    if(s->irmc) options.flags|=BC_KVM_TRANSPORT_NO_DHE;
    if(s->protocol==BC_CONSOLE_PROTOCOL_IDRAC || s->aten_websocket || s->lenovo_remote[0]) options.flags|=BC_KVM_TRANSPORT_BINARY_ONLY;
    if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC && s->generation!=1)options.flags|=BC_KVM_TRANSPORT_DEFLATE;
    bc_string headers[3]; uint32_t count=0; char *origin=NULL,*cookie=NULL;
    char auth[4112] = {0};
    int websocket=!strncmp(url,"wss:",4)||!strncmp(url,"ws:",3);
    if(websocket && s->origin) {
        size_t n=strlen(s->origin)+9; origin=malloc(n); if(!origin)return BC_NO_MEMORY;
        snprintf(origin,n,"Origin: %s",s->origin); headers[count++]=str(origin);
    }
    if(websocket && s->cookie && s->cookie[0]) {
        size_t n=strlen(s->cookie)+9; cookie=malloc(n); if(!cookie){free(origin);return BC_NO_MEMORY;}
        snprintf(cookie,n,"Cookie: %s",s->cookie); headers[count++]=str(cookie);
    }
    if (websocket && s->lenovo_xcc3) {
        uint32_t length = 0;
        bc_status copied = bc_endpoint_copy_auth_token(s->endpoint, (uint8_t *)auth + 14, sizeof(auth) - 15, &length);
        if (copied != BC_OK || !length) { free(origin); wipe_free(cookie); memset(auth, 0, sizeof(auth)); return copied == BC_OK ? BC_UNSUPPORTED : copied; }
        memcpy(auth, "X-Auth-Token: ", 14); headers[count++] = str(auth);
    }
    options.headers=headers; options.header_count=count;
    bc_status status=s->options.proxy?bc_kvm_transport_connect_proxy(&options,&s->proxy,out):bc_kvm_transport_connect(&options,out);
    if(status==BC_OK && s->protocol==BC_CONSOLE_PROTOCOL_ATEN && s->aten.tls) {
        bc_kvm_tls_options tls={sizeof(tls),BC_ABI_VERSION,s->options.cert_policy,s->options.tls_min,s->options.tls_max,client_remaining(s),0,str(s->ca_file)};
        if (s->aten_peer[0]) status = bc_kvm_transport_start_tls_pinned(*out, &tls, str(s->aten_peer));
        else if (s->aten_identity) status = bc_kvm_transport_start_tls_identity(*out, &tls,
            bc_aten_identity_certificate(s->aten_identity), bc_aten_identity_private_key(s->aten_identity));
        else status = BC_UNSUPPORTED;
        bc_aten_identity_destroy(s->aten_identity);s->aten_identity=NULL;
        if(status!=BC_OK){bc_kvm_transport_destroy(*out);*out=NULL;}
    }
    memset(auth, 0, sizeof(auth));
    free(origin); wipe_free(cookie);
    if(status==BC_OK && client_cancelled(s)) {bc_kvm_transport_destroy(*out);*out=NULL;status=BC_CANCELLED;}
    if(status==BC_OK && bc_kvm_transport_subprotocol(*out)==BC_KVM_TRANSPORT_SUBPROTOCOL_BASE64) {bc_kvm_transport_destroy(*out);*out=NULL;status=BC_UNSUPPORTED;}
    return status;
}
bc_status client_submit(void *user,bc_decode_job *job) {
    bc_console_client *s=user;
    return s->options.submit?s->options.submit(s->options.user,job):BC_UNSUPPORTED;
}
typedef struct { bc_console_client *client; uint32_t channel,control; } feed_job;
static bc_status execute_feed(void *user,const uint8_t *bytes,uint32_t size) {
    feed_job *job=user; bc_console_client *s=job->client;
    bc_status status=job->control?bc_console_session_control(s->console,job->control):bc_console_session_feed(s->console,job->channel,bytes,size);
    if(status==BC_OK) status=collect_output(s,job->channel);
    client_publish_protocol(s); return status;
}
static void release_feed(void *user) {free(user);}
static bc_status submit_feed(bc_console_client *s,uint32_t channel,const uint8_t *bytes,uint32_t size,uint32_t control) {
    feed_job *context=malloc(sizeof(*context)); if(!context)return BC_NO_MEMORY;
    *context=(feed_job){s,channel,control}; bc_decode_job *job=NULL;
    bc_status status=bc_decode_job_create(bytes,size,execute_feed,release_feed,context,&job);
    if(status!=BC_OK){free(context);return status;}
    status=client_submit(s,job); if(status!=BC_OK)bc_decode_job_destroy(job); return status;
}
static bc_status flush_media(bc_console_client *s) {
    uint32_t size=0; uint8_t *bytes=NULL; bc_status status=BC_OK;
    for(;;) {
        status=bc_media_session_output(s->media,NULL,0,&size);
        if(status==BC_BUSY||status==BC_UNSUPPORTED) {status=BC_OK;break;}
        if(status!=BC_LIMIT_EXCEEDED&&status!=BC_OK)break;
        if(status==BC_OK)continue;
        bytes=malloc(size); if(!bytes){status=BC_NO_MEMORY;break;}
        status=bc_media_session_output(s->media,bytes,size,&size);
        if(status==BC_OK)status=bc_kvm_transport_send(s->links[0],bytes,size);
        memset(bytes,0,size);free(bytes);bytes=NULL;if(status!=BC_OK)break;
    }
    return status;
}
static void publish_media(bc_console_client *s) {
    bc_media_session_info info={0};info.struct_size=sizeof(info);
    if(bc_media_session_info_get(s->media,&info)!=BC_OK)return;
    mutex_lock(&s->mutex);
    s->info.flags&=~(BC_CLIENT_SOURCE_ATTACHED|BC_CLIENT_MOUNT_CONFIRMED|BC_CLIENT_REMOVAL_UNCONFIRMED);
    if(info.flags&BC_MEDIA_SOURCE_ATTACHED)s->info.flags|=BC_CLIENT_SOURCE_ATTACHED;
    if(info.flags&BC_MEDIA_MOUNT_CONFIRMED)s->info.flags|=BC_CLIENT_MOUNT_CONFIRMED;
    if(info.flags&BC_MEDIA_REMOVAL_UNCONFIRMED)s->info.flags|=BC_CLIENT_REMOVAL_UNCONFIRMED;
    if(info.flags&BC_MEDIA_BYTES_READ_VALID)s->info.bytes_read=info.bytes_read;
    const bc_service_profile *profile=bc_media_session_profile_get(s->media);if(profile)s->info.profile=*profile;
    const bc_console_failure *failure=bc_media_session_failure_get(s->media);if(failure)s->info.failure=*failure;
    mutex_unlock(&s->mutex);
}
static bc_status pump_media(bc_console_client *s,uint32_t timeout) {
    bc_status status;
    if(s->lenovo_xcc3||s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI||s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC||s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT||s->protocol==BC_CONSOLE_PROTOCOL_ATEN) status=bc_media_session_poll(s->media,timeout);
    else {
        uint32_t size=0;status=bc_kvm_transport_recv(s->links[0],s->input,16u*1024u*1024u,&size,timeout);
        if(status==BC_OK)status=bc_media_session_feed(s->media,(bc_bytes){s->input,size});
        if(status==BC_TIMEOUT)status=BC_OK;
        if(status==BC_OK)status=bc_media_session_tick(s->media,bc_monotonic_ms());
        if(status==BC_OK)status=flush_media(s);
    }
    publish_media(s); return status;
}
static bc_status drain_input(bc_console_client *s) {
    for(;;) {
        mutex_lock(&s->mutex); client_message *message=s->input_head;
        if(message){s->input_head=message->next;if(!s->input_head)s->input_tail=NULL;--s->input_count;}
        mutex_unlock(&s->mutex); if(!message)break;
        bc_console_input input;memcpy(&input,message->data,sizeof(input));free(message);
        bc_status status=bc_console_session_input(s->console,&input);if(status!=BC_OK)return status;
        if(input.type==BC_CONSOLE_INPUT_KEY){
            uint32_t i=0;while(i<s->pressed_count&&s->pressed[i]!=input.keysym)++i;
            if(input.down&&i==s->pressed_count&&s->pressed_count<256)s->pressed[s->pressed_count++]=input.keysym;
            else if(!input.down&&i<s->pressed_count)s->pressed[i]=s->pressed[--s->pressed_count];
        } else s->pointer=input;
        if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC){status=collect_output(s,0);if(status!=BC_OK)return status;}
    }
    return client_drain(s);
}
bc_status client_pump(bc_console_client *s,uint32_t timeout,int starting) {
    if(!s->closing&&client_cancelled(s))return BC_CANCELLED;
    if(s->media)return pump_media(s,timeout);
    mutex_lock(&s->mutex);uint32_t controls=s->pending_controls;mutex_unlock(&s->mutex);
    if(controls) {
        bc_status result=BC_OK;
        for(uint32_t bit=1;bit<=BC_CONSOLE_CONTROL_SOURCE_DETACH;bit<<=1)if(controls&bit){result=bc_console_session_control(s->console,bit);if(result!=BC_OK)break;}
        if(result==BC_OK)result=collect_output(s,0);
        if(result==BC_OK && s->irmc)result=client_drain(s);
        mutex_lock(&s->mutex);s->pending_controls&=~controls;s->media_status=result;mutex_unlock(&s->mutex);
        if (s->irmc && result != BC_OK) return result;
    }
    mutex_lock(&s->mutex);int offer_needed=s->offer_requested&&!s->offer;mutex_unlock(&s->mutex);
    if(offer_needed){bc_media_offer *offer=NULL;bc_status result=bc_console_session_media_offer(s->console,&offer);if(result==BC_OK){mutex_lock(&s->mutex);s->offer=offer;s->offer_requested=0;mutex_unlock(&s->mutex);}}
    bc_status status=drain_input(s);if(status!=BC_OK)return status;
    if(s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI)status=bc_console_session_poll(s->console,timeout);
    else for(uint32_t channel=0;channel<s->channels;++channel) {
        uint32_t size=0;status=bc_kvm_transport_recv(s->links[channel],s->input,16u*1024u*1024u,&size,channel?0:timeout);
        if(status==BC_TIMEOUT){status=BC_OK;continue;}if(status!=BC_OK)break;
        if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC) {
            uint32_t offset=0;
            while(offset<size&&status==BC_OK){uint32_t used=0;status=bc_console_session_feed_some(s->console,0,s->input+offset,size-offset,&used);if(status==BC_OK&&!used)status=BC_PROTOCOL_ERROR;offset+=used;}
        } else if(starting) {status=bc_console_session_feed(s->console,channel,s->input,size);if(status==BC_OK)status=collect_output(s,channel);}
        else status=submit_feed(s,channel,s->input,size,0);
        if(status!=BC_OK)break;
    }
    if(status!=BC_OK&&status!=BC_TIMEOUT)return status;
    uint64_t now=bc_monotonic_ms();
    if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC){status=bc_console_session_tick(s->console,now);if(status==BC_OK)status=collect_output(s,0);}
    if(!starting && now-s->heartbeat>=(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC&&s->mega.single_port?10000u:20000u) && (bc_console_session_controls(s->console)&BC_CONSOLE_CONTROL_HEARTBEAT)) {
        s->heartbeat=now;
        if(s->protocol==BC_CONSOLE_PROTOCOL_IDRAC || s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT)status=submit_feed(s,0,NULL,0,BC_CONSOLE_CONTROL_HEARTBEAT);
        else {status=bc_console_session_control(s->console,BC_CONSOLE_CONTROL_HEARTBEAT);if(status==BC_OK)status=collect_output(s,0);}
    }
    return status==BC_OK?client_drain(s):status;
}
static bc_status create_console(bc_console_client *s) {
    if(s->protocol==BC_CONSOLE_PROTOCOL_ATEN)return bc_aten_console_create(&s->aten,client_emit,s,&s->console);
    if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC) {
        char address[256]={0};if(bc_kvm_transport_local_address(s->links[0],address,sizeof(address))!=BC_OK)snprintf(address,sizeof(address),"%s",s->host);
        bc_megarac_session_options configuration={0};configuration.struct_size=sizeof(configuration);configuration.kind=s->kind;
        configuration.info=&s->mega;configuration.client_ip=address;configuration.username=s->username;configuration.client_mac="";
        bc_status status=bc_console_launch_from_megarac(&configuration,s->keyboard_mode,&s->launch);if(status!=BC_OK)return status;
    }
    bc_console_options options={0};options.struct_size=sizeof(options);options.abi_version=BC_ABI_VERSION;options.launch=s->launch;
    options.display.struct_size=sizeof(options.display);options.display.abi_version=BC_ABI_VERSION;
    if(s->protocol==BC_CONSOLE_PROTOCOL_ILO||s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT){options.display.max_width=4096;options.display.max_height=4096;}
    options.emit=s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI?network_send:client_emit;
    options.receive=client_receive;options.transport_user=s;options.user=s;options.leds=leds;
    options.submit=client_submit;options.clock=client_clock;options.handshake_timeout_ms=client_remaining(s);options.heartbeat_interval_ms=1000;
    return bc_console_session_create(&options,&s->console);
}
static bc_status bootstrap_media(bc_console_client *s) {
    bc_status status=bc_console_bootstrap_create(s->launch,&s->bootstrap);
    if(status==BC_OK)status=client_network_open(s,s->urls[0],"binary",&s->bootstrap_link);
    while(status==BC_OK&&!s->offer) {
        if(!client_remaining(s)||client_cancelled(s))return client_cancelled(s)?BC_CANCELLED:BC_TIMEOUT;
        uint32_t size=0;status=bc_kvm_transport_recv(s->bootstrap_link,s->input,16u*1024u*1024u,&size,20);
        if(status==BC_TIMEOUT){status=BC_OK;continue;}
        if(status==BC_OK)status=bc_console_bootstrap_feed(s->bootstrap,(bc_bytes){s->input,size});
        uint8_t output[65536];uint32_t count=0;
        if(status==BC_OK)status=bc_console_bootstrap_output(s->bootstrap,output,sizeof(output),&count);
        if(status==BC_OK&&count)status=bc_kvm_transport_send(s->bootstrap_link,output,count);memset(output,0,sizeof(output));
        if(status==BC_OK){status=bc_console_bootstrap_media_offer(s->bootstrap,&s->offer);if(status==BC_BUSY)status=BC_OK;}
    }
    return status;
}
static bc_status avocent_transport(bc_console_client *s) {
    uint8_t nonce[32], data[BC_AVOCENT_APCP_SIZE];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return BC_IO_ERROR;
    bc_status status = bc_avocent_apcp_request(BC_AVOCENT_MEDIA, BC_AVOCENT_TRANSPORT_TLS, nonce, data);
    memset(nonce, 0, sizeof(nonce));
    if (status == BC_OK) status = network_send(s, data, sizeof(data));
    uint32_t used = 0;
    while (status == BC_OK && used < sizeof(data)) {
        if (client_cancelled(s)) return BC_CANCELLED;
        uint32_t received = 0, budget = client_remaining(s);
        if (!budget) return BC_TIMEOUT;
        status = client_receive(s, data + used, sizeof(data) - used, &received, budget < 50 ? budget : 50);
        if (status == BC_TIMEOUT) { status = BC_OK; continue; }
        if (status == BC_OK && (!received || received > sizeof(data) - used)) status = BC_PROTOCOL_ERROR;
        used += received;
    }
    bc_avocent_setup setup = {0};
    if (status == BC_OK) status = bc_avocent_apcp_parse(data, sizeof(data), &setup);
    if (status == BC_OK && (setup.major || setup.minor || setup.port ||
        setup.transports != BC_AVOCENT_TRANSPORT_TLS)) status = BC_UNSUPPORTED;
    bc_kvm_tls_options tls = {sizeof(tls), BC_ABI_VERSION, s->options.cert_policy,
        s->options.tls_min, s->options.tls_max, client_remaining(s), 0, str(s->ca_file)};
    if (status == BC_OK) status = bc_kvm_transport_start_tls(s->links[0], &tls);
    return status;
}
static bc_status media_start(bc_console_client *s) {
    bc_status status=BC_OK;
    if(s->protocol==BC_CONSOLE_PROTOCOL_IDRAC)status=bootstrap_media(s);
    if (s->protocol == BC_CONSOLE_PROTOCOL_ATEN && s->aten_websocket)
        status = client_supermicro_html5_media_prepare(s);
    const char *url=s->protocol==BC_CONSOLE_PROTOCOL_IDRAC?s->media_url:s->urls[0];
    int binary=s->protocol==BC_CONSOLE_PROTOCOL_IDRAC || s->aten_websocket ||
        (s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC && s->generation==1 &&
         (s->media_parameters.flags&BC_MEGARAC_MEDIA_WEBSOCKET));
    if(status==BC_OK)status=client_network_open(s,url,s->lenovo_remote[0]&&!s->lenovo_xcc3?"lws-dvc-protocol":binary?"binary":"",&s->links[0]);
    if(status==BC_OK && s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT && !s->lenovo_remote[0])status=avocent_transport(s);
    if(status==BC_OK && s->irmc)status=client_irmc_media_tunnel(s);
    bc_media_options options={0};options.struct_size=sizeof(options);options.abi_version=BC_ABI_VERSION;
    options.offer=s->offer;options.source=s->protocol==BC_CONSOLE_PROTOCOL_IDRAC?NULL:&s->source;
    options.timeout_ms=client_remaining(s);options.heartbeat_interval_ms=1000;options.user=s;options.clock=client_clock;
    if(s->lenovo_xcc3||s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC||s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI||s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT||s->protocol==BC_CONSOLE_PROTOCOL_ATEN){options.emit=network_send;options.receive=client_receive;}
    if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC && (s->media_parameters.flags&BC_MEGARAC_MEDIA_WEBSOCKET))options.flags=BC_MEDIA_TRANSPORT_WEBSOCKET;
    if(s->lenovo_remote[0])options.flags=BC_MEDIA_TRANSPORT_WEBSOCKET;
    if(s->irmc)options.flags=BC_MEDIA_TRANSPORT_JVIEWER_TUNNEL;
    if(status==BC_OK)status=bc_media_session_create(&options,&s->media);
    if(status==BC_OK)status=bc_media_session_control(s->media,BC_MEDIA_CONTROL_START);
    if(status==BC_OK)status=flush_media(s);
    if(s->protocol==BC_CONSOLE_PROTOCOL_IDRAC) {
        bc_media_session_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_CONNECTED)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}
        if(status==BC_OK)status=bc_media_session_attach(s->media,&s->source);
        if(status==BC_OK)status=flush_media(s);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_MOUNT_CONFIRMED)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}
    } else if(s->protocol==BC_CONSOLE_PROTOCOL_ILO) {
        bc_media_session_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_CONNECTED)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}
        if(status==BC_OK)status=client_media_readback(s,1);
    } else if (s->lenovo_xcc3) {
        bc_media_session_info info = {0}; info.struct_size = sizeof(info);
        while (status == BC_OK) {
            bc_media_session_info_get(s->media, &info);
            if (info.flags & BC_MEDIA_CONNECTED) break;
            if (client_cancelled(s)) { status = BC_CANCELLED; break; }
            if (!client_remaining(s)) { status = BC_TIMEOUT; break; }
            status = pump_media(s, 20);
        }
        if (status == BC_OK) status = client_media_readback(s, 1);
    } else if(s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT||s->protocol==BC_CONSOLE_PROTOCOL_ATEN) {
        bc_media_session_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_MOUNT_CONFIRMED)break;
            if(client_cancelled(s)){status=BC_CANCELLED;break;}if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}
    } else if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC) {
        bc_media_session_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_CONNECTED)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}
    }
    publish_media(s);return status;
}
bc_status bc_console_client_create(const bc_console_client_options *options,bc_console_client **out) {
    if(!out)return BC_INVALID_ARGUMENT;*out=NULL;
    if(!options||options->struct_size!=sizeof(*options)||options->abi_version!=BC_ABI_VERSION||
        options->service<BC_CLIENT_CONSOLE||options->service>BC_CLIENT_PREPARE_MEDIA||options->timeout_ms>INT32_MAX||
        (options->service==BC_CLIENT_CONSOLE&&!options->submit)||
        (options->service==BC_CLIENT_MEDIA&&(!options->source||options->source->struct_size!=sizeof(bc_media_source)||!options->source->read)))return BC_INVALID_ARGUMENT;
    bc_console_client *s=calloc(1,sizeof(*s));if(!s)return BC_NO_MEMORY;mutex_init(&s->mutex);
    s->options=*options;s->options.timeout_ms=options->timeout_ms?options->timeout_ms:60000;
    s->address=client_copy(options->address,8192);s->username=client_copy(options->username,1024);
    s->password=client_copy(options->password,1024);s->ca_file=client_copy(options->ca_file,8192);
    s->input=malloc(16u*1024u*1024u);s->info.struct_size=sizeof(s->info);s->published=s->info;
    if(options->source)s->source=*options->source;
    if(options->proxy){s->proxy=*options->proxy;s->proxy_host=client_copy(options->proxy->host,255);s->proxy_user=client_copy(options->proxy->username,255);s->proxy_password=client_copy(options->proxy->password,255);s->proxy.host=str(s->proxy_host);s->proxy.username=str(s->proxy_user);s->proxy.password=str(s->proxy_password);}
    if(!s->address||!s->username||!s->password||!s->ca_file||!s->input||
        (options->proxy&&(!s->proxy_host||!s->proxy_user||!s->proxy_password))){bc_console_client_destroy(s);return BC_NO_MEMORY;}
    s->options.address=str(s->address);s->options.username=str(s->username);s->options.password=str(s->password);s->options.ca_file=str(s->ca_file);
    s->options.proxy=options->proxy?&s->proxy:NULL;s->options.source=options->source?&s->source:NULL;
    *out=s;return BC_OK;
}
bc_status bc_console_client_start(bc_console_client *s) {
    if(!s||s->info.state!=BC_CLIENT_CREATED)return BC_INVALID_ARGUMENT;
    s->deadline=bc_monotonic_ms()+s->options.timeout_ms;s->info.state=BC_CLIENT_OPENING;
    bc_status status=s->parent?client_parent_media_start(s):client_http_open(s);
    if(status==BC_OK&&!s->parent) {
        uint32_t service=s->options.service;
        if(service==BC_CLIENT_PREPARE_MEDIA)s->options.service=BC_CLIENT_MEDIA;
        status=client_startup(s);s->options.service=service;
        if(status==BC_OK&&service==BC_CLIENT_PREPARE_MEDIA) {
            if((s->lenovo_xcc3 && s->offer) || s->protocol==BC_CONSOLE_PROTOCOL_IDRAC || (s->offer&&(s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT||s->protocol==BC_CONSOLE_PROTOCOL_ATEN||s->protocol==BC_CONSOLE_PROTOCOL_ILO||s->protocol==BC_CONSOLE_PROTOCOL_IDRAC)))s->info.flags|=BC_CLIENT_LOCAL_MEDIA;
            else status=BC_UNSUPPORTED;
        }
    }
    if(status==BC_OK&&s->options.service==BC_CLIENT_MEDIA) {
        if(!s->parent&&!s->lenovo_xcc3&&s->protocol!=BC_CONSOLE_PROTOCOL_IDRAC&&s->protocol!=BC_CONSOLE_PROTOCOL_ILO&&s->protocol!=BC_CONSOLE_PROTOCOL_AVOCENT&&s->protocol!=BC_CONSOLE_PROTOCOL_ATEN)status=BC_UNSUPPORTED;
        if(status==BC_OK&&s->protocol==BC_CONSOLE_PROTOCOL_ILO)status=client_media_readback(s,-1);
        if(status==BC_OK)status=media_start(s);
        if(status==BC_OK)status=client_parent_media_attached(s);
    } else if(status==BC_OK && s->options.service==BC_CLIENT_CONSOLE) {
        for(uint32_t i=0;i<s->channels&&status==BC_OK;++i)status=client_network_open(s,s->urls[i],s->lenovo_remote[0]&&!s->lenovo_xcc3?"lws-dvc-protocol":s->protocol==BC_CONSOLE_PROTOCOL_IDRAC||s->aten_websocket||
            (s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC&&(s->kind==BC_MEGARAC_KVM_H5VIEWER||s->kind==BC_MEGARAC_KVM_H5VIEWER_373))?"binary":"",&s->links[i]);
        if(status==BC_OK)status=create_console(s);
        if(status==BC_OK&&(bc_console_session_controls(s->console)&BC_CONSOLE_CONTROL_START))status=bc_console_session_control(s->console,BC_CONSOLE_CONTROL_START);
        if(status==BC_OK&&(s->protocol==BC_CONSOLE_PROTOCOL_ILO||s->protocol==BC_CONSOLE_PROTOCOL_AVOCENT)){for(uint32_t i=0;i<s->channels&&status==BC_OK;++i)status=collect_output(s,i);}
        if(status==BC_OK)status=client_drain(s);
        bc_console_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_console_session_info_get(s->console,&info);if(info.flags&BC_CONSOLE_INFO_READY)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=client_pump(s,20,1);}
        if(status==BC_OK&&s->protocol==BC_CONSOLE_PROTOCOL_ILO){status=bc_console_session_control(s->console,BC_CONSOLE_CONTROL_REFRESH);if(status==BC_OK)status=collect_output(s,0);if(status==BC_OK)status=client_drain(s);}
        if(status==BC_OK){if(s->lenovo_xcc3)s->info.profile.evidence|=BC_SERVICE_EVIDENCE_HANDSHAKE;client_publish_protocol(s);if(bc_console_session_input_capabilities(s->console)&BC_CONSOLE_INPUT_HAS_SCROLL)s->info.flags|=BC_CLIENT_SCROLL;
            if(s->protocol==BC_CONSOLE_PROTOCOL_HUAWEI||s->protocol==BC_CONSOLE_PROTOCOL_IDRAC||s->protocol==BC_CONSOLE_PROTOCOL_ILO||(s->irmc&&s->media_parameters.devices)||bc_megarac_media_parameters_transport_usable(&s->media_parameters))s->info.flags|=BC_CLIENT_LOCAL_MEDIA;}
    }
    mutex_lock(&s->mutex);s->info.status=status;s->info.state=status==BC_OK?BC_CLIENT_ACTIVE:BC_CLIENT_FAILED;s->published=s->info;mutex_unlock(&s->mutex);
    if(status!=BC_OK && s->info.failure.status!=status) {
        mutex_lock(&s->mutex);s->info.failure=(bc_console_failure){sizeof(bc_console_failure),status,s->console?BC_CONSOLE_PHASE_TRANSPORT:BC_CONSOLE_PHASE_LAUNCH,
            BC_CONSOLE_CAUSE_UNKNOWN,s->info.profile.variant,0,0,s->options.service==BC_CLIENT_MEDIA?BC_SERVICE_LOCAL_MEDIA:BC_SERVICE_KVM,s->info.profile.family};s->published=s->info;mutex_unlock(&s->mutex);
    }
    s->heartbeat=bc_monotonic_ms();return status;
}
bc_status bc_console_client_mode(const bc_console_client_options *options,
    uint32_t expected, uint32_t target, bc_console_mode_info *info) {
    if (!info || info->struct_size != sizeof(*info) || !options || options->struct_size != sizeof(*options) ||
        options->abi_version != BC_ABI_VERSION || target > BC_CONSOLE_MODE_JAVA ||
        (target && (!expected || expected > BC_CONSOLE_MODE_JAVA))) return BC_INVALID_ARGUMENT;
    info->current = info->supported_modes = 0;
    bc_console_client_options login = *options;
    login.service = BC_CLIENT_PREPARE;
    login.source = NULL;
    bc_console_client *s = NULL;
    bc_status status = bc_console_client_create(&login, &s);
    if (status != BC_OK) return status;
    s->deadline = bc_monotonic_ms() + s->options.timeout_ms;
    status = client_http_open(s);
    uint32_t kind = 0;
    if (status == BC_OK) status = client_web_login(s, &kind);
    if (status == BC_OK)
        status = kind == BC_WEB_LOGIN_ATEN_CGI ? client_supermicro_mode(s, expected, target, info) : BC_UNSUPPORTED;
    bc_console_client_destroy(s);
    return status;
}
uint32_t bc_console_client_recommended_mode(const bc_console_failure *failure) {
    if (!failure || failure->struct_size != sizeof(*failure)) return 0;
    if (failure->cause == BC_CONSOLE_CAUSE_LICENSE_REQUIRED && failure->service == BC_SERVICE_LOCAL_MEDIA &&
        failure->family == BC_SERVICE_FAMILY_ATEN && failure->profile == BC_SERVICE_ATEN_MEDIA_HTML5)
        return BC_CONSOLE_MODE_JAVA;
    return 0;
}
bc_status bc_console_client_poll(bc_console_client *s,uint32_t timeout) {
    if(!s||s->closed)return BC_SHUTTING_DOWN;
    bc_status status=client_pump(s,timeout>20?20:timeout,0);
    if(status!=BC_OK&&status!=BC_TIMEOUT){mutex_lock(&s->mutex);s->info.status=status;s->info.state=BC_CLIENT_FAILED;s->published=s->info;mutex_unlock(&s->mutex);}
    mutex_lock(&s->mutex);s->published=s->info;mutex_unlock(&s->mutex);
    return status;
}
bc_status bc_console_client_input(bc_console_client *s,const bc_console_input *input) {
    if(!s||!input||input->struct_size!=sizeof(*input))return BC_INVALID_ARGUMENT;
    client_message *m=malloc(sizeof(*m)+sizeof(*input));if(!m)return BC_NO_MEMORY;
    m->next=NULL;m->size=sizeof(*input);memcpy(m->data,input,sizeof(*input));
    mutex_lock(&s->mutex);
    if(s->published.state!=BC_CLIENT_ACTIVE||s->input_count>=CLIENT_MESSAGES){mutex_unlock(&s->mutex);free(m);return BC_BUSY;}
    if(s->input_tail)s->input_tail->next=m;else s->input_head=m;s->input_tail=m;++s->input_count;
    mutex_unlock(&s->mutex);return BC_OK;
}
bc_status bc_console_client_chord(bc_console_client *s,const uint32_t *keys,uint32_t count) {
    if(!s||!keys||!count||count>8)return BC_INVALID_ARGUMENT;
    client_message *head=NULL,*tail=NULL;
    for(uint32_t i=0;i<count*2;++i){
        client_message *m=calloc(1,sizeof(*m)+sizeof(bc_console_input));
        if(!m){while(head){client_message *next=head->next;free(head);head=next;}return BC_NO_MEMORY;}
        bc_console_input input={0};input.struct_size=sizeof(input);input.type=BC_CONSOLE_INPUT_KEY;
        input.keysym=i<count?keys[i]:keys[count*2-1-i];input.down=i<count;
        memcpy(m->data,&input,sizeof(input));m->size=sizeof(input);
        if(tail)tail->next=m;else head=m;tail=m;
    }
    mutex_lock(&s->mutex);
    if(s->published.state!=BC_CLIENT_ACTIVE||count*2>CLIENT_MESSAGES-s->input_count){mutex_unlock(&s->mutex);while(head){client_message *next=head->next;free(head);head=next;}return BC_BUSY;}
    if(s->input_tail)s->input_tail->next=head;else s->input_head=head;s->input_tail=tail;s->input_count+=count*2;
    mutex_unlock(&s->mutex);return BC_OK;
}
bc_status bc_console_client_tile(bc_console_client *s,bc_display_tile *tile) {return s&&s->console?bc_console_session_tile(s->console,tile):BC_BUSY;}
void bc_console_client_ack_display(bc_console_client *s){if(s&&s->console)bc_console_session_ack_display(s->console);}
bc_status bc_console_client_info_get(const bc_console_client *s,bc_console_client_info *info) {
    if(!s||!info||info->struct_size!=sizeof(*info))return BC_INVALID_ARGUMENT;
    mutex_lock((client_mutex *)&s->mutex);*info=s->published;mutex_unlock((client_mutex *)&s->mutex);return BC_OK;
}
bc_status bc_console_client_eject(bc_console_client *s) {
    if(!s||!s->media)return BC_UNSUPPORTED;
    uint64_t saved=s->deadline;s->deadline=bc_monotonic_ms()+15000;s->closing=1;
    bc_status status=bc_media_session_control(s->media,BC_MEDIA_CONTROL_EJECT);
    if(status==BC_OK)status=flush_media(s);
    if(status==BC_OK&&(s->protocol==BC_CONSOLE_PROTOCOL_ILO||s->lenovo_xcc3)){bc_kvm_transport_destroy(s->links[0]);s->links[0]=NULL;status=client_media_readback(s,0);}
    else if(status==BC_OK&&s->protocol==BC_CONSOLE_PROTOCOL_IDRAC){bc_media_session_info info={0};info.struct_size=sizeof(info);
        while(status==BC_OK){bc_media_session_info_get(s->media,&info);if(info.flags&BC_MEDIA_REMOVAL_CONFIRMED)break;if(!client_remaining(s)){status=BC_TIMEOUT;break;}status=pump_media(s,20);}}
    if (s->irmc_media_announced) {
        bc_kvm_transport_destroy(s->links[0]); s->links[0] = NULL;
        bc_status detach = client_irmc_media_detach(s);
        if (status == BC_OK) status = detach;
    }
    publish_media(s);s->deadline=saved;s->closing=0;mutex_lock(&s->mutex);s->published=s->info;mutex_unlock(&s->mutex);return status;
}
bc_status bc_console_client_close(bc_console_client *s) {
    if(!s)return BC_INVALID_ARGUMENT;if(s->closed)return s->info.cleanup_status;
    mutex_lock(&s->mutex);if(s->media_children){mutex_unlock(&s->mutex);return BC_BUSY;}s->closing=1;mutex_unlock(&s->mutex);
    bc_status cleanup=s->info.cleanup_status;
    if(s->media){bc_status status=bc_media_session_control(s->media,BC_MEDIA_CONTROL_CLOSE);if(status==BC_OK)status=flush_media(s);if(status!=BC_OK)cleanup=status;publish_media(s);}
    if(s->console){
        bc_console_input input={0};input.struct_size=sizeof(input);input.type=BC_CONSOLE_INPUT_KEY;
        while(s->pressed_count){input.keysym=s->pressed[--s->pressed_count];bc_console_session_input(s->console,&input);}
        if(s->pointer.width&&s->pointer.height){s->pointer.type=BC_CONSOLE_INPUT_POINTER;s->pointer.buttons=0;s->pointer.wheel=0;bc_console_session_input(s->console,&s->pointer);}
        if(s->protocol==BC_CONSOLE_PROTOCOL_MEGARAC)collect_output(s,0);
        client_drain(s);
        uint32_t controls=bc_console_session_controls(s->console);if(controls&BC_CONSOLE_CONTROL_CLOSE){bc_status status=bc_console_session_control(s->console,BC_CONSOLE_CONTROL_CLOSE);if(status==BC_OK)status=collect_output(s,0);if(status==BC_OK)status=client_drain(s);if(status!=BC_OK)cleanup=status;}}
    if(s->bootstrap){uint8_t bytes[65536];uint32_t size=0;bc_console_bootstrap_output(s->bootstrap,bytes,sizeof(bytes),&size);bc_status status=bc_console_bootstrap_close(s->bootstrap);if(status==BC_OK)status=bc_console_bootstrap_output(s->bootstrap,bytes,sizeof(bytes),&size);if(status==BC_OK&&size)status=bc_kvm_transport_send(s->bootstrap_link,bytes,size);memset(bytes,0,sizeof(bytes));if(status!=BC_OK)cleanup=status;}
    for(uint32_t i=0;i<2;++i){bc_kvm_transport_destroy(s->links[i]);s->links[i]=NULL;}
    bc_kvm_transport_destroy(s->bootstrap_link);s->bootstrap_link=NULL;
    if(s->media&&(s->protocol==BC_CONSOLE_PROTOCOL_ILO||s->lenovo_xcc3)&&s->media_uri[0]){uint64_t saved=s->deadline;s->deadline=bc_monotonic_ms()+(s->lenovo_xcc3?15000u:3000u);bc_status status=client_media_readback(s,0);s->deadline=saved;if(status!=BC_OK)cleanup=status;publish_media(s);}
    if (s->irmc_media_announced) {
        uint64_t saved = s->deadline; s->deadline = bc_monotonic_ms() + 1000;
        bc_status status = client_irmc_media_detach(s);
        if (status != BC_OK) cleanup = status;
        s->deadline = saved;
    }
    client_parent_media_close(s);
    if(s->context){bc_status status=client_http_close(s);if(status!=BC_OK)cleanup=status;}
    mutex_lock(&s->mutex);s->closed=1;s->info.state=BC_CLIENT_CLOSED;s->info.cleanup_status=cleanup;s->published=s->info;mutex_unlock(&s->mutex);return cleanup;
}
void bc_console_client_destroy(bc_console_client *s) {
    if(!s)return;if(bc_console_client_close(s)==BC_BUSY)return;
    bc_console_session_destroy(s->console);bc_media_session_destroy(s->media);bc_console_bootstrap_destroy(s->bootstrap);
    bc_console_launch_destroy(s->launch);bc_media_offer_destroy(s->offer);
    bc_request_release(s->login);bc_megarac_probe_release(s->probe);bc_web_session_release(s->web);
    bc_endpoint_release(s->public_endpoint);
    if(s->context){bc_context_shutdown(s->context);for(int i=0;i<16;++i)bc_context_poll(s->context,0);bc_context_destroy(s->context);}
    if(s->http)bc_curl_transport_destroy(s->http);
    client_message *m=s->output_head;while(m){client_message *next=m->next;memset(m->data,0,m->size);free(m);m=next;}
    m=s->input_head;while(m){client_message *next=m->next;free(m);m=next;}
    if(s->diagnostic_startup){memset(s->diagnostic_startup,0,s->diagnostic_startup_size);free(s->diagnostic_startup);}
    if(s->diagnostic_archive){memset(s->diagnostic_archive,0,s->diagnostic_archive_size);free(s->diagnostic_archive);}
    bc_aten_identity_destroy(s->aten_identity);
    wipe_free(s->address);wipe_free(s->username);wipe_free(s->password);wipe_free(s->ca_file);wipe_free(s->proxy_host);wipe_free(s->proxy_user);wipe_free(s->proxy_password);
    wipe_free(s->host);wipe_free(s->origin);wipe_free(s->cookie);wipe_free(s->urls[0]);wipe_free(s->urls[1]);wipe_free(s->media_url);free(s->input);mutex_destroy(&s->mutex);free(s);
}

bc_bytes bc_console_client_asset(const bc_console_client *s,uint32_t kind) {
    if(!s)return(bc_bytes){NULL,0};
    if(kind==BC_CLIENT_ASSET_STARTUP)return(bc_bytes){s->diagnostic_startup,s->diagnostic_startup_size};
    if(kind==BC_CLIENT_ASSET_ARCHIVE)return(bc_bytes){s->diagnostic_archive,s->diagnostic_archive_size};
    return(bc_bytes){NULL,0};
}
