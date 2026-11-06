#include "bcontrol/web_login.h"
#include "bcontrol/transport.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static const char script[] =
    "function submitLogin(){"
    "var user=$(\"#login_username\").val();var pass=$(\"#login_password\").val();"
    "var request=xmit.getset({url:\"/rpc/WEBSES/create.asp\",onrcv:finished,status:'',timeout:60});"
    "request.add('WEBVAR_USERNAME',user);request.add('WEBVAR_PASSWORD',pass);"
    "var client='';for(i=0;i<8;i++){client+=Math.floor(Math.random()*9);}"
    "request.add('WEBVAR_IPADDR',client);"
    "if(https){request.add('WEBVAR_TYPE','Https');}else{request.add('WEBVAR_TYPE','Http');}"
    "request.send();}function finished(arg){return arg;}";
static const char html[] = "<html><script src='../js/login.js' type='text/javascript'></script>"
    "<input type=text id=login_username><input type=password id=login_password></html>";
static bc_string text(const char *s) { return (bc_string){s, strlen(s)}; }
static bc_status parse(const char *s, bc_web_login_hint *out) {
    return bc_web_login_script_hint((const uint8_t *)s, (uint32_t)strlen(s), out);
}
static void pure_parser(void) {
    bc_web_login_hint hint;
    assert(parse(script, &hint) == BC_OK);
    assert(hint.kind == BC_WEB_LOGIN_LEGACY_RPC && hint.flags == 3);
    assert(!strcmp(hint.path, "/rpc/WEBSES/create.asp"));
    assert(!strcmp(hint.username_input, "login_username") && !strcmp(hint.password_input, "login_password"));
    const char *bad[] = {
        "// xmit.getset({url:'/rpc/WEBSES/create.asp'});",
        "var fake=\"request.add('WEBVAR_USERNAME',user);\";",
        "function wrong(){var r=xmit.getset({url:'/api/session',onrcv:done});r.send();}",
        "/* unterminated", "function broken(){", "function template(){return `dynamic`;}",
        "function escaped(){var r=xmit.getset({url:'/rpc/WEBSES/\\x63reate.asp',onrcv:done});r.send();}"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        assert(parse(bad[i], &hint) != BC_OK && !hint.kind && !hint.path[0]);
    }
    const char *from[] = {"request.send();", "request.add('WEBVAR_PASSWORD',pass);", "onrcv:finished", "request.add('WEBVAR_USERNAME',user);", "var request=", "var request=", "function finished(arg)"};
    const char *to[] = {"request.clear();request.send();", "request.add('WEBVAR_PASSWORD',hash(pass));", "onrcv:buildCallback()", "request.add('WEBVAR_USERNAME',user);user='changed';", "leak(user);var request=", "var request_alias=", "function missing(arg)"};
    for (unsigned i = 0; i < sizeof(from) / sizeof(from[0]); ++i) {
        char changed[4096]; const char *at = strstr(script, from[i]); assert(at);
        snprintf(changed, sizeof(changed), "%.*s%s%s", (int)(at - script), script, to[i], at + strlen(from[i]));
        assert(parse(changed, &hint) != BC_OK && !hint.kind);
    }
    char duplicate[4096]; snprintf(duplicate, sizeof(duplicate), "%s%s", script, script);
    assert(parse(duplicate, &hint) == BC_UNSUPPORTED && !hint.kind);
    for (uint32_t i = 0; i < sizeof(script) - 1; ++i) {
        assert(bc_web_login_script_hint((const uint8_t *)script, i, &hint) != BC_OK && !hint.kind);
    }
    assert(bc_web_login_script_hint(NULL, 1, &hint) == BC_INVALID_ARGUMENT);
    assert(bc_web_login_script_hint((const uint8_t *)script, 262145, &hint) == BC_LIMIT_EXCEEDED);
}
static const char xmit[] =
    "var DUMMY_SERVER=false;"
    "xmit.getset=function(options){var request=new xmit.goajax(options);return request;}"
    "xmit.goajax=function(options){var target=xmit.returnpath(options.url);this.url=target;this.data='';"
    "this.add=function(key,value){this.data=(this.data==''?(key+'='+xmit.encodespecial(value)):this.data+'&'+key+'='+xmit.encodespecial(value));};"
    "this.send=function(){if(((this.url+this.data).length>512)||(/[^a-zA-Z0-9_]/.exec(this.data)!=null)){"
    "this.method='POST';this.postdata=this.data;}else{this.method='GET';this.postdata=null;}"
    "this.xmldoc.open(this.method,this.url,this.async,this.username,this.password);"
    "if(this.method=='POST'){this.xmldoc.setRequestHeader('Content-type','application/x-www-form-urlencoded');}"
    "this.xmldoc.send(this.postdata);};}"
    "xmit.returnpath=function(target){if(DUMMY_SERVER==true){target='../dummy'+target;}return target;}"
    "xmit.encodespecial=function(value){if(typeof(value)=='string'){value=value.replace(/%/g,'%25');"
    "value=value.replace(/\\+/g,'%2B').replace(/&/g,'%26').replace(/#/g,'%23');}return value;}";
static void transport_parser(void) {
    uint32_t transport = 9;
    assert(bc_web_login_xmit_form_hint((const uint8_t *)xmit, strlen(xmit), &transport) == BC_OK);
    assert(transport == BC_WEB_LOGIN_XMIT_FORM_POST);
    const char *from[] = {"DUMMY_SERVER=false", "this.postdata=this.data", "this.method='POST'", "request=new xmit.goajax(options)",
        "this.data+'&'+key", "'%25'", "'%2B'", "/[^a-zA-Z0-9_]/", "this.xmldoc.send(this.postdata)", "application/x-www-form-urlencoded"};
    const char *to[] = {"DUMMY_SERVER=true", "this.postdata=this.get", "this.method='GET'", "request=new Other(options)",
        "this.data+'?'+key", "'%26'", "'%20'", "/[^0-z_]/", "this.xmldoc.send(other)", "application/json"};
    for (unsigned i = 0; i < sizeof(from) / sizeof(from[0]); ++i) {
        char changed[4096]; const char *at = strstr(xmit, from[i]); assert(at);
        snprintf(changed, sizeof(changed), "%.*s%s%s", (int)(at - xmit), xmit, to[i], at + strlen(from[i]));
        assert(bc_web_login_xmit_form_hint((const uint8_t *)changed, strlen(changed), &transport) != BC_OK && !transport);
    }
    for (uint32_t i = 0; i < sizeof(xmit) - 1; ++i)
        assert(bc_web_login_xmit_form_hint((const uint8_t *)xmit, i, &transport) != BC_OK && !transport);
    char guarded[4096]; const char *end = strstr(xmit, ";};}"); assert(end);
    snprintf(guarded, sizeof(guarded), "%.*s;};if(parent.gSessionCheck==true){if(!parent.application_checkSessionValid()){"
        "parent.gSessionCheck=false;this.send=parent.application_sessionTimedOut;}}return this;}%s",
        (int)(end - xmit), xmit, end + 4);
    assert(bc_web_login_xmit_form_hint((const uint8_t *)guarded, strlen(guarded), &transport) == BC_OK);
    assert(transport == (BC_WEB_LOGIN_XMIT_FORM_POST | BC_WEB_LOGIN_XMIT_SESSION_GUARD));
}
typedef struct { bc_transport_done done; void *arg; unsigned submits, graph_callbacks, allow_post, method, cookie_sets, owner_callbacks, last_timeout, cancels; uint64_t now; char path[1025], body[4096]; } mock;
static bc_status opened(void *u, const bc_endpoint_options *o, void **out) {
    (void)u; (void)o; *out = malloc(1); return *out ? BC_OK : BC_NO_MEMORY;
}
static void closed(void *u, void *e) { (void)u; free(e); }
static bc_status submitted(void *u, void *e, const bc_http_options *o, uint64_t max,
    bc_transport_done done, void *arg, void **out) {
    (void)e; (void)max; mock *m = u;
    assert(m->allow_post || (o->method == BC_HTTP_GET && !o->body.length));
    m->method = o->method; m->last_timeout = o->timeout_ms; assert(o->body.length < sizeof(m->body));
    if (o->body.length) memcpy(m->body, o->body.data, (size_t)o->body.length);
    m->body[o->body.length] = 0;
    assert(o->path.length < sizeof(m->path)); memcpy(m->path, o->path.data, (size_t)o->path.length); m->path[o->path.length] = 0;
    m->done = done; m->arg = arg; ++m->submits; *out = m; return BC_OK;
}
static bc_status cookie_set(void *user, void *endpoint, bc_string name, bc_string value) {
    (void)endpoint; assert(name.length && value.length); ++((mock *)user)->cookie_sets; return BC_OK;
}
static void cancelled(void *u, void *op) { (void)op; ++((mock *)u)->cancels; }
static bc_status polled(void *u, uint32_t ms) { (void)u; (void)ms; return BC_OK; }
static void completed(bc_request *r, const bc_response *response, void *u) { (void)r; (void)response; (void)u; }
static void unexpected_probe(bc_megarac_probe *p, const bc_megarac_probe_result *r, void *u) {
    (void)p; (void)r; (void)u; assert(0);
}
static bc_endpoint *endpoint_origin(bc_context *c, const char *origin) {
    bc_endpoint_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.flags = BC_ENDPOINT_COOKIE_JAR;
    o.origin = text(origin); o.endpoint_id = text("web"); o.device_id = text("fixture");
    bc_endpoint *e = NULL; assert(bc_endpoint_create(c, &o, &e) == BC_OK); return e;
}
static bc_endpoint *endpoint(bc_context *c) { return endpoint_origin(c,"https://bmc.example"); }
static bc_request *request(mock *m, bc_context *c, bc_endpoint *e, const char *path, const char *body) {
    bc_http_options o = {0}; o.struct_size = sizeof(o); o.abi_version = BC_ABI_VERSION;
    o.path = text(path); o.method = BC_HTTP_GET;
    bc_request *r = NULL; assert(bc_http_submit(e, &o, completed, NULL, &r) == BC_OK);
    if (body) {
        bc_response response = {0}; response.struct_size = sizeof(response); response.status = BC_OK;
        response.http_status = 200; response.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
        m->done(m->arg, &response); assert(bc_context_poll(c, 0) == BC_OK);
    }
    return r;
}
static void source_binding(void) {
    mock m = {0}; bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 262144, 4, 0}; bc_context *c = NULL, *other = NULL;
    assert(bc_context_create(&co, &c) == BC_OK && bc_context_create(&co, &other) == BC_OK);
    bc_endpoint *e = endpoint(c), *foreign = endpoint(other);
    bc_megarac_probe_options credentials = {0}; credentials.struct_size = sizeof(credentials); credentials.abi_version = BC_ABI_VERSION;
    credentials.host = text("bmc.example"); credentials.username = text("fixture"); credentials.password = text("fixture");
    bc_megarac_probe *probe = NULL;
    bc_megarac_login_contract invalid[] = {{0, 1, 0}, {sizeof(bc_megarac_login_contract), 0, 0},
        {sizeof(bc_megarac_login_contract), 1, 8}, {sizeof(bc_megarac_login_contract), 1, BC_MEGARAC_LOGIN_CLIENT_ID},
        {sizeof(bc_megarac_login_contract), BC_MEGARAC_LOGIN_H5_SESSION, 1}};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(bc_megarac_probe_start_with_login(e, &credentials, invalid + i, unexpected_probe, NULL, &probe) == BC_INVALID_ARGUMENT && !probe);
    assert(!m.submits);
    bc_request *page = request(&m, c, e, "/page/login.html", html), *js = request(&m, c, e, "/js/login.js", NULL);
    bc_web_login_evidence *op = NULL;
    assert(bc_web_login_evidence_from_requests(e, 7, page, js, &op) == BC_BUSY && !op);
    bc_response response = {0}; response.struct_size = sizeof(response); response.status = BC_OK; response.http_status = 200;
    response.body = (bc_bytes){(const uint8_t *)script, strlen(script)};
    m.done(m.arg, &response); assert(bc_context_poll(c, 0) == BC_OK);
    assert(bc_web_login_evidence_from_requests(foreign, 7, page, js, &op) == BC_INVALID_ARGUMENT && !op);
    unsigned before = m.submits;
    assert(bc_web_login_evidence_from_requests(e, 7, page, js, &op) == BC_OK && m.submits == before);
    assert(bc_web_login_evidence_hint_get(op, e, 7));
    assert(!bc_web_login_evidence_hint_get(op, foreign, 7) && !bc_web_login_evidence_hint_get(op, e, 8));
    bc_request_release(page); bc_request_release(js);
    bc_web_login_evidence_cancel(op); assert(!bc_web_login_evidence_hint_get(op, e, 7)); bc_web_login_evidence_release(op);
    const char *bad[] = {
        "<script src='https://foreign/js/login.js'></script><input id=login_username type=text><input id=login_password type=password>",
        "<!--<script src='../js/login.js'></script>--><input id=login_username type=text><input id=login_password type=password>",
        "<script src='../js/login.js'></script><input id=login_username type=password><input id=login_password type=password>",
        "<script src='../js/login.js'></script><input id=login_username type=text disabled><input id=login_password type=password>",
        "<base href='https://foreign/'><script src='../js/login.js'></script><input id=login_username type=text><input id=login_password type=password>",
        "<script src='../js/login.js' SRC='../js/login.js'></script><input id=login_username type=text><input id=login_password type=password>",
        "<script src='../js/login.js'></script><input id=login_username type=text><input id=login_password type=password><input id=login_password type=password>"
        ,"<textarea><script src='../js/login.js'></script></textarea><input id=login_username type=text><input id=login_password type=password>"
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        page = request(&m, c, e, "/page/login.html", bad[i]); js = request(&m, c, e, "/js/login.js", script);
        assert(bc_web_login_evidence_from_requests(e, 7, page, js, &op) != BC_OK && !op);
        bc_request_release(page); bc_request_release(js);
    }
    bc_endpoint_release(e); bc_endpoint_release(foreign);
    assert(bc_context_shutdown(c) == BC_OK && bc_context_destroy(c) == BC_OK);
    assert(bc_context_shutdown(other) == BC_OK && bc_context_destroy(other) == BC_OK);
}
static uint64_t now(void *user) { return ((mock *)user)->now; }
static void graph_completed(bc_web_entry_graph *op, void *user) { (void)op; ++((mock *)user)->graph_callbacks; }
static void graph_respond(mock *m, bc_context *c, const char *body, uint32_t http, const char *location) {
    bc_transport_response r = {0}; r.base.struct_size = sizeof(r); r.base.status = http < 400 ? BC_OK : BC_HTTP_ERROR;
    r.base.http_status = http; r.base.body = (bc_bytes){(const uint8_t *)body, strlen(body)};
    r.metadata.struct_size = sizeof(r.metadata); if (location) r.metadata.location = text(location);
    m->done(m->arg, &r.base); assert(bc_context_poll(c, 0) == BC_OK);
}
static bc_web_entry_options graph_options(mock *m) {
    return (bc_web_entry_options){sizeof(bc_web_entry_options), BC_ABI_VERSION, 17, 1000, 16, 6, 1048576, now, m};
}
static void limited_menu(char *out, size_t capacity) {
    size_t used = (size_t)snprintf(out,capacity,"window.open('discarded.html','console');function huge(){");
    for (unsigned i = 0; i < 33; ++i) used += (size_t)snprintf(out+used,capacity-used,"var item%u='x';",i);
    snprintf(out+used,capacity-used,"$('#menu').replaceWith(item0);}");
}
static const char entry[] = "<html><script src='index.js'></script></html>";
static const char navigation[] = "function initialize(){window.frames['topFrame'].location.href='page/login.html';}";
static void graph_walk(void) {
    mock m = {0}; bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, NULL};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 262144, 4, 0}; bc_context *c = NULL, *other = NULL;
    assert(bc_context_create(&co, &c) == BC_OK && bc_context_create(&co, &other) == BC_OK);
    bc_endpoint *e = endpoint(c), *foreign = endpoint(other); bc_web_entry_graph *op = NULL;
    bc_web_entry_options options = graph_options(&m);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    assert(!strcmp(m.path, "/") && !bc_web_entry_result_get(op, e, 17));
    graph_respond(&m, c, entry, 200, NULL); assert(!strcmp(m.path, "/index.js"));
    graph_respond(&m, c, navigation, 200, NULL); assert(!strcmp(m.path, "/page/login.html"));
    graph_respond(&m, c, html, 200, NULL); assert(!strcmp(m.path, "/js/login.js"));
    graph_respond(&m, c, script, 200, NULL);
    const bc_web_entry_result *result = bc_web_entry_result_get(op, e, 17);
    assert(result && result->status == BC_OK && result->hint.kind == BC_WEB_LOGIN_LEGACY_RPC && result->requests == 4);
    assert(!strcmp(result->page_path, "/page/login.html") && !strcmp(result->script_path, "/js/login.js"));
    assert(!bc_web_entry_result_get(op, e, 18) && !bc_web_entry_result_get(op, foreign, 17));
    m.now = 1000; assert(bc_web_entry_result_get(op, e, 17)->status == BC_TIMEOUT && !result->hint.kind);
    m.now = 1; assert(bc_web_entry_result_get(op, e, 17)->status == BC_TIMEOUT);
    assert(m.graph_callbacks == 1); bc_web_entry_release(op);
    for (unsigned reason = 0; reason < 6; ++reason) {
        m.now = 100; options = graph_options(&m); unsigned before = m.graph_callbacks;
        if (reason == 0) options.max_requests = 2;
        if (reason == 1) options.max_depth = 1;
        if (reason == 2) options.max_bytes = strlen(entry) - 1;
        assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
        if (reason == 3) m.now = 1100;
        if (reason == 4) m.now = 99;
        if (reason == 5) {
            assert(bc_web_entry_cancel(op) == BC_OK);
            assert(bc_context_poll(c, 0) == BC_OK);
        } else {
            graph_respond(&m, c, entry, 200, NULL);
            if (reason < 2) graph_respond(&m, c, navigation, 200, NULL);
        }
        result = bc_web_entry_result_get(op, e, 17);
        bc_status expected = reason < 3 ? BC_LIMIT_EXCEEDED : reason == 3 ? BC_TIMEOUT : reason == 4 ? BC_INVALID_ARGUMENT : BC_CANCELLED;
        assert(result && result->status == expected && !result->hint.kind && m.graph_callbacks == before + 1);
        bc_web_entry_limit limit = {0}; limit.struct_size = sizeof(limit); limit.abi_version = BC_ABI_VERSION;
        if (reason < 3) {
            assert(bc_web_entry_limit_get(op,e,17,&limit) == BC_OK);
            assert(limit.reason == (reason == 0 ? BC_WEB_LIMIT_CANDIDATES : reason == 1 ? BC_WEB_LIMIT_DEPTH : BC_WEB_LIMIT_TOTAL_BYTES));
            assert(limit.observed > limit.maximum && limit.requests == result->requests);
            assert(limit.source_index < bc_web_entry_resource_count(op,e,17));
            limit.struct_size = sizeof(limit); limit.abi_version = BC_ABI_VERSION;
            assert(bc_web_entry_limit_get(op,foreign,17,&limit) == BC_INVALID_ARGUMENT && !limit.reason);
        } else assert(bc_web_entry_limit_get(op,e,17,&limit) != BC_OK && !limit.reason);
        bc_web_entry_release(op);
    }
    m.now = 100; options = graph_options(&m);
    assert(bc_web_entry_start(e,&options,graph_completed,&m,&op) == BC_OK);
    graph_respond(&m,c,"<script src='large.js'></script>",200,NULL);
    char *large = malloc(65538); assert(large); memset(large,';',65537); large[65537] = 0;
    graph_respond(&m,c,large,200,NULL); free(large);
    assert(bc_web_entry_result_get(op,e,17)->status == BC_UNSUPPORTED && bc_web_entry_result_get(op,e,17)->unsupported_scripts == 1);
    bc_web_entry_limit parser_limit = {0}; parser_limit.struct_size = sizeof(parser_limit); parser_limit.abi_version = BC_ABI_VERSION;
    assert(bc_web_entry_limit_get(op,e,17,&parser_limit) == BC_OK && parser_limit.reason == BC_WEB_LIMIT_SCRIPT_PARSE);
    assert(parser_limit.observed == 65537 && !parser_limit.maximum && parser_limit.source_index == 1 && parser_limit.requests == 2);
    parser_limit.struct_size = sizeof(parser_limit); parser_limit.abi_version = BC_ABI_VERSION;
    assert(bc_web_entry_limit_get(op,e,18,&parser_limit) == BC_INVALID_ARGUMENT && !parser_limit.reason);
    m.now = 1200; parser_limit.struct_size = sizeof(parser_limit); parser_limit.abi_version = BC_ABI_VERSION;
    assert(bc_web_entry_limit_get(op,e,17,&parser_limit) == BC_TIMEOUT && !parser_limit.reason);
    m.now = 100; parser_limit.struct_size = sizeof(parser_limit); parser_limit.abi_version = BC_ABI_VERSION;
    assert(bc_web_entry_limit_get(op,e,17,&parser_limit) == BC_TIMEOUT && !parser_limit.reason);
    bc_web_entry_release(op);
    m.now = 100; options = graph_options(&m); options.max_depth = 1;
    assert(bc_web_entry_start(e,&options,graph_completed,&m,&op) == BC_OK);
    graph_respond(&m,c,"<iframe src='nested.html'></iframe>",200,NULL);
    graph_respond(&m,c,"<iframe src='/'></iframe>",200,NULL);
    assert(bc_web_entry_result_get(op,e,17)->status == BC_UNSUPPORTED && bc_web_entry_result_get(op,e,17)->requests == 2);
    bc_web_entry_release(op);
    m.now = 0; options = graph_options(&m);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "", 302, "/start.html"); assert(!strcmp(m.path, "/start.html"));
    graph_respond(&m, c, "<html></html>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 2); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, entry, 200, NULL);
    graph_respond(&m, c, "top.topFrame.tabFrame.location='page/login.html';", 200, NULL);
    assert(!strcmp(m.path, "/page/login.html"));
    graph_respond(&m, c, "<html></html>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 3); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, entry, 200, NULL);
    graph_respond(&m, c, "function execute(){window.open('page/launch.html','RemoteConsole','width=600');}", 200, NULL);
    assert(!strcmp(m.path, "/page/launch.html"));
    graph_respond(&m, c, "<html></html>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 3); bc_web_entry_release(op);
    const char *blocked[] = {
        "window.location='https://foreign.example/login.html';", "window.location=dynamic;",
        "window.location='/rpc/WEBSES/logout.asp';", "var fake=\"window.location='/login.html';\";",
        "var location='/login.html';", "window.open(dynamic,'RemoteConsole','width=600');",
        "window.open('/Java/jviewer.jnlp','RemoteConsole','width=600');",
        "window.open('https://foreign.example/page.html','RemoteConsole','width=600');"
    };
    for (unsigned i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
        graph_respond(&m, c, entry, 200, NULL); graph_respond(&m, c, blocked[i], 200, NULL);
        result = bc_web_entry_result_get(op, e, 17);
        assert(result && result->requests == 2 && result->status == BC_UNSUPPORTED && !result->hint.kind);
        bc_web_entry_release(op);
    }
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "<script src='index.js'></script><base href='/changed/'>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 1); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "<script>location='/';</script><iframe src='/'></iframe>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 1); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "", 302, "https://foreign.example/start.html");
    result = bc_web_entry_result_get(op, e, 17);
    assert(result && result->requests == 1 && result->skipped_links == 1); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "<meta http-equiv='refresh' content=\"0; URL='/login.html'\">", 200, NULL);
    assert(!strcmp(m.path, "/login.html")); graph_respond(&m, c, "<html></html>", 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->requests == 2); bc_web_entry_release(op);
    /* The same script is fetched once, but must retain its later HTML owner. */
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "<script src='js/login.js'></script><iframe src='page/login.html'></iframe>", 200, NULL);
    graph_respond(&m, c, script, 200, NULL); graph_respond(&m, c, html, 200, NULL);
    result = bc_web_entry_result_get(op, e, 17);
    assert(result && result->status == BC_OK && result->requests == 3 && result->hint.kind);
    assert(bc_web_entry_cancel(op) == BC_OK && !bc_web_entry_result_get(op, e, 17)->hint.kind); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "<script src='first.js'></script><script src='second.js'></script>"
        "<input type=text id=login_username><input type=password id=login_password>", 200, NULL);
    graph_respond(&m, c, script, 200, NULL);
    graph_respond(&m, c, "function submit(){var u=$('#login_username').val();var p=$('#login_password').val();"
        "var r=xmit.getset({url:'/rpc/WEBSES/create.asp',onrcv:done});"
        "r.add('WEBVAR_USERNAME',u);r.add('WEBVAR_PASSWORD',p);r.send();}function done(arg){return arg;}", 200, NULL);
    result = bc_web_entry_result_get(op, e, 17);
    assert(result && result->status == BC_UNSUPPORTED && !result->hint.kind); bc_web_entry_release(op);
    options.max_bytes = strlen(entry) + strlen(navigation) - 1;
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, entry, 200, NULL); graph_respond(&m, c, navigation, 200, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->status == BC_LIMIT_EXCEEDED); bc_web_entry_release(op);
    options = graph_options(&m);
    const char *library_pages[] = {
        "<script src='lib/xmit.js'></script><script src='js/login.js'></script><input type=text id=login_username><input type=password id=login_password>",
        "<script src='js/login.js'></script><script src='lib/xmit.js'></script><input type=text id=login_username><input type=password id=login_password>",
        "<script src='lib/xmit.js' async></script><script src='js/login.js'></script><input type=text id=login_username><input type=password id=login_password>"
    };
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t transport = 9;
        assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
        graph_respond(&m, c, library_pages[i], 200, NULL);
        graph_respond(&m, c, i == 1 ? script : xmit, 200, NULL);
        graph_respond(&m, c, i == 1 ? xmit : script, 200, NULL);
        assert(bc_web_entry_xmit_form_hint_get(op, e, 17, &transport) == (i ? BC_UNSUPPORTED : BC_OK));
        assert(transport == (i ? 0u : BC_WEB_LOGIN_XMIT_FORM_POST));
        assert(bc_web_entry_xmit_form_hint_get(op, foreign, 17, &transport) == BC_INVALID_ARGUMENT && !transport);
        bc_web_entry_release(op);
    }
    unsigned queued_before = m.graph_callbacks;
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    bc_response queued = {0}; queued.struct_size = sizeof(queued); queued.status = BC_OK; queued.http_status = 200;
    queued.body = (bc_bytes){(const uint8_t *)entry, strlen(entry)};
    m.done(m.arg, &queued); assert(bc_web_entry_cancel(op) == BC_OK);
    assert(bc_context_poll(c, 0) == BC_OK && m.graph_callbacks == queued_before + 1);
    result = bc_web_entry_result_get(op, e, 17);
    assert(result && result->status == BC_CANCELLED && result->requests == 1); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    graph_respond(&m, c, "", 401, NULL);
    assert(bc_web_entry_result_get(op, e, 17)->status == BC_AUTHENTICATION_FAILED); bc_web_entry_release(op);
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK);
    bc_response tls = {0}; tls.struct_size = sizeof(tls); tls.status = BC_TLS_ERROR;
    m.done(m.arg, &tls); assert(bc_context_poll(c, 0) == BC_OK);
    assert(bc_web_entry_result_get(op, e, 17)->status == BC_TLS_ERROR); bc_web_entry_release(op);
    unsigned before = m.graph_callbacks;
    assert(bc_web_entry_start(e, &options, graph_completed, &m, &op) == BC_OK); bc_web_entry_release(op);
    graph_respond(&m, c, "<html></html>", 200, NULL); assert(m.graph_callbacks == before + 1);
    bc_endpoint_release(e); bc_endpoint_release(foreign);
    assert(bc_context_shutdown(c) == BC_OK && bc_context_destroy(c) == BC_OK);
    assert(bc_context_shutdown(other) == BC_OK && bc_context_destroy(other) == BC_OK);
}
static void cookie_parser(void) {
    char name[65];
    const char *good = "var keySessionCookie='SessionCookie';function reset(){removeCookie(keySessionCookie);}";
    assert(bc_web_login_cookie_name_hint((const uint8_t *)good, (uint32_t)strlen(good), name) == BC_OK);
    assert(!strcmp(name, "SessionCookie"));
    const char *bad[] = {"var keySessionCookie=dynamic;", "var keySessionCookie='a';keySessionCookie='b';",
        "function f(){var keySessionCookie='SessionCookie';}", "var keySessionCookie='a';keySessionCookie++;",
        "var keySessionCookie='a b';", "var keySessionCookie='a';top.keySessionCookie='b';"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        assert(bc_web_login_cookie_name_hint((const uint8_t *)bad[i], (uint32_t)strlen(bad[i]), name) != BC_OK);
        assert(!name[0]);
    }
}
static void response_parser(void) {
    const char *source =
        "function submit(){var u=$('#u').val();var p=$('#p').val();"
        "var r=xmit.getset({url:'/rpc/WEBSES/create.asp',onrcv:login});"
        "r.add('WEBVAR_USERNAME',u);r.add('WEBVAR_PASSWORD',p);r.send();}"
        "function login(reply){if(reply.HAPI_STATUS===0){"
        "var key=WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0];"
        "top.gSessionCookie=key.SESSION_COOKIE;"
        "writeCookie(top.keySessionCookie,top.gSessionCookie,false);csrf(top.gSessionCookie);}}"
        "function csrf(session){var rpc=xmit.getset({url:'/rpc/token.asp',onrcv:token,status:'',timeout:60});"
        "rpc.add('SESSION_COOKIE',session);rpc.send();}"
        "function token(reply){if(reply.HAPI_STATUS===0){"
        "var key=WEBVAR_JSONVAR_GETCSRFTOKEN.WEBVAR_STRUCTNAME_GETCSRFTOKEN[0];"
        "top.gCSRFToken=key.CSRFTOKEN;top.topFrame.location='../page/top.html';return true;}}";
    bc_web_login_response_hint h;
    assert(bc_web_login_response_hint_get((const uint8_t *)source, (uint32_t)strlen(source), &h) == BC_OK);
    assert(h.flags == 3 && !strcmp(h.csrf_path, "/rpc/token.asp") && !strcmp(h.landing_relative, "../page/top.html"));
    const char *needles[] = {"key.SESSION_COOKIE", "rpc.add('SESSION_COOKIE',session)",
        "key.CSRFTOKEN", "reply.HAPI_STATUS===0", "top.gSessionCookie,false"};
    for (unsigned i = 0; i < sizeof(needles)/sizeof(*needles); ++i) {
        char changed[4096]; strcpy(changed, source);
        char *p = strstr(changed, needles[i]); assert(p); *p = 'X';
        memset(&h, 0xff, sizeof(h));
        assert(bc_web_login_response_hint_get((const uint8_t *)changed, (uint32_t)strlen(changed), &h) != BC_OK);
        assert(!h.flags && !h.csrf_path[0]);
    }
    for (size_t i = 1; i < strlen(source); ++i) {
        bc_status status = bc_web_login_response_hint_get((const uint8_t *)source, (uint32_t)i, &h);
        assert(status != BC_OK && !h.flags);
    }
}
static const char response_model[] =
    "function finished(reply){if(reply.HAPI_STATUS===0){"
    "var key=WEBVAR_JSONVAR_WEB_SESSION.WEBVAR_STRUCTNAME_WEB_SESSION[0];"
    "top.gSessionCookie=key.SESSION_COOKIE;"
    "writeCookie(top.keySessionCookie,top.gSessionCookie,false);csrf(top.gSessionCookie);}}"
    "function csrf(session){var rpc=xmit.getset({url:'/rpc/getcsrftoken.asp',onrcv:token,status:'',timeout:60});"
    "rpc.add('SESSION_COOKIE',session);rpc.send();}"
    "function token(reply){if(reply.HAPI_STATUS===0){"
    "var key=WEBVAR_JSONVAR_GETCSRFTOKEN.WEBVAR_STRUCTNAME_GETCSRFTOKEN[0];"
    "top.gCSRFToken=key.CSRFTOKEN;top.topFrame.location='../page/top.html';return true;}}";
static bc_web_entry_graph *public_contract(mock *m, bc_context *c, bc_endpoint *e, int cookie) {
    bc_web_entry_graph *graph = NULL; bc_web_entry_options options = graph_options(m);
    assert(bc_web_entry_start(e, &options, graph_completed, m, &graph) == BC_OK);
    graph_respond(m, c, "<script src='index.js'></script><iframe src='page/login.html'></iframe>", 200, NULL);
    graph_respond(m, c, cookie ? "var keySessionCookie='SessionCookie';" : "var unrelated='SessionCookie';", 200, NULL);
    graph_respond(m, c, "<script src='../lib/xmit.js'></script><script src='../js/login.js'></script>"
        "<input type=text id=login_username><input type=password id=login_password>", 200, NULL);
    graph_respond(m, c, xmit, 200, NULL);
    char source[4096]; const char *end = strstr(script, "function finished"); assert(end);
    snprintf(source, sizeof(source), "%.*s%s", (int)(end-script), script, response_model);
    graph_respond(m, c, source, 200, NULL);
    /* The response callback advertises a protected landing page. */
    assert(!strcmp(m->path, "/page/top.html")); graph_respond(m, c, "", 405, NULL);
    return graph;
}
static void owner_completed(bc_web_session *session, void *user) {
    assert(bc_web_session_result_get(session)); ++((mock *)user)->owner_callbacks;
}
static void web_owner(const char *origin, const char *authority) {
    mock m = {0}; m.allow_post = 1;
    bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, cookie_set};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 262144, 4, 0}; bc_context *c = NULL;
    assert(bc_context_create(&co, &c) == BC_OK); bc_endpoint *e = endpoint_origin(c,origin);
    bc_web_entry_graph *graph = public_contract(&m, c, e, 0); bc_web_login_contract *permit = NULL, *again = NULL;
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_UNSUPPORTED && !permit);
    bc_web_entry_release(graph);
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 18, &permit) == BC_INVALID_ARGUMENT && !permit);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK && permit);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &again) == BC_BUSY && !again);
    bc_web_session_options options = {sizeof(options), BC_ABI_VERSION, 1000, text("u+&%"), text("p#&"), text("12345678"), now, &m};
    bc_web_session *session = NULL;
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    assert(m.method == BC_HTTP_POST && !strcmp(m.path, "/rpc/WEBSES/create.asp"));
    assert(strstr(m.body, "WEBVAR_USERNAME=u%2B%26%25&WEBVAR_PASSWORD=p%23%26") && strstr(m.body, "WEBVAR_IPADDR=12345678&WEBVAR_TYPE=Https"));
    bc_web_session *duplicate = NULL;
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &duplicate) == BC_BUSY && !duplicate);
    bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'own-cookie'}]};", 200, NULL);
    assert(m.cookie_sets == 1 && !strcmp(m.path, "/rpc/getcsrftoken.asp") && !strcmp(m.body, "SESSION_COOKIE=own-cookie"));
    graph_respond(&m, c, "var WEBVAR_JSONVAR_GETCSRFTOKEN = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_GETCSRFTOKEN:[{CSRFTOKEN:'own-csrf'}]};", 200, NULL);
    const bc_web_session_result *result = bc_web_session_result_get(session);
    assert(result && result->status == BC_OK && !strcmp(result->landing_path, "/page/top.html"));
    bc_endpoint *owner = bc_web_session_endpoint(session);
    assert(owner && owner != e && bc_endpoint_revision(owner) != bc_endpoint_revision(e));
    assert(m.owner_callbacks == 1);
    /* Same own Web endpoint traverses only published remote links. A menu's
     * unused string cannot become a navigation edge. */
    bc_web_entry_options protected_options = graph_options(&m); protected_options.max_depth = 16;
    bc_web_entry_graph *protected_graph = NULL;
    assert(bc_web_entry_start_owned(session, &protected_options, graph_completed, &m, &protected_graph) == BC_OK);
    assert(!strcmp(m.path, "/page/top.html"));
    graph_respond(&m, c, "<script src='/oversized.js'></script><iframe src='menu/remote.html'></iframe><iframe src='unrelated.html'></iframe>", 200, NULL);
    assert(!strcmp(m.path,"/oversized.js"));
    char oversized[4096]; limited_menu(oversized,sizeof(oversized));
    graph_respond(&m,c,oversized,200,NULL);
    assert(!strcmp(m.path, "/page/menu/remote.html"));
    graph_respond(&m, c, "<script src='../../js/menu.js'></script>", 200, NULL);
    assert(!strcmp(m.path, "/js/menu.js"));
    graph_respond(&m, c, "function createMenu(){var start='<ul>';"
        "var item=\"<li><a href='../contents/remote/operation.html' \"+\"target='contentFrame'>\"+eLang.getString('remote','label')+'</a></li>';"
        "var unused=\"<a href='never.html'>unused</a>\";var html=start+item;$('#menu').replaceWith(html);}", 200, NULL);
    assert(!strcmp(m.path, "/page/contents/remote/operation.html"));
    graph_respond(&m, c, "<script src='../../../js/license.js'></script>", 200, NULL);
    graph_respond(&m, c, "function execute(){window.open('jviewer_launch.html','RemoteConsole','width=600');}", 200, NULL);
    assert(!strcmp(m.path, "/page/contents/remote/jviewer_launch.html"));
    graph_respond(&m, c, "<script src='../../../js/jviewer_launch.js'></script>", 200, NULL);
    graph_respond(&m, c, "window.location='/Java/jviewer.jnlp?ext_ip=bmc.example';", 200, NULL);
    assert(!strcmp(m.path, "/Java/jviewer.jnlp?ext_ip=bmc.example"));
    graph_respond(&m, c, "<jnlp><resources><jar href='viewer.jar' main='true'/></resources><application-desc>"
        "<argument>-hostname</argument><argument>bmc.example</argument>"
        "<argument>-kvmtoken</argument><argument>fixture</argument>"
        "<argument>-kvmport</argument><argument>7582</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>", 200, NULL);
    const bc_web_entry_result *protected_result = bc_web_entry_result_get(protected_graph, owner, 17);
    assert(protected_result && protected_result->status == BC_OK && protected_result->requests == 9);
    bc_web_entry_limit incomplete = {0}; incomplete.struct_size = sizeof(incomplete); incomplete.abi_version = BC_ABI_VERSION;
    assert(bc_web_entry_limit_get(protected_graph,owner,17,&incomplete) == BC_OK);
    assert(incomplete.reason == BC_WEB_LIMIT_SCRIPT_PARSE && incomplete.candidates == 10 && protected_result->unsupported_scripts == 1);
    bc_request *launch = bc_web_entry_launch_request_get(protected_graph, owner, 17);
    assert(launch && bc_request_endpoint(launch) == owner);
    unsigned diagnostics_submits = m.submits;
    assert(bc_web_entry_resource_count(protected_graph, owner, 17) == 9);
    assert(bc_web_entry_resource_request_get(protected_graph, owner, 17, 8) == launch);
    assert(!bc_web_entry_resource_request_get(protected_graph, owner, 17, 9));
    assert(!bc_web_entry_resource_count(protected_graph, e, 17));
    assert(!bc_web_entry_resource_count(protected_graph, owner, 18));
    assert(!bc_web_entry_resource_request_get(protected_graph, e, 17, 0));
    assert(!bc_web_entry_resource_request_get(protected_graph, owner, 18, 0));
    assert(m.submits == diagnostics_submits);
    assert(!bc_web_entry_launch_request_get(protected_graph, e, 17));
    bc_console_discovery *descriptor = NULL;
    assert(bc_console_discovery_from_request(owner, 17, launch, &descriptor) == BC_OK);
    const bc_console_discovery_result *metadata = bc_console_discovery_result_get(descriptor, owner, 17);
    assert(metadata && metadata->status == BC_OK && metadata->format == BC_CONSOLE_DESCRIPTOR_JVIEWER);
    assert(!bc_service_profile_can_attempt(&metadata->profile, BC_SERVICE_KVM));
    bc_console_discovery_release(descriptor);
    assert(bc_web_entry_cancel(protected_graph) == BC_OK);
    assert(!bc_web_entry_resource_count(protected_graph, owner, 17));
    assert(!bc_web_entry_resource_request_get(protected_graph, owner, 17, 0));
    bc_web_entry_release(protected_graph);
    for (unsigned missing = 0; missing < 2; ++missing) {
        bc_web_entry_options fair_options = protected_options; fair_options.max_requests = 32;
        assert(bc_web_entry_start_owned(session,&fair_options,graph_completed,&m,&protected_graph) == BC_OK);
        char flood[4096]; size_t used = 0;
        for (unsigned i = 0; i < 40; ++i) used += (size_t)snprintf(flood+used,sizeof(flood)-used,"<script src='lib%u.js'></script>",i);
        snprintf(flood+used,sizeof(flood)-used,"<iframe src='content.html'></iframe>");
        graph_respond(&m,c,flood,200,NULL);
        assert(!strcmp(m.path,"/page/lib0.js")); graph_respond(&m,c,";",200,NULL);
        assert(!strcmp(m.path,"/page/content.html")); graph_respond(&m,c,"<script src='lib39.js'></script><script src='bridge.js'></script>",200,NULL);
        assert(!strcmp(m.path,"/page/bridge.js"));
        graph_respond(&m,c,missing ? "window.location=dynamic;" : "window.location='/Java/jviewer.jnlp';",200,NULL);
        if (!missing) {
            assert(!strcmp(m.path,"/Java/jviewer.jnlp"));
            graph_respond(&m,c,"<jnlp><resources><jar href='viewer.jar'/></resources><application-desc>"
                "<argument>-hostname</argument><argument>bmc.example</argument><argument>-kvmtoken</argument><argument>fixture</argument>"
                "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>",200,NULL);
            assert(bc_web_entry_result_get(protected_graph,owner,17)->status == BC_OK);
            assert(bc_web_entry_result_get(protected_graph,owner,17)->requests == 5);
            assert(bc_web_entry_launch_request_get(protected_graph,owner,17));
        } else {
            while (!bc_web_entry_result_get(protected_graph,owner,17)) graph_respond(&m,c,";",200,NULL);
            assert(bc_web_entry_result_get(protected_graph,owner,17)->status == BC_LIMIT_EXCEEDED);
            assert(bc_web_entry_result_get(protected_graph,owner,17)->requests == 32);
            assert(!bc_web_entry_launch_request_get(protected_graph,owner,17));
        }
        bc_web_entry_release(protected_graph);
    }
    {
        bc_web_entry_options direct = protected_options; direct.max_requests = 32;
        assert(bc_web_entry_start_owned(session,&direct,graph_completed,&m,&protected_graph) == BC_OK);
        graph_respond(&m,c,"<script src='common.js'></script><script src='extra.js'></script><iframe src='a.html'></iframe><iframe src='b.html'></iframe><iframe src='c.html'></iframe>",200,NULL);
        graph_respond(&m,c,";",200,NULL);
        unsigned found = 0;
        while (!bc_web_entry_result_get(protected_graph,owner,17)) {
            if (strstr(m.path,".html")) {
                char script_path[128], html[256];
                snprintf(script_path,sizeof(script_path),"%.*s.js",(int)strlen(m.path)-5,m.path);
                const char *base = strrchr(script_path,'/') + 1;
                snprintf(html,sizeof(html),"<script src='%s'></script><script src='%.*s-tail.js'></script>",base,(int)strlen(base)-3,base);
                graph_respond(&m,c,html,200,NULL);
                assert(!strcmp(m.path,script_path));
            } else if (!strcmp(m.path,"/page/a-tail.js")) {
                graph_respond(&m,c,"window.location='nested.html';",200,NULL);
            } else if (!strcmp(m.path,"/page/nested.js")) {
                graph_respond(&m,c,"window.location='/Java/jviewer.jnlp';",200,NULL); found = 1;
            } else if (!strcmp(m.path,"/Java/jviewer.jnlp")) {
                graph_respond(&m,c,"<jnlp><resources><jar href='viewer.jar'/></resources><application-desc>"
                    "<argument>-hostname</argument><argument>bmc.example</argument><argument>-kvmtoken</argument><argument>fixture</argument>"
                    "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>",200,NULL);
            } else graph_respond(&m,c,";",200,NULL);
        }
        assert(found && bc_web_entry_result_get(protected_graph,owner,17)->status == BC_OK);
        assert(bc_web_entry_result_get(protected_graph,owner,17)->requests < 32);
        bc_web_entry_release(protected_graph);
    }
    {
        const char *source = "function start(){var parts=window.location.href.split('/');if(parts.length){"
            "var target='../../../Java/jviewer.jnlp'+'?ext_ip='+parts[2];}window.location.href=target;"
            "setTimeout(function(){window.close();},20000);}";
        const char *mutations[] = {NULL,"parts[2]","split('/')","if(parts.length)","+parts[2]","href=target;","?ext_ip=","../../../Java/jviewer.jnlp","setTimeout"};
        const char *changes[] = {NULL,"parts[1]","split(':')","if(other.length)","+other[2]","href=other;","?ext_ip=x","https://foreign.example/Java/jviewer.jnlp","var target='reassigned';setTimeout"};
        for (unsigned variant = 0; variant < sizeof(mutations)/sizeof(*mutations); ++variant) {
            assert(bc_web_entry_start_owned(session,&protected_options,graph_completed,&m,&protected_graph) == BC_OK);
            graph_respond(&m,c,"<iframe src='contents/remote/jviewer_launch.html'></iframe>",200,NULL);
            graph_respond(&m,c,"<script src='origin.js'></script>",200,NULL);
            char altered[1024]; strcpy(altered,source);
            if (variant) {
                char *at = strstr(altered,mutations[variant]); assert(at);
                char tail[1024]; strcpy(tail,at + strlen(mutations[variant]));
                strcpy(at,changes[variant]); strcat(at,tail);
            }
            graph_respond(&m,c,altered,200,NULL);
            if (!variant) {
                char expected[1025]; snprintf(expected,sizeof(expected),"/Java/jviewer.jnlp?ext_ip=%s",authority);
                assert(!strcmp(m.path,expected));
                graph_respond(&m,c,"<jnlp><resources><jar href='viewer.jar'/></resources><application-desc>"
                    "<argument>-hostname</argument><argument>bmc.example</argument><argument>-kvmtoken</argument><argument>fixture</argument>"
                    "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>",200,NULL);
                assert(bc_web_entry_result_get(protected_graph,owner,17)->status == BC_OK);
                assert(bc_web_entry_launch_request_get(protected_graph,owner,17));
            } else {
                assert(bc_web_entry_result_get(protected_graph,owner,17)->status == BC_UNSUPPORTED);
                assert(!bc_web_entry_launch_request_get(protected_graph,owner,17));
            }
            bc_web_entry_release(protected_graph);
        }
        assert(bc_web_entry_start_owned(session,&protected_options,graph_completed,&m,&protected_graph) == BC_OK);
        graph_respond(&m,c,"<iframe src='contents/remote/launch.html'></iframe>",200,NULL);
        graph_respond(&m,c,"<script src='origin.js'></script>",200,NULL);
        graph_respond(&m,c,"function connect(){var segments=window.location.href.split('/');if(segments.length){"
            "var route='../../../assets/viewer.jnlp'+'?viewer_host='+segments[2];}window.location.href=route;}",200,NULL);
        char expected[1025]; snprintf(expected,sizeof(expected),"/assets/viewer.jnlp?viewer_host=%s",authority);
        assert(!strcmp(m.path,expected));
        graph_respond(&m,c,"<jnlp><resources><jar href='viewer.jar'/></resources><application-desc>"
            "<argument>-hostname</argument><argument>bmc.example</argument><argument>-kvmtoken</argument><argument>fixture</argument>"
            "<argument>-kvmport</argument><argument>7582</argument><argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>",200,NULL);
        assert(bc_web_entry_result_get(protected_graph,owner,17)->status == BC_OK);
        bc_web_entry_release(protected_graph);
    }
    const char *unknown_navigation[] = {
        "function menu(){var item=\"<a href='\"+dynamic+\"'>x</a>\";$('#menu').replaceWith(item);}",
        "function menu(){var item=\"<a href='remote.html'>\"+unknown()+'</a>';$('#menu').replaceWith(item);}",
        "function launch(){window.open(dynamic,'RemoteConsole','width=600');}",
        "window.location='https://foreign.example/Java/jviewer.jnlp';"
    };
    for (unsigned i = 0; i < sizeof(unknown_navigation)/sizeof(*unknown_navigation); ++i) {
        assert(bc_web_entry_start_owned(session, &protected_options, graph_completed, &m, &protected_graph) == BC_OK);
        graph_respond(&m, c, "<script src='remote.js'></script>", 200, NULL);
        graph_respond(&m, c, unknown_navigation[i], 200, NULL);
        protected_result = bc_web_entry_result_get(protected_graph, owner, 17);
        assert(protected_result && protected_result->status == BC_UNSUPPORTED && protected_result->requests == 2);
        assert(!bc_web_entry_launch_request_get(protected_graph, owner, 17));
        assert(bc_web_entry_resource_count(protected_graph, owner, 17) == 2);
        assert(bc_web_entry_resource_request_get(protected_graph, owner, 17, 1));
        if (i == 0) {
            m.now = 1001;
            assert(!bc_web_entry_resource_count(protected_graph, owner, 17));
            assert(!bc_web_entry_resource_request_get(protected_graph, owner, 17, 0));
            m.now = 0;
            assert(!bc_web_entry_resource_count(protected_graph, owner, 17));
        }
        bc_web_entry_release(protected_graph);
    }
    assert(bc_web_entry_start_owned(session, &protected_options, graph_completed, &m, &protected_graph) == BC_OK);
    graph_respond(&m, c, "<iframe src='remote.html'></iframe><iframe src='other.html'></iframe>", 200, NULL);
    assert(!strcmp(m.path, "/page/remote.html")); graph_respond(&m, c, "denied", 401, NULL);
    protected_result = bc_web_entry_result_get(protected_graph, owner, 17);
    assert(protected_result && protected_result->status == BC_AUTHENTICATION_FAILED && protected_result->requests == 2);
    bc_web_entry_release(protected_graph);
    assert(bc_web_session_close(session, owner_completed, &m) == BC_OK && !bc_web_session_endpoint(session));
    assert(m.method == BC_HTTP_GET && !strcmp(m.path, "/rpc/WEBSES/logout.asp"));
    graph_respond(&m, c, "var response = {HAPI_STATUS:0};", 200, NULL);
    assert(bc_web_session_result_get(session)->cleanup_status == BC_OK && m.owner_callbacks == 2);
    bc_web_session_release(session);
    /* Explicit authentication errors never trigger another login or CSRF. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    unsigned submits = m.submits;
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:-2};", 200, NULL);
    assert(m.submits == submits && bc_web_session_result_get(session)->status == BC_AUTHENTICATION_FAILED);
    assert(bc_web_session_result_get(session)->cleanup_status == BC_OK);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* Releasing an in-flight login suppresses callbacks but still logs out a newly-created own session. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    unsigned callbacks = m.owner_callbacks; bc_web_session_release(session);
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'late-cookie'}]};", 200, NULL);
    assert(!strcmp(m.path, "/rpc/WEBSES/logout.asp"));
    graph_respond(&m, c, "var response = {HAPI_STATUS:0};", 200, NULL);
    assert(m.owner_callbacks == callbacks);
    bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* A failed CSRF response is reported only after own logout completes. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'csrf-cookie'}]};", 200, NULL);
    callbacks = m.owner_callbacks;
    graph_respond(&m, c, "denied", 403, NULL);
    assert(m.owner_callbacks == callbacks && !strcmp(m.path, "/rpc/WEBSES/logout.asp"));
    graph_respond(&m, c, "var response = {HAPI_STATUS:0};", 200, NULL);
    result = bc_web_session_result_get(session);
    assert(result->status == BC_AUTHENTICATION_FAILED && result->http_status == 403 && result->cleanup_status == BC_OK);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* Cancelling a submitted login observes its result, skips CSRF, and awaits own cleanup. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    unsigned cancels = m.cancels; callbacks = m.owner_callbacks;
    assert(bc_web_session_cancel(session) == BC_OK && bc_web_session_cancel(session) == BC_OK && m.cancels == cancels);
    assert(!bc_web_session_result_get(session)); m.now = 600;
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'cancel-cookie'}]};", 200, NULL);
    assert(!strcmp(m.path, "/rpc/WEBSES/logout.asp") && m.last_timeout == 1000 && m.owner_callbacks == callbacks);
    graph_respond(&m, c, "var response = {HAPI_STATUS:0};", 200, NULL);
    result = bc_web_session_result_get(session);
    assert(result->status == BC_CANCELLED && result->cleanup_status == BC_OK && m.owner_callbacks == callbacks + 1);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* CSRF cancellation can cancel its request because session ownership is already known. */
    m.now = 0; graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    m.now = 200;
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'csrf-cancel'}]};", 200, NULL);
    assert(m.last_timeout == 800); cancels = m.cancels; callbacks = m.owner_callbacks;
    assert(bc_web_session_cancel(session) == BC_OK && m.cancels == cancels + 1);
    assert(bc_context_poll(c, 0) == BC_OK && !strcmp(m.path, "/rpc/WEBSES/logout.asp") && m.owner_callbacks == callbacks);
    graph_respond(&m, c, "var response = {HAPI_STATUS:0};", 200, NULL);
    assert(bc_web_session_result_get(session)->status == BC_CANCELLED && bc_web_session_result_get(session)->cleanup_status == BC_OK);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* Login and CSRF share one deadline; cleanup has one separate short window. */
    m.now = 0; graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    m.now = 700;
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION = {HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'deadline-cookie'}]};", 200, NULL);
    assert(m.last_timeout == 300); m.now = 1000;
    graph_respond(&m, c, "var WEBVAR_JSONVAR_GETCSRFTOKEN={HAPI_STATUS:0,WEBVAR_STRUCTNAME_GETCSRFTOKEN:[{CSRFTOKEN:'late'}]};", 200, NULL);
    assert(!strcmp(m.path, "/rpc/WEBSES/logout.asp") && m.last_timeout == 1000);
    m.now = 1999; graph_respond(&m, c, "var response={HAPI_STATUS:0};", 200, NULL);
    result = bc_web_session_result_get(session); assert(result->status == BC_TIMEOUT && result->cleanup_status == BC_OK);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* Without a login response/cookie, cancellation cannot claim a session was deleted. */
    m.now = 0; graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    assert(bc_web_session_cancel(session) == BC_OK); submits = m.submits; m.now = 1000;
    bc_response timeout = {0}; timeout.struct_size = sizeof(timeout); timeout.status = BC_TIMEOUT;
    m.done(m.arg, &timeout); assert(bc_context_poll(c, 0) == BC_OK);
    result = bc_web_session_result_get(session);
    assert(result->status == BC_CANCELLED && result->cleanup_status == BC_OUTCOME_UNKNOWN && m.submits == submits);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph); m.now = 0;
    /* Cleanup never gets another fresh budget when released after an uncertain logout. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    assert(bc_web_session_cancel(session) == BC_OK);
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION={HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'cleanup-deadline'}]};", 200, NULL);
    m.now = 1000; graph_respond(&m, c, "var response={HAPI_STATUS:0};", 200, NULL);
    result = bc_web_session_result_get(session);
    assert(result->status == BC_CANCELLED && result->cleanup_status == BC_TIMEOUT);
    submits = m.submits; bc_web_session_release(session); assert(m.submits == submits);
    bc_web_login_contract_release(permit); bc_web_entry_release(graph); m.now = 0;
    /* A clear rejection remains clean even if cancellation was requested while awaiting it. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_OK);
    assert(bc_web_session_cancel(session) == BC_OK);
    graph_respond(&m, c, "var WEBVAR_JSONVAR_WEB_SESSION={HAPI_STATUS:-2};", 200, NULL);
    result = bc_web_session_result_get(session);
    assert(result->status == BC_CANCELLED && result->cleanup_status == BC_OK);
    bc_web_session_release(session); bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    /* An expired public permit performs no credential-bearing request. */
    graph = public_contract(&m, c, e, 1);
    assert(bc_web_login_contract_from_graph(graph, e, 17, &permit) == BC_OK);
    m.now = 1001; submits = m.submits;
    assert(bc_web_session_start(permit, &options, owner_completed, &m, &session) == BC_TIMEOUT && !session && submits == m.submits);
    bc_web_login_contract_release(permit); bc_web_entry_release(graph);
    bc_endpoint_release(e); assert(bc_context_shutdown(c) == BC_OK && bc_context_destroy(c) == BC_OK);
}
static void manual_probe_completed(bc_megarac_probe *probe, const bc_megarac_probe_result *result, void *user) {
    (void)probe; assert(result); ++((mock *)user)->owner_callbacks;
}
static void manual_http_contract(void) {
    mock m = {0}; m.allow_post = 1;
    bc_transport t = {sizeof(t), BC_ABI_VERSION, &m, opened, closed, submitted, cancelled, polled, cookie_set};
    bc_context_options co = {sizeof(co), BC_ABI_VERSION, &t, 262144, 4, 0}; bc_context *c = NULL;
    assert(bc_context_create(&co, &c) == BC_OK); bc_endpoint *e = endpoint(c);
    bc_megarac_probe_options options = {0}; options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.host = text("bmc.example"); options.username = text("fixture"); options.password = text("fixture");
    bc_megarac_login_contract login = {sizeof(login), BC_MEGARAC_LOGIN_H5_SESSION, 0};
    bc_megarac_probe *probe = NULL;
    assert(bc_megarac_probe_start_with_login(e, &options, &login, manual_probe_completed, &m, &probe) == BC_OK);
    assert(!strcmp(m.path, "/api/session") && m.method == BC_HTTP_POST && m.submits == 1);
    graph_respond(&m, c, "{}", 404, NULL);
    assert(m.submits == 1 && m.owner_callbacks == 1 && bc_megarac_probe_result_get(probe)->status == BC_UNSUPPORTED);
    bc_megarac_probe_release(probe);
    /* A separately chosen JViewer layout cannot change a manual HTTP form or infer CSRF. */
    bc_service_profile selected = {sizeof(selected), BC_SERVICE_KVM, BC_SERVICE_FAMILY_MEGARAC,
        BC_SERVICE_MEGARAC_KVM_JVIEWER_195, BC_SERVICE_EVIDENCE_MANUAL};
    login.kind = BC_MEGARAC_LOGIN_LEGACY_RPC;
    assert(bc_megarac_probe_start_with_login_profile(e, &options, &login, &selected, manual_probe_completed, &m, &probe) == BC_OK);
    assert(!strcmp(m.path, "/rpc/WEBSES/create.asp") && !strstr(m.body, "WEBVAR_TYPE") && !strstr(m.body, "WEBVAR_IPADDR"));
    graph_respond(&m, c, "var reply={HAPI_STATUS:0,WEBVAR_STRUCTNAME_WEB_SESSION:[{SESSION_COOKIE:'manual-cookie'}]};", 200, NULL);
    assert(strstr(m.path, "/Java/jviewer.jnlp?EXTRNIP=bmc.example&JNLPSTR=JViewer&ext_ip=bmc.example"));
    graph_respond(&m, c, "<jnlp><application-desc><argument>-hostname</argument><argument>bmc.example</argument>"
        "<argument>-kvmtoken</argument><argument>fixture</argument><argument>-kvmport</argument><argument>7582</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument></application-desc></jnlp>", 200, NULL);
    const bc_service_profile *profile = bc_megarac_probe_profile_get(probe);
    assert(profile && profile->variant == selected.variant && (profile->evidence & BC_SERVICE_EVIDENCE_MANUAL));
    assert(bc_megarac_probe_logout(probe, manual_probe_completed, &m) == BC_OK);
    graph_respond(&m, c, "var reply={HAPI_STATUS:0};", 200, NULL); bc_megarac_probe_release(probe);
    /* Conflicting descriptor/layout evidence stops after H5, never retries a different HTTP login. */
    login.kind = BC_MEGARAC_LOGIN_H5_SESSION;
    assert(bc_megarac_probe_start_with_login_profile(e, &options, &login, &selected, manual_probe_completed, &m, &probe) == BC_OK);
    graph_respond(&m, c, "{\"CSRFToken\":\"fixture-csrf\"}", 200, NULL);
    assert(!strcmp(m.path, "/api/settings/media/h5viewercfg"));
    graph_respond(&m, c, "{\"token\":\"fixture\",\"session\":\"fixture-session\",\"client_ip\":\"192.0.2.1\",\"server_ip\":\"192.0.2.2\"}", 200, NULL);
    assert(!strcmp(m.path, "/api/session") && m.method == BC_HTTP_DELETE);
    graph_respond(&m, c, "", 204, NULL);
    assert(bc_megarac_probe_result_get(probe)->status == BC_UNSUPPORTED);
    bc_megarac_probe_release(probe); bc_endpoint_release(e);
    assert(bc_context_shutdown(c) == BC_OK && bc_context_destroy(c) == BC_OK);
}
int main(void) { manual_http_contract(); web_owner("https://bmc.example","bmc.example"); web_owner("https://bmc.example:623","bmc.example%3A623"); web_owner("https://[2001:db8::1]:8443","%5B2001%3Adb8%3A%3A1%5D%3A8443"); cookie_parser(); response_parser(); pure_parser(); transport_parser(); source_binding(); graph_walk(); return 0; }
