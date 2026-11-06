#ifndef BC_CURL_SOCKET_H
#define BC_CURL_SOCKET_H
#include <curl/curl.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
static int bc_curl_socket_options(void *user, curl_socket_t socket, curlsocktype purpose) {
    (void)user; (void)purpose;
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled))) return CURL_SOCKOPT_ERROR;
#else
    (void)socket;
#endif
    return CURL_SOCKOPT_OK;
}
#endif
