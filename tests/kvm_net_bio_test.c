#include "../platform/kvm_net.c"
#include <assert.h>
#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#endif

#if defined(MSG_NOSIGNAL) && !defined(_WIN32)
static volatile sig_atomic_t broken_pipes;
static void broken_pipe(int signal_number) { (void)signal_number; ++broken_pipes; }
static int pipe_pending(void) {
    sigset_t pending;
    assert(sigpending(&pending) == 0);
    return sigismember(&pending, SIGPIPE);
}
static void test_filter(void) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    bc_kvm_transport transport = {0}; transport.socket = pair[0];
    transport.tls = SSL_CTX_new(TLS_client_method()); assert(transport.tls);
    transport.ssl = SSL_new(transport.tls); assert(transport.ssl && tls_set_socket(&transport));
    BIO *bio = SSL_get_wbio(transport.ssl);
    assert(BIO_get_fd(bio, NULL) == pair[0] && BIO_flush(bio) == 1);
    assert(BIO_write(bio, "a", 1) == 1);
    char value = 0; assert(read(pair[1], &value, 1) == 1 && value == 'a');
    assert(write(pair[1], "b", 1) == 1 && BIO_read(bio, &value, 1) == 1 && value == 'b');
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    assert(BIO_read(bio, &value, 1) < 0 && BIO_should_read(bio));
    close(pair[1]);
    assert(BIO_write(bio, "c", 1) < 0 && errno == EPIPE && !BIO_should_retry(bio));
    assert(broken_pipes == 0 && pipe_pending() == 0);
    sigset_t set, old, current;
    sigemptyset(&set); sigaddset(&set, SIGPIPE); sigaddset(&set, SIGUSR1);
    assert(pthread_sigmask(SIG_BLOCK, &set, &old) == 0);
    assert(raise(SIGPIPE) == 0 && pipe_pending() == 1);
    assert(BIO_puts(bio, "d") < 0 && errno == EPIPE);
    assert(pipe_pending() == 1 && pthread_sigmask(SIG_BLOCK, NULL, &current) == 0);
    assert(sigismember(&current, SIGPIPE) == 1 && sigismember(&current, SIGUSR1) == 1);
    int signal_number;
    sigdelset(&set, SIGUSR1);
    assert(sigwait(&set, &signal_number) == 0 && signal_number == SIGPIPE);
    assert(pthread_sigmask(SIG_SETMASK, &old, NULL) == 0);
    free_tls(&transport); close(pair[0]);
}
struct server { SSL_CTX *context; int socket; };
static void *serve(void *opaque) {
    struct server *server = opaque;
    SSL *ssl = SSL_new(server->context); assert(ssl);
    assert(SSL_set_fd(ssl, server->socket) == 1 && SSL_accept(ssl) == 1);
    assert(SSL_write(ssl, "x", 1) == 1);
    SSL_free(ssl); close(server->socket);
    return NULL;
}
static SSL_CTX *server_context(void) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048); assert(key);
    X509 *cert = X509_new(); assert(cert);
    assert(X509_set_version(cert, 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60) && X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    assert(X509_set_pubkey(cert, key) == 1);
    X509_NAME *name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0) == 1);
    assert(X509_set_issuer_name(cert, name) == 1 && X509_sign(cert, key, EVP_sha256()) > 0);
    SSL_CTX *context = SSL_CTX_new(TLS_server_method()); assert(context);
    assert(SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION) == 1);
    assert(SSL_CTX_use_certificate(context, cert) == 1 && SSL_CTX_use_PrivateKey(context, key) == 1);
    X509_free(cert); EVP_PKEY_free(key);
    return context;
}
static void test_tls(SSL_CTX *context, int operation) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    bc_kvm_transport transport = {0}; transport.socket = pair[0]; transport.timeout_ms = 1000;
    struct server server = {context, pair[1]}; pthread_t worker;
    assert(pthread_create(&worker, NULL, serve, &server) == 0);
    bc_kvm_transport_options options = {0}; options.cert_policy = BC_CERT_SKIP_ALL;
    options.tls_min = options.tls_max = BC_TLS_1_2;
    assert(tls_connect(&transport, "localhost", &options));
    transport.handshake_done = 1;
    bc_tls_peer_info peer;
    assert(bc_kvm_transport_peer_info(&transport, &peer) == BC_OK);
    assert(!peer.trusted && !strcmp(peer.subject, "CN=localhost") && strlen(peer.sha256) == 64);
    assert(strlen(peer.not_before) == 20 && strlen(peer.not_after) == 20);
    X509 *certificate = SSL_get1_peer_certificate(transport.ssl); assert(certificate);
    assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(transport.tls), certificate) == 1);
    X509_free(certificate);
    assert(bc_kvm_transport_peer_info(&transport, &peer) == BC_OK && peer.trusted);
    strcpy(transport.peer_host, "other.invalid");
    assert(bc_kvm_transport_peer_info(&transport, &peer) == BC_OK && !peer.trusted);
    strcpy(transport.peer_host, "localhost");
    assert(pthread_join(worker, NULL) == 0);
    ERR_clear_error();
    if (operation == 0) {
        char value;
        assert(SSL_read(transport.ssl, &value, 1) == 1 && value == 'x');
        assert(SSL_read(transport.ssl, &value, 1) <= 0);
    } else if (operation == 1) {
        int result = 1;
        for (int attempt = 0; attempt < 8 && result > 0; ++attempt)
            result = SSL_write(transport.ssl, "y", 1);
        assert(result <= 0);
    } else {
        assert(SSL_shutdown(transport.ssl) <= 0);
    }
    bc_kvm_transport_close(&transport);
    assert(broken_pipes == 0 && pipe_pending() == 0);
}
static void test_skip_chain_identity(SSL_CTX *context, const char *host, int expected) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    bc_kvm_transport transport = {0}; transport.socket = pair[0]; transport.timeout_ms = 1000;
    struct server server = {context, pair[1]}; pthread_t worker;
    assert(pthread_create(&worker, NULL, serve, &server) == 0);
    bc_kvm_transport_options options = {0}; options.cert_policy = BC_CERT_SKIP_CHAIN;
    options.tls_min = options.tls_max = BC_TLS_1_2;
    assert(tls_connect(&transport, host, &options) == expected);
    assert(pthread_join(worker, NULL) == 0);
    bc_kvm_transport_close(&transport);
}
static void test_failed_connect(void) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    close(pair[1]);
    bc_kvm_transport transport = {0}; transport.socket = pair[0]; transport.timeout_ms = 1000;
    bc_kvm_transport_options options = {0}; options.cert_policy = BC_CERT_SKIP_ALL;
    assert(!tls_connect(&transport, "localhost", &options));
    free_tls(&transport); close(pair[0]);
    assert(broken_pipes == 0 && pipe_pending() == 0);
}
#endif
#ifndef _WIN32
struct interrupted_read { bc_kvm_transport *transport; bc_status status; };
static void *read_interrupted(void *opaque) {
    struct interrupted_read *read = opaque;
    uint8_t data[8]; uint32_t count = 0;
    read->status = bc_kvm_transport_recv(read->transport, data, sizeof(data), &count, 60000);
    return NULL;
}
static void test_interrupt(void) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    bc_kvm_transport transport = {0};
    transport.socket = pair[0]; transport.kind = BC_KVM_TRANSPORT_TCP; transport.handshake_done = 1;
    struct interrupted_read read = {&transport, BC_OK}; pthread_t worker;
    assert(pthread_create(&worker, NULL, read_interrupted, &read) == 0);
    bc_kvm_transport_interrupt(&transport);
    assert(pthread_join(worker, NULL) == 0 && read.status == BC_IO_ERROR);
    assert(transport.socket == pair[0] && transport.handshake_done);
    bc_kvm_transport_close(&transport); close(pair[1]);
}
static void test_partial_websocket(void) {
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    bc_kvm_transport transport = {0};
    transport.socket = pair[0]; transport.kind = BC_KVM_TRANSPORT_WS; transport.flags = BC_KVM_TRANSPORT_BINARY_ONLY;
    transport.handshake_done = 1; transport.timeout_ms = 1000;
    uint8_t data[32]; uint32_t received;
    assert(write(pair[1], "\x82", 1) == 1);
    uint64_t start = bc_monotonic_ms();
    assert(bc_kvm_transport_recv(&transport, data, sizeof(data), &received, 10) == BC_TIMEOUT);
    assert(!received && bc_monotonic_ms() - start < 200);
    assert(bc_kvm_transport_send(&transport, (const uint8_t *)"key", 3) == BC_OK);
    assert(read(pair[1], data, sizeof(data)) == 9);
    assert(write(pair[1], "\x05" "ab", 3) == 3);
    assert(bc_kvm_transport_recv(&transport, data, sizeof(data), &received, 0) == BC_TIMEOUT);
    assert(write(pair[1], "cde", 3) == 3);
    assert(bc_kvm_transport_recv(&transport, data, sizeof(data), &received, 10) == BC_OK);
    assert(received == 5 && !memcmp(data, "abcde", 5));
    const uint8_t fragmented[] = {2, 0, 0x80, 2, 'o', 'k'};
    assert(write(pair[1], fragmented, sizeof(fragmented)) == sizeof(fragmented));
    assert(bc_kvm_transport_recv(&transport, data, sizeof(data), &received, 10) == BC_OK);
    assert(received == 2 && !memcmp(data, "ok", 2));
    const uint8_t text[] = {0x81, 1, 'x'};
    assert(write(pair[1], text, sizeof(text)) == sizeof(text));
    assert(bc_kvm_transport_recv(&transport, data, sizeof(data), &received, 10) == BC_IO_ERROR);
    free(transport.raw); free(transport.message); free(transport.fragments);
    close(pair[0]); close(pair[1]);
}
#endif
int main(void) {
#if defined(MSG_NOSIGNAL) && !defined(_WIN32)
    struct sigaction action = {0}, previous;
    action.sa_handler = broken_pipe; sigemptyset(&action.sa_mask);
    assert(sigaction(SIGPIPE, &action, &previous) == 0);
    test_filter(); test_failed_connect(); test_partial_websocket(); test_interrupt();
    SSL_CTX *context = server_context();
    for (int operation = 0; operation < 3; ++operation) test_tls(context, operation);
    test_skip_chain_identity(context, "localhost", 1);
    test_skip_chain_identity(context, "other.invalid", 0);
    test_skip_chain_identity(context, "127.0.0.1", 0);
    SSL_CTX_free(context);
    assert(sigaction(SIGPIPE, &previous, NULL) == 0);
    puts("KVM socket BIO and TLS disconnect tests passed");
#else
    puts("KVM MSG_NOSIGNAL BIO unavailable on this platform");
#endif
    return 0;
}
