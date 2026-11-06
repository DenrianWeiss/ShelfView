#include "bcontrol/ipmi_platform.h"
#include "../core/log_internal.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bc_ipmi_crypto api; } openssl_crypto;

static const char *digest_name(uint8_t algorithm) {
    switch (algorithm) {
    case BC_IPMI_AUTH_ALG_HMAC_SHA1: return "SHA1";
    case BC_IPMI_AUTH_ALG_HMAC_MD5: return "MD5";
    case BC_IPMI_AUTH_ALG_HMAC_SHA256: return "SHA256";
    case BC_IPMI_INTEGRITY_ALG_HMAC_SHA256_128: return "SHA256";
    default: return NULL;
    }
}

static bc_status openssl_hmac(void *userdata, uint8_t algorithm, const uint8_t *key, uint32_t key_length,
    const uint8_t *data, uint32_t data_length, uint8_t *out, uint32_t *out_length) {
    (void)userdata;
    const char *name = digest_name(algorithm);
    if (!name) {
        BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.crypto_hmac", "algorithm=%u status=unsupported", algorithm);
        return BC_UNSUPPORTED;
    }
    if (!out || !out_length || (data_length && !data) || (key_length && !key)) return BC_INVALID_ARGUMENT;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *context = mac ? EVP_MAC_CTX_new(mac) : NULL;
    bc_status status = BC_NO_MEMORY;
    if (context) {
        OSSL_PARAM parameters[2] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)name, 0), OSSL_PARAM_construct_end()};
        size_t written = 0;
        if (EVP_MAC_init(context, key, key_length, parameters) == 1 && EVP_MAC_update(context, data, data_length) == 1 &&
            EVP_MAC_final(context, out, &written, EVP_MAX_MD_SIZE) == 1) {
            *out_length = (uint32_t)written;
            status = BC_OK;
        }
    }
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    if (status != BC_OK) BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.crypto_hmac", "algorithm=%u status=%s",
        algorithm, bc_status_string(status));
    return status;
}

static bc_status openssl_cipher(int encrypt, uint8_t algorithm, const uint8_t *key, uint32_t key_length,
    const uint8_t *iv, const uint8_t *input, uint32_t input_length, uint8_t *output) {
    if (algorithm != BC_IPMI_CONFIDENTIALITY_ALG_AES_CBC_128) return BC_UNSUPPORTED;
    if (!key || key_length < 16 || !iv || !input || !output || input_length > INT_MAX || input_length % 16) return BC_INVALID_ARGUMENT;
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context) return BC_NO_MEMORY;
    int first = 0, final_length = 0;
    int ok = encrypt ? EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv)
                     : EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), NULL, key, iv);
    ok = ok && EVP_CIPHER_CTX_set_padding(context, 0);
    ok = ok && (encrypt ? EVP_EncryptUpdate(context, output, &first, input, (int)input_length)
                        : EVP_DecryptUpdate(context, output, &first, input, (int)input_length));
    ok = ok && (encrypt ? EVP_EncryptFinal_ex(context, output + first, &final_length)
                        : EVP_DecryptFinal_ex(context, output + first, &final_length));
    ok = ok && (uint32_t)(first + final_length) == input_length;
    EVP_CIPHER_CTX_free(context);
    if (!ok) BC_LOG_ERROR(BC_LOG_CATEGORY_IPMI, "ipmi.crypto_cipher", "operation=%s algorithm=%u status=io_error",
        encrypt ? "encrypt" : "decrypt", algorithm);
    return ok ? BC_OK : BC_IO_ERROR;
}

static bc_status openssl_encrypt(void *userdata, uint8_t algorithm, const uint8_t *key, uint32_t key_length,
    const uint8_t *iv, const uint8_t *input, uint32_t input_length, uint8_t *output) {
    (void)userdata;
    return openssl_cipher(1, algorithm, key, key_length, iv, input, input_length, output);
}

static bc_status openssl_decrypt(void *userdata, uint8_t algorithm, const uint8_t *key, uint32_t key_length,
    const uint8_t *iv, const uint8_t *input, uint32_t input_length, uint8_t *output) {
    (void)userdata;
    return openssl_cipher(0, algorithm, key, key_length, iv, input, input_length, output);
}

static bc_status openssl_random(void *userdata, uint8_t *out, uint32_t length) {
    (void)userdata;
    if (!out || length > INT_MAX) return BC_INVALID_ARGUMENT;
    return RAND_bytes(out, (int)length) == 1 ? BC_OK : BC_IO_ERROR;
}

bc_status bc_ipmi_openssl_crypto_create(bc_ipmi_crypto **out) {
    if (!out) return BC_INVALID_ARGUMENT;
    *out = NULL;
    openssl_crypto *crypto = calloc(1, sizeof(*crypto));
    if (!crypto) return BC_NO_MEMORY;
    crypto->api = (bc_ipmi_crypto){sizeof(bc_ipmi_crypto), BC_ABI_VERSION, crypto,
        openssl_hmac, openssl_encrypt, openssl_decrypt, openssl_random};
    *out = &crypto->api;
    return BC_OK;
}

void bc_ipmi_openssl_crypto_destroy(bc_ipmi_crypto *crypto) {
    free(crypto);
}
