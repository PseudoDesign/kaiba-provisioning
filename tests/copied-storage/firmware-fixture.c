/* Synthetic transport: exactly the comparison helper's bounded operation set. */
#include "harness.h"
#include <errno.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static uint32_t locks = DEVICE_TYPE;
static unsigned hmac_calls, lock_writes;
static uint32_t last_error;
static unsigned error_queries;
static bool fault(const char *name) {
    const char *value = getenv("KAIBA_TEST_FAULT"); return value && !strcmp(value, name);
}
int test_exchange(void *arena, size_t size) {
    uint32_t *m = arena, *v = m+5, tag = m[2], cap = m[3];
    if (m[0] != size || m[1] || m[4] || m[size/4-1]) abort();
    m[1] = 0x80000000; m[4] = 0x80000000 | cap;
    if (tag != 0x3008e) last_error = 0;
    switch (tag) {
    case 0x3008e:
        /* Query exactly once after the failed HMAC, before cleanup clears it.
         * Abort if a successful/interrupted/nontransport path queries it. */
        if (++error_queries > 1 || lock_writes != 1 ||
            hmac_calls != (fault("canary-einval") ? 2U : 1U) ||
            !(fault("hmac-einval") || fault("canary-einval") || fault("error-query-eio") || fault("error-query-malformed"))) abort();
        if (fault("error-query-eio")) { errno = EIO; return -1; }
        if (fault("error-query-malformed")) m[4] = 4;
        v[0] = last_error; return 0;
    case 0x3008f: v[0] = 1; return 0;
    case 0x30090: v[0] = fault("preclosed") ? DEVICE_TYPE | ALL_LOCKS : locks; return 0;
    case 0x3009c: v[0] = fault("wrong-usage") ? 9 : 8; return 0;
    case 0x38090:
        if (++lock_writes > 2 || v[0] != 1 ||
            v[1] != (DEVICE_TYPE | (lock_writes == 1 ? EARLY_LOCKS : ALL_LOCKS))) abort();
        if (!(fault("cleanup") && lock_writes == 2)) locks |= v[1];
        v[0] = 0; return 0;
    case 0x30092: {
        if (++hmac_calls > 3 || locks != (DEVICE_TYPE | EARLY_LOCKS) || cap != 2060 ||
            v[0] || v[1] != 1 || !v[2] || v[2] > 2048) abort();
        if (fault("hmac-einval") || fault("error-query-eio") || fault("error-query-malformed") ||
            (fault("canary-einval") && hmac_calls == 2)) {
            last_error = RPI_FW_CRYPTO_KEY_NOT_SET; errno = EINVAL; return -1;
        }
        if (fault("interrupted")) { raise(SIGTERM); errno = EINTR; return -1; }
        uint8_t key[32], out[32]; size_t n;
        memset(key, fault("other-board") ? 0x43 : 0x42, sizeof(key));
        if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, sizeof(key),
                       (const uint8_t *)(v+3), v[2], out, sizeof(out), &n) || n != 32) abort();
        if (fault("hmac-constant")) memset(out, 0x44, sizeof(out));
        if (fault("hmac-zero")) memset(out, 0, sizeof(out));
        if (fault("hmac-repeat-mismatch") && hmac_calls == 3) out[0] ^= 1;
        v[0] = 0; v[1] = fault("hmac-short") ? 31 : 32; memcpy(v+2, out, 32);
        explicit_bzero(key, sizeof(key)); explicit_bzero(out, sizeof(out)); return 0;
    }
    default: abort(); /* No raw reads, signing, generation, usage writes or retry. */
    }
}
