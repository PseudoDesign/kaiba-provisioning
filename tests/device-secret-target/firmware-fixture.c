/* Synthetic firmware only. Linked into separately named test derivations,
 * never into the production helper. No real mailbox device can be opened. */
#include "harness.h"
#include <errno.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static uint32_t locks = EARLY_LOCKS | DEVICE_TYPE;
static uint32_t last_error;
static bool fault(const char *name) {
    const char *value = getenv("KAIBA_TEST_FAULT");
    return value && !strcmp(value, name);
}
int test_exchange(void *arena, size_t size) {
    uint32_t *m = arena, *v = m+5, tag = m[2], capacity = m[3];
    if (m[0] != size || m[1] || m[4] & 0x80000000 || m[size/4-1] || size > 2084) abort();
    if (fault("ioctl-denied")) { errno = EPERM; return -1; }
    m[1] = 0x80000000; m[4] = 0x80000000 | capacity;
    if (fault("bad-header")) m[0]++;
    switch (tag) {
    case 0x0003008f: v[0] = fault("no-slots") ? 0 : 1; return 0;
    case 0x00030090: if (v[0] != 1) abort(); v[0] = locks; return 0;
    case 0x0003009c: if (v[0] != 1) abort(); v[0] = 8; return 0;
    case 0x0003008e: v[0] = fault("wrong-lock-error") ? 8 : last_error; return 0;
    case 0x00038090:
        if (v[0] != 1 || v[1] & ~(DEVICE_TYPE | ALL_LOCKS)) abort();
        locks = fault("clearable-locks") ? v[1] : locks | v[1];
        v[0] = 0; return 0;
    case 0x00030024:
        if (v[0] != 3 || v[1] != 0 || v[2] != 8 || capacity != 780) abort();
        v[0] = fault("legacy-zeros") ? 0 : 0x80000000; return 0;
    case 0x00030081:
        if (v[0] || v[1] != 8 || capacity != 40) abort();
        errno = fault("legacy-io") ? EIO : EINVAL; return -1;
    case 0x00030094:
        if (v[0] || v[1] != 1 || capacity != 1032) abort();
        if (fault("private-returned")) {
            v[0] = 0; v[1] = 32; memset(v+2, 0x5a, 32); return 0;
        }
        v[0] = 0x80000000; last_error = 4;
        if (fault("locked-with-secret")) { v[1] = 32; memset(v+2, 0x5a, 32); }
        return 0;
    case 0x00030091:
        if (v[0] || v[1] != 1 || v[2] != 32 || capacity != 128 || size != 160) abort();
        if (locks & ARM_CRYPTO_KEY_STATUS_SIGN_LOCKED) { v[0] = 0x80000000; last_error = 4; }
        else { v[0] = 0; v[1] = 72; memset(v+2, 0x30, 72); }
        return 0;
    case 0x00030092: {
        if (v[0] || v[1] != 1 || !v[2] || v[2] > 2048 || capacity != 2060) abort();
        if (locks & ARM_CRYPTO_KEY_STATUS_HMAC_LOCKED) { v[0] = 0x80000000; last_error = 4; return 0; }
        uint8_t key[32], out[32]; memset(key, fault("other-board") ? 0x43 : 0x42, 32); size_t n;
        if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, (const uint8_t *)(v+3), v[2], out, 32, &n) || n != 32) abort();
        v[0] = 0; v[1] = fault("hmac-short") ? 31 : 32;
        memcpy(v+2, out, 32); explicit_bzero(key, 32); explicit_bzero(out, 32); return 0;
    }
    default: abort(); /* Includes every OTP write / key generation tag. */
    }
}
