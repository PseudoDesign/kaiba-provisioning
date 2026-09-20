#include "firmware.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t locks = DEVICE_TYPE, error_code;
static unsigned hmac_calls;
static bool fault(const char *s) {
    const char *v = getenv("KAIBA_TEST_FAULT"); return v && !strcmp(v, s);
}
int test_exchange(void *buffer, size_t size) {
    uint32_t *m = buffer, *v = m + 5, tag = m[2], cap = m[3];
    if (m[0] != size || m[1] || (m[4] && !((tag == 0x30024 && m[4] == 780) || (tag == 0x30081 && m[4] == 40))) || m[size/4-1]) abort();
    fprintf(stderr, "TAG %08x\n", tag);
    if (fault("transport") || (fault("raw-einval") && tag == 0x30094)) {
        error_code = 4; errno = EINVAL; return -1;
    }
    m[1] = 0x80000000; m[4] = 0x80000000 | cap;
    if (fault("malformed")) m[0]++;
    switch (tag) {
    case 0x3008f: v[0] = fault("no-slots") ? 0 : 1; return 0;
    case 0x30090: v[0] = fault("preclosed") ? DEVICE_TYPE | ALL_LOCKS : locks; return 0;
    case 0x3009c: v[0] = fault("usage-mismatch") ? 9 : 8; return 0;
    case 0x3008e:
        if (fault("last-error-io")) { errno = EIO; return -1; }
        if (fault("last-error-malformed")) m[0]++;
        v[0] = fault("last-error-other") ? 8 : error_code; return 0;
    case 0x38090:
        if (v[0] != 1 || (v[1] != (DEVICE_TYPE | EARLY_LOCKS) && v[1] != (DEVICE_TYPE | ALL_LOCKS)
#ifdef KAIBA_LOCK_CHECKS
            && v[1] != DEVICE_TYPE
#endif
        )) abort();
        if (!(fault("cleanup") && v[1] == (DEVICE_TYPE | ALL_LOCKS))) locks = fault("clearable-locks") ? v[1] : locks | v[1];
        if (fault("clear-io-after-effect") && v[1] == DEVICE_TYPE) {
            locks = DEVICE_TYPE; errno = EIO; return -1;
        }
        v[0] = 0; return 0;
    case 0x30094:
        if (cap != 1032 || v[0] || v[1] != 1 || !(locks & ARM_CRYPTO_KEY_STATUS_READ_LOCKED)) abort();
        if (fault("private-returned")) {
            v[0] = 0; v[1] = 32; memcpy(v+2, "PRIVATE_MATERIAL_MUST_NOT_ESCAPE!", 32); return 0;
        }
        v[0] = 0x80000000; error_code = 4; return 0;
#ifdef KAIBA_LOCK_CHECKS
    case 0x30024:
        if (v[0] != 3 || v[1] || v[2] != 8 || cap != 780) abort();
        v[0] = fault("legacy-unlocked") ? 0 : 0x80000000; return 0;
    case 0x30081:
        if (v[0] || v[1] != 8 || cap != 40) abort();
        errno = fault("legacy-io") ? EIO : EINVAL; return -1;
    case 0x30091:
        if (cap != 128 || size != 160 || v[0] || v[1] != 1 || v[2] != 32) abort();
        if (locks & ARM_CRYPTO_KEY_STATUS_SIGN_LOCKED) {
            error_code = 4;
            if (fault("sign-einval")) { errno = EINVAL; return -1; }
            if (fault("sign-timeout")) { errno = ETIMEDOUT; return -1; }
            if (fault("sign-unlocked")) { v[0]=0;v[1]=64;memset(v+2,0x5a,64);return 0; }
            v[0] = 0x80000000; return 0;
        }
        if (fault("interrupt-sign-control")) raise(SIGTERM);
        if (fault("sign-control")) { errno=EINVAL;return -1; }
        v[0]=0;v[1]=64;memset(v+2,0x5a,64);
        if (fault("sign-status")) v[0]=1;
        if (fault("sign-length")) v[1]=0;
        if (fault("sign-response-length")) m[4]=0x80000000|64;
        return 0;
#endif
    case 0x30092:
        if (cap != 2060 || v[0] || v[1] != 1 || !v[2] || v[2] > 2048) abort();
        ++hmac_calls;
        const char *fail_call = getenv("KAIBA_TEST_HMAC_FAIL_CALL");
        if (fail_call && hmac_calls == strtoul(fail_call, NULL, 10)) {
            const char *failure = getenv("KAIBA_TEST_HMAC_ERRNO");
            if (!failure) abort();
            error_code = 4;
            if (fault("hmac-interrupted")) raise(SIGTERM);
            errno = (int)strtoul(failure, NULL, 10); return -1;
        }
        if (locks & ARM_CRYPTO_KEY_STATUS_HMAC_LOCKED) {
            v[0] = 0x80000000; error_code = 4; return 0;
        }
        unsigned char result = (unsigned char)v[2];
        v[0] = 0; v[1] = fault("short-hmac") ? 31 : 32;
        memset(v+2, fault("no-separation") ? 0x42 : result, 32); return 0;
    default: abort(); /* In particular, no generation, usage write, sign, legacy. */
    }
}
