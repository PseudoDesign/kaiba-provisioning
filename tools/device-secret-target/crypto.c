#include "harness.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

bool hash256(const void *data, size_t size, uint8_t out[32]) {
    unsigned n = 0;
    return EVP_Digest(data, size, out, &n, EVP_sha256(), NULL) == 1 && n == 32;
}
void hex(const uint8_t *in, size_t n, char *out) {
    const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[i*2] = digits[in[i] >> 4]; out[i*2+1] = digits[in[i] & 15]; }
    out[n*2] = 0;
}
bool unhex(const char *in, uint8_t *out, size_t n) {
    static const char digits[] = "0123456789abcdef";
    if (!in || strlen(in) != n*2) return false;
    for (size_t i = 0; i < n; ++i) {
        const char *a = strchr(digits, in[i*2]);
        const char *b = strchr(digits, in[i*2+1]);
        if (!a || !b) return false;
        out[i] = (uint8_t)(((a-digits) << 4) | (b-digits));
    }
    return true;
}
bool constant_same(const uint8_t a[32], const uint8_t b[32]) { return CRYPTO_memcmp(a, b, 32) == 0; }

/* Reuses firmware-hmac-v1's one-block counter construction from
 * nixos-raspberrypi d3360e0b/pkgs/raspberrypi/rpi-otp-derived-key.nix.
 * Salt is purpose || NUL || public nonce. This explicitly named Kaiba scheme
 * produces 32 binary bytes; it never migrates or opens an existing host keyslot.
 * [1]_32be || "rpi-otp-derived-key:firmware-hmac-v1:raw" || NUL
 *          || SHA256(salt) || [256]_32be
 */
bool derive_message(const char *purpose, const uint8_t nonce[32], uint8_t *out, size_t *size) {
    const char label[] = "rpi-otp-derived-key:firmware-hmac-v1:raw";
    uint8_t salt[128] = {0}, context[32] = {0};
    size_t n = strlen(purpose);
    if (n > 90) return false;
    memcpy(salt, purpose, n);
    memcpy(salt+n+1, nonce, 32);
    bool ok = hash256(salt, n+1+32, context);
    if (ok) {
        const uint8_t counter[4] = {0,0,0,1}, bits[4] = {0,0,1,0};
        memcpy(out, counter, 4); memcpy(out+4, label, sizeof(label));
        memcpy(out+4+sizeof(label), context, 32);
        memcpy(out+4+sizeof(label)+32, bits, 4);
        *size = 4+sizeof(label)+32+4;
    }
    explicit_bzero(salt, sizeof(salt)); explicit_bzero(context, sizeof(context));
    return ok;
}
