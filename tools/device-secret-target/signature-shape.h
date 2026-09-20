/* DER shape/range validation only, NOT signature verification. */
#ifndef KAIBA_SIGNATURE_SHAPE_H
#define KAIBA_SIGNATURE_SHAPE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
static bool p256_der_scalar(const uint8_t *p, size_t n) {
    static const uint8_t order[32] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
    };
    if (!n || n>33 || (p[0]&0x80)) return false;
    if (p[0]==0) {
        if (n==1 || !(p[1]&0x80)) return false; /* zero or redundant sign padding */
        ++p;--n;
    }
    if (n>32) return false;
    return n<32 || memcmp(p,order,32)<0;
}
static bool p256_der_signature(const uint8_t *p, size_t n) {
    if (n<8 || n>72 || p[0]!=0x30 || p[1]!=n-2) return false;
    size_t at=2;
    for (unsigned i=0;i<2;i++) {
        if (at+2>n || p[at++]!=0x02) return false;
        size_t bytes=p[at++];
        if (bytes>n-at || !p256_der_scalar(p+at,bytes)) return false;
        at+=bytes;
    }
    return at==n;
}
#endif
