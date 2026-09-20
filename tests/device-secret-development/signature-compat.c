#include "firmware.h"
#include "signature-shape.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
static uint8_t signature[128];
static uint32_t length=70, reported=40;
static unsigned bad, calls;
static void valid(void) {
    memset(signature,0x5a,sizeof(signature));
    signature[0]=0x30;signature[1]=68;signature[2]=2;signature[3]=32;signature[36]=2;signature[37]=32;
    length=70;reported=40;bad=0;
}
int test_exchange(void *raw,size_t size) {
    uint32_t *m=raw;assert(m[2]==0x30091 && size==160);++calls;
    m[1]=0x80000000;m[4]=0x80000000|reported;m[5]=0;m[6]=length;
    memcpy(m+7,signature,120);
    if(bad==1){errno=EINVAL;return -1;}
    if(bad==2)m[5]=1;
    if(bad==3)m[2]++;
    if(bad==4)m[4]=40;
    if(bad==5)m[size/4-1]=1;
    return 0;
}
static enum fw_result run(void) {calls=0;enum fw_result r=fw_sign(1);assert(calls==1);return r;}
int main(void) {
    valid();assert(p256_der_signature(signature,70));
    for(size_t n=0;n<70;n++)assert(!p256_der_signature(signature,n));
    assert(!p256_der_signature(signature,71));
    /* Short canonical values, zero, negative, padded, order and over-order. */
    uint8_t tiny[]={0x30,6,2,1,1,2,1,1};assert(p256_der_signature(tiny,sizeof(tiny)));
    tiny[4]=0;assert(!p256_der_signature(tiny,sizeof(tiny)));
    tiny[4]=0x80;assert(!p256_der_signature(tiny,sizeof(tiny)));
    uint8_t padded[]={0x30,7,2,2,0,1,2,1,1};assert(!p256_der_signature(padded,sizeof(padded)));
    padded[5]=0x80;assert(p256_der_signature(padded,sizeof(padded)));
    uint8_t order[]={0,0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
    assert(!p256_der_scalar(order,33));order[32]--;assert(p256_der_scalar(order,33));
    order[32]+=2;assert(!p256_der_scalar(order,33));
    valid();assert(fw_open());
#ifdef KAIBA_LOCK_CHECKS
    assert(run()==FW_OK);assert(!strcmp(fw_validation_reason(),"development-signature-length-compat"));
    assert(fw_sign_response_lengths().present);
    for(unsigned n=0;n<78;n++) {
        if(n==40)continue;
        reported=n;assert(run()==FW_INVALID);
    }
    reported=78;assert(run()==FW_OK);assert(!fw_sign_response_lengths().present);
    for(unsigned n=1;n<=5;n++){valid();bad=n;assert(run()!=FW_OK);}
    for(unsigned n=0;n<6;n++) {
        valid();
        if(n==0)signature[0]=0x31;
        if(n==1)signature[1]=0x81;
        if(n==2)signature[3]=33;
        if(n==3)signature[4]=0x80;
        if(n==4)signature[4]=0;
        if(n==5)signature[36]=3;
        assert(run()==FW_INVALID);assert(!strcmp(fw_validation_reason(),"signature-der-shape"));
    }
    valid();length=128;assert(run()==FW_INVALID); /* allocated but not P-256 DER */
    valid();length=129;assert(run()==FW_INVALID); /* rejected before parsing */
#else
    assert(run()==FW_INVALID); /* Qualification never takes the exception. */
    assert(!strcmp(fw_validation_reason(),"output-outside-response"));
    reported=78;assert(run()==FW_OK);
#endif
    fw_close();puts("signature compatibility boundaries passed");
}
