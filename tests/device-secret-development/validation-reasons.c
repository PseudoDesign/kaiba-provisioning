/* Synthetic response metadata only. This executable never opens hardware. */
#include "firmware.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
static const char *fault;
static unsigned calls;
#define IS(s) (!strcmp(fault, s))
int test_exchange(void *raw, size_t size) {
    uint32_t *m=raw, *v=m+5;
    ++calls;
    if (m[2] == 0x3008e) {
        assert(IS("error-query-failed")); errno=EIO; return -1;
    }
    assert(m[2]==0x30091 && size==160);
    m[1]=0x80000000; m[4]=0x80000000|128;
    v[0]=0; v[1]=64; memset(v+2,0x5a,64);
    if (IS("transport")) { errno=EINVAL;return -1; }
    if (IS("ioctl-return")) return 1;
    if (IS("message-size")) m[0]++;
    if (IS("message-code")) m[1]++;
    if (IS("tag-id")) m[2]++;
    if (IS("tag-capacity")) m[3]++;
    if (IS("response-unmarked")) m[4]=128;
    if (IS("response-over-capacity")) m[4]=0x80000000|129;
    if (IS("end-tag")) m[size/4-1]=1;
    if (IS("operation-status")) v[0]=1;
    if (IS("output-too-short")) v[1]=0;
    if (IS("output-too-long")) v[1]=129;
    if (IS("output-outside-response")) m[4]=0x80000000|64;
    if (IS("error-slot-changed")) {v[0]=0x80000000;v[1]=2;}
    if (IS("error-payload-changed")) {v[0]=0x80000000;v[1]=1;}
    if (IS("error-query-failed")) {v[0]=0x80000000;v[1]=0;memset(v+2,0,120);}
    return 0;
}
int main(void) {
    const char *cases[]={"ioctl-return","message-size","message-code","tag-id","tag-capacity",
      "response-unmarked","response-over-capacity","end-tag","operation-status","output-too-short",
      "output-too-long","output-outside-response","error-slot-changed","error-payload-changed","error-query-failed"};
    assert(fw_open());
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        fault=cases[i];calls=0;
        assert(fw_sign(1)==FW_INVALID);
        assert(!strcmp(fw_validation_reason(),fault));
        assert(calls==(IS("error-query-failed")?2U:1U));
        /* Reading diagnostics neither mutates the reason nor calls firmware. */
        assert(fw_snapshot().outcome==FW_INVALID);
        assert(!strcmp(fw_validation_reason(),fault));
        fault="valid";calls=0;assert(fw_sign(1)==FW_OK);
        assert(!strcmp(fw_validation_reason(),"none") && calls==1);
    }
    fault="operation-status";assert(fw_sign(1)==FW_INVALID);
    fault="transport";assert(fw_sign(1)==FW_IO);
    assert(!strcmp(fw_validation_reason(),"none"));
    fw_close();puts("15 rejection reasons and reset behavior passed");
}
