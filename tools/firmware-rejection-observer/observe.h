/* Public-only classification of the pinned firmware property-list ABI.
 * No payload byte, key, digest, address or request text leaves this function. */
#ifndef KAIBA_OBSERVE_H
#define KAIBA_OBSERVE_H
#if defined(KAIBA_BPF)
typedef __u32 u32;
typedef unsigned long size_t;
#include <stdbool.h>
#elif defined(__KERNEL__)
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef uint32_t u32;
#endif
#define OBS_WORDS 518
#define OBS_DONE 0x80000000U
struct observation {
 u32 tag;
 int result;
 bool request_valid, reply_valid, response_marked, operation_error;
 bool payload_unchanged_or_zero;
};
static inline unsigned int capacity_for(u32 tag)
{
 switch (tag) {
 case 0x30092: return 2060; /* HMAC */
 case 0x30091: return 128; /* signing */
 case 0x30094: return 1032; /* crypto private read */
 default: return 0;
 }
}
static inline bool request_valid(const u32 *v, size_t bytes)
{
 unsigned int cap;
 if (bytes < 12 || bytes > OBS_WORDS * 4 || bytes % 4) return false;
 cap=capacity_for(v[0]);
 if (!cap || v[1]!=cap || v[2]!=0 || bytes != (cap==128 ? 148 : cap+12)) return false;
 if (v[3]!=0 || v[4]<1 || v[4]>32) return false;
 if (v[0]==0x30092 && (!v[5] || v[5]>2048)) return false;
 if (v[0]==0x30091 && v[5]!=32) return false;
 return true;
}
static inline struct observation classify(const u32 *before, const u32 *after,
 size_t bytes, int result)
{
 struct observation o={0};
 size_t i;
 bool unchanged=true,zero=true;
 o.result=result;
 o.request_valid=request_valid(before,bytes);
 if (!o.request_valid) return o;
 o.tag=before[0];
 o.reply_valid=after[0]==before[0] && after[1]==before[1] &&
   (after[2]&~OBS_DONE)<=before[1];
 /* Signing has eight padding bytes after its payload. */
 for (i=0;i<OBS_WORDS;i++)
   if (i>=3+before[1]/4 && i<bytes/4 && after[i]!=before[i]) o.reply_valid=false;
 o.response_marked=(after[2]&OBS_DONE)!=0;
 o.operation_error=(after[3]&OBS_DONE)!=0;
 /* All returned data after the operation-status word: the original public
  * request or zeros are permitted; any new byte fails non-disclosure. */
 for (i=4;i<OBS_WORDS;i++) {
   if (i>=3+before[1]/4) break;
   if (after[i]!=before[i]) unchanged=false;
   if (after[i]!=0) zero=false;
 }
 o.payload_unchanged_or_zero=unchanged||zero;
 return o;
}
#endif
