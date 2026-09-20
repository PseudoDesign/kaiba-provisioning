#include "observe.h"
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
static void setup(u32 *v,u32 tag) {
 memset(v,0,OBS_WORDS*4);v[0]=tag;v[1]=capacity_for(tag);v[4]=1;
 if (tag==0x30092 || tag==0x30091) { v[5]=32;v[6]=0x5a5a5a5a; }
}
int main(void) {
 u32 a[OBS_WORDS],b[OBS_WORDS];struct observation o;
 u32 tags[]={0x30092,0x30091,0x30094};
 for (unsigned int i=0;i<3;i++) {
  setup(a,tags[i]);size_t bytes=tags[i]==0x30091?148:12+a[1];
  assert(request_valid(a,bytes));
  memcpy(b,a,sizeof(b));b[2]=OBS_DONE|a[1];b[3]=OBS_DONE;
  o=classify(a,b,bytes,-EINVAL);
  assert(o.request_valid&&o.reply_valid&&o.response_marked&&o.operation_error&&o.payload_unchanged_or_zero);
  /* Even the complete observation is not promoted to FW_LOCKED/pass. */
  assert(o.result==-EINVAL);
  b[10]=0x73656372;assert(!classify(a,b,bytes,-EINVAL).payload_unchanged_or_zero);
  memcpy(b,a,sizeof(b));b[2]=OBS_DONE|a[1];b[3]=OBS_DONE;
  memset(b+4,0,a[1]-4);assert(classify(a,b,bytes,-EINVAL).payload_unchanged_or_zero);
  b[0]++;assert(!classify(a,b,bytes,-EINVAL).reply_valid);b[0]--;
  b[1]++;assert(!classify(a,b,bytes,-EINVAL).reply_valid);b[1]--;
  b[2]=OBS_DONE|(a[1]+4);assert(!classify(a,b,bytes,-EINVAL).reply_valid);
  memcpy(b,a,sizeof(b));o=classify(a,b,bytes,-ETIMEDOUT);
  assert(!o.response_marked&&!o.operation_error&&o.result==-ETIMEDOUT);
  a[2]=OBS_DONE;assert(!request_valid(a,bytes));
 }
 setup(a,0x30092);
 for (size_t bytes=0;bytes<2072;bytes++)assert(!request_valid(a,bytes));
 a[4]=0;assert(!request_valid(a,2072));a[4]=33;assert(!request_valid(a,2072));a[4]=1;
 a[5]=0;assert(!request_valid(a,2072));a[5]=2049;assert(!request_valid(a,2072));
 setup(a,0x30091);memcpy(b,a,sizeof(b));b[36]=1;assert(!classify(a,b,148,0).reply_valid);
 setup(a,0x30095);assert(!request_valid(a,16)); /* Never observes generation. */
 puts("classifier: reply corruption, disclosure, transport and request bounds passed");
 return 0;
}
