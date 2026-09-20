// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#define KAIBA_BPF
#include "observe.h"
/* Fixed AArch64 register ABI; no kernel structure offsets or BTF relocation. */
struct registers { __u64 regs[31],sp,pc,pstate; };
struct pending { __u64 buffer,bytes; u32 before[OBS_WORDS]; u32 sequence; };
struct event { struct observation value; u32 complete,copy_failed; };
struct counters { u32 count,rejected; };
#define ARRAY_MAP(name,value_type,n) struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,n); __type(key,u32); __type(value,value_type); } name SEC(".maps")
ARRAY_MAP(target,u32,1);
ARRAY_MAP(stats,struct counters,1);
ARRAY_MAP(events,struct event,32);
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1); __type(key,__u64); __type(value,struct pending); } pending SEC(".maps");
struct scratch { struct pending p; u32 after[OBS_WORDS]; };
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,u32); __type(value,struct scratch); } scratch SEC(".maps");
static __always_inline void wipe(volatile u32 *v) {
 for (u32 i=0;i<OBS_WORDS;i++) v[i]=0;
}
SEC("kprobe/rpi_firmware_property_list")
int enter(struct registers *ctx) {
 u32 zero=0;
 __u64 tid=bpf_get_current_pid_tgid();
 u32 *pid=bpf_map_lookup_elem(&target,&zero);
 if (!pid || (tid>>32)!=*pid) return 0;
 struct counters *s=bpf_map_lookup_elem(&stats,&zero);
 struct scratch *w=bpf_map_lookup_elem(&scratch,&zero);
 if (!s || !w) return 0;
 __u64 bytes=ctx->regs[2];
 if (bytes<12 || bytes>sizeof(w->p.before) || bytes%4 ||
     bpf_probe_read_kernel(w->p.before,bytes,(void *)ctx->regs[1])) goto reject;
 if (!capacity_for(w->p.before[0])) goto done;
 if (!request_valid(w->p.before,bytes) || s->count>=32 || bpf_map_lookup_elem(&pending,&tid)) goto reject;
 w->p.buffer=ctx->regs[1];w->p.bytes=bytes;w->p.sequence=s->count++;
 if (bpf_map_update_elem(&pending,&tid,&w->p,BPF_NOEXIST)) goto reject;
 goto done;
reject:
 __sync_fetch_and_add(&s->rejected,1);
done:
 wipe(w->p.before);((volatile struct pending *)&w->p)->buffer=0;((volatile struct pending *)&w->p)->bytes=0;((volatile struct pending *)&w->p)->sequence=0;
 return 0;
}
SEC("kretprobe/rpi_firmware_property_list")
int leave(struct registers *ctx) {
 __u64 tid=bpf_get_current_pid_tgid();u32 zero=0;
 struct pending *p=bpf_map_lookup_elem(&pending,&tid);
 if (!p) return 0;
 struct scratch *w=bpf_map_lookup_elem(&scratch,&zero);
 struct event *e=bpf_map_lookup_elem(&events,&p->sequence);
 if (!w || !e) goto done;
 __u64 bytes=p->bytes;
 if (!bytes || bytes>sizeof(w->after) || bpf_probe_read_kernel(w->after,bytes,(void *)p->buffer)) e->copy_failed=1;
 else e->value=classify(p->before,w->after,bytes,(int)ctx->regs[0]);
 wipe(w->after);e->complete=1;
done:
 wipe(p->before);((volatile struct pending *)p)->buffer=0;((volatile struct pending *)p)->bytes=0;
 bpf_map_delete_elem(&pending,&tid);
 return 0;
}
char LICENSE[] SEC("license")="GPL";
