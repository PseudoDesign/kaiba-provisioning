#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "observe.h"
struct event { struct observation value; u32 complete,copy_failed; };
static pid_t child;
static int attaches;
static int fault(const char *name) { const char *v=getenv("FAULT");return v&&!strcmp(v,name); }
static void trace(const char *s) { FILE *f=fopen(getenv("TRACE"),"a");assert(f);fprintf(f,"%s\n",s);fclose(f); }
uid_t geteuid(void) { return 0; }
int uname(struct utsname *u) { memset(u,0,sizeof(*u));strcpy(u->machine,"aarch64");return 0; }
struct bpf_object *bpf_object__open_file(const char *p,const struct bpf_object_open_opts *o) { (void)p;(void)o;return (void *)1; }
long libbpf_get_error(const void *p) { return p?0:-1; }
int bpf_object__load(struct bpf_object *o) { (void)o;trace("load");return fault("load")?-1:0; }
void bpf_object__close(struct bpf_object *o) { (void)o;trace("close"); }
int bpf_object__find_map_fd_by_name(const struct bpf_object *o,const char *s) { (void)o;return !strcmp(s,"target")?1:!strcmp(s,"stats")?2:3; }
int bpf_map_update_elem(int fd,const void *key,const void *value,__u64 flags) { (void)fd;(void)key;(void)flags;child=*(const u32 *)value;trace("target");return fault("target")?-1:0; }
struct bpf_program *bpf_object__next_program(const struct bpf_object *o,struct bpf_program *p) { (void)o;return (uintptr_t)p<2?(void *)((uintptr_t)p+1):NULL; }
struct bpf_link *bpf_program__attach(const struct bpf_program *p) { (void)p;trace("attach");return ++attaches==2&&fault("attach")?NULL:(void *)1; }
int bpf_link__destroy(struct bpf_link *l) {
 (void)l;trace("detach");
 if (child&&!fault("attach")&&!fault("target")) {
  siginfo_t info={0};assert(waitid(P_PID,child,&info,WEXITED|WNOHANG|WNOWAIT)==0&&info.si_pid==child);
 }
 return 0;
}
int bpf_map_lookup_elem(int fd,const void *key,void *v) {
 if (fd==2) { u32 *s=v;s[0]=4;s[1]=0;return fault("stats")?-1:0; }
 struct event *e=v;memset(e,0,sizeof(*e));e->complete=1;e->value.tag=0x30092;
 if (*(const u32 *)key==3) e->value.result=-22;
 return fault("event")?-1:0;
}
