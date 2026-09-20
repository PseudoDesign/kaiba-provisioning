#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "observe.h"
struct event { struct observation value; u32 complete,copy_failed; };
struct counters { u32 count,rejected; };
static volatile sig_atomic_t interrupted;
static void stop(int sig) { (void)sig;interrupted=1; }
static const char *boolean(int b) { return b?"true":"false"; }
int main(int argc,char **argv) {
 /* Both file paths are exact reviewed packet inputs; no mailbox parameters
  * other than the existing helper's bounded slot/usage/boot configuration. */
 bool verify_only=argc==3&&!strcmp(argv[1],"--verify-only");
 if (!verify_only&&argc!=6) { fprintf(stderr,"usage: observer OBJECT HELPER SLOT USAGE BOOT_UUID\n");return 2; }
 struct utsname uts;
 struct rlimit zero={0,0};
 if (geteuid() || uname(&uts) || strcmp(uts.machine,"aarch64") ||
     setrlimit(RLIMIT_CORE,&zero) || prctl(PR_SET_DUMPABLE,0)) return 2;
 if (signal(SIGTERM,stop)==SIG_ERR || signal(SIGINT,stop)==SIG_ERR) return 2;
 struct bpf_object *obj=bpf_object__open_file(verify_only?argv[2]:argv[1],NULL);
 if (libbpf_get_error(obj)) return 3;
 if (bpf_object__load(obj)) { bpf_object__close(obj);return 3; }
 if (verify_only) {
  struct bpf_link *links[2]={0};unsigned int n=0;bool ok=true;
  struct bpf_program *prog;
  bpf_object__for_each_program(prog,obj) {
   if (n>=2) { ok=false;break; }
   struct bpf_link *link=bpf_program__attach(prog);
   if (libbpf_get_error(link)) { ok=false;break; }
   links[n++]=link;
  }
  for (unsigned int i=0;i<n;i++) bpf_link__destroy(links[i]);
  bpf_object__close(obj);
  if (ok&&n==2&&!interrupted) { puts("OBSERVER_PREFLIGHT passed; no helper or firmware operation");return 0; }
  return 3;
 }
 int gate[2];
 if (pipe2(gate,O_CLOEXEC)) { bpf_object__close(obj);return 3; }
 pid_t child=fork();
 if (child<0) { close(gate[0]);close(gate[1]);bpf_object__close(obj);return 3; }
 if (!child) {
  signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);
  close(gate[1]);
  if (prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()==1) _exit(125);
  char go=0;
  if (read(gate[0],&go,1)!=1 || go!='G') _exit(125);
  close(gate[0]);
  execl(argv[2],argv[2],"hmac","--slot-id",argv[3],"--expected-usage",argv[4],"--expected-boot-id",argv[5],(char *)NULL);
  _exit(125);
 }
 close(gate[0]);
 struct bpf_link *links[2]={0};unsigned n=0;bool released=false,observed_exit=false,natural_exit=false;
 int exitcode=3,status=0,pidfd=(int)syscall(SYS_pidfd_open,child,0);
 u32 key=0,pid=(u32)child;
 int target=bpf_object__find_map_fd_by_name(obj,"target");
 if (pidfd<0 || bpf_map_update_elem(target,&key,&pid,BPF_ANY)) goto cleanup;
 struct bpf_program *prog;
 bpf_object__for_each_program(prog,obj) {
  if (n>=2) goto cleanup;
  struct bpf_link *link=bpf_program__attach(prog);
  if (libbpf_get_error(link)) goto cleanup;
  links[n++]=link;
 }
 if (n!=2 || interrupted) goto cleanup;
 if (write(gate[1],"G",1)!=1) goto cleanup;
 released=true;close(gate[1]);gate[1]=-1;
 /* Never reap until probes detach: a zombie retains its numeric PID, so a
  * new process cannot inherit this filter. The helper's own bound is 30s. */
 struct pollfd pfd={.fd=pidfd,.events=POLLIN};
 for (unsigned tick=0;tick<450 && !interrupted;tick++) {
  int r=poll(&pfd,1,100);
  if (r>0 && (pfd.revents&POLLIN)) { observed_exit=true;natural_exit=true;break; }
  if (r<0 && errno!=EINTR) break;
 }
cleanup:
 if (!observed_exit) {
  kill(child,SIGTERM);
  struct pollfd pfd={.fd=pidfd,.events=POLLIN};
  if (pidfd>=0 && poll(&pfd,1,5000)>0 && (pfd.revents&POLLIN)) observed_exit=true;
  if (!observed_exit) kill(child,SIGKILL);
 }
 for (unsigned i=0;i<n;i++) bpf_link__destroy(links[i]);
 if (gate[1]>=0) close(gate[1]);
 if (pidfd>=0) close(pidfd);
 pid_t waited;
 do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
 struct counters counters={0};
 bool complete=waited==child&&released&&natural_exit&&!interrupted&&WIFEXITED(status);
 if (bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj,"stats"),&key,&counters) || counters.count>32) complete=false;
 struct event results[32]={0};
 int map=bpf_object__find_map_fd_by_name(obj,"events");
 for (u32 i=0;i<counters.count&&i<32;i++) {
  if (bpf_map_lookup_elem(map,&i,&results[i]) || !results[i].complete || results[i].copy_failed) complete=false;
 }
 printf("KAIBA_FIRMWARE_OBSERVER={\"schema_version\":\"kaiba.firmware-rejection-observation/v1alpha1\",\"complete\":%s,\"helper_exit\":%d,\"rejected\":%u,\"hardware_qualified\":false,\"events\":[",boolean(complete),WIFEXITED(status)?WEXITSTATUS(status):-1,counters.rejected);
 for (u32 i=0;i<counters.count&&i<32;i++) {
  struct event e=results[i];
  struct observation *o=&e.value;
  printf("%s{\"sequence\":%u,\"complete\":%s,\"copy_failed\":%s,\"tag\":%u,\"result\":%d,\"request_valid\":%s,\"reply_valid\":%s,\"response_marked\":%s,\"operation_error\":%s,\"payload_unchanged_or_zero\":%s}",i?",":"",i,boolean(e.complete),boolean(e.copy_failed),o->tag,o->result,boolean(o->request_valid),boolean(o->reply_valid),boolean(o->response_marked),boolean(o->operation_error),boolean(o->payload_unchanged_or_zero));
 }
 puts("]}");
 /* Exit zero denotes completed observation, never helper success. */
 if (complete) exitcode=0;
 bpf_object__close(obj);return exitcode;
}
