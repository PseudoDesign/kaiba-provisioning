/* Bounded, trusted-operator development. No provisioning/admission authority. */
#include "harness.h"
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <ext2fs/ext2_fs.h>
#include <fcntl.h>
#include <libcryptsetup.h>
#include <libdevmapper.h>
#include <linux/fs.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "tool-digests.h"

#define SCHEMA "kaiba.enrollment-storage-development/v1alpha1"
#define RUNTIME_SCHEMA "kaiba.enrollment-storage-runtime/v1alpha1"
#define BASE "/run/kaiba-enrollment-storage"
#define MOUNT BASE "/volume"
#define CREDENTIALS MOUNT "/credentials"
#define LINEAR "kaiba-secret-experiment-container"
#define OPENED "kaiba-secret-experiment-open"
#define DEVICE "/dev/mapper/" OPENED
#ifdef KAIBA_TESTING
#define MODE "synthetic-development"
#else
#define MODE "development"
#endif
static volatile sig_atomic_t interrupted;
static void interrupt_run(int unused) { (void)unused; interrupted = 1; }
static const char *string(json_t *j, const char *key) {
    json_t *v = json_object_get(j, key); const char *s = json_string_value(v);
    return s && strlen(s) == json_string_length(v) ? s : NULL;
}
static bool same_string(json_t *j, const char *key, const char *want) {
    const char *s = string(j, key); return s && want && !strcmp(s, want);
}
static bool regular_private(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
        st.st_nlink == 1 && (st.st_mode & 07777) == 0600;
}
static bool directory(const char *path, bool create) {
    if (create && mkdir(path, 0700) && errno != EEXIST) return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st; bool ok = fd >= 0 && !fstat(fd, &st) && !st.st_uid && (st.st_mode & 07777) == 0700;
    if (fd >= 0 && close(fd)) ok = false;
    return ok;
}
static bool empty_directory(const char *path) {
    if (!directory(path, false)) return false;
    DIR *d = opendir(path); if (!d) return false;
    struct dirent *e; bool empty = true;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) empty = false;
    if (closedir(d)) empty = false;
    return empty;
}
static bool write_json(const char *path, json_t *j) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = regular_private(fd) && json_dumpfd(j, fd, JSON_COMPACT | JSON_SORT_KEYS) == 0 && fsync(fd) == 0;
    if (close(fd)) ok = false;
    return ok;
}
static json_t *load_json(const char *path, bool private) {
    if (private) {
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        bool ok = fd >= 0 && regular_private(fd);
        if (fd >= 0 && close(fd)) ok = false;
        if (!ok) return NULL;
    }
    char data[8192]; size_t n;
    if (!read_file(path, data, sizeof(data), &n)) return NULL;
    return json_loadb(data, n, JSON_REJECT_DUPLICATES, NULL);
}
static bool runtime_valid(json_t *r, const struct observation *o) {
    struct utsname u; uint8_t hash[32];
    const char *kernel = string(r, "kernel_release"), *firmware = string(r, "firmware_version");
    if (!json_is_object(r) || json_object_size(r) != 5 ||
        !same_string(r, "schema_version", RUNTIME_SCHEMA) || !kernel || !firmware ||
        !unhex(string(r, "boot_image_sha256"), hash, 32) ||
        !unhex(string(r, "verity_root_hash"), hash, 32) ||
        !same_string(r, "boot_image_sha256", o->boot_hash) ||
        !same_string(r, "verity_root_hash", o->root_hash) || uname(&u) || strcmp(kernel, u.release)) return false;
#ifdef KAIBA_TESTING
    return !strcmp(firmware, "synthetic-firmware");
#else
    char version[128]; size_t n;
    return read_file("/proc/device-tree/chosen/bootloader/version", version, sizeof(version), &n) &&
        n == strlen(firmware) + 1 && !memcmp(version, firmware, n);
#endif
}
static bool drivers_ready(void) {
    struct dm_task *t = dm_task_create(DM_DEVICE_LIST_VERSIONS);
    bool crypt = false, linear = false;
    if (t && dm_task_run(t)) {
        struct dm_versions *v = dm_task_get_versions(t);
        while (v) {
            if (!strcmp(v->name, "crypt")) crypt = true;
            if (!strcmp(v->name, "linear")) linear = true;
            if (!v->next) break;
            v = (struct dm_versions *)((char *)v + v->next);
        }
    }
    if (t) dm_task_destroy(t);
    return crypt && linear;
}
static bool linear_create(struct storage *s) {
    struct stat st; if (fstat(s->fd, &st)) return false;
    char params[128];
    snprintf(params, sizeof(params), "%u:%u %llu", major(st.st_rdev), minor(st.st_rdev), (unsigned long long)(DATA_START / 512));
    struct dm_task *t = dm_task_create(DM_DEVICE_CREATE);
    bool ok = t && dm_task_set_name(t, LINEAR) && dm_task_add_target(t, 0, (STORAGE_BYTES-DATA_START)/512, "linear", params) && dm_task_run(t);
    if (t) dm_task_destroy(t);
    if (ok) { s->linear = true; dm_task_update_nodes(); }
    return ok;
}
static bool volume_open(struct storage *s, const struct config *c, const uint8_t key[32]) {
    if (!linear_create(s)) return false;
    struct crypt_device *cd = NULL;
    bool ok = crypt_init(&cd, "/dev/mapper/" LINEAR) == 0;
    /* The existing storage experiment's uniformly derived passphrase profile. */
    struct crypt_pbkdf_type pbkdf = {.type = CRYPT_KDF_PBKDF2, .hash = "sha256", .iterations = 10000, .flags = CRYPT_PBKDF_NO_BENCHMARK};
    struct crypt_params_luks2 params = {.pbkdf = &pbkdf, .sector_size = 512, .label = "kaiba-development-enrollment"};
    if (ok && !s->phase) ok = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", c->volume, NULL, 64, &params) == 0 &&
        crypt_keyslot_add_by_volume_key(cd, 0, NULL, 0, (const char *)key, 32) == 0;
    if (ok && s->phase) ok = crypt_load(cd, CRYPT_LUKS2, NULL) == 0;
    if (ok) {
        for (int i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); ++i) {
            crypt_keyslot_info state = crypt_keyslot_status(cd, i);
            if ((i == 0 && state != CRYPT_SLOT_ACTIVE_LAST) || (i != 0 && state != CRYPT_SLOT_INACTIVE)) ok = false;
        }
    }
    if (ok) ok = crypt_get_uuid(cd) && !strcmp(crypt_get_uuid(cd), c->volume) && crypt_volume_key_keyring(cd, 0) == 0 &&
        crypt_activate_by_passphrase(cd, OPENED, 0, (const char *)key, 32, 0) == 0;
    if (ok) s->opened = true;
    if (cd) crypt_free(cd);
    return ok;
}
/* Only sibling static executables whose complete bytes were pinned at build
 * time. No shell, PATH lookup, ambient config or caller-selected executable. */
static int tool_open(const char *name, const char *digest) {
    char path[4096]; ssize_t n = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (n <= 0 || n == (ssize_t)sizeof(path)-1) return -1;
    path[n] = 0; char *slash = strrchr(path, '/'); if (!slash) return -1;
    *slash = 0;
    size_t used = strlen(path);
    if (snprintf(path+used, sizeof(path)-used, "/../libexec/%s", name) >= (int)(sizeof(path)-used)) return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st; uint8_t want[32], actual[32];
    bool ok = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && !st.st_uid &&
        !(st.st_mode & 0222) && st.st_size > 0 && st.st_size <= 16*1024*1024 && unhex(digest, want, 32);
    void *data = ok ? mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    ok = ok && data != MAP_FAILED && hash256(data, (size_t)st.st_size, actual) && constant_same(want, actual);
    if (data != MAP_FAILED) munmap(data, (size_t)st.st_size);
    if (!ok) { if (fd >= 0) close(fd); return -1; }
    return fd;
}
static bool tool_run(int fd, char *const args[]) {
    if (fd < 0 || interrupted) return false;
    pid_t child = fork(); if (child < 0) return false;
    if (!child) {
        int null = open("/dev/null", O_RDWR);
        if (null < 0 || dup2(null, 0) < 0 || dup2(null, 1) < 0 || dup2(null, 2) < 0) _exit(127);
        if (null > 2) close(null);
        alarm(120);
        char *env[] = {"LC_ALL=C", "PATH=/no-command-search", "MKE2FS_CONFIG=/dev/null", "E2FSPROGS_UNDO_DIR=/nonexistent", NULL};
        fexecve(fd, args, env); _exit(127);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return false;
        if (interrupted) kill(child, SIGTERM);
    }
    return !interrupted && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool filesystem_valid(const struct config *c) {
    int fd = open(DEVICE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    /* Device mapper nodes may be symlinks; resolve only the fixed mapping. */
    if (fd < 0 && errno == ELOOP) fd = open(DEVICE, O_RDONLY | O_CLOEXEC);
    struct ext2_super_block sb; char compact[33]; size_t at = 0; uint8_t uuid[16];
    for (const char *p = c->volume; *p; ++p) if (*p != '-') compact[at++] = *p;
    compact[at] = 0;
    bool ok = fd >= 0 && pread(fd, &sb, sizeof(sb), 1024) == sizeof(sb) &&
        le16toh(sb.s_magic) == EXT2_SUPER_MAGIC && le16toh(sb.s_state) == EXT2_VALID_FS &&
        unhex(compact, uuid, 16) && !memcmp(sb.s_uuid, uuid, 16);
    if (fd >= 0 && close(fd)) ok = false;
    return ok;
}
static bool mounted_device(dev_t expected) {
    struct stat root, opened; struct statfs fs;
    return !stat(MOUNT, &root) && !stat(DEVICE, &opened) && S_ISBLK(opened.st_mode) &&
        root.st_dev == expected && opened.st_rdev == expected && !statfs(MOUNT, &fs) &&
        fs.f_type == EXT2_SUPER_MAGIC && (fs.f_flags & 15) == 14 && directory(MOUNT, false) && directory(CREDENTIALS, false);
}
static bool journal_digest(int fd, char out[65]) {
    uint8_t journal[16384], digest[32];
    bool ok = pread(fd, journal, sizeof(journal), 0) == sizeof(journal) && hash256(journal, sizeof(journal), digest);
    if (ok) hex(digest, sizeof(digest), out);
    explicit_bzero(journal, sizeof(journal)); return ok;
}
static bool detach(struct storage *s) {
    int fd = s->fd; s->fd = -1;
    bool ok = storage_close(s); s->fd = fd; return ok;
}
static bool session_save(struct storage *s, const struct config *c, json_t *runtime, const struct observation *o) {
    struct stat opened, linear, partition; char binding[65], journal[65];
    if (stat(DEVICE, &opened) || stat("/dev/mapper/" LINEAR, &linear) || fstat(s->fd, &partition) ||
        !mounted_device(opened.st_rdev) || !journal_digest(s->fd, journal)) return false;
    hex(s->binding, 32, binding);
    json_t *j = json_pack("{s:s,s:O,s:O,s:s,s:i,s:s,s:s,s:I,s:I,s:I}",
        "schema_version", SCHEMA, "config", c->json, "runtime", runtime, "boot_id", o->boot_id,
        "phase", s->phase, "binding", binding, "journal", journal,
        "opened_device", (json_int_t)opened.st_rdev, "linear_device", (json_int_t)linear.st_rdev,
        "partition_device", (json_int_t)partition.st_rdev);
    bool ok = j && write_json(BASE "/session.json", j);
    if (j) json_decref(j);
    return ok;
}
static bool linear_matches(dev_t partition) {
    struct dm_task *t = dm_task_create(DM_DEVICE_TABLE); bool ok = false;
    if (t && dm_task_set_name(t, LINEAR) && dm_task_run(t)) {
        uint64_t start, length; char *type, *params;
        void *next = dm_get_next_target(t, NULL, &start, &length, &type, &params);
        char want[128]; snprintf(want, sizeof(want), "%u:%u %llu", major(partition), minor(partition), (unsigned long long)(DATA_START/512));
        ok = !next && !start && length == (STORAGE_BYTES-DATA_START)/512 && type && !strcmp(type,"linear") && params && !strcmp(params,want);
    }
    if (t) dm_task_destroy(t);
    return ok;
}
static bool partition_serial_matches(dev_t device, const struct config *c) {
#ifdef KAIBA_TESTING
    (void)device; (void)c; return true;
#else
    char path[256], serial[128], encoded[65]; size_t n; uint8_t digest[32];
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/../device/serial",major(device),minor(device));
    if (!read_file(path,serial,sizeof(serial),&n)) return false;
    while (n && (serial[n-1]=='\n' || serial[n-1]==' ' || serial[n-1]=='\t')) --n;
    if (!n || !hash256(serial,n,digest)) return false;
    hex(digest,32,encoded); return !strcmp(encoded,c->disk_hash);
#endif
}
static bool session_load(struct storage *s, const struct config *c, json_t *runtime, const struct observation *o) {
    json_t *j = load_json(BASE "/session.json", true); bool ok = false;
    struct stat opened, linear, partition; char path[128], journal[65], compact[33], want[128], actual[256]; size_t n, at=0;
    if (!json_is_object(j) || json_object_size(j) != 10 || !same_string(j,"schema_version",SCHEMA) ||
        !json_equal(json_object_get(j,"config"),c->json) || !json_equal(json_object_get(j,"runtime"),runtime) ||
        !same_string(j,"boot_id",o->boot_id) || !json_is_integer(json_object_get(j,"phase")) ||
        json_integer_value(json_object_get(j,"phase")) < 0 || json_integer_value(json_object_get(j,"phase")) > 1 ||
        !unhex(string(j,"binding"),s->binding,32)) goto done;
    s->phase = (unsigned)json_integer_value(json_object_get(j,"phase"));
    snprintf(path,sizeof(path),"/dev/disk/by-partuuid/%s",c->partition);
    s->fd = open(path,O_RDWR|O_CLOEXEC|O_NONBLOCK);
    uint64_t bytes; int sector, readonly;
    if (s->fd < 0 || flock(s->fd,LOCK_EX|LOCK_NB) || fstat(s->fd,&partition) || !S_ISBLK(partition.st_mode) ||
        ioctl(s->fd,BLKGETSIZE64,&bytes) || bytes != STORAGE_BYTES || ioctl(s->fd,BLKSSZGET,&sector) || sector != 512 ||
        ioctl(s->fd,BLKROGET,&readonly) || readonly || !partition_serial_matches(partition.st_rdev,c) ||
        stat(DEVICE,&opened) || stat("/dev/mapper/" LINEAR,&linear) ||
        !S_ISBLK(opened.st_mode) || !S_ISBLK(linear.st_mode) ||
        (json_int_t)opened.st_rdev != json_integer_value(json_object_get(j,"opened_device")) ||
        (json_int_t)linear.st_rdev != json_integer_value(json_object_get(j,"linear_device")) ||
        (json_int_t)partition.st_rdev != json_integer_value(json_object_get(j,"partition_device")) ||
        !mounted_device(opened.st_rdev) || !linear_matches(partition.st_rdev) ||
        !journal_digest(s->fd,journal) || !same_string(j,"journal",journal)) goto done;
    for (const char *p=c->volume; *p; ++p) if (*p!='-') compact[at++]=*p;
    compact[at]=0;
    snprintf(want,sizeof(want),"CRYPT-LUKS2-%s-%s\n",compact,OPENED);
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/dm/uuid",major(opened.st_rdev),minor(opened.st_rdev));
    if (!read_file(path,actual,sizeof(actual)-1,&n)) goto done;
    actual[n]=0;
    if (strcmp(actual,want)) goto done;
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/slaves",major(opened.st_rdev),minor(opened.st_rdev));
    DIR *d=opendir(path); if (!d) goto done;
    struct dirent *e; unsigned count=0; bool slave=true;
    while ((e=readdir(d))) {
        if (e->d_name[0]=='.') continue;
        char devpath[512], number[64], expected[64]; size_t size;
        snprintf(devpath,sizeof(devpath),"%s/%s/dev",path,e->d_name);
        snprintf(expected,sizeof(expected),"%u:%u\n",major(linear.st_rdev),minor(linear.st_rdev));
        if (!read_file(devpath,number,sizeof(number)-1,&size)) { slave=false; break; }
        number[size]=0; if (strcmp(number,expected)) slave=false;
        ++count;
    }
    if (closedir(d) || !slave || count!=1) goto done;
    s->linear=true; s->opened=true; ok=true;
done:
    if (j) json_decref(j);
    return ok;
}

int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--version")) { puts(SCHEMA " " MODE); return 0; }
    bool closing=argc==6 && !strcmp(argv[1],"close");
    if (argc!=6 || (!closing && strcmp(argv[1],"create") && strcmp(argv[1],"reopen")) ||
        strcmp(argv[4],"--expected-boot-id") || !uuid_valid(argv[5])) {
        fputs("Usage: kaiba-enrollment-storage create|reopen|close CONFIG RUNTIME --expected-boot-id UUID\n",stderr); return 2;
    }
    struct config c={0}; struct observation o={0}; struct storage s={.fd=-1};
    json_t *runtime=NULL; uint8_t key[32]={0}, message[128]={0}; size_t length;
    bool passed=false, mounted=false, lock_needed=false, locks_closed=false, storage_closed=false, journal_completed=false;
    bool leave_mounted=false; int mkfs=-1, fsck=-1; uint32_t count=0,status=0,usage=0;
    const char *stop="configuration", *cleanup="none";
    struct fw_diagnostic diagnostic={FW_INVALID,0,0};
    if (!config_load_schema(argv[2],&c,SCHEMA) || !(runtime=load_json(argv[3],false))) goto done;
    stop="memory-protection"; if (!memory_protect()) goto done;
    struct sigaction action={.sa_handler=interrupt_run}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT,&action,NULL) || sigaction(SIGTERM,&action,NULL) || sigaction(SIGALRM,&action,NULL)) goto done;
    alarm(180);
    stop="runtime-binding";
    if (!runtime_observe_development(&c,&o) || strcmp(o.boot_id,argv[5]) || !runtime_valid(runtime,&o)) goto done;
    /* Include firmware/kernel expectations in the shared journal's config
     * digest as well as checking them against this boot. Changing the reviewed
     * runtime file cannot silently reopen a volume created under another one. */
    if (json_object_set(c.json,"runtime_binding",runtime)) goto done;
    stop="runtime-directory";
    struct statfs runfs;
    if (statfs("/run",&runfs) || runfs.f_type!=0x01021994 || !directory(BASE,!closing)) goto done;
    if (closing) {
        stop="close-binding";
        if (!session_load(&s,&c,runtime,&o)) goto done;
        mounted=true;
        stop="close-intent";
        if (!write_json(BASE "/close.intent.json",c.json)) goto done;
        stop="unmount";
        if (interrupted || umount(MOUNT)) goto done;
        mounted=false;
        stop="mapping-cleanup"; if (!detach(&s)) goto done;
        stop="journal-completion";
        if (interrupted || !storage_complete(&s,&o)) goto done;
        journal_completed=true; passed=true; goto done;
    }
    stop="filesystem-tools";
    mkfs=tool_open("mke2fs",MKFS_SHA256); fsck=tool_open("e2fsck",FSCK_SHA256);
    if (mkfs<0 || fsck<0) goto done;
    stop="same-boot-repeat";
    if (!write_json(BASE "/open.intent.json",c.json)) goto done;
    stop="mount-prestate";
    if (!directory(MOUNT,true) || !empty_directory(MOUNT)) goto done;
    struct stat before,parent; if (stat(MOUNT,&before) || stat(BASE,&parent) || before.st_dev!=parent.st_dev) goto done;
    stop="storage-prestate";
    if (!storage_open(&s,&c,&o) || s.phase!=(unsigned)!strcmp(argv[1],"reopen")) goto done;
    stop="storage-drivers"; if (!drivers_ready()) goto done;
    stop="firmware-metadata";
    if (!fw_open() || fw_count(&count)!=FW_OK || count<c.slot || count>32 || fw_status(c.slot,&status)!=FW_OK ||
        !(status&DEVICE_TYPE) || status&~(DEVICE_TYPE|EARLY_LOCKS) || fw_usage(c.slot,&usage)!=FW_OK || usage!=c.usage) goto done;
    stop="durable-intent"; if (!storage_intent(&s,&o)) goto done;
    lock_needed=true;
    stop="apply-runtime-locks";
    if (interrupted || fw_set_locks(c.slot,DEVICE_TYPE|EARLY_LOCKS)!=FW_OK || fw_status(c.slot,&status)!=FW_OK || status!=(DEVICE_TYPE|EARLY_LOCKS)) goto done;
    stop="luks-derivation";
    if (interrupted || !derive_message("kaiba:enrollment-storage:luks2:v1",c.nonce,message,&length) || fw_hmac(c.slot,message,length,key)!=FW_OK) goto done;
    stop="volume-open"; if (interrupted || !volume_open(&s,&c,key)) goto done;
    explicit_bzero(key,sizeof(key)); explicit_bzero(message,sizeof(message));
    stop="close-runtime-locks";
    if (fw_set_locks(c.slot,DEVICE_TYPE|ALL_LOCKS)!=FW_OK || fw_status(c.slot,&status)!=FW_OK || status!=(DEVICE_TYPE|ALL_LOCKS)) {
        /* The attempted closure is never repeated automatically. */
        lock_needed=false; goto done;
    }
    lock_needed=false; locks_closed=true;
    if (!s.phase) {
        stop="filesystem-create";
        char *args[]={"mke2fs","-q","-F","-t","ext4","-b","4096","-m","0","-U",(char *)c.volume,
            "-O","has_journal,extent,64bit,flex_bg,metadata_csum,dir_index,filetype",
            "-E","lazy_itable_init=0,lazy_journal_init=0",DEVICE,NULL};
        if (!tool_run(mkfs,args)) goto done;
    }
    stop="filesystem-check";
    char *check[]={"e2fsck","-f","-n",DEVICE,NULL};
    if (!tool_run(fsck,check) || !filesystem_valid(&c)) goto done;
    stop="mount";
    if (interrupted || mount(DEVICE,MOUNT,"ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC,"data=ordered")) goto done;
    mounted=true;
    if (!s.phase) {
        stop="credential-directory";
        if (chmod(MOUNT,0700) || !directory(CREDENTIALS,true)) goto done;
    }
    stop="session-record";
    if (interrupted || !session_save(&s,&c,runtime,&o)) goto done;
    passed=true; leave_mounted=true;
done:
    diagnostic=fw_snapshot();
    explicit_bzero(key,sizeof(key)); explicit_bzero(message,sizeof(message));
    if (lock_needed) {
        bool set=fw_set_locks(c.slot,DEVICE_TYPE|ALL_LOCKS)==FW_OK;
        enum fw_result r=fw_status(c.slot,&status);
        locks_closed=set && r==FW_OK && status==(DEVICE_TYPE|ALL_LOCKS);
        if (!locks_closed) { passed=false; cleanup="runtime-locks"; }
    }
    fw_close();
    if (interrupted) { passed=false; leave_mounted=false; if (!strcmp(stop,"session-record")) stop="interrupted"; }
    if (!leave_mounted) {
        /* Once close preflight rejects a substituted mount, s owns no mappings.
         * Once a close attempt starts, a busy mount is preserved, never forced. */
        if (mounted) {
            if (closing || umount(MOUNT)) { cleanup="mounted-state-retained"; passed=false; }
            else mounted=false;
        }
        if (!mounted) {
            storage_closed=storage_close(&s);
            if (!storage_closed) { passed=false; cleanup="mapping-cleanup"; }
        } else if (s.fd>=0) { close(s.fd); s.fd=-1; }
    } else if (s.fd>=0) { if (close(s.fd)) passed=false; s.fd=-1; }
    if (mkfs>=0) close(mkfs);
    if (fsck>=0) close(fsck);
    alarm(0);
    json_t *result=json_pack("{s:s,s:s,s:s,s:s,s:b,s:s,s:s,s:b,s:b,s:b,s:b,s:b,s:b,s:i,s:i,s:i}",
        "schema_version",SCHEMA,"mode",MODE,"phase",argv[1],"boot_id",o.boot_id,"passed",passed,
        "stop",passed?"complete":stop,"cleanup_error",cleanup,"mounted",mounted,
        "runtime_locks_closed",locks_closed,"storage_closed",storage_closed,"journal_completed",journal_completed,
        "hardware_qualified",0,"production_enrollment",0,
        "last_firmware_outcome",diagnostic.outcome,"last_mailbox_tag",(int)diagnostic.tag,"last_mailbox_errno",diagnostic.error);
    if (result) {
        json_object_set_new(result,"experiment_id",json_string(c.experiment ? c.experiment : ""));
        json_object_set_new(result,"source_revision",json_string(c.source ? c.source : ""));
        json_object_set_new(result,"volume_uuid",json_string(c.volume ? c.volume : ""));
        json_object_set_new(result,"boot_image_sha256",json_string(o.boot_hash));
        json_object_set_new(result,"verity_root_hash",json_string(o.root_hash));
        json_object_set_new(result,"nonce_sha256",json_string(o.nonce_hash));
        json_object_set_new(result,"runtime_lock_readback_performed",json_boolean(!closing && locks_closed));
    }
    bool emitted=result && json_dumpf(result,stdout,JSON_COMPACT|JSON_SORT_KEYS)==0 && putchar('\n')!=EOF;
    if (result) json_decref(result);
    if (runtime) json_decref(runtime);
    if (c.json) json_decref(c.json);
    OPENSSL_cleanup(); munlockall();
    return passed && emitted ? 0 : 3;
}
