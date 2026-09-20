#include "harness.h"
#include <dirent.h>
#include <endian.h>
#include <fcntl.h>
#include <libcryptsetup.h>
#include <libdevmapper.h>
#include <linux/fs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define LINEAR "kaiba-secret-experiment-container"
#define OPENED "kaiba-secret-experiment-open"
struct journal {
    char magic[16]; uint32_t stage; uint8_t binding[32]; char boot[37];
    uint8_t reserved[3975]; uint8_t hash[32];
};
_Static_assert(sizeof(struct journal) == 4096, "journal block size");
static void quiet_crypt(int level, const char *message, void *unused) { (void)level; (void)message; (void)unused; }
static void quiet_dm(int level, const char *file, int line, int dm_errno, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)dm_errno; (void)format;
}
static bool all_zero(const void *v, size_t size) {
    const uint8_t *b = v; uint8_t value = 0;
    for (size_t i = 0; i < size; ++i) value |= b[i];
    return value == 0;
}
static bool journal_make(struct journal *j, unsigned stage, const uint8_t binding[32], const char *boot) {
    memset(j, 0, sizeof(*j)); memcpy(j->magic, "KAIBA_SECRET_V1", 15);
    j->stage = htole32(stage); memcpy(j->binding, binding, 32); memcpy(j->boot, boot, 37);
    return hash256(j, sizeof(*j)-32, j->hash);
}
static bool journal_valid(const struct journal *j, unsigned stage, const uint8_t binding[32]) {
    if (j->boot[36] || !uuid_valid(j->boot)) return false;
    struct journal expected;
    bool ok = journal_make(&expected, stage, binding, j->boot) && memcmp(&expected, j, sizeof(expected)) == 0;
    explicit_bzero(&expected, sizeof(expected)); return ok;
}
static bool checkpoint(struct storage *s, unsigned stage, const char *boot) {
    struct journal previous, next, actual;
    off_t offset = (off_t)(stage-1) * 4096;
    bool ok = pread(s->fd, &previous, sizeof(previous), offset) == sizeof(previous) && all_zero(&previous, sizeof(previous)) &&
        journal_make(&next, stage, s->binding, boot) && pwrite(s->fd, &next, sizeof(next), offset) == sizeof(next) &&
        fsync(s->fd) == 0 && pread(s->fd, &actual, sizeof(actual), offset) == sizeof(actual) && !memcmp(&actual, &next, sizeof(next));
    explicit_bzero(&previous, sizeof(previous)); explicit_bzero(&next, sizeof(next)); explicit_bzero(&actual, sizeof(actual));
    return ok;
}
static bool empty_holders(unsigned ma, unsigned mi) {
    char path[128]; snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/holders", ma, mi);
    DIR *dir = opendir(path); if (!dir) return false;
    struct dirent *e; bool empty = true;
    while ((e = readdir(dir))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) empty = false;
    if (closedir(dir)) empty = false;
    return empty;
}
static bool device_identity(int fd, const struct config *c) {
    struct stat st; uint64_t size = 0; int readonly = 1, sector = 0;
    if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || st.st_uid || ioctl(fd, BLKGETSIZE64, &size) || size != STORAGE_BYTES ||
        ioctl(fd, BLKROGET, &readonly) || readonly || ioctl(fd, BLKSSZGET, &sector) || sector != 512 ||
        !empty_holders(major(st.st_rdev), minor(st.st_rdev))) return false;
    FILE *mounts = fopen("/proc/self/mountinfo", "re");
    if (!mounts) return false;
    char line[4096]; bool unmounted = true;
    while (fgets(line, sizeof(line), mounts)) {
        unsigned a, b, ma, mi;
        if (sscanf(line, "%u %u %u:%u", &a, &b, &ma, &mi) != 4 ||
            (ma == major(st.st_rdev) && mi == minor(st.st_rdev))) unmounted = false;
    }
    if (ferror(mounts) || fclose(mounts)) unmounted = false;
    if (!unmounted) return false;
#ifdef KAIBA_TESTING
    (void)c;
    return true;
#else
    char path[256], part[32], serial[128], encoded[65]; uint8_t digest[32]; size_t n;
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/partition", major(st.st_rdev), minor(st.st_rdev));
    if (!read_file(path, part, sizeof(part), &n) || !n) return false;
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/../device/serial", major(st.st_rdev), minor(st.st_rdev));
    if (!read_file(path, serial, sizeof(serial), &n)) return false;
    while (n && (serial[n-1] == '\n' || serial[n-1] == ' ' || serial[n-1] == '\t')) --n;
    if (!n || !hash256(serial, n, digest)) return false;
    hex(digest, 32, encoded);
    return strcmp(encoded, c->disk_hash) == 0;
#endif
}
bool storage_open(struct storage *s, const struct config *c, const struct observation *o) {
    s->fd = -1;
    crypt_set_log_callback(NULL, quiet_crypt, NULL); dm_log_with_errno_init(quiet_dm);
    if (access("/dev/mapper/" LINEAR, F_OK) == 0 || access("/dev/mapper/" OPENED, F_OK) == 0) return false;
    char path[128]; snprintf(path, sizeof(path), "/dev/disk/by-partuuid/%s", c->partition);
    s->fd = open(path, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (s->fd < 0 || flock(s->fd, LOCK_EX | LOCK_NB) || !device_identity(s->fd, c)) return false;
    char *encoded = json_dumps(c->json, JSON_COMPACT | JSON_SORT_KEYS);
    if (!encoded) return false;
    size_t length = strlen(encoded);
    char binding[8192];
    int size = snprintf(binding, sizeof(binding), "%s\n%s\n%s\n", encoded, o->boot_hash, o->root_hash);
    free(encoded);
    if (length > 7000 || size < 0 || (size_t)size >= sizeof(binding) || !hash256(binding, (size_t)size, s->binding)) return false;
    struct journal j[4];
    if (pread(s->fd, j, sizeof(j), 0) != sizeof(j)) return false;
    if (all_zero(j, sizeof(j))) {
        /* First creation requires the entire approved 65 MiB partition blank. */
        uint8_t block[65536];
        for (uint64_t offset = 0; offset < STORAGE_BYTES; offset += sizeof(block)) {
            if (pread(s->fd, block, sizeof(block), (off_t)offset) != sizeof(block) || !all_zero(block, sizeof(block))) return false;
        }
        s->phase = 0;
    } else {
        if (!journal_valid(&j[0], 1, s->binding) || !journal_valid(&j[1], 2, s->binding) ||
            strcmp(j[0].boot, j[1].boot) || !strcmp(j[0].boot, o->boot_id) ||
            !all_zero(&j[2], sizeof(j[2])) || !all_zero(&j[3], sizeof(j[3]))) return false;
        s->phase = 1; memcpy(s->prior_boot, j[0].boot, 37);
    }
    explicit_bzero(j, sizeof(j));
    return true;
}
bool storage_intent(struct storage *s, const struct observation *o) { return checkpoint(s, s->phase ? 3 : 1, o->boot_id); }
bool storage_complete(struct storage *s, const struct observation *o) { return checkpoint(s, s->phase ? 4 : 2, o->boot_id); }

static bool linear_create(struct storage *s) {
    struct stat st; if (fstat(s->fd, &st)) return false;
    char params[128]; snprintf(params, sizeof(params), "%u:%u %llu", major(st.st_rdev), minor(st.st_rdev), (unsigned long long)(DATA_START/512));
    struct dm_task *task = dm_task_create(DM_DEVICE_CREATE);
    if (!task) return false;
    bool ok = dm_task_set_name(task, LINEAR) && dm_task_add_target(task, 0, (STORAGE_BYTES-DATA_START)/512, "linear", params) && dm_task_run(task);
    dm_task_destroy(task);
    if (ok) { s->linear = true; dm_task_update_nodes(); }
    return ok;
}
static bool canary(int fd, unsigned phase, const struct config *c, const uint8_t key[32]) {
    /* Authenticated private random test record inside the LUKS mapping. Nothing
     * persists outside it except public journal and LUKS metadata. */
    uint8_t record[4096] = {0}, mac[32] = {0}; size_t n = 0;
    bool ok;
    if (!phase) {
        memcpy(record, "KAIBA_PRIVATE_RECORD_V1", 23); memcpy(record+32, c->volume, 36);
        ok = RAND_bytes(record+128, 128) == 1 &&
            EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, record, sizeof(record)-32, mac, 32, &n) && n == 32;
        if (ok) {
            memcpy(record+sizeof(record)-32, mac, 32);
            ok = pwrite(fd, record, sizeof(record), 0) == sizeof(record) && fsync(fd) == 0;
        }
    } else ok = true;
    explicit_bzero(record, sizeof(record));
    if (ok) ok = pread(fd, record, sizeof(record), 0) == sizeof(record) &&
        !memcmp(record, "KAIBA_PRIVATE_RECORD_V1", 23) && !memcmp(record+32, c->volume, 36) &&
        EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, record, sizeof(record)-32, mac, 32, &n) && n == 32 &&
        CRYPTO_memcmp(record+sizeof(record)-32, mac, 32) == 0;
    explicit_bzero(record, sizeof(record)); explicit_bzero(mac, sizeof(mac));
    return ok;
}
bool storage_volume(struct storage *s, const struct config *c, const uint8_t key[32], const uint8_t canary_key[32]) {
    struct crypt_device *cd = NULL;
    if (!linear_create(s)) return false;
    bool ok = crypt_init(&cd, "/dev/mapper/" LINEAR) == 0;
    struct crypt_pbkdf_type pbkdf = {.type = CRYPT_KDF_PBKDF2, .hash = "sha256", .iterations = 10000, .flags = CRYPT_PBKDF_NO_BENCHMARK};
    struct crypt_params_luks2 params = {.pbkdf = &pbkdf, .sector_size = 512, .label = "kaiba-disposable-experiment"};
    /* A uniformly derived 256-bit passphrase, never a human password. Fixed
     * PBKDF cost avoids a benchmark and is only an experiment profile. */
    if (ok && !s->phase) ok = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", c->volume, NULL, 64, &params) == 0 &&
        crypt_keyslot_add_by_volume_key(cd, 0, NULL, 0, (const char *)key, 32) == 0;
    if (ok && s->phase) ok = crypt_load(cd, CRYPT_LUKS2, NULL) == 0;
    if (ok) ok = crypt_get_uuid(cd) && !strcmp(crypt_get_uuid(cd), c->volume) &&
        crypt_volume_key_keyring(cd, 0) == 0 &&
        crypt_activate_by_passphrase(cd, OPENED, 0, (const char *)key, 32, s->phase ? CRYPT_ACTIVATE_READONLY : 0) == 0;
    if (ok) {
        s->opened = true;
        int fd = open("/dev/mapper/" OPENED, (s->phase ? O_RDONLY : O_RDWR) | O_CLOEXEC);
        ok = fd >= 0 && canary(fd, s->phase, c, canary_key);
        if (fd >= 0 && close(fd)) ok = false;
    }
    if (s->opened) {
        if (crypt_deactivate(cd, OPENED) == 0) s->opened = false;
        else ok = false;
    }
    if (cd) crypt_free(cd);
    return ok;
}
bool storage_close(struct storage *s) {
    bool ok = true;
    if (s->opened) {
        if (crypt_deactivate(NULL, OPENED) == 0) s->opened = false;
        else ok = false;
    }
    if (s->linear) {
        struct dm_task *task = dm_task_create(DM_DEVICE_REMOVE);
        /* udev/blkid can briefly hold a newly created container, especially
         * after a fast wrong-key rejection. The pinned libdevmapper bounds
         * EBUSY-only REMOVE retries to 25 x 200 ms; it neither defers deletion
         * nor retries format, unlock, writes or firmware calls. Persistent
         * holders still fail cleanup and leave the attempt stopped. */
        if (!task || !dm_task_set_name(task, LINEAR) || !dm_task_retry_remove(task) || !dm_task_run(task)) ok = false;
        else s->linear = false;
        if (task) dm_task_destroy(task);
        dm_task_update_nodes();
    }
    if (s->fd >= 0) { if (close(s->fd)) ok = false; s->fd = -1; }
    return ok;
}
