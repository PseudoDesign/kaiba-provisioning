/* Trusted-operator development comparison. Opens only a hash-bound tmpfs copy;
 * neither the completed source journal nor a physical disk is writable here. */
#include "harness.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <libcryptsetup.h>
#include <libdevmapper.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define SCHEMA "kaiba.copied-storage-comparison/v1alpha1"
#define RESULT "kaiba.copied-storage-result/v1alpha1"
#define MAPPING "kaiba-copied-storage-open"
#define CONTROL "/dev/shm/kaiba-copied-storage-control.img"
#ifdef KAIBA_TESTING
#define MODE "synthetic-development"
#else
#define MODE "development"
#endif
struct request {
    json_t *json;
    const char *role, *board, *kernel, *firmware, *image, *boot_image, *root;
    uint8_t challenge[32];
    uint32_t usage;
};
struct loop { int fd; bool attached; char path[64]; };
struct volume { struct crypt_device *cd; bool opened; };
struct journal {
    char magic[16]; uint32_t stage; uint8_t binding[32]; char boot[37];
    uint8_t reserved[3975]; uint8_t hash[32];
};
_Static_assert(sizeof(struct journal) == 4096, "journal block size");
static volatile sig_atomic_t interrupted;
static void interrupt_run(int unused) { (void)unused; interrupted = 1; }
static void quiet_crypt(int level, const char *text, void *unused) { (void)level; (void)text; (void)unused; }
static void quiet_dm(int level, const char *file, int line, int err, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)err; (void)format;
}
static bool test_fault(const char *name) {
#ifdef KAIBA_TESTING
    const char *value = getenv("KAIBA_TEST_FAULT"); return value && !strcmp(value, name);
#else
    (void)name; return false;
#endif
}
static const char *string(json_t *object, const char *key) {
    json_t *v = json_object_get(object, key); const char *s = json_string_value(v);
    return s && strlen(s) == json_string_length(v) ? s : NULL;
}
static bool digest(const char *s, size_t size) {
    uint8_t bytes[32], zero[32] = {0};
    return unhex(s, bytes, size) && memcmp(bytes, zero, size);
}
static json_t *safe_string(const char *value) { return json_string(value ? value : ""); }
static bool request_load(const char *path, struct request *r) {
    char bytes[8192]; size_t n;
    if (!read_file(path, bytes, sizeof(bytes), &n)) return false;
    r->json = json_loadb(bytes, n, JSON_REJECT_DUPLICATES, NULL);
    if (!json_is_object(r->json) || json_object_size(r->json) != 11) return false;
    const char *schema = string(r->json, "schema_version");
    r->role = string(r->json, "role"); r->board = string(r->json, "board_serial_sha256");
    r->kernel = string(r->json, "kernel_release"); r->firmware = string(r->json, "firmware_version");
    r->image = string(r->json, "image_sha256"); r->boot_image = string(r->json, "source_boot_image_sha256");
    r->root = string(r->json, "source_verity_root_hash");
    json_t *usage = json_object_get(r->json, "expected_usage");
    const char *challenge = string(r->json, "challenge_hex");
    const char *scheme = string(r->json, "scheme");
    if (!schema || strcmp(schema, SCHEMA) || !scheme || strcmp(scheme, SCHEME) || !r->role ||
        (strcmp(r->role, "original") && strcmp(r->role, "comparison")) ||
        !digest(r->board, 32) || !digest(r->image, 32) || !digest(r->boot_image, 32) || !digest(r->root, 32) ||
        !digest(r->firmware, 20) || !r->kernel || !*r->kernel || strlen(r->kernel) > 128 ||
        !digest(challenge, 32) || !unhex(challenge, r->challenge, 32) || !json_is_integer(usage) ||
        (json_integer_value(usage) != 0 && (json_integer_value(usage) < 8 || json_integer_value(usage) > 14))) return false;
    r->usage = (uint32_t)json_integer_value(usage);
    return true;
}
static bool source_config_load(const char *path, struct config *c) {
    char bytes[8192]; size_t n;
    if (!read_file(path, bytes, sizeof(bytes), &n)) return false;
    json_t *j = json_loadb(bytes, n, JSON_REJECT_DUPLICATES, NULL);
    const char *schema = string(j, "schema_version");
    bool offline = schema && !strcmp(schema, "kaiba.device-secret-storage-offline-development/v1alpha1");
    bool remote = schema && !strcmp(schema, "kaiba.device-secret-storage-development/v1alpha1");
    bool ok = (offline || remote) && config_load_schema(path, c, schema);
    if (j) json_decref(j);
    return ok;
}
static bool runtime(const struct request *r, const char *boot) {
    char bytes[256]; size_t n;
    if (!read_file("/proc/sys/kernel/random/boot_id", bytes, sizeof(bytes), &n) || n != 37 ||
        memcmp(bytes, boot, 36) || bytes[36] != '\n') return false;
#ifndef KAIBA_TESTING
    struct utsname u; uint8_t value[32]; char encoded[65];
    if (uname(&u) || strcmp(u.machine, "aarch64") || strcmp(u.release, r->kernel) ||
        !read_file("/proc/device-tree/serial-number", bytes, sizeof(bytes), &n) || n != 17 || bytes[16] ||
        !hash256(bytes, 16, value)) return false;
    hex(value, 32, encoded); if (strcmp(encoded, r->board)) return false;
    if (!read_file("/proc/device-tree/chosen/bootloader/version", bytes, sizeof(bytes), &n) ||
        n != 41 || bytes[40] || memcmp(bytes, r->firmware, 40)) return false;
#else
    (void)r;
#endif
    return true;
}
static bool drivers(void) {
    struct dm_task *task = dm_task_create(DM_DEVICE_LIST_VERSIONS); bool ready = false;
    if (task && dm_task_run(task)) {
        struct dm_versions *v = dm_task_get_versions(task);
        while (v) {
            if (!strcmp(v->name, "crypt")) ready = true;
            if (!v->next) break;
            v = (struct dm_versions *)((char *)v + v->next);
        }
    }
    if (task) dm_task_destroy(task);
    return ready;
}
static bool file_hash(int fd, char encoded[65]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); uint8_t block[65536], hash[32]; unsigned n;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    for (off_t off = 0; ok && off < (off_t)STORAGE_BYTES; off += sizeof(block))
        ok = pread(fd, block, sizeof(block), off) == sizeof(block) && EVP_DigestUpdate(ctx, block, sizeof(block)) == 1;
    if (ok) ok = EVP_DigestFinal_ex(ctx, hash, &n) == 1 && n == 32;
    if (ok) hex(hash, 32, encoded);
    EVP_MD_CTX_free(ctx); explicit_bzero(block, sizeof(block)); explicit_bzero(hash, sizeof(hash));
    return ok;
}
static bool completed_journal(int fd, const struct request *r, const struct config *c) {
    char *canonical = json_dumps(c->json, JSON_COMPACT | JSON_SORT_KEYS);
    if (!canonical) return false;
    char text[8192]; uint8_t binding[32];
    int size = snprintf(text, sizeof(text), "%s\n%s\n%s\n", canonical, r->boot_image, r->root);
    free(canonical);
    if (size < 0 || (size_t)size >= sizeof(text) || !hash256(text, (size_t)size, binding)) return false;
    struct journal blocks[4], expected;
    if (pread(fd, blocks, sizeof(blocks), 0) != sizeof(blocks)) return false;
    for (unsigned i = 0; i < 4; ++i) {
        if (blocks[i].boot[36] || !uuid_valid(blocks[i].boot)) return false;
        memset(&expected, 0, sizeof(expected)); memcpy(expected.magic, "KAIBA_SECRET_V1", 15);
        expected.stage = htole32(i+1); memcpy(expected.binding, binding, 32); memcpy(expected.boot, blocks[i].boot, 37);
        if (!hash256(&expected, sizeof(expected)-32, expected.hash) || memcmp(&expected, &blocks[i], sizeof(expected))) return false;
    }
    return !strcmp(blocks[0].boot, blocks[1].boot) && !strcmp(blocks[2].boot, blocks[3].boot) &&
        strcmp(blocks[0].boot, blocks[2].boot);
}
static bool ram_file(int fd, uint64_t size) {
    struct stat st; struct statfs fs;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 0077) &&
        st.st_nlink == 1 && (uint64_t)st.st_size == size && fstatfs(fd, &fs) == 0 && fs.f_type == TMPFS_MAGIC;
}
static bool loop_attach(struct loop *l, int fd, uint64_t offset, bool readonly) {
    int control = open("/dev/loop-control", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (control < 0) return false;
    int number = ioctl(control, LOOP_CTL_GET_FREE); close(control);
    if (number < 0) return false;
    snprintf(l->path, sizeof(l->path), "/dev/loop%d", number);
    l->fd = open(l->path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (l->fd < 0) return false;
    struct loop_config cfg = {.fd = (uint32_t)fd, .block_size = 512};
    cfg.info.lo_offset = offset; cfg.info.lo_sizelimit = STORAGE_BYTES-DATA_START;
    cfg.info.lo_flags = LO_FLAGS_AUTOCLEAR | (readonly ? LO_FLAGS_READ_ONLY : 0);
    if (ioctl(l->fd, LOOP_CONFIGURE, &cfg)) return false;
    l->attached = true;
    struct loop_info64 actual;
    return ioctl(l->fd, LOOP_GET_STATUS64, &actual) == 0 && actual.lo_offset == offset &&
        actual.lo_sizelimit == STORAGE_BYTES-DATA_START && actual.lo_flags == cfg.info.lo_flags;
}
static bool loop_close(struct loop *l) {
    bool ok = true;
    if (l->attached) {
        /* Linux may defer LOOP_CLR_FD while udev holds another descriptor.
         * Request it once, release our descriptor, then observe disappearance.
         * No repeated detach or crypto request; persistent holders fail. */
        ok = ioctl(l->fd, LOOP_CLR_FD) == 0;
        if (close(l->fd)) ok = false;
        l->fd = -1;
        char backing[128]; snprintf(backing, sizeof(backing), "/sys/block/%s/loop/backing_file", l->path+5);
        struct stat st;
        for (unsigned i = 0; i < 25; ++i) {
            if (lstat(backing, &st) < 0) {
                if (errno == ENOENT) l->attached = false;
                else ok = false;
                break;
            }
            struct timespec pause = {.tv_nsec = 200000000}; nanosleep(&pause, NULL);
        }
        if (l->attached) ok = false;
    }
    if (l->fd >= 0) { if (close(l->fd)) ok = false; l->fd = -1; }
    return ok;
}
static bool volume_close(struct volume *v) {
    if (v->opened) {
        if (crypt_deactivate(v->cd, MAPPING)) return false;
        v->opened = false;
    }
    if (v->cd) { crypt_free(v->cd); v->cd = NULL; }
    return true;
}
static bool volume_load(struct volume *v, const char *path, const char *uuid) {
    if (crypt_init(&v->cd, path) || crypt_load(v->cd, CRYPT_LUKS2, NULL) ||
        !crypt_get_uuid(v->cd) || strcmp(crypt_get_uuid(v->cd), uuid) ||
        !crypt_get_cipher(v->cd) || !crypt_get_cipher_mode(v->cd) ||
        strcmp(crypt_get_cipher(v->cd), "aes") || strcmp(crypt_get_cipher_mode(v->cd), "xts-plain64") ||
        crypt_get_volume_key_size(v->cd) != 64 || crypt_get_sector_size(v->cd) != 512 ||
        crypt_keyslot_status(v->cd, 0) != CRYPT_SLOT_ACTIVE_LAST || crypt_volume_key_keyring(v->cd, 0)) return false;
    return true;
}
/* The existing random record supplies a disposable test identity. This is not a
 * fleet credential or a new hardware signing mechanism. Seed stays in memory. */
static bool proof(const uint8_t record[4096], const uint8_t challenge[32], char public_hex[65], char signature_hex[129]) {
    static const char domain[] = "kaiba:copied-storage:fixture-identity:v1";
    uint8_t input[sizeof(domain)+128], seed[32], pub[32], signature[64];
    memcpy(input, domain, sizeof(domain)); memcpy(input+sizeof(domain), record+128, 128);
    EVP_PKEY *key = NULL; EVP_MD_CTX *ctx = NULL; size_t pn = sizeof(pub), sn = sizeof(signature);
    bool ok = hash256(input, sizeof(input), seed) &&
        (key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, seed, 32)) &&
        EVP_PKEY_get_raw_public_key(key, pub, &pn) == 1 && pn == 32 && (ctx = EVP_MD_CTX_new()) &&
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, signature, &sn, challenge, 32) == 1 && sn == 64;
    if (ok) ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, signature, sn, challenge, 32) == 1;
    if (ok) { hex(pub, 32, public_hex); hex(signature, 64, signature_hex); }
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    explicit_bzero(input, sizeof(input)); explicit_bzero(seed, sizeof(seed));
    explicit_bzero(pub, sizeof(pub)); explicit_bzero(signature, sizeof(signature));
    return ok;
}
static bool record_check(int fd, const char *uuid, const uint8_t key[32], const uint8_t challenge[32],
                         bool create, char pub[65], char signature[129]) {
    uint8_t record[4096] = {0}, mac[32] = {0}; size_t n = 0; bool ok = true;
    if (create) {
        memcpy(record, "KAIBA_PRIVATE_RECORD_V1", 23); memcpy(record+32, uuid, 36);
        ok = RAND_bytes(record+128, 128) == 1 &&
            EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, record, sizeof(record)-32, mac, 32, &n) && n == 32;
        if (ok) { memcpy(record+sizeof(record)-32, mac, 32); ok = pwrite(fd, record, sizeof(record), 0) == sizeof(record) && fsync(fd) == 0; }
    }
    explicit_bzero(record, sizeof(record));
    if (ok) ok = pread(fd, record, sizeof(record), 0) == sizeof(record) &&
        !memcmp(record, "KAIBA_PRIVATE_RECORD_V1", 23) && !memcmp(record+32, uuid, 36) &&
        EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, record, sizeof(record)-32, mac, 32, &n) && n == 32 &&
        CRYPTO_memcmp(mac, record+sizeof(record)-32, 32) == 0 && proof(record, challenge, pub, signature);
    explicit_bzero(record, sizeof(record)); explicit_bzero(mac, sizeof(mac)); return ok;
}
static bool control_run(struct volume *v, const struct loop *l, const struct config *c, const struct request *r,
                        const uint8_t key[32], const uint8_t mac[32]) {
    struct crypt_pbkdf_type pbkdf = {.type = CRYPT_KDF_PBKDF2, .hash = "sha256", .iterations = 10000, .flags = CRYPT_PBKDF_NO_BENCHMARK};
    struct crypt_params_luks2 params = {.pbkdf = &pbkdf, .sector_size = 512, .label = "kaiba-disposable-comparison-control"};
    char pub[65] = {0}, signature[129] = {0}, reopened_pub[65] = {0};
    if (crypt_init(&v->cd, l->path) ||
        crypt_format(v->cd, CRYPT_LUKS2, "aes", "xts-plain64", c->volume, NULL, 64, &params) ||
        crypt_keyslot_add_by_volume_key(v->cd, 0, NULL, 0, (const char *)key, 32) != 0 ||
        crypt_volume_key_keyring(v->cd, 0) || crypt_activate_by_passphrase(v->cd, MAPPING, 0, (const char *)key, 32, 0) != 0) return false;
    v->opened = true;
    int fd = open("/dev/mapper/" MAPPING, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    /* /dev/mapper nodes are normally symlinks; resolve only this fixed mapping. */
    if (fd < 0 && errno == ELOOP) fd = open("/dev/mapper/" MAPPING, O_RDWR | O_CLOEXEC);
    bool ok = fd >= 0 && record_check(fd, c->volume, mac, r->challenge, true, pub, signature);
    if (fd >= 0 && close(fd)) ok = false;
    if (!volume_close(v)) return false;
    if (!ok || !volume_load(v, l->path, c->volume)) return false;
    uint8_t wrong[32] = {0};
    if (crypt_activate_by_passphrase(v->cd, MAPPING, 0, (const char *)(test_fault("control-reopen") ? wrong : key), 32, CRYPT_ACTIVATE_READONLY) != 0) return false;
    v->opened = true;
    fd = open("/dev/mapper/" MAPPING, O_RDONLY | O_CLOEXEC);
    ok = fd >= 0 && record_check(fd, c->volume, mac, r->challenge, false, reopened_pub, signature) && !strcmp(pub, reopened_pub);
    if (fd >= 0 && close(fd)) ok = false;
    if (!volume_close(v)) ok = false;
    return ok;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts(RESULT " " MODE "; hardware_qualified=false"); return 0; }
    bool validate = argc == 4 && !strcmp(argv[1], "--check-config");
    if (!validate && !(argc == 7 && !strcmp(argv[1], "run") && !strcmp(argv[5], "--expected-boot-id") && uuid_valid(argv[6]))) {
        fputs("Usage: copied storage --version | --check-config CONFIG SOURCE_CONFIG | run CONFIG SOURCE_CONFIG IMAGE --expected-boot-id UUID\n", stderr); return 2;
    }
    struct request r = {0}; struct config c = {0};
    struct loop source_loop = {.fd = -1}, control_loop = {.fd = -1};
    struct volume source = {0}, control = {0};
    int image_fd = -1, control_fd = -1; bool control_created = false, locks_needed = false;
    bool passed = false, locks_closed = false, storage_closed = false, unchanged = false, image_is_ram = false;
    bool control_verified = false, source_key_accepted = false, source_unlocked = false, source_verified = false, rejected = false;
    uint8_t key[32] = {0}, mac[32] = {0}, repeat[32] = {0}, zero[32] = {0}, message[128] = {0}; size_t size;
    uint32_t count = 0, status = 0, usage = 0; char encoded[65] = {0}, public_hex[65] = {0}, signature_hex[129] = {0};
    const char *stop = "configuration"; int source_rc = 0;
    struct fw_diagnostic diagnostic = {FW_INVALID, 0, 0};
    if (!request_load(argv[2], &r) || !source_config_load(argv[3], &c) ||
        ((!strcmp(r.role, "original")) != (!strcmp(r.board, c.board_hash))) ||
        (!strcmp(r.role, "original") && r.usage != c.usage)) goto done;
    if (validate) { json_decref(r.json); json_decref(c.json); return 0; }
    stop = "memory-protection"; if (!memory_protect()) goto done;
    struct sigaction action = {.sa_handler = interrupt_run}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) || sigaction(SIGALRM, &action, NULL)) goto done;
    alarm(180);
    crypt_set_log_callback(NULL, quiet_crypt, NULL); dm_log_with_errno_init(quiet_dm);
    stop = "runtime-identity"; if (!runtime(&r, argv[6])) goto done;
    stop = "source-copy";
    image_fd = open(argv[4], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (image_fd < 0 || !ram_file(image_fd, STORAGE_BYTES)) goto done;
    image_is_ram = true;
    if (flock(image_fd, LOCK_SH | LOCK_NB) ||
        !file_hash(image_fd, encoded) || strcmp(encoded, r.image) || !completed_journal(image_fd, &r, &c)) goto done;
    stop = "storage-drivers"; if (!drivers()) goto done;
    stop = "storage-prestate";
    if (access("/dev/mapper/" MAPPING, F_OK) == 0 || access(CONTROL, F_OK) == 0 ||
        !loop_attach(&source_loop, image_fd, DATA_START, true) || !volume_load(&source, source_loop.path, c.volume)) goto done;
    stop = "same-boot-repeat";
    int once = open("/run/kaiba-copied-storage-attempted", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (once < 0) goto done;
    bool marked = write(once, argv[6], 36) == 36 && fsync(once) == 0;
    if (close(once) || !marked) goto done;
    stop = "control-file";
    control_fd = open(CONTROL, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (control_fd < 0) goto done;
    control_created = true;
    if (ftruncate(control_fd, STORAGE_BYTES-DATA_START) || !ram_file(control_fd, STORAGE_BYTES-DATA_START) ||
        !loop_attach(&control_loop, control_fd, 0, false)) goto done;
    stop = "firmware-metadata";
    if (!fw_open() || fw_count(&count) != FW_OK || count < 1 || count > 32 ||
        fw_status(1, &status) != FW_OK || !(status & DEVICE_TYPE) || status & ~(DEVICE_TYPE | EARLY_LOCKS) ||
        fw_usage(1, &usage) != FW_OK || usage != r.usage) goto done;
    locks_needed = true;
    stop = "apply-runtime-locks";
    if (interrupted || fw_set_locks(1, DEVICE_TYPE | EARLY_LOCKS) != FW_OK ||
        fw_status(1, &status) != FW_OK || status != (DEVICE_TYPE | EARLY_LOCKS)) goto done;
    stop = "luks-derivation";
    if (interrupted || !derive_message("kaiba:protected-state:luks2:v1", c.nonce, message, &size) || fw_hmac(1, message, size, key) != FW_OK) goto done;
    stop = "canary-derivation";
    if (interrupted || !derive_message("kaiba:protected-state:canary:v1", c.nonce, message, &size) || fw_hmac(1, message, size, mac) != FW_OK) goto done;
    stop = "hmac-positive-control";
    if (interrupted || constant_same(key, zero) || constant_same(mac, zero) || constant_same(key, mac) ||
        !derive_message("kaiba:protected-state:luks2:v1", c.nonce, message, &size) ||
        fw_hmac(1, message, size, repeat) != FW_OK || !constant_same(key, repeat)) goto done;
    explicit_bzero(repeat, sizeof(repeat));
    stop = "local-positive-control";
    if (interrupted || !control_run(&control, &control_loop, &c, &r, key, mac)) goto done;
    control_verified = true;
    stop = "source-unlock";
    if (interrupted) goto done;
    /* name=NULL checks the passphrase without requesting a kernel mapping.
     * A device-mapper permission failure must not count as a wrong-key result. */
    source_rc = crypt_activate_by_passphrase(source.cd, NULL, 0, (const char *)key, 32, 0);
    if (source_rc >= 0) {
        source_key_accepted = true;
        if (strcmp(r.role, "original")) { stop = "unexpected-source-key"; goto done; }
        stop = "source-activation";
        if (interrupted || crypt_activate_by_passphrase(source.cd, MAPPING, 0, (const char *)key, 32, CRYPT_ACTIVATE_READONLY) != 0) goto done;
        source.opened = true; source_unlocked = true;
        stop = "source-record";
        int fd = open("/dev/mapper/" MAPPING, O_RDONLY | O_CLOEXEC);
        source_verified = fd >= 0 && record_check(fd, c.volume, mac, r.challenge, false, public_hex, signature_hex);
        if (fd >= 0 && close(fd)) source_verified = false;
        if (!source_verified) goto done;
        passed = true;
    } else if (source_rc == -EPERM && !strcmp(r.role, "comparison")) { rejected = true; passed = true; }
done:
    diagnostic = fw_snapshot();
    explicit_bzero(key, sizeof(key)); explicit_bzero(mac, sizeof(mac));
    explicit_bzero(repeat, sizeof(repeat)); explicit_bzero(message, sizeof(message));
    /* Cleanup's successful mailbox calls can clear the global error. Preserve
     * the original operation diagnostic above, then make one metadata query
     * before cleanup. This is uncorrelated diagnostic data, never a pass, a
     * retry or proof that the source passphrase was rejected. */
    if (!interrupted && diagnostic.outcome == FW_IO && diagnostic.tag == 0x30092) {
        uint32_t error = 0;
        enum fw_result query = fw_error(&error);
        struct fw_diagnostic observed = fw_snapshot();
        fprintf(stderr, "KAIBA_COPIED_STORAGE_LAST_ERROR query_outcome=%u query_errno=%d available=%s value=%u transaction_correlated=false\n",
                (unsigned)query, observed.error, query == FW_OK ? "true" : "false", query == FW_OK ? error : 0);
    }
    if (locks_needed) {
        bool set = fw_set_locks(1, DEVICE_TYPE | ALL_LOCKS) == FW_OK;
        locks_closed = fw_status(1, &status) == FW_OK && set && status == (DEVICE_TYPE | ALL_LOCKS);
        if (!locks_closed) { passed = false; stop = "cleanup-locks"; }
    }
    fw_close();
    bool a = volume_close(&source), b = volume_close(&control);
    bool x = loop_close(&source_loop), y = loop_close(&control_loop);
    storage_closed = a && b && x && y;
    if (control_fd >= 0 && close(control_fd)) storage_closed = false;
    if (control_created && storage_closed && unlink(CONTROL)) storage_closed = false;
    if (!storage_closed) { passed = false; stop = "storage-cleanup"; }
    if (image_fd >= 0) {
        unchanged = image_is_ram && r.image && file_hash(image_fd, encoded) && !strcmp(encoded, r.image);
        if (close(image_fd)) unchanged = false;
    }
    if (passed && !unchanged) { passed = false; stop = "source-changed"; }
    alarm(0); if (interrupted) { passed = false; stop = "interrupted"; }
    json_t *out = json_object();
#define S(k,v) json_object_set_new(out, k, safe_string(v))
#define B(k,v) json_object_set_new(out, k, json_boolean(v))
#define I(k,v) json_object_set_new(out, k, json_integer(v))
    S("schema_version", RESULT); S("mode", MODE); S("role", r.role); S("stop", passed ? "complete" : stop);
    S("boot_id", validate ? "" : argv[6]); S("board_serial_sha256", r.board); S("image_sha256", r.image);
    S("firmware_version", r.firmware); S("kernel_release", r.kernel); S("volume_uuid", c.volume);
    S("source_boot_image_sha256", r.boot_image); S("source_verity_root_hash", r.root);
    char nonce[65] = {0}, challenge[65] = {0}; hex(c.nonce, 32, nonce); hex(r.challenge, 32, challenge);
    S("nonce_hex", nonce); S("challenge_hex", challenge); I("expected_usage", r.usage);
    S("fixture_public_key_hex", public_hex); S("fixture_signature_hex", signature_hex);
    B("passed", passed); B("local_control_verified", control_verified); B("source_unlocked", source_unlocked);
    B("source_key_accepted", source_key_accepted);
    B("source_record_verified", source_verified); B("copied_fixture_rejected", rejected);
    B("runtime_locks_closed", locks_closed); B("storage_closed", storage_closed); B("image_unchanged", unchanged);
    B("hardware_qualified", false); B("fleet_identity_qualified", false); B("lock_rejection_qualified", false);
    I("source_unlock_return_code", source_rc); I("last_firmware_outcome", diagnostic.outcome);
    I("last_mailbox_tag", diagnostic.tag); I("last_mailbox_errno", diagnostic.error);
    bool emitted = out && json_dumpf(out, stdout, JSON_COMPACT | JSON_SORT_KEYS) == 0 && putchar('\n') != EOF;
    json_decref(out); if (r.json) json_decref(r.json); if (c.json) json_decref(c.json);
    OPENSSL_cleanup(); munlockall();
    return passed && emitted ? 0 : 3;
}
