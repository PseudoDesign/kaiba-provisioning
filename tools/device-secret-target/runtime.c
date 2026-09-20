#include "harness.h"
#include <dirent.h>
#include <fcntl.h>
#include <libdevmapper.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>

bool memory_protect(void) {
    struct rlimit zero = {0,0};
    char swaps[4096]; size_t n;
    if (geteuid() || !read_file("/proc/swaps", swaps, sizeof(swaps)-1, &n)) return false;
    swaps[n] = 0;
    char *line = strchr(swaps, '\n');
    if (!line || line[1] || setrlimit(RLIMIT_CORE, &zero) || prctl(PR_SET_DUMPABLE, 0)) return false;
    /* Cover internal library and mailbox copies as well as application buffers. */
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) return false;
    return mlockall(MCL_CURRENT | MCL_FUTURE) == 0;
}

#ifndef KAIBA_TESTING
static bool observed_root(char digest[65]) {
    struct dm_task *task = dm_task_create(DM_DEVICE_TABLE);
    struct dm_info info = {0}; struct stat root; struct statvfs fs;
    bool ok = false;
    if (!task || !dm_task_set_name(task, "root") || !dm_task_run(task) ||
        !dm_task_get_info(task, &info) || !info.exists || !info.read_only ||
        stat("/", &root) || statvfs("/", &fs) || !(fs.f_flag & ST_RDONLY) ||
        root.st_dev != makedev(info.major, info.minor)) goto done;
    uint64_t start = 0, length = 0; char *type = NULL, *params = NULL;
    void *next = dm_get_next_target(task, NULL, &start, &length, &type, &params);
    if (next || start || !length || !type || strcmp(type, "verity") || !params || strlen(params) > 1024) goto done;
    char copy[1025]; strcpy(copy, params);
    char *save = NULL, *items[11] = {0}; size_t count = 0;
    for (char *p = strtok_r(copy, " ", &save); p && count < 11; p = strtok_r(NULL, " ", &save)) items[count++] = p;
    uint8_t bytes[32];
    if (count != 10 || strcmp(items[0], "1") || strcmp(items[3], "4096") || strcmp(items[4], "4096") ||
        strcmp(items[7], "sha256") || !unhex(items[8], bytes, 32)) goto done;
    memcpy(digest, items[8], 65); ok = true;
done:
    if (task) dm_task_destroy(task);
    return ok;
}
#endif

static bool observe(const struct config *c, struct observation *o, bool require_isolation) {
    uint8_t digest[32], property[64], signed_bits[4]; size_t n;
    if (!hash256(c->nonce, 32, digest)) return false;
    hex(digest, 32, o->nonce_hash);
    if (!read_file("/proc/sys/kernel/random/boot_id", o->boot_id, 36, &n)) {
        char boot[38];
        if (!read_file("/proc/sys/kernel/random/boot_id", boot, sizeof(boot), &n) || n != 37 || boot[36] != '\n') return false;
        memcpy(o->boot_id, boot, 36);
    }
    o->boot_id[36] = 0;
    if (!uuid_valid(o->boot_id)) return false;
#ifdef KAIBA_TESTING
    (void)property; (void)signed_bits; (void)require_isolation;
    memset(o->boot_hash, 'b', 64); o->boot_hash[64] = 0;
    memset(o->root_hash, 'c', 64); o->root_hash[64] = 0;
    return true;
#else
    struct utsname u;
    if (uname(&u) || strcmp(u.machine, "aarch64")) return false;
    if (!read_file("/proc/device-tree/chosen/bootloader/signed", signed_bits, 4, &n) || n != 4 || !(signed_bits[3] & 8)) return false;
    if (!read_file("/proc/device-tree/chosen/bootloader/boot_img_sha256", property, 64, &n) || n != 64) return false;
    uint8_t zero[32] = {0};
    if (memcmp(property+32, zero, 32) || !memcmp(property, zero, 32)) return false;
    hex(property, 32, o->boot_hash);
    char serial[65], serial_hash[65];
    if (!read_file("/proc/device-tree/serial-number", serial, sizeof(serial), &n) || n != 17 || serial[16]) return false;
    for (size_t i = 0; i < 16; ++i) if (!strchr("0123456789abcdef", serial[i])) return false;
    if (!hash256(serial, 16, digest)) return false;
    hex(digest, 32, serial_hash);
    if (strcmp(serial_hash, c->board_hash)) return false;
    if (!observed_root(o->root_hash)) return false;
    if (!require_isolation) return true;
    DIR *net = opendir("/sys/class/net");
    if (!net) return false;
    bool isolated = true; struct dirent *entry;
    while ((entry = readdir(net))) {
        if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo")) continue;
        char path[512], state[32];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", entry->d_name);
        if (!read_file(path, state, sizeof(state), &n) || (n == 3 && !memcmp(state, "up\n", 3))) isolated = false;
    }
    if (closedir(net)) isolated = false;
    return isolated;
#endif
}

bool runtime_observe(const struct config *c, struct observation *o) {
    return observe(c, o, true);
}

bool runtime_observe_development(const struct config *c, struct observation *o) {
    return observe(c, o, false);
}

int events_open(void) {
#ifdef KAIBA_TESTING
    return dup(STDOUT_FILENO);
#else
    /* The image module also disables getty and journal console forwarding.
     * A malformed/interleaved record still fails in the independent host reader.
     */
    if (klogctl(6, NULL, 0) < 0) return -1;
    return open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC);
#endif
}
