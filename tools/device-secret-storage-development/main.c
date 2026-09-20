/* Online, trusted-operator development only. The qualification harness remains
 * separate: no private-read/signing probes and no behavioral lock-pass claim. */
#include "harness.h"
#include <fcntl.h>
#include <libdevmapper.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef KAIBA_STORAGE_OFFLINE
#define CONFIG_SCHEMA "kaiba.device-secret-storage-offline-development/v1alpha1"
#define RESULT_SCHEMA "kaiba.device-secret-storage-offline-result/v1alpha1"
#define MODE_SUFFIX "offline-development"
#else
#define CONFIG_SCHEMA "kaiba.device-secret-storage-development/v1alpha1"
#define RESULT_SCHEMA "kaiba.device-secret-storage-result/v1alpha1"
#define MODE_SUFFIX "development"
#endif
#ifdef KAIBA_TESTING
#define RESULT_MODE "synthetic-" MODE_SUFFIX
#else
#define RESULT_MODE MODE_SUFFIX
#endif
static volatile sig_atomic_t interrupted;
static void interrupt_run(int unused) { (void)unused; interrupted = 1; }

static bool storage_drivers_ready(void) {
    struct dm_task *task = dm_task_create(DM_DEVICE_LIST_VERSIONS);
    bool crypt = false, linear = false;
    if (task && dm_task_run(task)) {
        struct dm_versions *v = dm_task_get_versions(task);
        while (v) {
            if (!strcmp(v->name, "crypt")) crypt = true;
            if (!strcmp(v->name, "linear")) linear = true;
            if (!v->next) break;
            v = (struct dm_versions *)((char *)v + v->next);
        }
    }
    if (task) dm_task_destroy(task);
    return crypt && linear;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
#ifdef KAIBA_TESTING
        puts(CONFIG_SCHEMA " TEST FIRMWARE ONLY; hardware_qualified=false");
#else
        puts(CONFIG_SCHEMA " " SCHEME "; development-only");
#endif
        return 0;
    }
    bool validate_only = argc == 3 && !strcmp(argv[1], "--check-config");
#ifdef KAIBA_STORAGE_OFFLINE
    if (!validate_only && !(argc == 3 && !strcmp(argv[1], "--run-reviewed-experiment"))) {
        fputs("Usage: offline storage helper --version | --check-config CONFIG | --run-reviewed-experiment CONFIG\n", stderr);
        return 2;
    }
    const char *phase = "unknown";
#else
    if (!validate_only && !(argc == 5 && (!strcmp(argv[1], "create") || !strcmp(argv[1], "reopen")) &&
        !strcmp(argv[3], "--expected-boot-id") && uuid_valid(argv[4]))) {
        fputs("Usage: kaiba-device-secret-storage-development --version | --check-config CONFIG | create|reopen CONFIG --expected-boot-id UUID\n", stderr);
        return 2;
    }
    const char *phase = argv[1];
#endif
    struct config c = {0}; struct observation o = {0}; struct storage s = {.fd = -1};
    uint8_t key[32] = {0}, canary_key[32] = {0}, message[128] = {0}; size_t size = 0;
    uint32_t count = 0, status = 0, usage = 0;
    bool passed = false, lock_needed = false, locks_closed = false, storage_closed = false;
    bool volume_verified = false, complete = false;
    const char *stop = "configuration";
    struct fw_diagnostic diagnostic = {FW_INVALID, 0, 0};
    if (!config_load_schema(argv[2], &c, CONFIG_SCHEMA)) goto done;
    if (validate_only) { json_decref(c.json); return 0; }
#ifdef KAIBA_STORAGE_OFFLINE
    stop = "console";
    int console = events_open();
    if (console < 0) goto done;
    bool redirected = dup2(console, STDOUT_FILENO) >= 0;
    if (close(console) || !redirected) goto done;
#endif
    stop = "memory-protection";
    if (!memory_protect()) goto done;
    struct sigaction action = {.sa_handler = interrupt_run}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) || sigaction(SIGALRM, &action, NULL)) goto done;
    alarm(180);
    stop = "runtime-identity";
#ifdef KAIBA_STORAGE_OFFLINE
    if (!runtime_observe(&c, &o)) goto done;
#else
    if (!runtime_observe_development(&c, &o) || strcmp(o.boot_id, argv[4])) goto done;
#endif
    stop = "same-boot-repeat";
    int once = open("/run/kaiba-device-secret-storage-attempted", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (once < 0) goto done;
    bool marked = write(once, o.boot_id, 36) == 36 && fsync(once) == 0;
    if (close(once) || !marked) goto done;
    stop = "storage-prestate";
    if (!storage_open(&s, &c, &o)) goto done;
#ifdef KAIBA_STORAGE_OFFLINE
    /* Only storage_open's validated, image-bound one-use journal selects a phase.
     * Incomplete/completed journals fail before any firmware operation. */
    phase = s.phase ? "reopen" : "create";
#else
    if (s.phase != (unsigned)!strcmp(argv[1], "reopen")) goto done;
#endif
    stop = "storage-drivers";
    if (!storage_drivers_ready()) goto done;
    stop = "firmware-metadata";
    if (!fw_open() || fw_count(&count) != FW_OK || count < c.slot || count > 32 ||
        fw_status(c.slot, &status) != FW_OK || !(status & DEVICE_TYPE) ||
        status & ~(DEVICE_TYPE | EARLY_LOCKS) || fw_usage(c.slot, &usage) != FW_OK || usage != c.usage) goto done;
    stop = "durable-intent";
    if (!storage_intent(&s, &o)) goto done;
    lock_needed = true; /* Cleanup remains required even if the first SET fails. */
    stop = "apply-runtime-locks";
    if (interrupted || fw_set_locks(c.slot, DEVICE_TYPE | EARLY_LOCKS) != FW_OK ||
        fw_status(c.slot, &status) != FW_OK || status != (DEVICE_TYPE | EARLY_LOCKS)) goto done;
    stop = "luks-derivation";
    if (interrupted || !derive_message("kaiba:protected-state:luks2:v1", c.nonce, message, &size) ||
        fw_hmac(c.slot, message, size, key) != FW_OK) goto done;
    stop = "canary-derivation";
    if (interrupted || !derive_message("kaiba:protected-state:canary:v1", c.nonce, message, &size) ||
        fw_hmac(c.slot, message, size, canary_key) != FW_OK) goto done;
    stop = "volume-verification";
    if (interrupted || !storage_volume(&s, &c, key, canary_key)) goto done;
    volume_verified = true;
    passed = true;
done:
    /* Snapshot the original firmware diagnostic BEFORE any cleanup call. */
    diagnostic = fw_snapshot();
    explicit_bzero(key, sizeof(key)); explicit_bzero(canary_key, sizeof(canary_key)); explicit_bzero(message, sizeof(message));
    if (lock_needed) {
        bool set = fw_set_locks(c.slot, DEVICE_TYPE | ALL_LOCKS) == FW_OK;
        enum fw_result r = fw_status(c.slot, &status);
        locks_closed = set && r == FW_OK && status == (DEVICE_TYPE | ALL_LOCKS);
        if (!locks_closed) { passed = false; stop = "cleanup-locks"; }
    }
    fw_close();
    if (interrupted) { passed = false; stop = "interrupted"; }
    if (passed) {
        complete = storage_complete(&s, &o);
        if (!complete) { passed = false; stop = "storage-completion"; }
    }
    storage_closed = storage_close(&s);
    if (!storage_closed) { passed = false; stop = "storage-cleanup"; }
    alarm(0);
    if (interrupted) { passed = false; stop = "interrupted"; }
    json_t *result = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:b,s:s,s:b,s:b,s:b,s:b,s:b,s:b,s:i,s:i,s:i}",
        "schema_version", RESULT_SCHEMA, "mode", RESULT_MODE,
        "phase", phase, "boot_id", o.boot_id, "boot_image_sha256", o.boot_hash, "verity_root_hash", o.root_hash,
        "volume_uuid", c.volume ? c.volume : "", "nonce_sha256", o.nonce_hash,
        "passed", passed, "stop", passed ? "complete" : stop, "volume_verified", volume_verified,
        "runtime_locks_closed", locks_closed, "storage_closed", storage_closed, "journal_completed", complete,
        "hardware_qualified", 0, "lock_rejection_qualified", 0,
        "last_firmware_outcome", diagnostic.outcome, "last_mailbox_tag", (int)diagnostic.tag,
        "last_mailbox_errno", diagnostic.error);
#ifdef KAIBA_STORAGE_OFFLINE
    /* A dedicated console service supplies exclusive UART output. Capture still
     * rejects missing, duplicated or interleaved records; this is not an audit. */
    bool prefix = fputs("KAIBA_DEVICE_SECRET_STORAGE_RESULT=", stdout) >= 0;
#else
    bool prefix = true;
#endif
    bool emitted = prefix && result && json_dumpf(result, stdout, JSON_COMPACT | JSON_SORT_KEYS) == 0 && putchar('\n') != EOF;
    if (result) json_decref(result);
    if (c.json) json_decref(c.json);
    OPENSSL_cleanup(); munlockall();
    return passed && emitted ? 0 : 3;
}
