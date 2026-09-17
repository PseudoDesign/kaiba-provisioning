#include "harness.h"
#include <fcntl.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static void interrupt_run(int unused) { (void)unused; interrupted = 1; }

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
#ifdef KAIBA_TESTING
        puts("kaiba-device-secret-target TEST FIRMWARE ONLY; hardware_qualified=false");
#else
        puts("kaiba-device-secret-target/v1alpha1 " SCHEME "; hardware_qualified=false");
#endif
        return 0;
    }
    bool validate_only = argc == 3 && !strcmp(argv[1], "--check-config");
    if (!validate_only && !(argc == 3 && !strcmp(argv[1], "--run-reviewed-experiment"))) {
        fputs("Usage: kaiba-device-secret-target --version | --check-config CONFIG | --run-reviewed-experiment CONFIG\n", stderr);
        return 2;
    }
    struct config c = {0}; struct observation o = {0}; struct storage s = {.fd = -1};
    uint8_t key[32] = {0}, other[32] = {0}, canary_key[32] = {0}, nonce[32] = {0}, message[128] = {0};
    size_t message_size = 0;
    const char *stop = "configuration"; int fd = -1, result = 3;
    bool lock_target = false, locked = false; unsigned sequence = 0;
    if (!config_load(argv[2], &c)) goto done;
    if (validate_only) { result = 0; goto done; }
    stop = "memory-protection";
    if (!memory_protect()) goto done;
    signal(SIGTERM, interrupt_run); signal(SIGINT, interrupt_run); signal(SIGALRM, interrupt_run);
    alarm(180);
    stop = "runtime-identity";
    if (!runtime_observe(&c, &o)) goto done;
    stop = "same-boot-repeat";
    int once = open("/run/kaiba-device-secret-attempted", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (once < 0) goto done;
    if (write(once, o.boot_id, 36) != 36 || fsync(once)) { close(once); goto done; }
    if (close(once)) goto done;
    stop = "firmware-metadata";
    uint32_t count = 0, status = 0, usage = 0;
    if (!fw_open() || fw_count(&count) != FW_OK || count < 1 || count > 32 || c.slot < 1 || c.slot > count ||
        fw_status(c.slot, &status) != FW_OK || status != (DEVICE_TYPE | EARLY_LOCKS) ||
        fw_usage(c.slot, &usage) != FW_OK || usage != c.usage) goto done;
    stop = "storage-prestate";
    if (!storage_open(&s, &c, &o)) goto done;
    stop = "capture-output";
    fd = events_open();
    if (fd < 0) goto done;
    stop = "durable-intent";
    if (!storage_intent(&s, &o)) goto done;
    lock_target = true;

#define CHECK(name, expression) do { \
    stop = name; bool passed = !interrupted && (expression); ++sequence; \
    if (!passed) dprintf(fd, "KAIBA_DEVICE_SECRET_DIAGNOSTIC=check:%s last_firmware_outcome:%s\n", name, fw_last_outcome()); \
    if (!event_emit(fd, &c, &o, s.phase, name, sequence, passed) || !passed) goto done; \
} while (0)
    CHECK("started", true);
    CHECK("raw_read_blocked", fw_raw_read(c.slot) == FW_LOCKED);
    CHECK("legacy_read_blocked", fw_legacy_read() == FW_LOCKED);
    CHECK("key_write_locked", fw_status(c.slot, &status) == FW_OK && status == (DEVICE_TYPE | EARLY_LOCKS));
    CHECK("same_input", derive_message("kaiba:protected-state:luks2:v1", c.nonce, message, &message_size) &&
        fw_hmac(c.slot, message, message_size, key) == FW_OK &&
        fw_hmac(c.slot, message, message_size, other) == FW_OK && constant_same(key, other));
    CHECK("domain_separation", derive_message("kaiba:protected-state:separation:v1", c.nonce, message, &message_size) &&
        fw_hmac(c.slot, message, message_size, other) == FW_OK && !constant_same(key, other));
    memcpy(nonce, c.nonce, 32); nonce[0] ^= 1;
    CHECK("nonce_separation", derive_message("kaiba:protected-state:luks2:v1", nonce, message, &message_size) &&
        fw_hmac(c.slot, message, message_size, other) == FW_OK && !constant_same(key, other));
    if (interrupted) goto done;
    bool canary_ready = derive_message("kaiba:protected-state:canary:v1", c.nonce, message, &message_size) &&
        fw_hmac(c.slot, message, message_size, canary_key) == FW_OK;
    CHECK(s.phase ? "volume_reopened" : "volume_created", canary_ready && storage_volume(&s, &c, key, canary_key));
    explicit_bzero(key, sizeof(key)); explicit_bzero(other, sizeof(other)); explicit_bzero(canary_key, sizeof(canary_key));
    if (interrupted) goto done;
    bool signing_was_open = fw_sign(c.slot) == FW_OK;
    locked = fw_set_locks(c.slot, DEVICE_TYPE | ALL_LOCKS) == FW_OK &&
        fw_status(c.slot, &status) == FW_OK && status == (DEVICE_TYPE | ALL_LOCKS);
    CHECK("hmac_closed", locked && fw_hmac(c.slot, message, message_size, other) == FW_LOCKED);
    CHECK("signing_closed", signing_was_open && fw_sign(c.slot) == FW_LOCKED);
    /* A successful SET with unchanged sticky bits is also a rejected clearing.
     * There are no generation or usage-write negative probes in this program. */
    CHECK("locks_cannot_clear", fw_set_locks(c.slot, DEVICE_TYPE) == FW_OK &&
        fw_status(c.slot, &status) == FW_OK && status == (DEVICE_TYPE | ALL_LOCKS));
    explicit_bzero(other, sizeof(other));
    stop = "storage-completion";
    if (interrupted || !storage_complete(&s, &o) || !storage_close(&s)) goto done;
    fw_close(); lock_target = false;
    CHECK("complete", true);
    result = 0;
done:
    alarm(0);
    /* Never leave a successful result after a cleanup failure. An interrupted
     * journal remains consumed. No crypto, format or unlock operation retries. */
    if (lock_target && result != 0) {
        uint32_t final = 0;
        if (fw_set_locks(c.slot, DEVICE_TYPE | ALL_LOCKS) != FW_OK ||
            fw_status(c.slot, &final) != FW_OK || final != (DEVICE_TYPE | ALL_LOCKS)) stop = "failure-lock-closure";
    }
    fw_close();
    explicit_bzero(key, sizeof(key)); explicit_bzero(other, sizeof(other)); explicit_bzero(canary_key, sizeof(canary_key));
    explicit_bzero(message, sizeof(message)); explicit_bzero(nonce, sizeof(nonce));
    if (!storage_close(&s)) { result = 3; stop = "storage-cleanup"; }
    if (fd >= 0 && close(fd)) { result = 3; stop = "output-cleanup"; }
#ifndef KAIBA_TESTING
    if (fd >= 0) (void)klogctl(7, NULL, 0);
#endif
    if (c.json) json_decref(c.json);
    if (result) fprintf(stderr, "KAIBA_DEVICE_SECRET_STOP=%s hardware_qualified=false\n", stop);
    OPENSSL_cleanup(); munlockall();
    return result;
}
