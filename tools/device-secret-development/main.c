/* Development-only, RAM-resident checks using the SAME mailbox implementation
 * as the qualification harness. No block device, arbitrary message, key export,
 * generation, usage write, signing, or persistent installation interface. */
#include "firmware.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static void interrupt(int signal_number) { (void)signal_number; interrupted = 1; }
struct step {
    const char *name;
    bool passed, has_value;
    uint32_t value;
    struct fw_diagnostic diagnostic;
};
static struct step steps[20];
static size_t step_count;
static bool record(const char *name, bool passed, bool has_value, uint32_t value) {
    if (step_count == sizeof(steps)/sizeof(steps[0])) abort();
    steps[step_count++] = (struct step){name, passed, has_value, value, fw_snapshot()};
    return passed && !interrupted;
}
static bool decimal(const char *s, uint32_t *v, unsigned low, unsigned high) {
    if (!*s || (s[0] == '0' && s[1])) return false;
    for (const char *p = s; *p; ++p) if (*p < '0' || *p > '9') return false;
    errno = 0; unsigned long n = strtoul(s, NULL, 10);
    if (errno || n < low || n > high) return false;
    *v = (uint32_t)n; return true;
}
static bool uuid(const char *s) {
    if (strlen(s) != 36) return false;
    for (unsigned i = 0; i < 36; ++i)
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return false; }
        else if (!strchr("0123456789abcdef", s[i])) return false;
    return true;
}
static bool protect(const char *boot) {
#ifdef KAIBA_TESTING
    return !strcmp(boot, "11111111-1111-4111-8111-111111111111");
#else
    struct rlimit zero = {0, 0}; char actual[38], swaps[256];
    if (geteuid() || setrlimit(RLIMIT_CORE, &zero) || prctl(PR_SET_DUMPABLE, 0)) return false;
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!f) return false;
    size_t n = fread(actual, 1, sizeof(actual), f); fclose(f);
    if (n != 37 || actual[36] != '\n' || memcmp(actual, boot, 36)) return false;
    f = fopen("/proc/swaps", "re"); if (!f) return false;
    n = fread(swaps, 1, sizeof(swaps)-1, f); bool ok = !ferror(f) && feof(f); fclose(f);
    swaps[n] = 0; char *line = strchr(swaps, '\n');
    return ok && line && !line[1] && mlockall(MCL_CURRENT | MCL_FUTURE) == 0;
#endif
}
static bool same(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t diff = 0; for (size_t i = 0; i < 32; ++i) diff |= a[i] ^ b[i]; return diff == 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("kaiba-device-secret-development 0.1.0 transport=vcio development-only"); return 0;
    }
    uint32_t slot, expected_usage;
    if (argc != 8 || (strcmp(argv[1], "inspect") && strcmp(argv[1], "read-lock") && strcmp(argv[1], "hmac")) ||
        strcmp(argv[2], "--slot-id") || !decimal(argv[3], &slot, 1, 32) ||
        strcmp(argv[4], "--expected-usage") || !decimal(argv[5], &expected_usage, 0, 14) ||
        (expected_usage > 0 && expected_usage < 8) || strcmp(argv[6], "--expected-boot-id") || !uuid(argv[7])) {
        fputs("usage: kaiba-device-secret-development inspect|read-lock|hmac --slot-id ID --expected-usage USAGE --expected-boot-id UUID\n", stderr);
        return 2;
    }
    const char *stop = "memory-or-boot-preflight";
    bool passed = false, cleanup_needed = false, cleaned = false;
    uint32_t count = 0, status = 0, usage = 0, error = 0;
    uint8_t a[32] = {0}, b[32] = {0};
    if (!protect(argv[7])) goto done;
    struct sigaction action = {.sa_handler = interrupt}; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) || sigaction(SIGALRM, &action, NULL)) goto done;
    alarm(30);
    stop = "mailbox-open"; if (!fw_open()) goto done;
#define CHECK(name, expression) do { stop = name; if (interrupted || !record(name, (expression), false, 0)) goto done; } while (0)
#define META(name, call, variable, predicate) do { stop = name; enum fw_result r = (call); \
    if (!record(name, r == FW_OK && (predicate), r == FW_OK, variable)) goto done; } while (0)
    META("count", fw_count(&count), count, count >= slot && count <= 32);
    META("status", fw_status(slot, &status), status,
         (status & DEVICE_TYPE) && !(status & ~(DEVICE_TYPE | ALL_LOCKS)));
    META("usage", fw_usage(slot, &usage), usage, usage == expected_usage);
    if (!strcmp(argv[1], "inspect")) { passed = true; goto done; }
    /* A later helper never clears locks. Reboot is a separate recorded action.
     * Set cleanup intent BEFORE the first volatile mutation, even if it fails. */
    stop = "preclosed-key"; if (status & (ARM_CRYPTO_KEY_STATUS_HMAC_LOCKED | ARM_CRYPTO_KEY_STATUS_SIGN_LOCKED)) goto done;
    cleanup_needed = true;
    CHECK("apply-runtime-locks", fw_set_locks(slot, DEVICE_TYPE | EARLY_LOCKS) == FW_OK);
    META("runtime-locks", fw_status(slot, &status), status, status == (DEVICE_TYPE | EARLY_LOCKS));
    if (!strcmp(argv[1], "read-lock")) {
        stop = "raw-read-blocked";
        enum fw_result result = fw_raw_read(slot);
        bool blocked = record(stop, result == FW_LOCKED, false, 0);
        /* Separate diagnostic query; NEVER promote EINVAL plus a last-error
         * value to a successful lock test. Preserve the original result first. */
        if (result == FW_IO && !interrupted) {
            enum fw_result diagnostic = fw_error(&error);
            record("last-error-after-transport-failure", diagnostic == FW_OK,
                   diagnostic == FW_OK, error);
        }
        if (!blocked) goto done;
    } else {
        static const uint8_t first[] = "kaiba:development:hmac:v1:control";
        static const uint8_t second[] = "kaiba:development:hmac:v1:separation";
        CHECK("hmac-control", fw_hmac(slot, first, sizeof(first)-1, a) == FW_OK);
        CHECK("hmac-repeat", fw_hmac(slot, first, sizeof(first)-1, b) == FW_OK && same(a, b));
        CHECK("hmac-separation", fw_hmac(slot, second, sizeof(second)-1, b) == FW_OK && !same(a, b));
    }
    passed = true;
done:
    explicit_bzero(a, sizeof(a)); explicit_bzero(b, sizeof(b));
    if (cleanup_needed) {
        /* Bounded cleanup also runs after failure. No retries. */
        bool set = fw_set_locks(slot, DEVICE_TYPE | ALL_LOCKS) == FW_OK;
        record("close-runtime-locks", set, false, 0);
        enum fw_result r = fw_status(slot, &status);
        cleaned = set && r == FW_OK && status == (DEVICE_TYPE | ALL_LOCKS);
        record("closed-status", cleaned, r == FW_OK, status);
        if (passed && cleaned && !interrupted && !strcmp(argv[1], "hmac")) {
            passed = record("hmac-closed", fw_hmac(slot, (const uint8_t *)"kaiba:development:closed", 24, b) == FW_LOCKED, false, 0);
            if (!passed) stop = "hmac-closed";
        }
        if (!cleaned) { passed = false; stop = "cleanup-locks"; }
    }
    explicit_bzero(b, sizeof(b)); fw_close(); alarm(0);
    if (interrupted) { passed = false; stop = "interrupted"; }
    printf("{\"schema_version\":\"kaiba.device-secret-development/v1alpha1\",\"mode\":\"development\","
           "\"check\":\"%s\",\"boot_id\":\"%s\",\"slot_id\":%u,\"expected_usage\":%u,"
           "\"passed\":%s,\"stop\":\"%s\",\"cleanup_locks_closed\":%s,\"hardware_qualified\":false,\"steps\":[",
           argv[1], argv[7], slot, expected_usage, passed ? "true" : "false", passed ? "complete" : stop,
           cleanup_needed ? (cleaned ? "true" : "false") : "null");
    for (size_t i = 0; i < step_count; ++i) {
        struct step *s = &steps[i];
        printf("%s{\"name\":\"%s\",\"passed\":%s,\"outcome\":%u,\"mailbox_tag\":%u,\"mailbox_errno\":%d,\"value\":",
               i ? "," : "", s->name, s->passed ? "true" : "false", s->diagnostic.outcome,
               s->diagnostic.tag, s->diagnostic.error);
        if (s->has_value) printf("%u", s->value); else fputs("null", stdout);
        putchar('}');
    }
    puts("]}"); munlockall();
    return passed ? 0 : 3;
}
