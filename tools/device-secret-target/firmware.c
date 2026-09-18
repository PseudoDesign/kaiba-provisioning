/* Fixed ABI subset from raspberrypi/utils 292dbe7e/rpifwcrypto/rpifwcrypto.c.
 * Deliberately no key generation, OTP write, usage write, public-key export,
 * arbitrary tag, path, payload, or fallback transport. /dev/vcio is explicit:
 * the pinned restricted node omits usage and legacy reads. All returned bytes
 * stay in locked process memory and are wiped, including malformed responses.
 */
#include "harness.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define DONE UINT32_C(0x80000000)
#define MBOX _IOWR(100, 0, char *)
static int mailbox = -1;
static enum fw_result last_outcome = FW_INVALID;
static uint32_t last_mailbox_tag;
static int last_mailbox_errno;
static enum fw_result outcome(enum fw_result r) { last_outcome = r; return r; }
const char *fw_last_outcome(void) {
    static const char *names[] = { "success", "key-locked", "transport-failure", "malformed-reply", "firmware-rejected" };
    return names[last_outcome];
}
void fw_diagnostic(int fd, const char *check) {
    /* Only fixed operation names, result categories and transport metadata.
     * Never include request/response buffers or perform another mailbox call. */
    (void)dprintf(fd, "KAIBA_DEVICE_SECRET_DIAGNOSTIC=check:%s last_firmware_outcome:%s last_mailbox_tag:0x%08x last_mailbox_errno:%d\n",
                  check, fw_last_outcome(), (unsigned)last_mailbox_tag, last_mailbox_errno);
}
struct message { uint32_t size, code, tag, capacity, response; uint32_t data[515]; uint32_t end; };

#ifdef KAIBA_TESTING
extern int test_exchange(void *, size_t);
#endif
bool fw_open(void) {
#ifdef KAIBA_TESTING
    mailbox = 100; return true;
#else
    mailbox = open("/dev/vcio", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (mailbox < 0 || fstat(mailbox, &st) || !S_ISCHR(st.st_mode) || st.st_uid ||
        major(st.st_rdev) != 10 || flock(mailbox, LOCK_EX | LOCK_NB)) { fw_close(); return false; }
    return true;
#endif
}
void fw_close(void) {
#ifndef KAIBA_TESTING
    if (mailbox >= 0) close(mailbox);
#endif
    mailbox = -1;
}
static enum fw_result exchange(struct message *m, uint32_t tag, uint32_t capacity, uint32_t request) {
    last_mailbox_tag = tag;
    last_mailbox_errno = 0;
    size_t size = capacity <= 8 ? 40 : (tag == 0x00030091 ? 160 : 24 + capacity);
    m->size = (uint32_t)size; m->tag = tag; m->capacity = capacity; m->response = request;
    /* End tag is directly after the selected capacity, not the arena's end. */
    uint32_t *end = (uint32_t *)((uint8_t *)m + size - 4);
    *end = 0;
    if (mailbox < 0) { last_mailbox_errno = EBADF; return FW_IO; }
    errno = 0;
#ifdef KAIBA_TESTING
    int rc = test_exchange(m, size);
#else
    int rc = ioctl(mailbox, MBOX, m);
#endif
    if (rc < 0) { last_mailbox_errno = errno; return FW_IO; }
    if (rc || m->size != size || m->code != DONE || m->tag != tag || m->capacity != capacity ||
        !(m->response & DONE) || (m->response & ~DONE) > capacity || *end) return FW_INVALID;
    return FW_OK;
}
static enum fw_result scalar(uint32_t tag, uint32_t id, uint32_t value, uint32_t *out) {
    struct message m = {0}; m.data[0] = id; m.data[1] = value;
    uint32_t bytes = tag == 0x00038090 ? 8 : 4;
    enum fw_result result = exchange(&m, tag, bytes, 0);
    if (result == FW_OK && m.response != (DONE | bytes) &&
        !(tag == 0x00038090 && m.response == (DONE | 4))) result = FW_INVALID;
    if (result == FW_OK && (m.data[0] & DONE)) result = FW_REJECTED;
    if (result == FW_OK && out) *out = m.data[0];
    explicit_bzero(&m, sizeof(m)); return outcome(result);
}
enum fw_result fw_count(uint32_t *v) { return scalar(0x0003008f, 0, 0, v); }
enum fw_result fw_status(uint32_t id, uint32_t *v) { return scalar(0x00030090, id, 0, v); }
enum fw_result fw_usage(uint32_t id, uint32_t *v) { return scalar(0x0003009c, id, 0, v); }
enum fw_result fw_set_locks(uint32_t id, uint32_t v) { return scalar(0x00038090, id, v, NULL); }

static bool unchanged_or_zero(const void *actual, const void *request, size_t n) {
    if (!memcmp(actual, request, n)) return true;
    const uint8_t *p = actual; uint8_t value = 0;
    for (size_t i = 0; i < n; ++i) value |= p[i];
    return value == 0;
}
static enum fw_result crypto_result(struct message *m, enum fw_result result, uint32_t minimum, uint32_t maximum, const void *request) {
    if (result != FW_OK) return result; /* ioctl failure is not a lock result */
    if (m->data[0] & DONE) {
        /* A lock error accompanied by new payload bytes is not successful
         * non-disclosure. Firmware may leave the public request or clear it. */
        uint32_t original_id;
        memcpy(&original_id, request, sizeof(original_id));
        if ((m->data[1] != 0 && m->data[1] != original_id) ||
            !unchanged_or_zero(m->data+2, (const uint8_t *)request+4, m->capacity-8)) return FW_INVALID;
        uint32_t error = 0;
        if (scalar(0x0003008e, 0, 0, &error) != FW_OK) return FW_INVALID;
        return error == RPI_FW_CRYPTO_KEY_LOCKED ? FW_LOCKED : FW_REJECTED;
    }
    uint32_t bytes = m->response & ~DONE;
    if (m->data[0] || m->data[1] < minimum || m->data[1] > maximum || bytes < 8 + m->data[1]) return FW_INVALID;
    return FW_OK;
}
enum fw_result fw_hmac(uint32_t id, const uint8_t *input, size_t length, uint8_t out[32]) {
    if (!length || length > 2048) return outcome(FW_INVALID);
    struct message m = {0}; m.data[1] = id; m.data[2] = (uint32_t)length;
    memcpy(m.data+3, input, length);
    uint8_t request[2056]; memcpy(request, m.data+1, sizeof(request));
    enum fw_result r = exchange(&m, 0x00030092, 2060, 0);
    r = crypto_result(&m, r, 32, 32, request);
    if (r == FW_OK) memcpy(out, m.data+2, 32);
    else explicit_bzero(out, 32);
    explicit_bzero(&m, sizeof(m)); return outcome(r);
}
enum fw_result fw_raw_read(uint32_t id) {
    struct message m = {0}; m.data[1] = id;
    uint8_t request[1028]; memcpy(request, m.data+1, sizeof(request));
    enum fw_result r = exchange(&m, 0x00030094, 1032, 0);
    r = crypto_result(&m, r, 1, 1024, request);
    explicit_bzero(&m, sizeof(m)); return outcome(r);
}
enum fw_result fw_sign(uint32_t id) {
    struct message m = {0}; m.data[1] = id; m.data[2] = 32;
    /* Public, fixed digest, no production identity statement. */
    memset(m.data+3, 0x5a, 32);
    uint8_t request[124]; memcpy(request, m.data+1, sizeof(request));
    enum fw_result r = exchange(&m, 0x00030091, 128, 0);
    r = crypto_result(&m, r, 8, 128, request);
    explicit_bzero(&m, sizeof(m)); return outcome(r);
}
enum fw_result fw_legacy_read(void) {
    /* GET_USER_OTP, block 3 (private), words 0..7, from the pinned Pi 5 DT
     * and nvmem driver. Error result must be explicit; zero bytes aren't proof.
     * The dedicated GET_CUSTOMER_PRIVATE_KEY path fails the entire mailbox;
     * its pinned driver's EINVAL is accepted only alongside this explicit
     * rejection and the caller's live READ_LOCKED and successful HMAC controls.
     */
    struct message m = {0}; m.data[0] = 3; m.data[2] = 8;
    uint8_t request[776]; memcpy(request, m.data+1, sizeof(request));
    enum fw_result r = exchange(&m, 0x00030024, 780, 780);
    if (r == FW_OK) r = m.data[0] == DONE && unchanged_or_zero(m.data+1, request, sizeof(request)) ? FW_LOCKED : FW_REJECTED;
    explicit_bzero(&m, sizeof(m));
    if (r != FW_LOCKED) return outcome(r);
    m.data[1] = 8;
    errno = 0;
    r = exchange(&m, 0x00030081, 40, 40);
    int saved_errno = errno;
    uint8_t zero[32] = {0};
    bool empty = !memcmp(m.data+2, zero, 32);
    explicit_bzero(&m, sizeof(m));
    return outcome(r == FW_IO && saved_errno == EINVAL && empty ? FW_LOCKED : FW_REJECTED);
}
