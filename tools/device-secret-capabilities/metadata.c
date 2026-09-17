/* Explicit metadata-only transport for the pinned Raspberry Pi mailbox ABI.
 * Implements only the three query functions used by main.c. Do not link the
 * general crypto library into this executable. GET-prefixed tags are NOT a
 * read-only class: some other GET tags generate keys or perform cryptography.
 * ABI source: raspberrypi/utils 292dbe7e35296e556d839a0b9ae2ca957ac8c961,
 * rpifwcrypto/rpifwcrypto.c. No caller-supplied paths, tags or message buffers.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <rpifwcrypto.h>

#define MBOX_PROPERTY _IOWR(100, 0, char *)
#define COMPLETE UINT32_C(0x80000000)

enum metadata_query { KEY_COUNT, KEY_STATUS, KEY_USAGE };
struct metadata_message {
    uint32_t size, code, tag, value_size, response_size;
    uint32_t value[4];
    uint32_t end;
};
_Static_assert(sizeof(struct metadata_message) == 40, "pinned mailbox ABI");

static int query(enum metadata_query kind, uint32_t id, uint32_t *value) {
    uint32_t tag;
    switch (kind) {
    case KEY_COUNT: tag = 0x0003008f; break;
    case KEY_STATUS: tag = 0x00030090; break;
    case KEY_USAGE: tag = 0x0003009c; break;
    default: return -RPI_FW_CRYPTO_EINVAL;
    }
    if (!value || (kind == KEY_COUNT ? id != 0 : id < 1 || id > 32))
        return -RPI_FW_CRYPTO_EINVAL;
    if (geteuid() != 0) {
        fputs("metadata transport requires root; device permissions are not changed\n", stderr);
        return -RPI_FW_CRYPTO_ERROR_UNKNOWN;
    }
    int fd = open("/dev/vcio", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        perror("opening metadata mailbox /dev/vcio");
        return -RPI_FW_CRYPTO_ERROR_UNKNOWN;
    }
    struct stat node;
    if (fstat(fd, &node) < 0 || !S_ISCHR(node.st_mode) || node.st_uid != 0 || major(node.st_rdev) != 10) {
        fputs("metadata mailbox must be a root-owned misc character device\n", stderr);
        close(fd);
        return -RPI_FW_CRYPTO_ERROR_UNKNOWN;
    }
    struct metadata_message message = {
        .size = sizeof(message), .tag = tag, .value_size = sizeof(uint32_t),
        .value = {id},
    };
    int result = ioctl(fd, MBOX_PROPERTY, &message);
    if (result < 0) perror("metadata mailbox query");
    close(fd);
    /* Never retry a rejected query, use a different node or dump the buffer. */
    if (result < 0) return -RPI_FW_CRYPTO_ERROR_UNKNOWN;
    if (result != 0 || message.size != sizeof(message) || message.code != COMPLETE ||
        message.tag != tag || message.value_size != sizeof(uint32_t) ||
        message.response_size != (COMPLETE | sizeof(uint32_t)) || message.end ||
        message.value[1] || message.value[2] || message.value[3]) {
        fputs("invalid metadata mailbox response\n", stderr);
        return -RPI_FW_CRYPTO_OPERATION_FAILED;
    }
    if (message.value[0] & COMPLETE) return -RPI_FW_CRYPTO_KEY_NOT_FOUND;
    if ((kind == KEY_COUNT && message.value[0] > 32) ||
        (kind == KEY_USAGE && message.value[0] >= RPI_FW_CRYPTO_KEY_USAGE_INVALID)) {
        fputs("metadata value outside the pinned interface range\n", stderr);
        return -RPI_FW_CRYPTO_OPERATION_FAILED;
    }
    *value = message.value[0];
    return RPI_FW_CRYPTO_SUCCESS;
}

int rpi_fw_crypto_get_num_otp_keys(void) {
    uint32_t count = 0;
    int result = query(KEY_COUNT, 0, &count);
    return result ? result : (int)count;
}

int rpi_fw_crypto_get_key_status(uint32_t id, uint32_t *status) {
    return query(KEY_STATUS, id, status);
}

int rpi_fw_crypto_get_key_usage(uint32_t id, RPI_FW_CRYPTO_KEY_USAGE *usage) {
    if (!usage) return -RPI_FW_CRYPTO_EINVAL;
    uint32_t value = 0;
    int result = query(KEY_USAGE, id, &value);
    if (!result) *usage = (RPI_FW_CRYPTO_KEY_USAGE)value;
    return result;
}
