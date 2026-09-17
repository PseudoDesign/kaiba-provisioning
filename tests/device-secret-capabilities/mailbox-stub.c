#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int flag(const char *name) { return getenv(name) != NULL; }
static unsigned number(const char *name, unsigned fallback) {
    const char *value = getenv(name);
    return value ? (unsigned)strtoul(value, NULL, 0) : fallback;
}
static unsigned calls, opens, closes;
static void finish(void) { assert(opens == closes); }
uid_t __wrap_geteuid(void) { return flag("TEST_NONROOT") ? 1000 : 0; }
int __wrap_open(const char *path, int flags, ...) {
    assert(strcmp(path, "/dev/vcio") == 0);
    assert(flags == (O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    fprintf(stderr, "OPEN /dev/vcio\n");
    if (flag("TEST_OPEN_FAIL")) { errno = EACCES; return -1; }
    if (!opens) atexit(finish);
    ++opens;
    return 73;
}
int __wrap_fstat(int fd, struct stat *node) {
    assert(fd == 73);
    memset(node, 0, sizeof(*node));
    node->st_mode = flag("TEST_REGULAR_FILE") ? S_IFREG : S_IFCHR;
    node->st_uid = flag("TEST_NODE_NONROOT") ? 1000 : 0;
    node->st_rdev = makedev(flag("TEST_WRONG_MAJOR") ? 8 : 10, 258);
    if (flag("TEST_STAT_FAIL")) { errno = EIO; return -1; }
    return 0;
}
int __wrap_close(int fd) { assert(fd == 73); ++closes; return 0; }
int __wrap_ioctl(int fd, unsigned long request, ...) {
    assert(fd == 73 && request == _IOWR(100, 0, char *));
    va_list args;
    va_start(args, request);
    uint32_t *msg = va_arg(args, uint32_t *);
    va_end(args);
    const uint32_t tags[] = {0x3008f, 0x30090, 0x3009c};
    /* This asserts the exact sequence, bounds and complete request buffer;
     * any other tag, extra call, retry or bundled operation aborts the test. */
    assert(calls < 3 && msg[2] == tags[calls++]);
    assert(msg[0] == 40 && msg[1] == 0 && msg[3] == 4 && msg[4] == 0);
    assert(msg[5] == (calls == 1 ? 0 : number("TEST_ID", 1)));
    for (unsigned i = 6; i < 10; ++i) assert(msg[i] == 0);
    fprintf(stderr, "QUERY %08x %u\n", msg[2], msg[5]);
    if (number("TEST_FAIL_QUERY", 0) == calls) { errno = EPERM; return -1; }
    msg[1] = 0x80000000;
    msg[4] = 0x80000004;
    msg[5] = calls == 1 ? number("TEST_COUNT", 2) :
             calls == 2 ? number("TEST_STATUS", 0x1301) : number("TEST_USAGE", 8);
    if (number("TEST_BAD_QUERY", 0) == calls) {
        unsigned word = number("TEST_BAD_WORD", 0);
        assert(word < 10);
        msg[word] ^= number("TEST_BAD_XOR", 1);
    }
    return number("TEST_POSITIVE_RC", 0);
}
