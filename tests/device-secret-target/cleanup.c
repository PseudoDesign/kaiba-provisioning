/* VM-only regression for transient/persistent readers of a synthetic zero
 * mapping. Never included in the production helper or native artifact export. */
#include "harness.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "transient") && strcmp(argv[1], "persistent"))) return 2;
    int fd = open("/dev/mapper/kaiba-secret-experiment-container", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 2;
    pid_t child = fork();
    if (child < 0) { close(fd); return 2; }
    if (!child) {
        /* A persistent reader outlives the library's five-second retry bound. */
        usleep(!strcmp(argv[1], "persistent") ? 10000000 : 800000);
        close(fd); _exit(0);
    }
    close(fd);
    struct storage s = {.fd = -1, .linear = true};
    bool removed = storage_close(&s);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 2;
    return removed ? 0 : 3;
}
