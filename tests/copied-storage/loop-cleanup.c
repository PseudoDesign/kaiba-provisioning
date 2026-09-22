#define main comparison_main
#include "main.c"
#undef main
#include <sys/wait.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "transient") && strcmp(argv[1], "persistent"))) return 2;
    bool persistent = !strcmp(argv[1], "persistent");
    const char *path = "/dev/shm/kaiba-loop-cleanup-control.img";
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    struct loop loop = {.fd = -1}; int ready[2];
    if (fd < 0 || ftruncate(fd, STORAGE_BYTES-DATA_START) || !loop_attach(&loop, fd, 0, false) || pipe(ready)) return 3;
    pid_t child = fork();
    if (child < 0) return 4;
    if (!child) {
        close(ready[0]); close(loop.fd); close(fd);
        int held = open(loop.path, O_RDONLY | O_CLOEXEC);
        if (held < 0 || write(ready[1], "R", 1) != 1) _exit(5);
        close(ready[1]); sleep(persistent ? 7 : 1); close(held); _exit(0);
    }
    close(ready[1]); char byte;
    if (read(ready[0], &byte, 1) != 1 || byte != 'R') return 6;
    close(ready[0]);
    bool closed = loop_close(&loop); int status;
    if (waitpid(child, &status, 0) != child || status != 0) return 7;
    if (close(fd) || unlink(path)) return 8;
    return closed != persistent ? 0 : 9;
}
