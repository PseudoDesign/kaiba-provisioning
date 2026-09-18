#include "harness.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 && !(argc == 3 && !strcmp(argv[2], "--diagnostics"))) return 2;
    if (!strcmp(argv[1], "message")) {
        uint8_t nonce[32], message[128]; size_t n; char out[257];
        for (unsigned i = 0; i < 32; ++i) nonce[i] = (uint8_t)i;
        if (!derive_message("kaiba:protected-state:luks2:v1", nonce, message, &n)) return 3;
        hex(message, n, out); puts(out); return 0;
    }
    if (!fw_open()) return 3;
    uint32_t value = 0; uint8_t out[32] = {0};
    enum fw_result r = FW_INVALID;
    if (!strcmp(argv[1], "count")) r = fw_count(&value);
    if (!strcmp(argv[1], "status")) r = fw_status(1, &value);
    if (!strcmp(argv[1], "usage")) r = fw_usage(1, &value);
    if (!strcmp(argv[1], "raw")) r = fw_raw_read(1);
    if (!strcmp(argv[1], "legacy")) r = fw_legacy_read();
    if (!strcmp(argv[1], "hmac")) r = fw_hmac(1, (const uint8_t *)"public", 6, out);
    if (!strcmp(argv[1], "legacy-then-hmac")) {
        if (fw_legacy_read() != FW_LOCKED) return 3;
        r = fw_hmac(1, (const uint8_t *)"public", 6, out);
    }
    if (!strcmp(argv[1], "sign")) r = fw_sign(1);
    if (!strcmp(argv[1], "close")) {
        if (fw_set_locks(1, DEVICE_TYPE | ALL_LOCKS) != FW_OK) return 3;
        r = fw_hmac(1, (const uint8_t *)"public", 6, out);
    }
    fw_close();
    printf("%u %u\n", (unsigned)r, value);
    if (argc == 3) fw_diagnostic(STDOUT_FILENO, "synthetic-check");
    for (size_t i = 0; i < sizeof(out); ++i) if (r != FW_OK && out[i]) return 4;
    explicit_bzero(out, sizeof(out));
    return 0;
}
