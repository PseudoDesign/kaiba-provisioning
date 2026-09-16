/* Read-only firmware capability queries. This program has no key-read,
 * derivation, signing, generation, usage-write, or lock-write command. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <rpifwcrypto.h>

#ifndef FWCRYPTO_REVISION
#define FWCRYPTO_REVISION "test"
#endif

static void usage(FILE *stream) {
    fputs("Usage: kaiba-device-secret-capabilities [--key-id 1..32]\n"
          "Queries only key count, status and usage. No secret values are read.\n", stream);
}

int main(int argc, char **argv) {
    unsigned long key_id = 0;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("kaiba-device-secret-capabilities/v1 fwcrypto=" FWCRYPTO_REVISION);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc != 1) {
        if (argc != 3 || strcmp(argv[1], "--key-id") != 0 || argv[2][0] < '1' || argv[2][0] > '9') {
            usage(stderr);
            return 2;
        }
        char *end = NULL;
        errno = 0;
        key_id = strtoul(argv[2], &end, 10);
        if (errno || *end || key_id == 0 || key_id > 32) {
            usage(stderr);
            return 2;
        }
    }
    int count = rpi_fw_crypto_get_num_otp_keys();
    if (count < 0 || count > 32) {
        printf("{\"schema_version\":\"provisioning.kaiba.network/device-secret-capabilities/v1alpha1\","
               "\"status\":\"unavailable\",\"operation\":\"get_num_otp_keys\",\"return_code\":%d,"
               "\"feasibility\":\"pending\"}\n", count);
        return 1;
    }
    if (key_id > (unsigned)count) {
        fputs("selected key ID exceeds the reported slot count\n", stderr);
        return 2;
    }
    uint32_t status = 0;
    RPI_FW_CRYPTO_KEY_USAGE usage_value = RPI_FW_CRYPTO_KEY_USAGE_UNDEFINED;
    int status_rc = 0, usage_rc = 0;
    if (key_id) {
        status_rc = rpi_fw_crypto_get_key_status((uint32_t)key_id, &status);
        usage_rc = rpi_fw_crypto_get_key_usage((uint32_t)key_id, &usage_value);
    }
    printf("{\"schema_version\":\"provisioning.kaiba.network/device-secret-capabilities/v1alpha1\","
           "\"status\":\"%s\",\"fwcrypto_revision\":\"" FWCRYPTO_REVISION "\","
           "\"key_count\":%d,\"feasibility\":\"pending\",\"key\":",
           status_rc || usage_rc ? "partial" : "observed", count);
    if (!key_id) {
        fputs("null", stdout);
    } else {
        printf("{\"id\":%lu,\"status_return_code\":%d,\"usage_return_code\":%d,\"status_bits\":",
               key_id, status_rc, usage_rc);
        if (status_rc) fputs("null", stdout); else printf("%u", status);
        fputs(",\"usage\":", stdout);
        if (usage_rc) fputs("null", stdout); else printf("%u", (unsigned)usage_value);
        fputs("}", stdout);
    }
    puts("}");
    return status_rc || usage_rc ? 1 : 0;
}
