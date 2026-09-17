#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <rpifwcrypto.h>
static int number(const char *name, int fallback) {
    const char *value = getenv(name);
    return value ? atoi(value) : fallback;
}
int rpi_fw_crypto_get_num_otp_keys(void) { return number("TEST_KEY_COUNT", 2); }
int rpi_fw_crypto_get_key_status(uint32_t id, uint32_t *status) {
    if (id != 1) abort();
    *status = 0x1301;
    return number("TEST_STATUS_RC", 0);
}
int rpi_fw_crypto_get_key_usage(uint32_t id, RPI_FW_CRYPTO_KEY_USAGE *usage) {
    if (id != 1) abort();
    *usage = RPI_FW_CRYPTO_KEY_USAGE_USER_DEFINED_0;
    return number("TEST_USAGE_RC", 0);
}
/* Only the three read APIs are defined: any new hardware API reference makes
 * the contract-test link fail, including indirect addition of secret reads. */
