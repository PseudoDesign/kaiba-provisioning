#ifndef KAIBA_DEVICE_SECRET_FIRMWARE_H
#define KAIBA_DEVICE_SECRET_FIRMWARE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rpifwcrypto.h>

#define EARLY_LOCKS (ARM_CRYPTO_KEY_STATUS_READ_LOCKED | ARM_CRYPTO_KEY_STATUS_GEN_LOCKED | ARM_CRYPTO_KEY_STATUS_USAGE_LOCKED)
#define ALL_LOCKS (EARLY_LOCKS | ARM_CRYPTO_KEY_STATUS_SIGN_LOCKED | ARM_CRYPTO_KEY_STATUS_HMAC_LOCKED)
#define DEVICE_TYPE ARM_CRYPTO_KEY_STATUS_TYPE_DEVICE_PRIVATE_KEY

enum fw_result { FW_OK, FW_LOCKED, FW_IO, FW_INVALID, FW_REJECTED };
struct fw_diagnostic { enum fw_result outcome; uint32_t tag; int error; };
bool fw_open(void);
void fw_close(void);
enum fw_result fw_count(uint32_t *);
enum fw_result fw_status(uint32_t, uint32_t *);
enum fw_result fw_usage(uint32_t, uint32_t *);
enum fw_result fw_error(uint32_t *);
enum fw_result fw_set_locks(uint32_t, uint32_t);
enum fw_result fw_hmac(uint32_t, const uint8_t *, size_t, uint8_t[32]);
enum fw_result fw_raw_read(uint32_t);
enum fw_result fw_legacy_read(void);
enum fw_result fw_sign(uint32_t);
const char *fw_last_outcome(void);
struct fw_diagnostic fw_snapshot(void);
void fw_diagnostic(int, const char *);
#endif
