#ifndef KAIBA_DEVICE_SECRET_H
#define KAIBA_DEVICE_SECRET_H
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <jansson.h>
#include "firmware.h"

#define STORAGE_BYTES (UINT64_C(65) * 1024 * 1024)
#define DATA_START (UINT64_C(1024) * 1024)
#define SCHEME "kaiba-firmware-hmac-counter-v1"

struct config {
    json_t *json;
    const char *experiment, *target, *source, *volume, *partition, *board_hash, *disk_hash;
    uint32_t slot, usage;
    uint8_t nonce[32];
};
struct observation { char boot_id[37], boot_hash[65], root_hash[65], nonce_hash[65]; };
struct storage { int fd; bool linear, opened; unsigned phase; uint8_t binding[32]; char prior_boot[37]; };

bool hash256(const void *, size_t, uint8_t[32]);
bool unhex(const char *, uint8_t *, size_t);
void hex(const uint8_t *, size_t, char *);
bool uuid_valid(const char *);
bool read_file(const char *, void *, size_t, size_t *);
bool config_load(const char *, struct config *);
bool runtime_observe(const struct config *, struct observation *);
bool memory_protect(void);
int events_open(void);
bool event_emit(int, const struct config *, const struct observation *, unsigned, const char *, unsigned, bool);
bool derive_message(const char *, const uint8_t[32], uint8_t *, size_t *);
bool constant_same(const uint8_t[32], const uint8_t[32]);

bool storage_open(struct storage *, const struct config *, const struct observation *);
bool storage_intent(struct storage *, const struct observation *);
bool storage_volume(struct storage *, const struct config *, const uint8_t[32], const uint8_t[32]);
bool storage_complete(struct storage *, const struct observation *);
bool storage_close(struct storage *);

#endif
