#include "harness.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool read_file(const char *path, void *out, size_t bound, size_t *length) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    size_t n = 0;
    while (ok && n < bound) {
        ssize_t r = read(fd, (char *)out+n, bound-n);
        if (r < 0) { ok = false; break; }
        if (!r) break;
        n += (size_t)r;
    }
    char extra;
    if (ok && read(fd, &extra, 1) != 0) ok = false;
    if (close(fd)) ok = false;
    *length = n;
    return ok;
}
static bool identifier(const char *s) {
    if (!s || !*s || strlen(s) > 64 || !isalnum((unsigned char)*s)) return false;
    for (; *s; ++s) if (!(*s >= 'a' && *s <= 'z') && !isdigit((unsigned char)*s) && *s != '-') return false;
    return true;
}
bool uuid_valid(const char *s) {
    if (!s || strlen(s) != 36) return false;
    bool nonzero = false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return false; }
        else { if (!strchr("0123456789abcdef", s[i])) return false; if (s[i] != '0') nonzero = true; }
    }
    return nonzero;
}
static const char *string(json_t *j, const char *key) {
    json_t *v = json_object_get(j, key);
    const char *s = json_string_value(v);
    return s && strlen(s) == json_string_length(v) ? s : NULL;
}
static bool digest_valid(const char *s, size_t n) {
    uint8_t data[32] = {0}, zero[32] = {0};
    return unhex(s, data, n) && memcmp(data, zero, n) != 0;
}
bool config_load_schema(const char *path, struct config *c, const char *expected_schema) {
    char bytes[8192]; size_t n = 0;
    if (!read_file(path, bytes, sizeof(bytes), &n)) return false;
    c->json = json_loadb(bytes, n, JSON_REJECT_DUPLICATES, NULL);
    if (!json_is_object(c->json) || json_object_size(c->json) != 12) return false;
    const char *schema = string(c->json, "schema_version"), *scheme = string(c->json, "scheme");
    c->experiment = string(c->json, "experiment_id"); c->target = string(c->json, "target_reference");
    c->source = string(c->json, "source_revision"); c->volume = string(c->json, "volume_uuid");
    c->partition = string(c->json, "partition_uuid"); c->board_hash = string(c->json, "board_serial_sha256");
    c->disk_hash = string(c->json, "disk_serial_sha256");
    json_t *slot = json_object_get(c->json, "slot_id"), *usage = json_object_get(c->json, "expected_usage");
    if (!schema || strcmp(schema, expected_schema) || !scheme || strcmp(scheme, SCHEME) ||
        !identifier(c->experiment) || !identifier(c->target) || !digest_valid(c->source, 20) ||
        !uuid_valid(c->volume) || !uuid_valid(c->partition) || !strcmp(c->volume, c->partition) ||
        !digest_valid(c->board_hash, 32) || !digest_valid(c->disk_hash, 32) ||
        !digest_valid(string(c->json, "nonce_hex"), 32) || !unhex(string(c->json, "nonce_hex"), c->nonce, 32) ||
        !json_is_integer(slot) || json_integer_value(slot) != 1 ||
        !json_is_integer(usage) || (json_integer_value(usage) != 0 &&
        (json_integer_value(usage) < 8 || json_integer_value(usage) > 14))) return false;
    c->slot = 1; c->usage = (uint32_t)json_integer_value(usage);
    return true;
}

bool config_load(const char *path, struct config *c) {
    return config_load_schema(path, c, "kaiba.device-secret-target/v1alpha1");
}

bool event_emit(int fd, const struct config *c, const struct observation *o, unsigned phase,
                const char *check, unsigned sequence, bool passed) {
    json_t *j = json_pack("{s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:i,s:s,s:s,s:i,s:s,s:b}",
        "schema_version", "kaiba.device-secret-experiment-event/v1alpha1",
        "experiment_id", c->experiment, "target_reference", c->target, "source_revision", c->source,
        "boot_image_sha256", o->boot_hash, "verity_root_hash", o->root_hash,
        "volume_uuid", c->volume, "nonce_sha256", o->nonce_hash, "slot_id", (int)c->slot,
        "phase", phase == 0 ? "create" : "reopen", "boot_id", o->boot_id,
        "sequence", (int)sequence, "check", check, "passed", passed);
    if (!j) return false;
    char *encoded = json_dumps(j, JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    json_decref(j);
    if (!encoded) return false;
    char line[2048];
#ifdef KAIBA_TESTING
    const char *prefix = "KAIBA_DEVICE_SECRET_TEST_EVENT=";
#else
    const char *prefix = "KAIBA_DEVICE_SECRET_EVENT=";
#endif
    int size = snprintf(line, sizeof(line), "%s%s\n", prefix, encoded);
    free(encoded);
    return size > 0 && (size_t)size < sizeof(line) && write(fd, line, (size_t)size) == size;
}
