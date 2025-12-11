#include <string.h>
#include "entry.h"
#include "crypto.h"
#include "zlib.h"
#include "util.h"

LogEntry entry_create(uint64_t timestamp,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *description,
                      const uint8_t prev_hash[HASH_SIZE])
{
    LogEntry e = {0};
    e.timestamp = timestamp;
    e.event_type = event_type;
    e.player_id = player_id;
    e.description_len = (uint16_t)strlen(description);
    strncpy(e.description, description, e.description_len);
    memcpy(e.prev_hash, prev_hash, HASH_SIZE);
    return e;
}

size_t entry_serialize_for_hash(const LogEntry *e, uint8_t *buf, size_t max)
{
    uint16_t dlen = e->description_len;

    size_t needed =
        ENTRY_HEADER_SIZE + dlen + HASH_SIZE;  // prev_hash included

    if (max < needed)
        return 0;

    uint8_t *p = buf;

    write_u64_le(p, e->timestamp);
    p += TIMESTAMP_SIZE;
    write_u32_le(p, e->event_type);
    p += EVENT_TYPE_SIZE;
    write_u32_le(p, e->player_id);
    p += PLAYER_ID_SIZE;
    write_u16_le(p, dlen);
    p += DESCRIPTION_LEN_SIZE;

    memcpy(p, e->description, dlen);
    p += dlen;

    memcpy(p, e->prev_hash, HASH_SIZE);
    p += HASH_SIZE;

    return p - buf;   // number of bytes written
}

int entry_deserialize(LogEntry *e, const uint8_t *buf, size_t total_size)
{
    uint16_t dlen = 0;
    uint32_t length_suffix = 0;
    uint32_t crc_stored = 0;
    uint32_t crc_calc = 0;
    uint32_t body_size = 0;
    size_t expected_total = 0;

    if (total_size < ENTRY_LENGTH_PREFIX_SIZE + FOOTER_SIZE)
        return -1;

    // Get prefix length of body
    body_size = read_u32_le(buf);
    expected_total = ENTRY_LENGTH_PREFIX_SIZE + body_size + FOOTER_SIZE;

    if (expected_total != total_size)
        return -1;

    const uint8_t *body = buf + ENTRY_LENGTH_PREFIX_SIZE;

    // Get footer data
    length_suffix = read_u32_le(buf + ENTRY_LENGTH_PREFIX_SIZE + body_size);
    crc_stored = read_u32_le(buf + ENTRY_LENGTH_PREFIX_SIZE + body_size + ENTRY_LENGTH_SUFFIX_SIZE);

    // Make sure length prefix and suffix match
    if (length_suffix != body_size)
        return -1;

    // Do CRC32 check
    crc_calc = crc32(0L, body, body_size);
    if (crc_calc != crc_stored)
        return -1;

    // Parse body fields
    const uint8_t *p = body;
    memset(e, 0, sizeof(LogEntry));

    e->timestamp = read_u64_le(p);
    p += TIMESTAMP_SIZE;
    e->event_type = read_u32_le(p);
    p += EVENT_TYPE_SIZE;
    e->player_id = read_u32_le(p);
    p += PLAYER_ID_SIZE;

    dlen = read_u16_le(p);
    p += DESCRIPTION_LEN_SIZE;
    if (dlen >= DESCRIPTION_MAX) {
        return -1;
    }

    memcpy(e->description, p, dlen);
    e->description_len = dlen;
    p += dlen;

    memcpy(e->prev_hash, p, HASH_SIZE);
    p += HASH_SIZE;
    memcpy(e->entry_hash, p, HASH_SIZE);
    p += HASH_SIZE;
    memcpy(e->signature, p, crypto_sign_BYTES);
    p += crypto_sign_BYTES;

    return 0;
}

size_t entry_serialize(const LogEntry *e, uint8_t *buf, size_t max)
{
    uint16_t dlen = e->description_len;

    size_t base_size =
        ENTRY_HEADER_SIZE + dlen +
        HASH_SIZE + HASH_SIZE + crypto_sign_BYTES;

    size_t total_size = ENTRY_LENGTH_PREFIX_SIZE + base_size + FOOTER_SIZE;

    if (max < total_size)
        return 0;

    uint8_t *p = buf;

    write_u32_le(p, base_size);
    p += ENTRY_LENGTH_PREFIX_SIZE;
    write_u64_le(p, e->timestamp);
    p += TIMESTAMP_SIZE;
    write_u32_le(p, e->event_type);
    p += EVENT_TYPE_SIZE;
    write_u32_le(p, e->player_id);
    p += PLAYER_ID_SIZE;
    write_u16_le(p, dlen);
    p += DESCRIPTION_LEN_SIZE;
    memcpy(p, e->description, dlen);
    p += dlen;

    memcpy(p, e->prev_hash, HASH_SIZE);
    p += HASH_SIZE;
    memcpy(p, e->entry_hash, HASH_SIZE);
    p += HASH_SIZE;
    memcpy(p, e->signature, crypto_sign_BYTES);
    p += crypto_sign_BYTES;

    // Compute CRC32 over entry data (no footer, no length prefix)
    uint32_t crc = crc32(0L, buf + ENTRY_LENGTH_PREFIX_SIZE, base_size);

    write_u32_le(p, (uint32_t)base_size);
    p += ENTRY_LENGTH_SUFFIX_SIZE;
    write_u32_le(p, crc);
    p += ENTRY_CRC32_SIZE;

    return total_size;
}

int entry_compute_hash(LogEntry *entry, uint8_t out_hash[HASH_SIZE])
{
    uint8_t buffer[1024];
    size_t len = entry_serialize_for_hash(entry, buffer, sizeof(buffer));
    return do_hash(buffer, len, out_hash);
}
