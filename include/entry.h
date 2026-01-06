#ifndef ENTRY_H
#define ENTRY_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

#define DESCRIPTION_MAX 256
#define ENTRY_LENGTH_PREFIX_SIZE 4
#define TIMESTAMP_SIZE 8
#define AUTHOR_NODE_ID_SIZE 4
#define NONCE_SIZE 8
#define EVENT_TYPE_SIZE 4
#define PLAYER_ID_SIZE 4
#define DESCRIPTION_LEN_SIZE 2
#define ENTRY_HEADER_SIZE (TIMESTAMP_SIZE + AUTHOR_NODE_ID_SIZE + NONCE_SIZE + EVENT_TYPE_SIZE + PLAYER_ID_SIZE + DESCRIPTION_LEN_SIZE)
#define HASH_SIZE 32
#define ENTRY_LENGTH_SUFFIX_SIZE 4
#define ENTRY_CRC32_SIZE 4
#define FOOTER_SIZE (ENTRY_LENGTH_SUFFIX_SIZE + ENTRY_CRC32_SIZE)     // 4 bytes length + 4 bytes CRC32

typedef struct {
    uint32_t entry_length_prefix;      // LENGTH OF BODY ONLY (not including prefix or footer)

    uint64_t timestamp;
    uint32_t author_node_id;
    uint64_t nonce;
    uint32_t event_type;
    uint32_t player_id;
    uint16_t description_len;

    char description[DESCRIPTION_MAX];

    uint8_t prev_hash[HASH_SIZE];
    uint8_t entry_hash[HASH_SIZE];
    uint8_t signature[crypto_sign_BYTES];

    uint32_t entry_length;  // L.E. -- length of serialized entry on disk excluding this field and crc32
    uint32_t entry_crc32;   // L.E. -- checksum of serialized entry on disk excluding this field and entry_length

} LogEntry;

/* Construct a new entry in memory before hashing/signing */
LogEntry entry_create(uint64_t timestamp,
                      uint32_t author_node_id,
                      uint64_t nonce,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *description,
                      const uint8_t prev_hash[HASH_SIZE]);

/* Computes entry_hash (but does NOT sign) */
int entry_compute_hash(LogEntry *entry, uint8_t out_hash[HASH_SIZE]);

/* Serialize entry for hashing/signing (excluding entry_hash & signature) */
size_t entry_serialize_for_hash(const LogEntry *entry, uint8_t *buf, size_t buf_size);

/* Serialize entire entry to disk */
size_t entry_serialize(const LogEntry *entry, uint8_t *buf, size_t buf_size);

/* Deserialize entry from disk */
int entry_deserialize(LogEntry *entry, const uint8_t *buf, size_t buf_size);

#endif
