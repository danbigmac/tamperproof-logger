#ifndef ENTRY_H
#define ENTRY_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

/** Maximum description stringlength */
#define DESCRIPTION_MAX 256
/** Size of entry length prefix size field */
#define ENTRY_LENGTH_PREFIX_SIZE 4
/** Size of timestamp field */
#define TIMESTAMP_SIZE 8
/** Size of author node ID field */
#define AUTHOR_NODE_ID_SIZE 4
/** Size of nonce field */
#define NONCE_SIZE 8
/** Size of log index field */
#define LOG_INDEX_SIZE 8
/** Size of event type field */
#define EVENT_TYPE_SIZE 4
/** Size of player ID field */
#define PLAYER_ID_SIZE 4
/** Size of description length field */
#define DESCRIPTION_LEN_SIZE 2
/** Size of entry header (does not include entry length prefix field) */
#define ENTRY_HEADER_SIZE (TIMESTAMP_SIZE + AUTHOR_NODE_ID_SIZE + NONCE_SIZE + LOG_INDEX_SIZE + EVENT_TYPE_SIZE + PLAYER_ID_SIZE + DESCRIPTION_LEN_SIZE)
/** Size of hash field */
#define HASH_SIZE 32
/** Size of entry length suffix field */
#define ENTRY_LENGTH_SUFFIX_SIZE 4
/** Size of CRC32 field */
#define ENTRY_CRC32_SIZE 4
/** Size of footer */
#define FOOTER_SIZE (ENTRY_LENGTH_SUFFIX_SIZE + ENTRY_CRC32_SIZE)

/**
 * Log entry structure.
 * Includes entry length prefix and suffix for more efficient serialization.
 * Supports variable-length descriptions, up to DESCRIPTION_MAX bytes.
 * Includes checksum for data integrity verification.
 */
typedef struct {
    uint32_t entry_length_prefix;      // LENGTH OF BODY ONLY (not including prefix or footer)

    uint64_t timestamp;
    uint32_t author_node_id;
    uint64_t nonce;
    uint64_t log_index;
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

/** Construct a new entry in memory before hashing/signing */
LogEntry entry_create(uint64_t timestamp,
                      uint32_t author_node_id,
                      uint64_t nonce,
                      uint64_t log_index,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *description,
                      const uint8_t prev_hash[HASH_SIZE]);

/** Computes entry_hash (but does NOT sign) */
int entry_compute_hash(LogEntry *entry, uint8_t out_hash[HASH_SIZE]);

/** Serialize entry for hashing/signing (excluding entry_hash & signature) */
size_t entry_serialize_for_hash(const LogEntry *entry, uint8_t *buf, size_t buf_size);

/** Serialize entire entry to disk */
size_t entry_serialize(const LogEntry *entry, uint8_t *buf, size_t buf_size);

/** Deserialize entry from disk */
int entry_deserialize(LogEntry *entry, const uint8_t *buf, size_t buf_size);

#endif
