#ifndef IDEM_H
#define IDEM_H

#include <stdint.h>
#include <stddef.h>

#define IDEM_HASH_SIZE 32

typedef struct {
    uint32_t author;
    uint64_t nonce;
    uint8_t  entry_hash[IDEM_HASH_SIZE];
    uint8_t  state;   // 0=empty, 1=filled, 2=tombstone (optional)
} IdemSlot;

typedef struct {
    IdemSlot *slots;
    size_t cap;       // number of slots (power of 2)
    size_t used;      // filled slots (state==1)
} IdemTable;

// Initialize with capacity (must be power of 2). Example: 4096 or 16384.
int  idem_init(IdemTable *t, size_t capacity_pow2);
void idem_free(IdemTable *t);

// Returns 1 if found, 0 if not found, -1 on error.
int  idem_get(const IdemTable *t, uint32_t author, uint64_t nonce,
              uint8_t out_hash[IDEM_HASH_SIZE]);

// Insert/update. Returns 0 on success, -1 on error.
int  idem_put(IdemTable *t, uint32_t author, uint64_t nonce,
              const uint8_t entry_hash[IDEM_HASH_SIZE]);

// Optional maintenance: clear table (keeps capacity).
void idem_clear(IdemTable *t);

#endif
