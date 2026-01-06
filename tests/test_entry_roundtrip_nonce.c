#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#include "entry.h"

int main(void)
{
    assert(sodium_init() != -1);

    uint8_t zeros[HASH_SIZE] = {0};

    LogEntry e = entry_create(
        123456789ULL,
        42,                 // author_node_id
        999999ULL,          // nonce
        2,                  // event_type
        23,                 // player_id
        "hello",
        zeros
    );

    // Pretend these were computed
    memset(e.entry_hash, 0xAB, HASH_SIZE);
    memset(e.signature,  0xCD, crypto_sign_BYTES);

    uint8_t buf[2048];
    size_t n = entry_serialize(&e, buf, sizeof(buf));
    assert(n > 0);

    LogEntry d;
    assert(entry_deserialize(&d, buf, n) == 0);

    assert(d.timestamp == e.timestamp);
    assert(d.author_node_id == e.author_node_id);
    assert(d.nonce == e.nonce);
    assert(d.event_type == e.event_type);
    assert(d.player_id == e.player_id);
    assert(d.description_len == e.description_len);
    assert(memcmp(d.description, e.description, e.description_len) == 0);
    assert(memcmp(d.prev_hash, e.prev_hash, HASH_SIZE) == 0);
    assert(memcmp(d.entry_hash, e.entry_hash, HASH_SIZE) == 0);
    assert(memcmp(d.signature, e.signature, crypto_sign_BYTES) == 0);

    // Tamper a byte in body to ensure CRC fails
    buf[ENTRY_LENGTH_PREFIX_SIZE + 1] ^= 0xFF;
    assert(entry_deserialize(&d, buf, n) != 0);

    printf("PASS test_entry_roundtrip_nonce\n");
    return 0;
}
