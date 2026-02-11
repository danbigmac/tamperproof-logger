#include "../include/entry.h"
#include "../include/crypto.h"
#include "../include/util.h"
#include "test.h"
#include <string.h>

void test_entry_roundtrip(void)
{
    uint8_t prev_hash[HASH_SIZE] = {0};

    LogEntry e1 = entry_create(
        123456789,
        42 /*author*/,
        12345ULL /*nonce*/,
        1,  // log_index
        1,
        23,
        "hello world",
        prev_hash
    );

    entry_compute_hash(&e1, e1.entry_hash);
    do_sign(e1.entry_hash, e1.signature);

    uint8_t buf[2048];
    size_t n = entry_serialize(&e1, buf, sizeof(buf));
    TEST_ASSERT(n > 0);

    LogEntry e2;
    TEST_ASSERT(entry_deserialize(&e2, buf, n) == 0);

    TEST_ASSERT(e2.timestamp == e1.timestamp);
    TEST_ASSERT(e2.event_type == e1.event_type);
    TEST_ASSERT(e2.player_id == e1.player_id);
    TEST_ASSERT(e2.description_len == e1.description_len);
    TEST_ASSERT(memcmp(e2.description, e1.description, e1.description_len) == 0);
    TEST_ASSERT(memcmp(e2.prev_hash, e1.prev_hash, HASH_SIZE) == 0);
    TEST_ASSERT(memcmp(e2.entry_hash, e1.entry_hash, HASH_SIZE) == 0);

    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) return 1;
    load_or_create_keys("data/test_pub.key", "data/test_priv.key");

    test_entry_roundtrip();
}
