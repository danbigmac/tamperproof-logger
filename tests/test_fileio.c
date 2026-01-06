#include "../include/entry.h"
#include "../include/fileio.h"
#include "../include/crypto.h"
#include "../include/util.h"
#include "test.h"
#include <string.h>

void test_fileio(void)
{
    const char *path = "data/test_log.bin";
    remove(path);

    uint8_t prev_hash[HASH_SIZE] = {0};

    // Build entry 1
    LogEntry e1 = entry_create(util_timestamp_now(), 42 /*author*/, 12345ULL /*nonce*/, 1, 10, "first", prev_hash);
    entry_compute_hash(&e1, e1.entry_hash);
    do_sign(e1.entry_hash, e1.signature);
    TEST_ASSERT(fileio_append_entry(path, &e1) == 0);

    // Load last
    LogEntry last;
    TEST_ASSERT(fileio_read_last(path, &last) == 0);
    TEST_ASSERT(memcmp(last.entry_hash, e1.entry_hash, HASH_SIZE) == 0);

    // Append entry 2
    LogEntry e2 = entry_create(util_timestamp_now(), 42 /*author*/, 12346ULL /*nonce*/, 2, 20, "second", e1.entry_hash);
    entry_compute_hash(&e2, e2.entry_hash);
    do_sign(e2.entry_hash, e2.signature);
    TEST_ASSERT(fileio_append_entry(path, &e2) == 0);

    // Read all
    size_t count;
    LogEntry *entries = fileio_read_all(path, &count);
    TEST_ASSERT(entries != NULL);
    TEST_ASSERT(count == 2);
    TEST_ASSERT(memcmp(entries[0].entry_hash, e1.entry_hash, HASH_SIZE) == 0);
    TEST_ASSERT(memcmp(entries[1].entry_hash, e2.entry_hash, HASH_SIZE) == 0);
    free(entries);

    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) return 1;
    load_or_create_keys("data/test_pub.key", "data/test_priv.key");
    test_fileio();
}
