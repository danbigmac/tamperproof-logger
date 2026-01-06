#include "../include/logger.h"
#include "../include/crypto.h"
#include "../include/util.h"
#include "../include/event_type.h"
#include "test.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

// Helpers to remove test artifacts safely
static void cleanup_files(const char *log_path, const char *pub_path, const char *priv_path)
{
    remove(log_path);
    remove(pub_path);
    remove(priv_path);
}

// Flip a byte in the log to simulate tampering
static void tamper_file(const char *path, long offset)
{
    FILE *f = fopen(path, "r+b");
    TEST_ASSERT(f != NULL);

    TEST_ASSERT(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    TEST_ASSERT(size > 0);

    // clamp offset into the file so test is stable across sizes
    if (offset < 0) offset = 0;
    if (offset >= size) offset = size / 2;

    TEST_ASSERT(fseek(f, offset, SEEK_SET) == 0);

    int c = fgetc(f);
    TEST_ASSERT(c != EOF);

    TEST_ASSERT(fseek(f, offset, SEEK_SET) == 0);
    fputc((unsigned char)(c ^ 0xFF), f);  // flip bits

    fclose(f);
}

void test_key_rotation_end_to_end(void)
{
    const char *log_path  = "data/test_rotation.log";
    const char *pub_path  = "data/test_rotation_public.key";  // root public key
    const char *priv_path = "data/test_rotation_private.key"; // current private key

    cleanup_files(log_path, pub_path, priv_path);

    // Root keys created here
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0);

    // Add entries under initial signing key
    TEST_ASSERT(logger_add(log_path, 42 /*author*/, 12345ULL /*nonce*/, (uint32_t)EVENT_SCORE, 23, "first key: score") == 0);
    TEST_ASSERT(logger_add(log_path, 42 /*author*/, 12346ULL /*nonce*/, (uint32_t)EVENT_FOUL,  12, "first key: foul") == 0);

    // Rotate keys: appends KEY_ROTATION entry, switches signing key
    TEST_ASSERT(logger_rotate_keys(log_path, priv_path, 42 /*author*/, 12347ULL /*nonce*/) == 0);

    // Add entries under rotated signing key
    TEST_ASSERT(logger_add(log_path, 42 /*author*/, 12348ULL /*nonce*/, (uint32_t)EVENT_SCORE, 7, "second key: score") == 0);
    TEST_ASSERT(logger_add(log_path, 42 /*author*/, 12349ULL /*nonce*/, (uint32_t)EVENT_SUB,   8, "second key: sub") == 0);

    // Rotate a second time to prove multiple rotations work
    TEST_ASSERT(logger_rotate_keys(log_path, priv_path, 42 /*author*/, 12350ULL /*nonce*/) == 0);
    TEST_ASSERT(logger_add(log_path, 42 /*author*/, 12349ULL /*nonce*/, (uint32_t)EVENT_SCORE, 99, "third key: score") == 0);

    // IMPORTANT: reset in-memory public key to the ROOT key before verifying
    // Because logger_verify() uses do_verify() which relies on current in-memory pub key,
    // and logger_verify() is supposed to start from the root and then follow rotation entries.
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0);

    // Verify should succeed across rotations
    TEST_ASSERT(logger_verify(log_path) == 0);

    // Tamper with the file and ensure verification fails
    tamper_file(log_path, 264);  // arbitrary offset; clamped safely
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0); // reset root pub in memory
    TEST_ASSERT(logger_verify(log_path) != 0);

    // Cleanup
    cleanup_files(log_path, pub_path, priv_path);

    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    test_key_rotation_end_to_end();
    return 0;
}
