#include "../include/logger.h"
#include "../include/fileio.h"
#include "../include/entry.h"
#include "../include/event_type.h"
#include "../include/crypto.h"
#include "../include/util.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

// Remove test artifacts
static void cleanup_files(const char *log_path, const char *pub_path, const char *priv_path)
{
    remove(log_path);
    remove(pub_path);
    remove(priv_path);
}

// Flip one hex character in a KEY_ROTATION entry description, in-place, on disk.
static int tamper_rotation_pubkey_hex_in_file(const char *log_path)
{
    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries || count == 0) {
        free(entries);
        return -1;
    }

    // Find the first KEY_ROTATION entry index
    size_t rot_i = (size_t)-1;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].event_type == EVENT_KEY_ROTATION) {
            rot_i = i;
            break;
        }
    }
    free(entries);

    if (rot_i == (size_t)-1) {
        fprintf(stderr, "tamper: no KEY_ROTATION entry found\n");
        return -1;
    }

    // Now we need to locate the KEY_ROTATION entry byte offset in the file.
    // Because entries are variable-size, we re-scan the file by reading the prefix lengths
    // and summing total sizes until we reach rot_i.
    FILE *f = fopen(log_path, "r+b");
    if (!f) return -1;

    long rot_offset = 0;

    for (size_t i = 0; i < rot_i; i++) {
        uint8_t prefix[ENTRY_LENGTH_PREFIX_SIZE];
        if (fread(prefix, 1, ENTRY_LENGTH_PREFIX_SIZE, f) != ENTRY_LENGTH_PREFIX_SIZE) {
            fclose(f);
            return -1;
        }
        uint32_t body_size = read_u32_le(prefix);
        long total_size = (long)ENTRY_LENGTH_PREFIX_SIZE + (long)body_size + (long)FOOTER_SIZE;

        // skip remainder of this entry (we already consumed prefix)
        if (fseek(f, total_size - ENTRY_LENGTH_PREFIX_SIZE, SEEK_CUR) != 0) {
            fclose(f);
            return -1;
        }

        rot_offset += total_size;
    }

    // We are now positioned at start of rotation entry.
    // Read its prefix to get body_size.
    uint8_t prefix[ENTRY_LENGTH_PREFIX_SIZE];
    if (fread(prefix, 1, ENTRY_LENGTH_PREFIX_SIZE, f) != ENTRY_LENGTH_PREFIX_SIZE) {
        fclose(f);
        return -1;
    }
    uint32_t body_size = read_u32_le(prefix);

    // Read just the body into memory so we can locate description.
    uint8_t *body = (uint8_t *)malloc(body_size);
    TEST_ASSERT(body != NULL);

    if (fread(body, 1, body_size, f) != body_size) {
        free(body);
        fclose(f);
        return -1;
    }

    // Body layout:
    // timestamp(8) event_type(4) player_id(4) desc_len(2) desc(dlen) prev_hash(32) entry_hash(32) sig(64)
    size_t off = 0;
    off += TIMESTAMP_SIZE;
    off += EVENT_TYPE_SIZE;
    off += PLAYER_ID_SIZE;

    uint16_t dlen = read_u16_le(body + off);
    off += DESCRIPTION_LEN_SIZE;

    // Sanity: description should be hex pubkey
    if (dlen < 2) {
        free(body);
        fclose(f);
        return -1;
    }

    // Choose a byte inside the description to flip (first character is fine),
    // but ensure we flip it to another valid hex char so decode doesn't fail
    size_t desc_off_in_body = off; // start of description within body
    char c = (char)body[desc_off_in_body];

    // Replace with another hex character different from current
    char replacement = (c == 'a') ? 'b' : 'a';
    body[desc_off_in_body] = (uint8_t)replacement;

    // Now write back the modified body bytes to the file.
    // File position is currently: start_of_entry + prefix + body (we read it).
    // We want to seek back to the start of body and overwrite it.
    // Current pos = rot_offset + prefix_size + body_size.
    long body_start_pos = rot_offset + ENTRY_LENGTH_PREFIX_SIZE;

    if (fseek(f, body_start_pos, SEEK_SET) != 0) {
        free(body);
        fclose(f);
        return -1;
    }

    if (fwrite(body, 1, body_size, f) != body_size) {
        free(body);
        fclose(f);
        return -1;
    }

    free(body);
    fclose(f);
    return 0;
}

void test_rotation_pubkey_tamper_detected(void)
{
    const char *log_path  = "data/test_rotation_tamper.log";
    const char *pub_path  = "data/test_rotation_tamper_public.key";
    const char *priv_path = "data/test_rotation_tamper_private.key";

    cleanup_files(log_path, pub_path, priv_path);

    // Root keys
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0);

    // Add some initial entries with root signing key
    TEST_ASSERT(logger_add(log_path, (uint32_t)EVENT_SCORE, 23, "root: score") == 0);
    TEST_ASSERT(logger_add(log_path, (uint32_t)EVENT_FOUL,  12, "root: foul") == 0);

    // Rotate once and add one post-rotation entry
    TEST_ASSERT(logger_rotate_keys(log_path, priv_path) == 0);
    TEST_ASSERT(logger_add(log_path, (uint32_t)EVENT_SCORE, 7, "newkey: score") == 0);

    // Reset verification to start from root public key in memory
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0);
    TEST_ASSERT(logger_verify(log_path) == 0);

    // Tamper with the pubkey hex inside the KEY_ROTATION entry
    TEST_ASSERT(tamper_rotation_pubkey_hex_in_file(log_path) == 0);

    // Reset again to root and verify: MUST FAIL now
    TEST_ASSERT(load_or_create_keys(pub_path, priv_path) == 0);
    TEST_ASSERT(logger_verify(log_path) != 0);

    cleanup_files(log_path, pub_path, priv_path);
    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    test_rotation_pubkey_tamper_detected();
    return 0;
}
