#include "logger.h"
#include "fileio.h"
#include "entry.h"
#include "event_type.h"
#include "crypto.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

int logger_add(const char *log_path,
               uint32_t event_type,
               uint32_t player_id,
               const char *description)
{
    LogEntry prev = {0};
    uint8_t prev_hash[HASH_SIZE] = {0};

    // Load last entry if exists
    if (fileio_read_last(log_path, &prev) == 0) {
        memcpy(prev_hash, prev.entry_hash, HASH_SIZE);
    }

    // Create a new entry
    LogEntry entry = entry_create(
        util_timestamp_now(),
        event_type,
        player_id,
        description,
        prev_hash
    );

    // Compute the entry hash
    entry_compute_hash(&entry, entry.entry_hash);

    // Sign entry hash
    do_sign(entry.entry_hash, entry.signature);

    // Append entry to log
    return fileio_append_entry(log_path, &entry);
}

int logger_verify(const char *log_path)
{
    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries) return -1;

    for (size_t i = 0; i < count; i++) {

        //
        // Verify signature: signature(entry_hash)
        //
        if (do_verify(entries[i].entry_hash, entries[i].signature) != 0) {
            printf("Signature invalid at entry %zu\n", i);
            free(entries);
            return -1;
        }

        //
        // Verify hash correctness: recompute hash(entry_body)
        //
        uint8_t expected_hash[HASH_SIZE];
        entry_compute_hash(&entries[i], expected_hash);

        if (memcmp(entries[i].entry_hash, expected_hash, HASH_SIZE) != 0) {
            printf("Entry %zu hash mismatch (tampered entry data)\n", i);
            free(entries);
            return -1;
        }

        //
        // Verify hash chain: entry[i].prev_hash == entry[i-1].entry_hash
        //
        if (i > 0) {
            if (memcmp(entries[i].prev_hash, entries[i-1].entry_hash, HASH_SIZE) != 0) {
                printf("Entry %zu chain broken: prev_hash mismatch\n", i);
                free(entries);
                return -1;
            }
        }
    }

    printf("Log verified: all entries valid.\n");
    free(entries);
    return 0;
}

int logger_print(const char *log_path)
{
    size_t count;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries) return -1;

    for (size_t i = 0; i < count; i++) {
        printf("Entry %zu:\n", i);
        printf("  time:   %llu\n", (unsigned long long)entries[i].timestamp);
        printf("  player: %u\n", entries[i].player_id);
        printf("  type:   %s\n", event_type_name(entries[i].event_type));
        printf("  desc:   %.*s\n", entries[i].description_len, entries[i].description);

        // Show hash chain for debugging
        printf("  hash:   ");
        util_print_hex(entries[i].entry_hash, HASH_SIZE);

        printf("  prev:   ");
        util_print_hex(entries[i].prev_hash, HASH_SIZE);

        printf("\n");
    }

    free(entries);
    return 0;
}
