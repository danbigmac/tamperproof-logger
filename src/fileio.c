#include "fileio.h"
#include "entry.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int fileio_append_entry(const char *path, const LogEntry *entry)
{
    FILE *f = fopen(path, "ab");
    if (!f) return -1;

    uint8_t buf[2048];
    size_t len = entry_serialize(entry, buf, sizeof(buf));
    if (len == 0) {
        fclose(f);
        return -1;
    }

    if (fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

LogEntry *fileio_read_all(const char *path, size_t *count_out)
{
    *count_out = 0;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    size_t capacity = 16;
    size_t count = 0;
    LogEntry *entries = malloc(capacity * sizeof(LogEntry));
    if (!entries) {
        fclose(f);
        return NULL;
    }

    while (1) {
        //
        // Read prefix
        //
        uint8_t prefix_buf[ENTRY_LENGTH_PREFIX_SIZE];
        size_t n = fread(prefix_buf, 1, ENTRY_LENGTH_PREFIX_SIZE, f);

        if (n == 0) {
            // clean EOF
            break;
        }
        if (n != ENTRY_LENGTH_PREFIX_SIZE) {
            // Truncated prefix -> corruption
            free(entries);
            fclose(f);
            return NULL;
        }

        uint32_t body_size = read_u32_le(prefix_buf);

        // Safety guard against insane lengths (prevents OOM on corruption)
        if (body_size > (1u << 20)) { // 1MB cap for now
            free(entries);
            fclose(f);
            return NULL;
        }

        //
        // Compute total entry size
        //
        size_t total_size = ENTRY_LENGTH_PREFIX_SIZE + body_size + FOOTER_SIZE;

        //
        // Read entire remaining entry into a buffer
        //
        uint8_t *buf = malloc(total_size);
        if (!buf) {
            free(entries);
            fclose(f);
            return NULL;
        }

        // Copy prefix in place
        memcpy(buf, prefix_buf, ENTRY_LENGTH_PREFIX_SIZE);

        // Read body + footer
        if (fread(buf + ENTRY_LENGTH_PREFIX_SIZE, 1,
                  body_size + FOOTER_SIZE, f)
            != (body_size + FOOTER_SIZE))
        {
            // Truncated entry -> corruption
            free(buf);
            free(entries);
            fclose(f);
            return NULL;
        }

        //
        // Deserialize
        //
        LogEntry e;
        if (entry_deserialize(&e, buf, total_size) != 0) {
            // CRC/length/footer mismatch -> tampering or corruption
            free(buf);
            free(entries);
            fclose(f);
            return NULL;
        }

        free(buf);

        //
        // Append
        //
        if (count == capacity) {
            capacity *= 2;
            LogEntry *tmp = realloc(entries, capacity * sizeof(LogEntry));
            if (!tmp) {
                free(entries);
                fclose(f);
                return NULL;
            }
            entries = tmp;
        }

        entries[count++] = e;
    }

    fclose(f);

    if (count == 0) {
        free(entries);
        *count_out = 0;
        return NULL;
    }

    *count_out = count;
    return entries;
}

int fileio_read_last(const char *path, LogEntry *entry_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);

    if (filesize < FOOTER_SIZE) {
        fclose(f);
        return -1;
    }

    // Read footer
    uint8_t footer[FOOTER_SIZE];
    fseek(f, filesize - FOOTER_SIZE, SEEK_SET);

    if (fread(footer, 1, FOOTER_SIZE, f) != FOOTER_SIZE) {
        fclose(f);
        return -1;
    }

    uint32_t entry_len = read_u32_le(footer);
    uint32_t total_entry_size = ENTRY_LENGTH_PREFIX_SIZE + entry_len + FOOTER_SIZE;

    // Safety: prevent bogus huge sizes
    if ((entry_len > (1u << 20)) || (total_entry_size > (uint64_t)filesize)) {
        fclose(f);
        return -1;
    }

    long entry_start = filesize - total_entry_size;
    if (entry_start < 0) {
        fclose(f);
        return -1;
    }

    // Read entry body
    uint8_t *buf = malloc(total_entry_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    fseek(f, entry_start, SEEK_SET);
    if (fread(buf, 1, total_entry_size, f) != total_entry_size) {
        free(buf);
        fclose(f);
        return -1;
    }

    fclose(f);

    // Deserialize with CRC check
    memset(entry_out, 0, sizeof(LogEntry));
    int r = entry_deserialize(entry_out, buf, total_entry_size);

    free(buf);
    return r;
}

int fileio_get_tip(const char *path,
                   uint64_t *last_index_out,
                   uint8_t last_hash_out[HASH_SIZE])
{
    if (!path || !last_index_out || !last_hash_out) {
        return -1;
    }

    LogEntry last;
    if (fileio_read_last(path, &last) == 0) {
        *last_index_out = last.log_index;
        memcpy(last_hash_out, last.entry_hash, HASH_SIZE);
        return 0;
    }

    *last_index_out = 0;
    memset(last_hash_out, 0, HASH_SIZE);
    return 0;
}

int fileio_truncate_after(const char *path, uint64_t keep_log_index)
{
    if (!path) {
        return -1;
    }

    if (keep_log_index == 0) {
        FILE *f = fopen(path, "wb");
        if (!f) return -1;
        fclose(f);
        return 0;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    long keep_end = -1;
    long offset = 0;

    while (1) {
        uint8_t prefix_buf[ENTRY_LENGTH_PREFIX_SIZE];
        size_t n = fread(prefix_buf, 1, ENTRY_LENGTH_PREFIX_SIZE, f);

        if (n == 0) {
            break;
        }
        if (n != ENTRY_LENGTH_PREFIX_SIZE) {
            fclose(f);
            return -1;
        }

        uint32_t body_size = read_u32_le(prefix_buf);
        if (body_size > (1u << 20)) {
            fclose(f);
            return -1;
        }

        size_t total_size = ENTRY_LENGTH_PREFIX_SIZE + body_size + FOOTER_SIZE;
        uint8_t *buf = (uint8_t *)malloc(total_size);
        if (!buf) {
            fclose(f);
            return -1;
        }

        memcpy(buf, prefix_buf, ENTRY_LENGTH_PREFIX_SIZE);
        if (fread(buf + ENTRY_LENGTH_PREFIX_SIZE, 1, body_size + FOOTER_SIZE, f) !=
            body_size + FOOTER_SIZE) {
            free(buf);
            fclose(f);
            return -1;
        }

        LogEntry e;
        if (entry_deserialize(&e, buf, total_size) != 0) {
            free(buf);
            fclose(f);
            return -1;
        }
        free(buf);

        offset += (long)total_size;
        if (e.log_index == keep_log_index) {
            keep_end = offset;
            break;
        }
    }

    fclose(f);

    if (keep_end < 0) {
        return -1;
    }

    if (truncate(path, keep_end) != 0) {
        return -1;
    }

    return 0;
}
