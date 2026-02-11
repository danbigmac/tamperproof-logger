#ifndef FILEIO_H
#define FILEIO_H

#include "entry.h"

/* Append one entry to log file */
int fileio_append_entry(const char *path, const LogEntry *entry);

/* Read entire log into memory (returns dynamically allocated array) */
LogEntry *fileio_read_all(const char *path, size_t *count_out);

/* Read last entry (fast path) */
int fileio_read_last(const char *path, LogEntry *entry_out);

/* Read current tip as (last_index, last_hash). Empty log -> index=0, hash=zeros. */
int fileio_get_tip(const char *path,
                   uint64_t *last_index_out,
                   uint8_t last_hash_out[HASH_SIZE]);

/* Truncate log after keep_log_index (0 => truncate entire log). */
int fileio_truncate_after(const char *path, uint64_t keep_log_index);

#endif
