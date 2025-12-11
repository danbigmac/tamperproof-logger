#ifndef FILEIO_H
#define FILEIO_H

#include "entry.h"

/* Append one entry to log file */
int fileio_append_entry(const char *path, const LogEntry *entry);

/* Read entire log into memory (returns dynamically allocated array) */
LogEntry *fileio_read_all(const char *path, size_t *count_out);

/* Read last entry (fast path) */
int fileio_read_last(const char *path, LogEntry *entry_out);

#endif
