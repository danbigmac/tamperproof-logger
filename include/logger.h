#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stddef.h>

/* Adds a new log entry, returns 0 on success */
int logger_add(const char *log_path,
               uint32_t event_type,
               uint32_t player_id,
               const char *description);

/* Verifies entire log chain and signatures */
int logger_verify(const char *log_path);

/* Prints entries in human-readable form */
int logger_print(const char *log_path);

#endif
