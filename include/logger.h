#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stddef.h>

/* Adds a new log entry, returns 0 on success */
int logger_add(const char *log_path,
               uint32_t author_node_id,
               uint64_t nonce,
               uint32_t event_type,
               uint32_t player_id,
               const char *description);

/* Adds a new log entry with automatically generated nonce and author_node_id of 0; returns 0 on success */
int logger_add_auto(const char *log_path,
                    uint32_t event_type,
                    uint32_t player_id,
                    const char *description);

/* Verifies entire log chain and signatures */
int logger_verify(const char *log_path);

/**
 * Verify a log where entries may have different authors, using peers.conf
 * as the source of truth for author_node_id -> pubkey mapping.
 */
int logger_verify_peers(const char *log_path, const char *peers_conf_path);

/* Prints entries in human-readable form */
int logger_print(const char *log_path);

/* Rotates the signing keys for the logger */
int logger_rotate_keys(const char *log_path,
                       const char *priv_path,
                       uint32_t author_node_id,
                       uint64_t nonce);

#endif
