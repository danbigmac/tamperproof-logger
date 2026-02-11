#include "logger.h"
#include "fileio.h"
#include "entry.h"
#include "event_type.h"
#include "crypto.h"
#include "util.h"
#include "peers.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static uint64_t random_nonce_u64(void)
{
    uint64_t x = 0;
    randombytes_buf(&x, sizeof(x));
    return x;
}

int logger_add_auto(const char *log_path,
                    uint32_t event_type,
                    uint32_t player_id,
                    const char *description)
{
    uint32_t author_node_id = 0;
    uint64_t nonce = random_nonce_u64();
    return logger_add(log_path, author_node_id, nonce, event_type, player_id, description);
}

int logger_add(const char *log_path,
               uint32_t author_node_id,
               uint64_t nonce,
               uint32_t event_type,
               uint32_t player_id,
               const char *description)
{
    uint8_t prev_hash[HASH_SIZE] = {0};
    uint64_t last_index = 0;

    if (fileio_get_tip(log_path, &last_index, prev_hash) != 0) {
        fprintf(stderr, "logger_add: failed to read log tip\n");
        return -1;
    }

    // Create a new entry
    LogEntry entry = entry_create(
        util_timestamp_now(),
        author_node_id,
        nonce,
        last_index + 1,
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

/** Entry policy function type */
typedef int (*entry_policy_fn)(void *ctx, const LogEntry *e, size_t idx);
/** Leader policy context */
typedef struct {
    uint32_t leader_id;
} LeaderPolicyCtx;

/* return 0 ok, nonzero -> fail */
static int policy_none(void *ctx, const LogEntry *e, size_t idx)
{
    (void)ctx; (void)e; (void)idx;
    return 0;
}

static int policy_require_leader_author(void *ctx, const LogEntry *e, size_t idx)
{
    LeaderPolicyCtx *lp = (LeaderPolicyCtx *)ctx;
    if (e->author_node_id != lp->leader_id) {
        fprintf(stderr, "verify: entry %zu author=%u != leader=%u\n",
                idx, e->author_node_id, lp->leader_id);
        return -1;
    }
    return 0;
}

/** Public key resolver function type */
typedef const uint8_t *(*pubkey_resolver_fn)(void *ctx, uint32_t author_node_id);

/* -------------------------
 * Pubkey resolvers
 * ------------------------- */

static const uint8_t *resolve_pub_single(void *ctx, uint32_t author_node_id)
{
    (void)ctx;
    (void)author_node_id;
    return get_public_key();
}

static const uint8_t *resolve_pub_from_peers(void *ctx, uint32_t author_node_id)
{
    PeerSet *ps = (PeerSet *)ctx;
    return peers_get_pubkey(ps, author_node_id);
}

/* -------------------------
 * Shared verification core
 * ------------------------- */
static int verify_entries_with_resolver(const char *log_path,
                                       pubkey_resolver_fn resolve_pub,
                                       void *resolve_ctx,
                                       entry_policy_fn policy,
                                       void *policy_ctx)
{
    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries) {
        fprintf(stderr, "verify: no entries or failed to read log (corruption/truncation?)\n");
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        // Apply entry policy if set
        if (policy && policy(policy_ctx, &entries[i], i) != 0) {
            fprintf(stderr, "verify: entry %zu failed policy check\n", i);
            free(entries);
            return -1;
        }

        // 1) Verify hash correctness: recompute hash(entry_body)
        uint8_t expected_hash[HASH_SIZE];
        if (entry_compute_hash(&entries[i], expected_hash) != 0) {
            fprintf(stderr, "verify: failed to compute hash at entry %zu\n", i);
            free(entries);
            return -1;
        }

        if (memcmp(entries[i].entry_hash, expected_hash, HASH_SIZE) != 0) {
            fprintf(stderr, "verify: entry %zu hash mismatch (tampered entry data)\n", i);
            free(entries);
            return -1;
        }

        // 2) Verify hash chain: entry[i].prev_hash == entry[i-1].entry_hash
        if (i > 0) {
            if (memcmp(entries[i].prev_hash, entries[i-1].entry_hash, HASH_SIZE) != 0) {
                fprintf(stderr, "verify: entry %zu chain broken (prev_hash mismatch)\n", i);
                free(entries);
                return -1;
            }
        } else {
            // Optional: require genesis prev_hash == zeros
            // (comment out if you don't want this rule)
            uint8_t zeros[HASH_SIZE] = {0};
            if (memcmp(entries[i].prev_hash, zeros, HASH_SIZE) != 0) {
                fprintf(stderr, "verify: genesis entry has non-zero prev_hash\n");
                free(entries);
                return -1;
            }
        }

        // 3) Verify signature using resolver(author_node_id)
        const uint8_t *pub = resolve_pub(resolve_ctx, entries[i].author_node_id);
        if (!pub) {
            fprintf(stderr, "verify: unknown author_node_id=%u at entry %zu\n",
                    entries[i].author_node_id, i);
            free(entries);
            return -1;
        }

        if (do_verify_with_pub(entries[i].entry_hash, entries[i].signature, pub) != 0) {
            fprintf(stderr, "verify: signature invalid at entry %zu (author=%u)\n",
                    i, entries[i].author_node_id);
            free(entries);
            return -1;
        }

        // 4) (Optional / legacy) key rotation handling
        //
        // If you're moving toward "pubkey determined by peers.conf",
        // then key-rotation-on-log is less central.
        //
        // If you still want to support it for single-key mode, you can keep
        // it ONLY in logger_verify() by handling it there (see below).
        //
        // For verify-peers: DO NOT mutate global PUBLIC_KEY based on log data.
        // That would make verification depend on entry order and global state,
        // and it conflicts with "peers.conf is source of truth".
    }

    free(entries);
    printf("Log verified: all entries valid.\n");
    return 0;
}

/* -------------------------
 * Public API
 * ------------------------- */

int logger_verify(const char *log_path)
{
    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries) {
        fprintf(stderr, "verify: no entries or failed to read log (corruption/truncation?)\n");
        return -1;
    }

    uint8_t current_pub[crypto_sign_PUBLICKEYBYTES];
    memcpy(current_pub, get_public_key(), sizeof(current_pub));

    for (size_t i = 0; i < count; i++) {
        uint8_t expected_hash[HASH_SIZE];
        if (entry_compute_hash(&entries[i], expected_hash) != 0) {
            fprintf(stderr, "verify: failed to compute hash at entry %zu\n", i);
            free(entries);
            return -1;
        }
        if (memcmp(entries[i].entry_hash, expected_hash, HASH_SIZE) != 0) {
            fprintf(stderr, "verify: entry %zu hash mismatch (tampered entry data)\n", i);
            free(entries);
            return -1;
        }

        if (i == 0) {
            uint8_t zeros[HASH_SIZE] = {0};
            if (memcmp(entries[i].prev_hash, zeros, HASH_SIZE) != 0) {
                fprintf(stderr, "verify: genesis entry has non-zero prev_hash\n");
                free(entries);
                return -1;
            }
        } else {
            if (memcmp(entries[i].prev_hash, entries[i - 1].entry_hash, HASH_SIZE) != 0) {
                fprintf(stderr, "verify: entry %zu chain broken (prev_hash mismatch)\n", i);
                free(entries);
                return -1;
            }
        }

        if (do_verify_with_pub(entries[i].entry_hash, entries[i].signature, current_pub) != 0) {
            fprintf(stderr, "verify: signature invalid at entry %zu (author=%u)\n",
                    i, entries[i].author_node_id);
            free(entries);
            return -1;
        }

        if (entries[i].event_type == EVENT_KEY_ROTATION) {
            uint8_t next_pub[crypto_sign_PUBLICKEYBYTES];
            int decoded = decode_pubkey_hex(next_pub,
                                            sizeof(next_pub),
                                            entries[i].description,
                                            entries[i].description_len);
            if (decoded != crypto_sign_PUBLICKEYBYTES) {
                fprintf(stderr, "verify: invalid KEY_ROTATION pubkey encoding at entry %zu\n", i);
                free(entries);
                return -1;
            }
            memcpy(current_pub, next_pub, sizeof(current_pub));
        }
    }

    free(entries);
    printf("Log verified: all entries valid.\n");
    return 0;
}

int logger_verify_local(const char *log_path, uint32_t leader_id)
{
    LeaderPolicyCtx p = { .leader_id = leader_id };
    return verify_entries_with_resolver(log_path,
                                        resolve_pub_single, NULL,
                                        policy_require_leader_author, &p);
}

int logger_verify_peers(const char *log_path, const char *peers_conf_path)
{
    if (!peers_conf_path) {
        fprintf(stderr, "logger_verify_peers: peers_conf_path required\n");
        return -1;
    }

    PeerSet ps;
    memset(&ps, 0, sizeof(ps));

    if (peers_load(&ps, peers_conf_path) != 0) {
        fprintf(stderr, "logger_verify_peers: failed to load peers from %s\n", peers_conf_path);
        peers_free(&ps);
        return -1;
    }

    int rc = verify_entries_with_resolver(log_path, resolve_pub_from_peers, &ps, policy_none, NULL);

    peers_free(&ps);
    return rc;
}

// int logger_verify(const char *log_path)
// {
//     size_t count = 0;
//     LogEntry *entries = fileio_read_all(log_path, &count);
//     if (!entries) {
//         fprintf(stderr, "logger_verify: no entries or failed to read log due to corruption or truncation\n");
//         return -1;
//     }

//     for (size_t i = 0; i < count; i++) {

//         //
//         // Verify signature: signature(entry_hash)
//         //
//         if (do_verify(entries[i].entry_hash, entries[i].signature) != 0) {
//             printf("Signature invalid at entry %zu\n", i);
//             free(entries);
//             return -1;
//         }

//         //
//         // Verify hash correctness: recompute hash(entry_body)
//         //
//         uint8_t expected_hash[HASH_SIZE];
//         entry_compute_hash(&entries[i], expected_hash);

//         if (memcmp(entries[i].entry_hash, expected_hash, HASH_SIZE) != 0) {
//             printf("Entry %zu hash mismatch (tampered entry data)\n", i);
//             free(entries);
//             return -1;
//         }

//         //
//         // Verify hash chain: entry[i].prev_hash == entry[i-1].entry_hash
//         //
//         if (i > 0) {
//             if (memcmp(entries[i].prev_hash, entries[i-1].entry_hash, HASH_SIZE) != 0) {
//                 printf("Entry %zu chain broken: prev_hash mismatch\n", i);
//                 free(entries);
//                 return -1;
//             }
//         }

//         // Handle key rotation entries
//         if (entries[i].event_type == EVENT_KEY_ROTATION) {
//             // description field must contain new public key in hex
//             uint8_t new_pub[crypto_sign_PUBLICKEYBYTES];
//             int decoded = decode_pubkey_hex(
//                 new_pub,
//                 sizeof(new_pub),
//                 entries[i].description,
//                 entries[i].description_len
//             );
//             if (decoded != crypto_sign_PUBLICKEYBYTES) {
//                 fprintf(stderr, "Invalid KEY_ROTATION entry at %zu (bad pubkey length)\n", i);
//                 free(entries);
//                 return -1;
//             }
//             // Switch to new public key from rotation event data for subsequent verifications
//             if (set_public_key(NULL, new_pub, 0) != 0) {
//                 fprintf(stderr, "logger_verify: failed to set new public key in memory\n");
//                 free(entries);
//                 return -1;
//             }
//         }
//     }

//     printf("Log verified: all entries valid.\n");
//     free(entries);
//     return 0;
// }

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

int logger_rotate_keys(const char *log_path,
                       const char *priv_path,
                       uint32_t author_node_id,
                       uint64_t nonce)
{
    // Generate new keypair
    uint8_t new_pub[crypto_sign_PUBLICKEYBYTES];
    uint8_t new_priv[crypto_sign_SECRETKEYBYTES];

    if (crypto_sign_keypair(new_pub, new_priv) != 0) {
        fprintf(stderr, "logger_rotate_keys: crypto_sign_keypair failed\n");
        return -1;
    }

    // Build description as hex-encoded new_pub
    char desc[DESCRIPTION_MAX];
    if (encode_pubkey_hex(desc, sizeof(desc), new_pub, crypto_sign_PUBLICKEYBYTES) != 0) {
        fprintf(stderr, "logger_rotate_keys: description buffer too small\n");
        return -1;
    }

    // Get prev_hash/index from last entry (or zeros/0 if none)
    uint8_t prev_hash[HASH_SIZE] = {0};
    uint64_t last_index = 0;
    if (fileio_get_tip(log_path, &last_index, prev_hash) != 0) {
        fprintf(stderr, "logger_rotate_keys: failed to read log tip\n");
        return -1;
    }

    // Create KEY_ROTATION log entry
    LogEntry entry = entry_create(
        util_timestamp_now(),
        author_node_id,
        nonce,
        last_index + 1,
        EVENT_KEY_ROTATION,
        0,          // player_id not meaningful here
        desc,
        prev_hash
    );

    // Compute hash and sign with the *old* private key
    entry_compute_hash(&entry, entry.entry_hash);
    do_sign(entry.entry_hash, entry.signature);

    if (fileio_append_entry(log_path, &entry) != 0) {
        fprintf(stderr, "logger_rotate_keys: failed to append rotation entry\n");
        return -1;
    }

    // Save new private key (root public key stays the same!)
    if (set_private_key(priv_path, new_priv, 1) != 0) {
        fprintf(stderr, "logger_rotate_keys: failed to save new private key\n");
        return -1;
    }

    printf("Key rotation entry appended. New key will be used for future entries.\n");
    return 0;
}
