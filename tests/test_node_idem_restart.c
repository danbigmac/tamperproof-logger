// tests/test_node_idem_restart.c
//
// Verifies idempotency survives a node restart by rebuilding the idem table
// from the on-disk log in node_create().
//
// Expectations:
//   - First submit appends a new entry (rc == 0), log count becomes 1.
//   - After node_destroy + node_create, submitting SAME (author,node_nonce)
//     returns duplicate (rc == 1), returns SAME hash, log count stays 1.
//   - Submitting a different nonce appends (rc == 0), log count becomes 2.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "node.h"
#include "fileio.h"
#include "entry.h"
#include "event_type.h" // for an event constant like EVENT_SCORE (adjust as needed)

static void rm(const char *path) { remove(path); }

static int count_entries(const char *log_path, size_t *out_count)
{
    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries) {
        *out_count = 0;
        return 0; // treat missing/empty as 0
    }
    free(entries);
    *out_count = count;
    return 0;
}

static NodeConfig make_cfg(uint32_t node_id,
                           const char *log_path,
                           const char *pub_path,
                           const char *priv_path)
{
    NodeConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.node_id = node_id;
    cfg.listen_host = "127.0.0.1";
    cfg.listen_port = 0;          // unused
    cfg.log_path = log_path;
    cfg.pub_path = pub_path;
    cfg.priv_path = priv_path;
    cfg.peers_conf_path = NULL;
    return cfg;
}

int main(void)
{
    if (sodium_init() == -1) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    const char *log_path  = "data/test_node_idem_restart.log";
    const char *pub_path  = "data/test_node_idem_restart_root_public.key";
    const char *priv_path = "data/test_node_idem_restart_private.key";

    // clean slate
    rm(log_path);
    rm(pub_path);
    rm(priv_path);

    NodeConfig cfg = make_cfg(42, log_path, pub_path, priv_path);

    // ---- First start: submit once ----
    Node *n1 = node_create(&cfg);
    if (!n1) {
        fprintf(stderr, "node_create (n1) failed\n");
        return 1;
    }

    uint64_t nonce = 7777777ULL;
    uint8_t h1[HASH_SIZE];

    const char *desc = "restart-idem";
    int rc = node_submit_local(n1,
                              EVENT_SCORE, // change if needed
                              23,
                              desc,
                              (uint16_t)strlen(desc),
                              nonce,
                              h1);
    if (rc != 0) {
        fprintf(stderr, "expected first submit rc=0, got %d\n", rc);
        node_destroy(n1);
        return 1;
    }

    size_t count = 0;
    count_entries(log_path, &count);
    if (count != 1) {
        fprintf(stderr, "expected 1 entry after first submit, got %zu\n", count);
        node_destroy(n1);
        return 1;
    }

    node_destroy(n1);

    // ---- Restart: create node again (should rebuild idem from log) ----
    Node *n2 = node_create(&cfg);
    if (!n2) {
        fprintf(stderr, "node_create (n2) failed\n");
        return 1;
    }

    uint8_t h2[HASH_SIZE];
    rc = node_submit_local(n2,
                           EVENT_SCORE, // change if needed
                           23,
                           desc,
                           (uint16_t)strlen(desc),
                           nonce,  // SAME nonce
                           h2);
    if (rc != 1) {
        fprintf(stderr, "expected duplicate submit after restart rc=1, got %d\n", rc);
        node_destroy(n2);
        return 1;
    }

    if (memcmp(h1, h2, HASH_SIZE) != 0) {
        fprintf(stderr, "expected same hash returned for duplicate after restart\n");
        node_destroy(n2);
        return 1;
    }

    count_entries(log_path, &count);
    if (count != 1) {
        fprintf(stderr, "expected still 1 entry after duplicate post-restart, got %zu\n", count);
        node_destroy(n2);
        return 1;
    }

    // ---- New nonce should append ----
    uint8_t h3[HASH_SIZE];
    uint64_t nonce2 = nonce + 1;

    rc = node_submit_local(n2,
                           EVENT_SCORE, // change if needed
                           23,
                           "restart-idem-2",
                           (uint16_t)strlen("restart-idem-2"),
                           nonce2,
                           h3);
    if (rc != 0) {
        fprintf(stderr, "expected new nonce submit rc=0, got %d\n", rc);
        node_destroy(n2);
        return 1;
    }

    count_entries(log_path, &count);
    if (count != 2) {
        fprintf(stderr, "expected 2 entries after second nonce, got %zu\n", count);
        node_destroy(n2);
        return 1;
    }

    node_destroy(n2);

    printf("PASS: test_node_idempotency_survives_restart\n");
    return 0;
}
