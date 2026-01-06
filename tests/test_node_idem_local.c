#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "node.h"
#include "fileio.h"
#include "entry.h"
#include "crypto.h"
#include "event_type.h"

static void rm(const char *path) { remove(path); }

int main(void)
{
    if (sodium_init() == -1) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    const char *log_path  = "data/test_node_idem.log";
    const char *pub_path  = "data/test_node_idem_root_public.key";
    const char *priv_path = "data/test_node_idem_private.key";

    // clean slate
    rm(log_path);
    rm(pub_path);
    rm(priv_path);

    NodeConfig cfg = {0};
    cfg.node_id = 42;
    cfg.listen_host = "127.0.0.1";
    cfg.listen_port = 0; // unused
    cfg.log_path = log_path;
    cfg.pub_path = pub_path;
    cfg.priv_path = priv_path;
    cfg.peers_conf_path = NULL;

    Node *n = node_create(&cfg);
    if (!n) {
        fprintf(stderr, "node_create failed\n");
        return 1;
    }

    uint64_t nonce = 123456789ULL;
    uint8_t h1[HASH_SIZE], h2[HASH_SIZE];

    int rc1 = node_submit_local(n,
                               EVENT_SCORE,   // or any valid event constant
                               23,
                               "first",
                               (uint16_t)strlen("first"),
                               nonce,
                               h1);
    if (rc1 != 0) {
        fprintf(stderr, "expected rc1=0, got %d\n", rc1);
        node_destroy(n);
        return 1;
    }

    size_t count = 0;
    LogEntry *entries = fileio_read_all(log_path, &count);
    if (!entries || count != 1) {
        fprintf(stderr, "expected 1 entry after first submit, got %zu\n", count);
        free(entries);
        node_destroy(n);
        return 1;
    }
    free(entries);

    int rc2 = node_submit_local(n,
                               EVENT_SCORE,
                               23,
                               "first",
                               (uint16_t)strlen("first"),
                               nonce,
                               h2);
    if (rc2 != 1) {
        fprintf(stderr, "expected rc2=1 (duplicate), got %d\n", rc2);
        node_destroy(n);
        return 1;
    }

    if (memcmp(h1, h2, HASH_SIZE) != 0) {
        fprintf(stderr, "expected duplicate submit to return same hash\n");
        node_destroy(n);
        return 1;
    }

    count = 0;
    entries = fileio_read_all(log_path, &count);
    if (!entries || count != 1) {
        fprintf(stderr, "expected still 1 entry after duplicate submit, got %zu\n", count);
        free(entries);
        node_destroy(n);
        return 1;
    }
    free(entries);

    // Different nonce -> new entry
    uint8_t h3[HASH_SIZE];
    int rc3 = node_submit_local(n,
                               EVENT_SCORE,
                               23,
                               "second",
                               (uint16_t)strlen("second"),
                               nonce + 1,
                               h3);
    if (rc3 != 0) {
        fprintf(stderr, "expected rc3=0, got %d\n", rc3);
        node_destroy(n);
        return 1;
    }

    count = 0;
    entries = fileio_read_all(log_path, &count);
    if (!entries || count != 2) {
        fprintf(stderr, "expected 2 entries after second nonce, got %zu\n", count);
        free(entries);
        node_destroy(n);
        return 1;
    }
    free(entries);

    node_destroy(n);

    printf("PASS: test_node_idempotency_local\n");
    return 0;
}
