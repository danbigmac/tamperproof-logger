#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include "entry.h"

typedef struct Node Node;

typedef struct {
    uint32_t node_id;
    const char *listen_host;
    uint16_t listen_port;

    const char *log_path;

    // Keys for this node (root pub stays constant; priv rotates)
    const char *pub_path;
    const char *priv_path;

    const char *peers_conf_path;
} NodeConfig;

Node *node_create(const NodeConfig *cfg);
int   node_run(Node *n);       // blocking accept loop
void  node_destroy(Node *n);
// Submit an entry locally without networking.
// Returns:
//   0  -> new entry appended
//   1  -> duplicate (same author+nonce) already processed; out_hash is existing
//  -1  -> error
int node_submit_local(Node *n,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *desc,
                      uint16_t desc_len,
                      uint64_t client_nonce,
                      uint8_t out_hash[HASH_SIZE]);

#endif
