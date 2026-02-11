#ifndef PEERS_H
#define PEERS_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

typedef struct {
    uint32_t node_id;
    char host[64];
    uint16_t port;
    uint8_t pubkey[crypto_sign_PUBLICKEYBYTES];
} Peer;

typedef struct {
    Peer *items;
    size_t count;
} PeerSet;

// Load peers from a config file (peers.conf). Returns 0 on success.
int peers_load(PeerSet *ps, const char *path);

// Free memory held by PeerSet.
void peers_free(PeerSet *ps);

// Lookup peer by node_id. Returns NULL if missing.
const Peer *peers_get(const PeerSet *ps, uint32_t node_id);

// Convenience: get pubkey pointer by node_id.
const uint8_t *peers_get_pubkey(const PeerSet *ps, uint32_t node_id);

#endif
