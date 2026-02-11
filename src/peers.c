#include "peers.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_decode(uint8_t *out, size_t out_len, const char *hex)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval((unsigned char)hex[2*i]);
        int lo = hexval((unsigned char)hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void peers_init(PeerSet *ps)
{
    ps->items = NULL;
    ps->count = 0;
}

void peers_free(PeerSet *ps)
{
    if (!ps) {
        return;
    }
    free(ps->items);
    ps->items = NULL;
    ps->count = 0;
}

const Peer *peers_get(const PeerSet *ps, uint32_t node_id)
{
    if (!ps) {
        return NULL;
    }
    for (size_t i = 0; i < ps->count; i++) {
        if (ps->items[i].node_id == node_id) {
            return &ps->items[i];
        }
    }
    return NULL;
}

const uint8_t *peers_get_pubkey(const PeerSet *ps, uint32_t node_id)
{
    const Peer *p = peers_get(ps, node_id);
    return p ? p->pubkey : NULL;
}

int peers_load(PeerSet *ps, const char *path)
{
    if (!ps || !path) {
        return -1;
    }

    peers_init(ps);

    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    size_t cap = 8;
    Peer *arr = (Peer *)calloc(cap, sizeof(Peer));
    if (!arr) {
        fclose(f);
        return -1;
    }

    char line[2048];

    while (fgets(line, sizeof(line), f)) {
        // Trim leading spaces
        char *s = line;
        while (*s && isspace((unsigned char)*s)) {
            s++;
        }

        // Skip empty/comment lines
        if (*s == '\0' || *s == '\n' || *s == '#') {
            continue;
        }

        // Parse: node_id host port pubkey_hex
        // pubkey_hex should be 64 hex chars for 32-byte ed25519 pubkey.
        uint32_t node_id = 0;
        char host[64] = {0};
        uint32_t port_u = 0;
        char pub_hex[256] = {0};

        int n = sscanf(s, "%u %63s %u %255s", &node_id, host, &port_u, pub_hex);
        if (n != 4) {
            // bad line; fail fast so config issues are obvious
            free(arr);
            fclose(f);
            return -1;
        }

        if (port_u == 0 || port_u > 65535) {
            free(arr);
            fclose(f);
            return -1;
        }

        Peer p = {0};
        p.node_id = node_id;
        strncpy(p.host, host, sizeof(p.host) - 1);
        p.port = (uint16_t)port_u;

        if (hex_decode(p.pubkey, crypto_sign_PUBLICKEYBYTES, pub_hex) != 0) {
            free(arr);
            fclose(f);
            return -1;
        }

        // append
        if (ps->count == cap) {
            cap *= 2;
            Peer *tmp = (Peer *)realloc(arr, cap * sizeof(Peer));
            if (!tmp) {
                free(arr);
                fclose(f);
                return -1;
            }
            arr = tmp;
        }

        arr[ps->count++] = p;
    }

    fclose(f);

    ps->items = arr;
    return 0;
}
