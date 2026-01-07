#include "node.h"
#include "net.h"
#include "msg.h"
#include "logger.h"
#include "fileio.h"
#include "entry.h"
#include "crypto.h"
#include "util.h"
#include "event_type.h"
#include "peers.h"
#include "idem.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    Node *node;
    int fd;
} ConnArgs;

struct Node {
    NodeConfig cfg;

    int listen_fd;
    pthread_mutex_t lock;

    uint8_t last_hash[HASH_SIZE];
    int has_last_hash;

    PeerSet peers;

    IdemTable idem_table;
};

static int node_seed_idempotency_from_log(Node *n, size_t max_entries_to_load)
{
    if (!n) {
        fprintf(stderr, "node_seed_idempotency_from_log: null node pointer\n");
        return -1;
    }

    size_t count = 0;
    LogEntry *entries = fileio_read_all(n->cfg.log_path, &count);
    if (!entries) {
        // no log yet is not an error
        fprintf(stderr, "node_seed_idempotency_from_log: no log entries found\n");
        return 0;
    }

    // If max_entries_to_load is nonzero, only load the last N entries
    size_t start = 0;
    if (max_entries_to_load > 0 && count > max_entries_to_load) {
        start = count - max_entries_to_load;
    }

    // Rebuild idem table from entries[start..count)
    // (If duplicates exist in log, the latest mapping wins, which is fine.)
    for (size_t i = start; i < count; i++) {
        idem_put(&n->idem_table,
                 entries[i].author_node_id,
                 entries[i].nonce,
                 entries[i].entry_hash);
    }

    // Seed last_hash from the actual last entry
    memcpy(n->last_hash, entries[count - 1].entry_hash, HASH_SIZE);
    n->has_last_hash = 1;

    free(entries);
    return 0;
}

// Return 1 if node is leader, 0 otherwise.
static int node_is_leader(Node *n) {
    if (!n) {
        fprintf(stderr, "node_is_leader: null node pointer... so returning 0\n");
        return 0;
    }
    return (n->cfg.node_id == n->cfg.leader_id);
}

// Best-effort broadcast of a serialized entry to peers.
// Called AFTER the entry is appended locally.
static void broadcast_entry(Node *n, const uint8_t *entry_bytes, size_t entry_len)
{
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (msg_build_entry_payload(&payload, &payload_len, entry_bytes, entry_len) != 0) {
        return;
    }

    for (size_t i = 0; i < n->peers.count; i++) {
        const Peer *p = &n->peers.items[i];
        if (p->node_id == n->cfg.node_id) {
            continue;
        }
        int fd = net_connect_tcp(p->host, p->port);
        if (fd < 0) continue;

        // optional: timeouts so peers can’t stall you
        // dont really care about return value here
        net_set_timeouts(fd, 1000, 1000);

        msg_send(fd, MSG_ENTRY, payload, payload_len);
        net_close(&fd);
    }

    free(payload);
}

// ---------- Handlers ----------

static int send_ack(int fd, const uint8_t entry_hash[HASH_SIZE])
{
    uint8_t payload[1 + HASH_SIZE];
    payload[0] = 1; // ok
    memcpy(payload + 1, entry_hash, HASH_SIZE);
    return msg_send(fd, MSG_ACK, payload, sizeof(payload));
}

static int send_nack(int fd, uint8_t reason)
{
    uint8_t payload[2];
    payload[0] = 0; // ok=0
    payload[1] = reason;
    return msg_send(fd, MSG_NACK, payload, sizeof(payload));
}

static int forward_submit_to_leader(Node *n, int client_fd,
                                    const uint8_t *payload, size_t payload_len)
{
    // Find leader endpoint
    const Peer *leader = peers_get(&n->peers, n->cfg.leader_id);
    if (!leader) {
        // We don't know where the leader is
        fprintf(stderr, "forward_submit_to_leader: unknown leader node ID %u\n", n->cfg.leader_id);
        return send_nack(client_fd, NACK_NOT_LEADER);
    }

    // Connect to leader
    int leader_fd = net_connect_tcp(leader->host, leader->port);
    if (leader_fd < 0) {
        fprintf(stderr, "forward_submit_to_leader: failed to connect to leader %s:%u\n",
                leader->host, leader->port);
        return send_nack(client_fd, NACK_LEADER_UNREACH);
    }

    net_set_timeouts(leader_fd, 2000, 2000);

    // Send submit to leader (same payload)
    if (msg_send(leader_fd, MSG_SUBMIT, payload, payload_len) != 0) {
        net_close(&leader_fd);
        fprintf(stderr, "forward_submit_to_leader: msg_send to leader failed\n");
        return send_nack(client_fd, NACK_LEADER_UNREACH);
    }

    // Receive leader response (expect ACK or NACK)
    uint8_t rtype = 0, rver = 0;
    uint8_t *rpayload = NULL;
    size_t rpayload_len = 0;

    MsgResult rr = msg_recv(leader_fd, &rtype, &rver, &rpayload, &rpayload_len);

    net_close(&leader_fd);

    if (rr != MSG_OK || rver != MSG_VERSION) {
        free(rpayload);
        fprintf(stderr, "forward_submit_to_leader: msg_recv from leader failed\n");
        return send_nack(client_fd, NACK_LEADER_UNREACH);
    }

    // Relay leader response to client
    // We forward ACK/NACK exactly as leader produced it.
    if (rtype != MSG_ACK && rtype != MSG_NACK) {
        free(rpayload);
        fprintf(stderr, "forward_submit_to_leader: unexpected response type %u from leader\n", rtype);
        return send_nack(client_fd, NACK_INTERNAL_ERROR);
    }

    int rc = msg_send(client_fd, rtype, rpayload, rpayload_len);
    free(rpayload);
    return rc;
}

// Handle MSG_SUBMIT: client asks this node to create+sign+append entry.
static int handle_submit(Node *n, int fd, const uint8_t *payload, size_t payload_len)
{
    uint32_t event_type = 0, player_id = 0;
    const char *desc = NULL;
    uint16_t desc_len = 0;
    uint64_t client_nonce = 0;

    // If not leader, forward to leader node
    if (!node_is_leader(n)) {
        return forward_submit_to_leader(n, fd, payload, payload_len);
    }

    if (msg_parse_submit_payload(payload, payload_len,
                                &event_type, &player_id,
                                &desc, &desc_len,
                                &client_nonce) != 0)
    {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    // Enforce your entry constraints
    if (desc_len >= DESCRIPTION_MAX) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    // Ensure keys are loaded (root pub + current priv)
    // (Call once in node_create ideally; this is safe too)
    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    uint8_t prev_hash[HASH_SIZE] = {0};
    uint8_t existing_hash[HASH_SIZE];

    pthread_mutex_lock(&n->lock);

    int already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        // already processed this nonce for this node
        pthread_mutex_unlock(&n->lock);
        fprintf(stderr, "handle_submit: duplicate nonce %lu from client\n", (unsigned long)client_nonce);
        return send_ack(fd, existing_hash);
    }

    if (n->has_last_hash) {
        memcpy(prev_hash, n->last_hash, HASH_SIZE);
    } else {
        // try load last hash from disk
        LogEntry last;
        if (fileio_read_last(n->cfg.log_path, &last) == 0) {
            memcpy(prev_hash, last.entry_hash, HASH_SIZE);
            memcpy(n->last_hash, last.entry_hash, HASH_SIZE);
            n->has_last_hash = 1;
        }
    }

    pthread_mutex_unlock(&n->lock);

    // Create entry (timestamp comes from node; client nonce not yet integrated in your LogEntry)
    // For now, you can include nonce in description prefix if you want idempotency later.
    // Better: add nonce field to LogEntry soon.
    char desc_buf[DESCRIPTION_MAX];
    memcpy(desc_buf, desc, desc_len);
    desc_buf[desc_len] = '\0';

    LogEntry entry = entry_create(
        util_timestamp_now(),
        n->cfg.node_id,
        client_nonce,
        event_type,
        player_id,
        desc_buf,
        prev_hash
    );

    entry_compute_hash(&entry, entry.entry_hash);
    do_sign(entry.entry_hash, entry.signature);

    // Serialize for disk + network
    uint8_t entry_bytes[2048];
    size_t entry_len = entry_serialize(&entry, entry_bytes, sizeof(entry_bytes));
    if (entry_len == 0) {
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    // Append and update shared state under lock
    pthread_mutex_lock(&n->lock);

    // Chain check again under lock (ensures no race with another append)
    if (n->has_last_hash && memcmp(entry.prev_hash, n->last_hash, HASH_SIZE) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_DOES_NOT_EXTEND_CHAIN);
    }

    if (fileio_append_entry(n->cfg.log_path, &entry) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    memcpy(n->last_hash, entry.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;

    idem_put(&n->idem_table, entry.author_node_id, entry.nonce, entry.entry_hash);

    pthread_mutex_unlock(&n->lock);

    // Broadcast outside lock (don’t block other threads)
    broadcast_entry(n, entry_bytes, entry_len);

    return send_ack(fd, entry.entry_hash);
}

// Handle MSG_ENTRY: peer propagates a fully formed entry (already signed).
static int handle_entry(Node *n, int fd, const uint8_t *payload, size_t payload_len)
{
    const uint8_t *entry_bytes = NULL;
    size_t entry_len = 0;

    if (msg_parse_entry_payload(payload, payload_len, &entry_bytes, &entry_len) != 0) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    LogEntry e;
    if (entry_deserialize(&e, entry_bytes, entry_len) != 0) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    // Ignore self-originated entries (prevents accidental loops)
    if (e.author_node_id == n->cfg.node_id) {
        return send_nack(fd, NACK_DUPLICATE); // or just return 0
    }

    // Verify signature and hash correctness.
    // Note: do_verify() uses whatever pubkey is currently loaded in memory.
    // In a true multi-node setup, you should verify using the SENDER/AUTHOR node's pubkey.
    // For now (v1), assume a shared root key or same keys for all nodes, or extend crypto API.
    uint8_t expected_hash[HASH_SIZE];
    entry_compute_hash(&e, expected_hash);
    if (memcmp(expected_hash, e.entry_hash, HASH_SIZE) != 0) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    // if (do_verify(e.entry_hash, e.signature) != 0) {
    //     return send_nack(fd, NACK_BAD_SIGNATURE);
    // }

    const uint8_t *pub = peers_get_pubkey(&n->peers, e.author_node_id);
    if (!pub) {
        fprintf(stderr, "handle_entry: unknown peer author_node_id %u\n", e.author_node_id);
        return send_nack(fd, NACK_UNKNOWN_PEER);
    }
    if (do_verify_with_pub(e.entry_hash, e.signature, pub) != 0) {
        fprintf(stderr, "handle_entry: bad signature from author_node_id %u\n", e.author_node_id);
        return send_nack(fd, NACK_BAD_SIGNATURE);
    }

    // Serialize check: already have bytes; we append the LogEntry using fileio_append_entry
    // which will serialize again. That’s OK for v1 simplicity.
    pthread_mutex_lock(&n->lock);

    if (idem_get(&n->idem_table, e.author_node_id, e.nonce, NULL) == 1) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_DUPLICATE);
    }

    // Load last hash if needed
    if (!n->has_last_hash) {
        LogEntry last;
        if (fileio_read_last(n->cfg.log_path, &last) == 0) {
            memcpy(n->last_hash, last.entry_hash, HASH_SIZE);
            n->has_last_hash = 1;
        }
    }

    // Chain check (simple v1 rule: must extend local tip)
    if (n->has_last_hash) {
        if (memcmp(e.prev_hash, n->last_hash, HASH_SIZE) != 0) {
            pthread_mutex_unlock(&n->lock);
            return send_nack(fd, NACK_DOES_NOT_EXTEND_CHAIN);
        }
    } else {
        // empty log: accept genesis only if prev_hash is zero
        uint8_t zeros[HASH_SIZE] = {0};
        if (memcmp(e.prev_hash, zeros, HASH_SIZE) != 0) {
            pthread_mutex_unlock(&n->lock);
            return send_nack(fd, NACK_DOES_NOT_EXTEND_CHAIN);
        }
    }

    // Append
    if (fileio_append_entry(n->cfg.log_path, &e) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    memcpy(n->last_hash, e.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;

    idem_put(&n->idem_table, e.author_node_id, e.nonce, e.entry_hash);

    pthread_mutex_unlock(&n->lock);

    // In v1, you can either ACK or just ignore.
    // ACK is useful for debugging.
    //return send_ack(fd, e.entry_hash);
    return 0;
}

static int handle_pubkey_req(Node *n, int fd)
{
    // Ensure keys loaded (should already be in node_create, but safe)
    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        fprintf(stderr, "handle_pubkey_req: failed to load or create keys\n");
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    uint8_t payload[4 + crypto_sign_PUBLICKEYBYTES];
    write_u32_le(payload, n->cfg.node_id);
    memcpy(payload + 4, get_public_key(), crypto_sign_PUBLICKEYBYTES);

    return msg_send(fd, MSG_PUBKEY_RESP, payload, sizeof(payload));
}


// ---------- Connection thread ----------

static void *conn_thread_main(void *arg)
{
    ConnArgs *a = (ConnArgs *)arg;
    Node *n = a->node;
    int fd = a->fd;
    free(a);

    net_set_timeouts(fd, 5000, 5000);

    while (1) {
        uint8_t type = 0, ver = 0;
        uint8_t *payload = NULL;
        size_t payload_len = 0;

        MsgResult res = msg_recv(fd, &type, &ver, &payload, &payload_len);
        if (res == MSG_EOF) {
            free(payload);
            break;
        }
        if (res != MSG_OK) {
            free(payload);
            break;
        }

        if (ver != MSG_VERSION) {
            free(payload);
            (void)send_nack(fd, NACK_BAD_FORMAT);
            continue;
        }

        switch (type) {
            case MSG_SUBMIT:
                (void)handle_submit(n, fd, payload, payload_len);
                break;
            case MSG_ENTRY:
                (void)handle_entry(n, fd, payload, payload_len);
                break;
            case MSG_PUBKEY_REQ:
                (void)handle_pubkey_req(n, fd);
                break;
            default:
                (void)send_nack(fd, NACK_BAD_FORMAT);
                break;
        }

        free(payload);

        // We expect exactly one request per connection in v1:
        break;
    }

    net_close(&fd);
    return NULL;
}

// ---------- Public Node API ----------

int node_submit_local(Node *n,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *desc,
                      uint16_t desc_len,
                      uint64_t client_nonce,
                      uint8_t out_hash[HASH_SIZE])
{
    if (!n || (!desc && desc_len > 0)) {
        fprintf(stderr, "node_submit_local: invalid arguments\n");
        return -1;
    }
    if (desc_len >= DESCRIPTION_MAX) {
        fprintf(stderr, "node_submit_local: description too long\n");
        return -1;
    }
    if (!out_hash) {
        fprintf(stderr, "node_submit_local: out_hash is NULL\n");
        return -1;
    }

    // Ensure keys are loaded (safe even if already loaded)
    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        fprintf(stderr, "node_submit_local: failed to load or create keys\n");
        return -1;
    }

    uint8_t prev_hash[HASH_SIZE] = {0};
    uint8_t existing_hash[HASH_SIZE];

    // ---- lock: idempotency + determine prev_hash ----
    pthread_mutex_lock(&n->lock);

    int already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        memcpy(out_hash, existing_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        return 1; // duplicate
    }

    if (n->has_last_hash) {
        memcpy(prev_hash, n->last_hash, HASH_SIZE);
    } else {
        LogEntry last;
        if (fileio_read_last(n->cfg.log_path, &last) == 0) {
            memcpy(prev_hash, last.entry_hash, HASH_SIZE);
            memcpy(n->last_hash, last.entry_hash, HASH_SIZE);
            n->has_last_hash = 1;

            // Optional: seed idem table from last entry only (you already do this in node_create)
            // idem_put(&n->idem_table, last.author_node_id, last.nonce, last.entry_hash);
        }
    }

    pthread_mutex_unlock(&n->lock);

    // ---- build entry ----
    char desc_buf[DESCRIPTION_MAX];
    if (desc_len > 0) {
        memcpy(desc_buf, desc, desc_len);
    }
    desc_buf[desc_len] = '\0';

    LogEntry entry = entry_create(
        util_timestamp_now(),
        n->cfg.node_id,
        client_nonce,
        event_type,
        player_id,
        desc_buf,
        prev_hash
    );

    if (entry_compute_hash(&entry, entry.entry_hash) != 0) {
        fprintf(stderr, "node_submit_local: failed to compute entry hash\n");
        return -1;
    }
    if (do_sign(entry.entry_hash, entry.signature) != 0) {
        fprintf(stderr, "node_submit_local: failed to sign entry hash\n");
        return -1;
    }

    // ---- lock: chain check + append + update shared state + idem_put ----
    pthread_mutex_lock(&n->lock);

    // Re-check idempotency to avoid race if you ever call this concurrently
    already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        memcpy(out_hash, existing_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        fprintf(stderr, "node_submit_local: duplicate detected on re-check\n");
        return 1;
    }

    // Chain check (must extend current tip)
    if (n->has_last_hash && memcmp(entry.prev_hash, n->last_hash, HASH_SIZE) != 0) {
        pthread_mutex_unlock(&n->lock);
        fprintf(stderr, "node_submit_local: entry does not extend chain\n");
        return -1;
    }

    if (fileio_append_entry(n->cfg.log_path, &entry) != 0) {
        pthread_mutex_unlock(&n->lock);
        fprintf(stderr, "node_submit_local: failed to append entry to log\n");
        return -1;
    }

    memcpy(n->last_hash, entry.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;

    idem_put(&n->idem_table, entry.author_node_id, entry.nonce, entry.entry_hash);

    pthread_mutex_unlock(&n->lock);

    memcpy(out_hash, entry.entry_hash, HASH_SIZE);

    return 0;
}

Node *node_create(const NodeConfig *cfg)
{
    if (!cfg) return NULL;

    Node *n = (Node *)calloc(1, sizeof(Node));
    if (!n) {
        fprintf(stderr, "node_create: calloc failed\n");
        return NULL;
    }

    if (idem_init(&n->idem_table, 4096) != 0) {  // 4096 slots to start
        node_destroy(n);
        fprintf(stderr, "node_create: failed to init idem table.. destroyed node.\n");
        return NULL;
    }

    n->cfg = *cfg;
    n->listen_fd = -1;
    pthread_mutex_init(&n->lock, NULL);

    // Preload keys for this node process
    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        node_destroy(n);
        fprintf(stderr, "node_create: failed to load or create keys.. destroyed node.\n");
        return NULL;
    }

    if (n->cfg.peers_conf_path) {
        if (peers_load(&n->peers, n->cfg.peers_conf_path) != 0) {
            fprintf(stderr, "node_create: failed to load peers from %s\n", n->cfg.peers_conf_path);
            node_destroy(n);
            return NULL;
        }
    }

    // Rebuild idempotency + tip from disk.
    // max_entries_to_load = 0 means "load all". Capping at 4096 currently, but
    //   adjust as needed.
    if (node_seed_idempotency_from_log(n, 4096) != 0) {
        fprintf(stderr, "node_create: failed to seed idempotency from log\n");
        node_destroy(n);
        return NULL;
    }

    return n;
}

int node_run(Node *n)
{
    if (!n) return -1;

    n->listen_fd = net_listen_tcp(n->cfg.listen_host, n->cfg.listen_port, 64);
    if (n->listen_fd < 0) {
        fprintf(stderr, "node_run: failed to listen on %s:%u\n",
                n->cfg.listen_host ? n->cfg.listen_host : "0.0.0.0",
                (unsigned)n->cfg.listen_port);
        return -1;
    }

    printf("node %u listening on %s:%u\n",
           n->cfg.node_id,
           n->cfg.listen_host ? n->cfg.listen_host : "0.0.0.0",
           (unsigned)n->cfg.listen_port);

    while (1) {
        int fd = net_accept(n->listen_fd);
        if (fd < 0) continue;

        ConnArgs *args = (ConnArgs *)malloc(sizeof(ConnArgs));
        if (!args) {
            net_close(&fd);
            continue;
        }
        args->node = n;
        args->fd = fd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, conn_thread_main, args) != 0) {
            free(args);
            net_close(&fd);
            continue;
        }

        // Detached threads so we don’t have to join
        pthread_detach(tid);
    }

    return 0;
}

void node_destroy(Node *n)
{
    if (!n) return;

    if (n->listen_fd >= 0) {
        net_close(&n->listen_fd);
    }

    peers_free(&n->peers);

    idem_free(&n->idem_table);

    pthread_mutex_destroy(&n->lock);
    free(n);
}
