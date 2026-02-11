#include "node.h"
#include "net.h"
#include "msg.h"
#include "fileio.h"
#include "entry.h"
#include "crypto.h"
#include "util.h"
#include "peers.h"
#include "idem.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    Node *node;
    int fd;
} ConnArgs;

struct Node {
    NodeConfig cfg;

    int listen_fd;
    pthread_mutex_t lock;
    int lock_inited;

    uint8_t last_hash[HASH_SIZE];
    int has_last_hash;

    uint64_t last_index;
    int has_last_index;

    PeerSet peers;

    IdemTable idem_table;

    pthread_mutex_t fanout_lock;
    int fanout_lock_inited;
    pthread_cond_t fanout_cv;
    int fanout_cv_inited;
    pthread_t fanout_tid;
    int fanout_thread_started;
    int fanout_stop;
    int fanout_pending;
    uint64_t fanout_target_index;
    uint8_t fanout_target_hash[HASH_SIZE];
};

static void *fanout_thread_main(void *arg);

static int node_seed_idempotency_from_log(Node *n, size_t max_entries_to_load)
{
    if (!n) {
        fprintf(stderr, "node_seed_idempotency_from_log: null node pointer\n");
        return -1;
    }

    size_t count = 0;
    LogEntry *entries = fileio_read_all(n->cfg.log_path, &count);
    if (!entries) {
        // Empty log is fine.
        n->last_index = 0;
        n->has_last_index = 0;
        n->has_last_hash = 0;
        return 0;
    }

    size_t start = 0;
    if (max_entries_to_load > 0 && count > max_entries_to_load) {
        start = count - max_entries_to_load;
    }

    for (size_t i = start; i < count; i++) {
        (void)idem_put(&n->idem_table,
                       entries[i].author_node_id,
                       entries[i].nonce,
                       entries[i].entry_hash);
    }

    memcpy(n->last_hash, entries[count - 1].entry_hash, HASH_SIZE);
    n->has_last_hash = 1;
    n->last_index = entries[count - 1].log_index;
    n->has_last_index = 1;

    free(entries);
    return 0;
}

static int node_is_leader(Node *n)
{
    if (!n) return 0;
    return (n->cfg.node_id == n->cfg.leader_id);
}

// Must be called with n->lock held.
static int node_ensure_tip_locked(Node *n)
{
    if (!n) return -1;

    if (n->has_last_hash && n->has_last_index) {
        return 0;
    }

    uint64_t last_index = 0;
    uint8_t last_hash[HASH_SIZE] = {0};
    if (fileio_get_tip(n->cfg.log_path, &last_index, last_hash) != 0) {
        return -1;
    }

    if (last_index == 0) {
        n->last_index = 0;
        n->has_last_index = 0;
        n->has_last_hash = 0;
        memset(n->last_hash, 0, HASH_SIZE);
        return 0;
    }

    n->last_index = last_index;
    n->has_last_index = 1;
    memcpy(n->last_hash, last_hash, HASH_SIZE);
    n->has_last_hash = 1;
    return 0;
}

// Must be called with n->lock held.
static int node_get_tip_locked(Node *n,
                               uint8_t prev_hash_out[HASH_SIZE],
                               uint64_t *next_index_out)
{
    if (!n || !prev_hash_out || !next_index_out) {
        return -1;
    }

    if (node_ensure_tip_locked(n) != 0) {
        return -1;
    }

    if (n->has_last_hash) {
        memcpy(prev_hash_out, n->last_hash, HASH_SIZE);
    } else {
        memset(prev_hash_out, 0, HASH_SIZE);
    }

    *next_index_out = (n->has_last_index ? n->last_index : 0) + 1;
    return 0;
}

// Must be called with n->lock held.
static int node_reload_state_from_disk_locked(Node *n)
{
    if (!n) {
        return -1;
    }

    idem_clear(&n->idem_table);

    n->last_index = 0;
    n->has_last_index = 0;
    n->has_last_hash = 0;
    memset(n->last_hash, 0, HASH_SIZE);

    size_t count = 0;
    LogEntry *entries = fileio_read_all(n->cfg.log_path, &count);
    if (!entries || count == 0) {
        free(entries);
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        (void)idem_put(&n->idem_table,
                       entries[i].author_node_id,
                       entries[i].nonce,
                       entries[i].entry_hash);
    }

    n->last_index = entries[count - 1].log_index;
    n->has_last_index = 1;
    memcpy(n->last_hash, entries[count - 1].entry_hash, HASH_SIZE);
    n->has_last_hash = 1;

    free(entries);
    return 0;
}

// Must be called with n->lock held.
static int node_lookup_entry_by_index_locked(Node *n,
                                             uint64_t log_index,
                                             LogEntry *entry_out)
{
    if (!n || !entry_out) {
        return -1;
    }

    size_t count = 0;
    LogEntry *entries = fileio_read_all(n->cfg.log_path, &count);
    if (!entries || count == 0) {
        free(entries);
        return -1;
    }

    int rc = -1;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].log_index == log_index) {
            *entry_out = entries[i];
            rc = 0;
            break;
        }
    }

    free(entries);
    return rc;
}

static int node_snapshot_log(Node *n, LogEntry **entries_out, size_t *count_out)
{
    if (!n || !entries_out || !count_out) {
        return -1;
    }

    pthread_mutex_lock(&n->lock);
    LogEntry *entries = fileio_read_all(n->cfg.log_path, count_out);
    pthread_mutex_unlock(&n->lock);

    if (!entries || *count_out == 0) {
        free(entries);
        *count_out = 0;
        return -1;
    }

    *entries_out = entries;
    return 0;
}

static const LogEntry *find_entry_by_index(const LogEntry *entries,
                                           size_t count,
                                           uint64_t log_index)
{
    if (!entries) return NULL;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].log_index == log_index) {
            return &entries[i];
        }
    }
    return NULL;
}

static int node_find_entry_by_author_nonce(Node *n,
                                           uint32_t author_node_id,
                                           uint64_t nonce,
                                           LogEntry *entry_out)
{
    if (!n || !entry_out) {
        return -1;
    }

    LogEntry *entries = NULL;
    size_t count = 0;
    if (node_snapshot_log(n, &entries, &count) != 0) {
        return -1;
    }

    int found = -1;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].author_node_id == author_node_id && entries[i].nonce == nonce) {
            *entry_out = entries[i];
            found = 0;
            break;
        }
    }

    free(entries);
    return found;
}

static int send_ack(int fd, const uint8_t entry_hash[HASH_SIZE])
{
    uint8_t payload[1 + HASH_SIZE];
    payload[0] = 1;
    memcpy(payload + 1, entry_hash, HASH_SIZE);
    return msg_send(fd, MSG_ACK, payload, sizeof(payload));
}

static int send_nack(int fd, uint8_t reason)
{
    uint8_t payload[2];
    payload[0] = 0;
    payload[1] = reason;
    return msg_send(fd, MSG_NACK, payload, sizeof(payload));
}

static int send_repl_ack(int fd,
                         uint8_t ok,
                         uint64_t log_index,
                         const uint8_t entry_hash[HASH_SIZE],
                         uint8_t reason)
{
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (msg_build_repl_ack_payload(&payload, &payload_len,
                                   ok, log_index, entry_hash, reason) != 0) {
        return -1;
    }

    int rc = msg_send(fd, MSG_REPL_ACK, payload, payload_len);
    free(payload);
    return rc;
}

static int send_repl_entry_and_wait_ack(int fd,
                                        const LogEntry *entry,
                                        uint8_t *ok_out,
                                        uint64_t *log_index_out,
                                        uint8_t hash_out[HASH_SIZE],
                                        uint8_t *reason_out)
{
    uint8_t entry_bytes[2048];
    size_t entry_len = entry_serialize(entry, entry_bytes, sizeof(entry_bytes));
    if (entry_len == 0) {
        return -1;
    }

    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (msg_build_entry_payload(&payload, &payload_len, entry_bytes, entry_len) != 0) {
        return -1;
    }

    if (msg_send(fd, MSG_REPL_ENTRY, payload, payload_len) != 0) {
        free(payload);
        return -1;
    }
    free(payload);

    uint8_t type = 0, ver = 0;
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    MsgResult r = msg_recv(fd, &type, &ver, &resp, &resp_len);
    if (r != MSG_OK || ver != MSG_VERSION || type != MSG_REPL_ACK) {
        free(resp);
        return -1;
    }

    int rc = msg_parse_repl_ack_payload(resp, resp_len,
                                        ok_out, log_index_out, hash_out, reason_out);
    free(resp);
    return rc;
}

static int replicate_one_peer_once(const Peer *p,
                                   const LogEntry *entries,
                                   size_t count,
                                   uint64_t target_index,
                                   const uint8_t target_hash[HASH_SIZE])
{
    if (!p || !entries || count == 0 || !target_hash) {
        return -1;
    }

    const LogEntry *target_entry = find_entry_by_index(entries, count, target_index);
    if (!target_entry) {
        return -1;
    }
    if (memcmp(target_entry->entry_hash, target_hash, HASH_SIZE) != 0) {
        return -1;
    }

    int fd = net_connect_tcp(p->host, p->port);
    if (fd < 0) {
        return -1;
    }

    (void)net_set_timeouts(fd, 1000, 1000);

    uint64_t next_to_send = target_index;
    size_t safety = 0;
    size_t safety_limit = (count * 4) + 16;
    if (safety_limit < 32) {
        safety_limit = 32;
    }

    while (safety++ < safety_limit) {
        const LogEntry *e = find_entry_by_index(entries, count, next_to_send);
        if (!e) {
            net_close(&fd);
            return -1;
        }

        uint8_t ok = 0;
        uint64_t ack_index = 0;
        uint8_t ack_hash[HASH_SIZE] = {0};
        uint8_t reason = 0;

        if (send_repl_entry_and_wait_ack(fd, e,
                                         &ok, &ack_index, ack_hash, &reason) != 0) {
            net_close(&fd);
            return -1;
        }

        if (ok == 1) {
            if (ack_index != e->log_index) {
                net_close(&fd);
                return -1;
            }
            if (memcmp(ack_hash, e->entry_hash, HASH_SIZE) != 0) {
                net_close(&fd);
                return -1;
            }

            if (ack_index == target_index &&
                memcmp(ack_hash, target_hash, HASH_SIZE) == 0) {
                net_close(&fd);
                return 0;
            }

            if (next_to_send >= target_index) {
                net_close(&fd);
                return -1;
            }

            next_to_send++;
            continue;
        }

        if (reason == REPL_NACK_INDEX_MISMATCH) {
            if (ack_index == 0) {
                net_close(&fd);
                return -1;
            }

            // Peer ahead: re-send target index so follower can trim divergent tail.
            if (ack_index > target_index) {
                next_to_send = target_index;
                continue;
            }

            if (ack_index == next_to_send) {
                net_close(&fd);
                return -1;
            }

            // Peer behind: backfill from the index it expects next.
            next_to_send = ack_index;
            continue;
        }

        if (reason == REPL_NACK_DUPLICATE) {
            if (ack_index != e->log_index) {
                net_close(&fd);
                return -1;
            }
            if (memcmp(ack_hash, e->entry_hash, HASH_SIZE) != 0) {
                net_close(&fd);
                return -1;
            }

            if (ack_index == target_index) {
                net_close(&fd);
                return 0;
            }

            if (next_to_send >= target_index) {
                net_close(&fd);
                return -1;
            }

            next_to_send++;
            continue;
        }

        if (reason == REPL_NACK_DOES_NOT_EXTEND_CHAIN) {
            // Step back and search for common prefix, then replay forward.
            if (next_to_send <= 1) {
                net_close(&fd);
                return -1;
            }
            next_to_send--;
            continue;
        }

        net_close(&fd);
        return -1;
    }

    net_close(&fd);
    return -1;
}

static int replicate_one_peer(const Peer *p,
                              const LogEntry *entries,
                              size_t count,
                              uint64_t target_index,
                              const uint8_t target_hash[HASH_SIZE])
{
    const int max_attempts = 3;

    for (int attempt = 0; attempt < max_attempts; attempt++) {
        if (replicate_one_peer_once(p, entries, count, target_index, target_hash) == 0) {
            return 0;
        }
    }

    return -1;
}

static int replicate_to_quorum(Node *n,
                               uint64_t target_index,
                               const uint8_t target_hash[HASH_SIZE])
{
    if (!n || !target_hash) {
        return -1;
    }

    size_t total_nodes = n->peers.count;
    size_t quorum = (total_nodes / 2) + 1;
    size_t acks = 1; // leader local append

    if (acks >= quorum) {
        return 0;
    }

    LogEntry *entries = NULL;
    size_t count = 0;
    if (node_snapshot_log(n, &entries, &count) != 0) {
        return -1;
    }

    int rc = -1;

    for (size_t i = 0; i < n->peers.count; i++) {
        const Peer *p = &n->peers.items[i];
        if (p->node_id == n->cfg.node_id) {
            continue;
        }

        if (replicate_one_peer(p, entries, count, target_index, target_hash) == 0) {
            acks++;
            if (acks >= quorum) {
                rc = 0;
                break;
            }
        }
    }

    free(entries);
    return rc;
}

static int replicate_to_all(Node *n,
                            uint64_t target_index,
                            const uint8_t target_hash[HASH_SIZE],
                            size_t *failed_peers_out)
{
    if (!n || !target_hash) {
        return -1;
    }

    if (failed_peers_out) {
        *failed_peers_out = 0;
    }

    LogEntry *entries = NULL;
    size_t count = 0;
    if (node_snapshot_log(n, &entries, &count) != 0) {
        return -1;
    }

    size_t failed = 0;
    for (size_t i = 0; i < n->peers.count; i++) {
        const Peer *p = &n->peers.items[i];
        if (p->node_id == n->cfg.node_id) {
            continue;
        }

        if (replicate_one_peer(p, entries, count, target_index, target_hash) != 0) {
            failed++;
        }
    }

    free(entries);

    if (failed_peers_out) {
        *failed_peers_out = failed;
    }
    return (failed == 0) ? 0 : -1;
}

static void node_schedule_async_fanout(Node *n,
                                       uint64_t target_index,
                                       const uint8_t target_hash[HASH_SIZE])
{
    if (!n || !target_hash || !node_is_leader(n)) {
        return;
    }

    pthread_mutex_lock(&n->fanout_lock);

    int should_update = 0;
    if (!n->fanout_pending) {
        should_update = 1;
    } else if (target_index > n->fanout_target_index) {
        should_update = 1;
    } else if (target_index == n->fanout_target_index &&
               memcmp(n->fanout_target_hash, target_hash, HASH_SIZE) != 0) {
        should_update = 1;
    }

    if (should_update) {
        n->fanout_pending = 1;
        n->fanout_target_index = target_index;
        memcpy(n->fanout_target_hash, target_hash, HASH_SIZE);
        pthread_cond_signal(&n->fanout_cv);
    }

    pthread_mutex_unlock(&n->fanout_lock);
}

static void *fanout_thread_main(void *arg)
{
    Node *n = (Node *)arg;
    if (!n) {
        return NULL;
    }

    while (1) {
        uint64_t target_index = 0;
        uint8_t target_hash[HASH_SIZE] = {0};

        pthread_mutex_lock(&n->fanout_lock);
        while (!n->fanout_stop && !n->fanout_pending) {
            pthread_cond_wait(&n->fanout_cv, &n->fanout_lock);
        }

        if (n->fanout_stop) {
            pthread_mutex_unlock(&n->fanout_lock);
            break;
        }

        target_index = n->fanout_target_index;
        memcpy(target_hash, n->fanout_target_hash, HASH_SIZE);
        n->fanout_pending = 0;
        pthread_mutex_unlock(&n->fanout_lock);

        useconds_t backoff_us = 200000;
        while (1) {
            if (replicate_to_all(n, target_index, target_hash, NULL) == 0) {
                break;
            }

            pthread_mutex_lock(&n->fanout_lock);
            int stop = n->fanout_stop;
            int superseded = 0;
            if (n->fanout_pending) {
                if (n->fanout_target_index > target_index) {
                    superseded = 1;
                } else if (n->fanout_target_index == target_index &&
                           memcmp(n->fanout_target_hash, target_hash, HASH_SIZE) != 0) {
                    superseded = 1;
                }
            }
            pthread_mutex_unlock(&n->fanout_lock);

            if (stop || superseded) {
                break;
            }

            usleep(backoff_us);
            if (backoff_us < 1000000) {
                backoff_us *= 2;
                if (backoff_us > 1000000) {
                    backoff_us = 1000000;
                }
            }
        }
    }

    return NULL;
}

static int leader_retry_duplicate(Node *n,
                                  int client_fd,
                                  uint64_t client_nonce,
                                  const uint8_t existing_hash[HASH_SIZE])
{
    LogEntry existing_entry;
    if (node_find_entry_by_author_nonce(n, n->cfg.node_id, client_nonce, &existing_entry) != 0) {
        return send_nack(client_fd, NACK_INTERNAL_ERROR);
    }

    if (replicate_to_quorum(n, existing_entry.log_index, existing_entry.entry_hash) != 0) {
        return send_nack(client_fd, NACK_QUORUM_NOT_REACHED);
    }

    node_schedule_async_fanout(n, existing_entry.log_index, existing_entry.entry_hash);
    return send_ack(client_fd, existing_hash);
}

static int forward_submit_to_leader(Node *n, int client_fd,
                                    const uint8_t *payload, size_t payload_len)
{
    const Peer *leader = peers_get(&n->peers, n->cfg.leader_id);
    if (!leader) {
        fprintf(stderr, "forward_submit_to_leader: unknown leader node ID %u\n", n->cfg.leader_id);
        return send_nack(client_fd, NACK_NOT_LEADER);
    }

    int leader_fd = net_connect_tcp(leader->host, leader->port);
    if (leader_fd < 0) {
        fprintf(stderr, "forward_submit_to_leader: failed to connect to leader %s:%u\n",
                leader->host, leader->port);
        return send_nack(client_fd, NACK_LEADER_UNREACH);
    }

    (void)net_set_timeouts(leader_fd, 2000, 2000);

    if (msg_send(leader_fd, MSG_SUBMIT, payload, payload_len) != 0) {
        net_close(&leader_fd);
        fprintf(stderr, "forward_submit_to_leader: msg_send to leader failed\n");
        return send_nack(client_fd, NACK_LEADER_UNREACH);
    }

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

    if (rtype != MSG_ACK && rtype != MSG_NACK) {
        free(rpayload);
        fprintf(stderr, "forward_submit_to_leader: unexpected response type %u from leader\n", rtype);
        return send_nack(client_fd, NACK_INTERNAL_ERROR);
    }

    int rc = msg_send(client_fd, rtype, rpayload, rpayload_len);
    free(rpayload);
    return rc;
}

static int handle_submit(Node *n, int fd, const uint8_t *payload, size_t payload_len)
{
    uint32_t event_type = 0, player_id = 0;
    const char *desc = NULL;
    uint16_t desc_len = 0;
    uint64_t client_nonce = 0;

    if (!node_is_leader(n)) {
        return forward_submit_to_leader(n, fd, payload, payload_len);
    }

    if (msg_parse_submit_payload(payload, payload_len,
                                 &event_type, &player_id,
                                 &desc, &desc_len,
                                 &client_nonce) != 0) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    if (desc_len >= DESCRIPTION_MAX) {
        return send_nack(fd, NACK_BAD_FORMAT);
    }

    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    uint8_t prev_hash[HASH_SIZE] = {0};
    uint64_t new_log_index = 1;
    uint8_t existing_hash[HASH_SIZE] = {0};

    pthread_mutex_lock(&n->lock);

    int already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        pthread_mutex_unlock(&n->lock);
        return leader_retry_duplicate(n, fd, client_nonce, existing_hash);
    }

    if (node_get_tip_locked(n, prev_hash, &new_log_index) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    pthread_mutex_unlock(&n->lock);

    char desc_buf[DESCRIPTION_MAX];
    memcpy(desc_buf, desc, desc_len);
    desc_buf[desc_len] = '\0';

    LogEntry entry = entry_create(
        util_timestamp_now(),
        n->cfg.node_id,
        client_nonce,
        new_log_index,
        event_type,
        player_id,
        desc_buf,
        prev_hash
    );

    if (entry_compute_hash(&entry, entry.entry_hash) != 0) {
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }
    if (do_sign(entry.entry_hash, entry.signature) != 0) {
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    pthread_mutex_lock(&n->lock);

    already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        pthread_mutex_unlock(&n->lock);
        return leader_retry_duplicate(n, fd, client_nonce, existing_hash);
    }

    uint8_t current_prev_hash[HASH_SIZE] = {0};
    uint64_t current_next_index = 1;
    if (node_get_tip_locked(n, current_prev_hash, &current_next_index) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    if (memcmp(entry.prev_hash, current_prev_hash, HASH_SIZE) != 0 ||
        entry.log_index != current_next_index) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_DOES_NOT_EXTEND_CHAIN);
    }

    if (fileio_append_entry(n->cfg.log_path, &entry) != 0) {
        pthread_mutex_unlock(&n->lock);
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    memcpy(n->last_hash, entry.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;
    n->last_index = entry.log_index;
    n->has_last_index = 1;

    (void)idem_put(&n->idem_table, entry.author_node_id, entry.nonce, entry.entry_hash);

    pthread_mutex_unlock(&n->lock);

    if (replicate_to_quorum(n, entry.log_index, entry.entry_hash) != 0) {
        return send_nack(fd, NACK_QUORUM_NOT_REACHED);
    }

    node_schedule_async_fanout(n, entry.log_index, entry.entry_hash);
    return send_ack(fd, entry.entry_hash);
}

static int handle_repl_entry(Node *n, int fd, const uint8_t *payload, size_t payload_len)
{
    const uint8_t *entry_bytes = NULL;
    size_t entry_len = 0;

    if (msg_parse_entry_payload(payload, payload_len, &entry_bytes, &entry_len) != 0) {
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_BAD_FORMAT);
    }

    LogEntry e;
    if (entry_deserialize(&e, entry_bytes, entry_len) != 0) {
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_BAD_FORMAT);
    }

    uint8_t expected_hash[HASH_SIZE];
    if (entry_compute_hash(&e, expected_hash) != 0 ||
        memcmp(expected_hash, e.entry_hash, HASH_SIZE) != 0) {
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, e.log_index, zeros, REPL_NACK_BAD_FORMAT);
    }

    const uint8_t *pub = peers_get_pubkey(&n->peers, e.author_node_id);
    if (!pub) {
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, e.log_index, zeros, REPL_NACK_UNKNOWN_PEER);
    }

    if (do_verify_with_pub(e.entry_hash, e.signature, pub) != 0) {
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, e.log_index, zeros, REPL_NACK_BAD_SIGNATURE);
    }

    pthread_mutex_lock(&n->lock);

    uint8_t expected_prev_hash[HASH_SIZE] = {0};
    uint64_t expected_index = 1;

    if (node_get_tip_locked(n, expected_prev_hash, &expected_index) != 0) {
        pthread_mutex_unlock(&n->lock);
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_INTERNAL_ERROR);
    }

    if (e.log_index < expected_index) {
        LogEntry local_at_index;
        if (node_lookup_entry_by_index_locked(n, e.log_index, &local_at_index) != 0) {
            uint8_t tip_hash[HASH_SIZE] = {0};
            memcpy(tip_hash, expected_prev_hash, HASH_SIZE);
            pthread_mutex_unlock(&n->lock);
            return send_repl_ack(fd, 0, expected_index, tip_hash, REPL_NACK_INDEX_MISMATCH);
        }

        if (memcmp(local_at_index.entry_hash, e.entry_hash, HASH_SIZE) == 0) {
            // Entry already matches. If we have extra tail beyond this point, trim it.
            if (expected_index > e.log_index + 1) {
                if (fileio_truncate_after(n->cfg.log_path, e.log_index) != 0 ||
                    node_reload_state_from_disk_locked(n) != 0) {
                    pthread_mutex_unlock(&n->lock);
                    uint8_t zeros[HASH_SIZE] = {0};
                    return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_INTERNAL_ERROR);
                }
            }

            pthread_mutex_unlock(&n->lock);
            return send_repl_ack(fd, 1, e.log_index, e.entry_hash, 0);
        }

        // Divergence at this index: rollback and replay from leader.
        if (e.log_index == 0 ||
            fileio_truncate_after(n->cfg.log_path, e.log_index - 1) != 0 ||
            node_reload_state_from_disk_locked(n) != 0) {
            pthread_mutex_unlock(&n->lock);
            uint8_t zeros[HASH_SIZE] = {0};
            return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_INTERNAL_ERROR);
        }

        if (node_get_tip_locked(n, expected_prev_hash, &expected_index) != 0) {
            pthread_mutex_unlock(&n->lock);
            uint8_t zeros[HASH_SIZE] = {0};
            return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_INTERNAL_ERROR);
        }
    }

    uint8_t existing_hash[HASH_SIZE] = {0};
    int dup = idem_get(&n->idem_table, e.author_node_id, e.nonce, existing_hash);
    if (dup == 1) {
        pthread_mutex_unlock(&n->lock);

        if (memcmp(existing_hash, e.entry_hash, HASH_SIZE) == 0) {
            return send_repl_ack(fd, 1, e.log_index, e.entry_hash, 0);
        }
        return send_repl_ack(fd, 0, e.log_index, existing_hash, REPL_NACK_DUPLICATE);
    }
    if (dup < 0) {
        pthread_mutex_unlock(&n->lock);
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, 0, zeros, REPL_NACK_INTERNAL_ERROR);
    }

    if (e.log_index > expected_index) {
        uint8_t tip_hash[HASH_SIZE] = {0};
        memcpy(tip_hash, expected_prev_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        return send_repl_ack(fd, 0, expected_index, tip_hash, REPL_NACK_INDEX_MISMATCH);
    }

    if (memcmp(e.prev_hash, expected_prev_hash, HASH_SIZE) != 0) {
        uint8_t tip_hash[HASH_SIZE] = {0};
        memcpy(tip_hash, expected_prev_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        return send_repl_ack(fd, 0, expected_index, tip_hash, REPL_NACK_DOES_NOT_EXTEND_CHAIN);
    }

    if (fileio_append_entry(n->cfg.log_path, &e) != 0) {
        pthread_mutex_unlock(&n->lock);
        uint8_t zeros[HASH_SIZE] = {0};
        return send_repl_ack(fd, 0, expected_index, zeros, REPL_NACK_INTERNAL_ERROR);
    }

    memcpy(n->last_hash, e.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;
    n->last_index = e.log_index;
    n->has_last_index = 1;

    (void)idem_put(&n->idem_table, e.author_node_id, e.nonce, e.entry_hash);

    pthread_mutex_unlock(&n->lock);

    return send_repl_ack(fd, 1, e.log_index, e.entry_hash, 0);
}

static int handle_pubkey_req(Node *n, int fd)
{
    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        fprintf(stderr, "handle_pubkey_req: failed to load or create keys\n");
        return send_nack(fd, NACK_INTERNAL_ERROR);
    }

    uint8_t payload[4 + crypto_sign_PUBLICKEYBYTES];
    write_u32_le(payload, n->cfg.node_id);
    memcpy(payload + 4, get_public_key(), crypto_sign_PUBLICKEYBYTES);

    return msg_send(fd, MSG_PUBKEY_RESP, payload, sizeof(payload));
}

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
            case MSG_REPL_ENTRY:
                (void)handle_repl_entry(n, fd, payload, payload_len);
                break;
            case MSG_PUBKEY_REQ:
                (void)handle_pubkey_req(n, fd);
                break;
            default:
                (void)send_nack(fd, NACK_BAD_FORMAT);
                break;
        }

        free(payload);
        break;
    }

    net_close(&fd);
    return NULL;
}

int node_submit_local(Node *n,
                      uint32_t event_type,
                      uint32_t player_id,
                      const char *desc,
                      uint16_t desc_len,
                      uint64_t client_nonce,
                      uint8_t out_hash[HASH_SIZE])
{
    if (!n || (!desc && desc_len > 0) || !out_hash) {
        fprintf(stderr, "node_submit_local: invalid arguments\n");
        return -1;
    }
    if (desc_len >= DESCRIPTION_MAX) {
        fprintf(stderr, "node_submit_local: description too long\n");
        return -1;
    }

    if (load_or_create_keys(n->cfg.pub_path, n->cfg.priv_path) != 0) {
        fprintf(stderr, "node_submit_local: failed to load or create keys\n");
        return -1;
    }

    uint8_t prev_hash[HASH_SIZE] = {0};
    uint64_t new_log_index = 1;
    uint8_t existing_hash[HASH_SIZE] = {0};

    pthread_mutex_lock(&n->lock);

    int already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        memcpy(out_hash, existing_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        return 1;
    }

    if (node_get_tip_locked(n, prev_hash, &new_log_index) != 0) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }

    pthread_mutex_unlock(&n->lock);

    char desc_buf[DESCRIPTION_MAX];
    if (desc_len > 0) {
        memcpy(desc_buf, desc, desc_len);
    }
    desc_buf[desc_len] = '\0';

    LogEntry entry = entry_create(
        util_timestamp_now(),
        n->cfg.node_id,
        client_nonce,
        new_log_index,
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

    pthread_mutex_lock(&n->lock);

    already = idem_get(&n->idem_table, n->cfg.node_id, client_nonce, existing_hash);
    if (already == 1) {
        memcpy(out_hash, existing_hash, HASH_SIZE);
        pthread_mutex_unlock(&n->lock);
        return 1;
    }

    uint8_t current_prev_hash[HASH_SIZE] = {0};
    uint64_t current_next_index = 1;
    if (node_get_tip_locked(n, current_prev_hash, &current_next_index) != 0) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }

    if (memcmp(entry.prev_hash, current_prev_hash, HASH_SIZE) != 0 ||
        entry.log_index != current_next_index) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }

    if (fileio_append_entry(n->cfg.log_path, &entry) != 0) {
        pthread_mutex_unlock(&n->lock);
        return -1;
    }

    memcpy(n->last_hash, entry.entry_hash, HASH_SIZE);
    n->has_last_hash = 1;
    n->last_index = entry.log_index;
    n->has_last_index = 1;

    (void)idem_put(&n->idem_table, entry.author_node_id, entry.nonce, entry.entry_hash);

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

    if (idem_init(&n->idem_table, 4096) != 0) {
        node_destroy(n);
        fprintf(stderr, "node_create: failed to init idem table.. destroyed node.\n");
        return NULL;
    }

    n->cfg = *cfg;
    n->listen_fd = -1;
    pthread_mutex_init(&n->lock, NULL);
    n->lock_inited = 1;
    pthread_mutex_init(&n->fanout_lock, NULL);
    n->fanout_lock_inited = 1;
    pthread_cond_init(&n->fanout_cv, NULL);
    n->fanout_cv_inited = 1;

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

    if (node_seed_idempotency_from_log(n, 4096) != 0) {
        fprintf(stderr, "node_create: failed to seed idempotency from log\n");
        node_destroy(n);
        return NULL;
    }

    if (node_is_leader(n)) {
        if (pthread_create(&n->fanout_tid, NULL, fanout_thread_main, n) != 0) {
            fprintf(stderr, "node_create: failed to start fanout thread\n");
            node_destroy(n);
            return NULL;
        }
        n->fanout_thread_started = 1;
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

        pthread_detach(tid);
    }

    return 0;
}

void node_destroy(Node *n)
{
    if (!n) return;

    if (n->fanout_thread_started && n->fanout_lock_inited) {
        pthread_mutex_lock(&n->fanout_lock);
        n->fanout_stop = 1;
        if (n->fanout_cv_inited) {
            pthread_cond_signal(&n->fanout_cv);
        }
        pthread_mutex_unlock(&n->fanout_lock);
        pthread_join(n->fanout_tid, NULL);
    }

    if (n->listen_fd >= 0) {
        net_close(&n->listen_fd);
    }

    peers_free(&n->peers);
    idem_free(&n->idem_table);

    if (n->fanout_cv_inited) {
        pthread_cond_destroy(&n->fanout_cv);
    }
    if (n->fanout_lock_inited) {
        pthread_mutex_destroy(&n->fanout_lock);
    }
    if (n->lock_inited) {
        pthread_mutex_destroy(&n->lock);
    }
    free(n);
}
