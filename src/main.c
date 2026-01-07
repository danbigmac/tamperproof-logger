#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sodium.h>

#include "event_type.h" // parse_event_type, EventType
#include "logger.h"     // logger_add, logger_verify, logger_print, logger_rotate_keys
#include "util.h"       // get_arg, get_flag_value, has_flag
#include "crypto.h"     // load_or_create_keys
#include "node.h"       // node_create, node_run, node_destroy
#include "net.h"        // net_connect_tcp, net_close
#include "msg.h"        // msg_build_submit_payload, msg_send, msg_recv, Msg

static void print_usage(void)
{
    printf("Usage:\n");
    printf("  logger add <event_type> <player_id> <description> [--author N] [--nonce N] [--log PATH] [--pub PATH] [--priv PATH]\n");
    printf("  logger verify [logfile] [--log PATH] [--pub PATH] [--priv PATH]\n");
    printf("  logger rotate_keys [--author N] [--nonce N] [--log PATH] [--pub PATH] [--priv PATH]\n");
    printf("  logger print [logfile] [--log PATH]\n");
    printf("\nNotes:\n");
    printf("  --nonce is a client-provided idempotency token. If omitted, a random nonce is generated and printed.\n");
}

static int parse_u16(const char *s, uint16_t *out)
{
    if (!s || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    if (v > 0xFFFFUL) return -1;
    *out = (uint16_t)v;
    return 0;
}

static int parse_u32(const char *s, uint32_t *out)
{
    if (!s || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    if (v > 0xFFFFFFFFUL) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
    if (!s || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_hostport(const char *s, char *host_out, size_t host_cap, uint16_t *port_out)
{
    if (!s || !host_out || !port_out) {
        fprintf(stderr, "parse_hostport: NULL argument\n");
        return -1;
    }

    const char *colon = strrchr(s, ':');
    if (!colon) {
        fprintf(stderr, "parse_hostport: missing colon in host:port\n");
        return -1;
    }

    size_t host_len = (size_t)(colon - s);
    if (host_len == 0 || host_len >= host_cap) {
        fprintf(stderr, "parse_hostport: invalid host length\n");
        return -1;
    }

    memcpy(host_out, s, host_len);
    host_out[host_len] = '\0';

    char *end = NULL;
    long port = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || port <= 0 || port > 65535) {
        fprintf(stderr, "parse_hostport: invalid port\n");
        return -1;
    }

    *port_out = (uint16_t)port;
    return 0;
}

static uint64_t random_nonce_u64(void)
{
    uint64_t x = 0;
    randombytes_buf(&x, sizeof(x));
    return x;
}

static int client_submit(const char *host, uint16_t port,
                         uint32_t event_type, uint32_t player_id,
                         const char *desc, uint16_t desc_len,
                         uint64_t nonce,
                         uint8_t out_hash[HASH_SIZE])
{
    int fd = net_connect_tcp(host, port);
    if (fd < 0) {
        fprintf(stderr, "client_submit: failed to connect to %s:%u\n", host, port);
        return -1;
    }

    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (msg_build_submit_payload(&payload, &payload_len,
                                 event_type, player_id,
                                 desc, desc_len,
                                 nonce) != 0)
    {
        net_close(&fd);
        fprintf(stderr, "client_submit: msg_build_submit_payload failed\n");
        return -1;
    }

    if (msg_send(fd, MSG_SUBMIT, payload, payload_len) != 0) {
        free(payload);
        net_close(&fd);
        fprintf(stderr, "client_submit: msg_send failed\n");
        return -1;
    }
    free(payload);

    uint8_t type = 0, ver = 0;
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    MsgResult r = msg_recv(fd, &type, &ver, &resp, &resp_len);
    net_close(&fd);

    if (r != MSG_OK || ver != MSG_VERSION || !resp) {
        free(resp);
        fprintf(stderr, "client_submit: msg_recv failed or invalid response\n");
        return -1;
    }

    if (type == MSG_ACK) {
        if (resp_len != 1 + HASH_SIZE || resp[0] != 1) {
            free(resp);
            fprintf(stderr, "client_submit: invalid ack response format\n");
            return -1;
        }
        memcpy(out_hash, resp + 1, HASH_SIZE);
        free(resp);
        return 0;
    }

    if (type == MSG_NACK) {
        // resp: [0][reason]
        uint8_t reason = (resp_len >= 2) ? resp[1] : 0xFF;
        free(resp);
        fprintf(stderr, "submit rejected (nack=%u)\n", (unsigned)reason);
        return -1;
    }

    free(resp);
    return -1;
}

int main(int argc, char **argv)
{
    // Always initialize libsodium early and once.
    if (sodium_init() == -1) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    if (argc < 2 || has_flag(argc, argv, "--help") || has_flag(argc, argv, "-h")) {
        print_usage();
        return (argc < 2) ? 1 : 0;
    }

    const char *cmd = argv[1];

    // Defaults (override with flags)
    const char *log_path  = "data/game.log";
    const char *pub_path  = "data/root_public.key";
    const char *priv_path = "data/private.key";

    const char *log_arg  = get_flag_value(argc, argv, "--log");
    const char *pub_arg  = get_flag_value(argc, argv, "--pub");
    const char *priv_arg = get_flag_value(argc, argv, "--priv");
    if (log_arg)  log_path  = log_arg;
    if (pub_arg)  pub_path  = pub_arg;
    if (priv_arg) priv_path = priv_arg;

    // Optional author/nonce flags
    uint32_t author = 0;
    uint64_t nonce = 0;
    int nonce_provided = 0;

    const char *author_arg = get_flag_value(argc, argv, "--author");
    if (author_arg) {
        if (parse_u32(author_arg, &author) != 0) {
            fprintf(stderr, "Invalid --author value: %s\n", author_arg);
            return 1;
        }
    }

    const char *nonce_arg = get_flag_value(argc, argv, "--nonce");
    if (nonce_arg) {
        if (parse_u64(nonce_arg, &nonce) != 0) {
            fprintf(stderr, "Invalid --nonce value: %s\n", nonce_arg);
            return 1;
        }
        nonce_provided = 1;
    } else {
        nonce = random_nonce_u64();
    }

    //
    // -------------------------------
    // Command: ADD
    // -------------------------------
    //
    if (strcmp(cmd, "add") == 0) {

        if (load_or_create_keys(pub_path, priv_path) != 0) {
            fprintf(stderr, "Could not load or create keypair\n");
            return 1;
        }

        // Positional args (unchanged)
        const char *event_type_str = get_arg(argc, argv, 2);
        const char *player_id_str  = get_arg(argc, argv, 3);
        const char *description    = get_arg(argc, argv, 4);

        if (!event_type_str || !player_id_str || !description) {
            fprintf(stderr, "Missing arguments for add\n\n");
            print_usage();
            return 1;
        }

        EventType etype = parse_event_type(event_type_str);
        if (etype == EVENT_UNKNOWN) {
            fprintf(stderr, "Unknown event type: %s\n", event_type_str);
            return 1;
        }

        uint32_t player_id = (uint32_t)atoi(player_id_str);

        // Updated signature: logger_add(log, author, nonce, ...)
        int rc = logger_add(log_path,
                            author,
                            nonce,
                            (uint32_t)etype,
                            player_id,
                            description);
        if (rc != 0) {
            fprintf(stderr, "logger_add failed\n");
            return 1;
        }

        if (nonce_provided) {
            printf("Entry added. author=%u nonce=%llu\n",
                   author, (unsigned long long)nonce);
        } else {
            printf("Entry added. author=%u nonce=%llu (generated)\n",
                   author, (unsigned long long)nonce);
        }

        return 0;
    }

    //
    // -------------------------------
    // Command: VERIFY
    // -------------------------------
    //
    else if (strcmp(cmd, "verify") == 0) {

        if (load_or_create_keys(pub_path, priv_path) != 0) {
            fprintf(stderr, "Could not load or create keypair\n");
            return 1;
        }

        // Optional positional logfile override: logger verify <logfile>
        const char *pos_logfile = get_arg(argc, argv, 2);
        if (pos_logfile) log_path = pos_logfile;

        int rc = logger_verify(log_path);
        if (rc == 0) {
            printf("Log verified: OK.\n");
            return 0;
        } else {
            printf("Log verification FAILED.\n");
            return 1;
        }
    }

    //
    // -------------------------------
    // Command: ROTATE_KEYS
    // -------------------------------
    //
    else if (strcmp(cmd, "rotate_keys") == 0) {

        if (load_or_create_keys(pub_path, priv_path) != 0) {
            fprintf(stderr, "Could not load or create keypair\n");
            return 1;
        }

        // Updated signature: logger_rotate_keys(log, priv, author, nonce)
        if (logger_rotate_keys(log_path, priv_path, author, nonce) != 0) {
            fprintf(stderr, "Key rotation failed\n");
            return 1;
        }

        printf("Key rotation completed. author=%u nonce=%llu\n",
               author, (unsigned long long)nonce);
        return 0;
    }

    //
    // -------------------------------
    // Command: NODE
    // -------------------------------
    //
    else if (strcmp(cmd, "node") == 0) {

        const char *nodeid = get_flag_value(argc, argv, "--node-id");
        const char *leader_id = get_flag_value(argc, argv, "--leader-id"); // unused in v1
        const char *listen = get_flag_value(argc, argv, "--listen");
        const char *log_path = get_flag_value(argc, argv, "--log");
        const char *pub_path = get_flag_value(argc, argv, "--pub");
        const char *priv_path = get_flag_value(argc, argv, "--priv");
        const char *peers_path = get_flag_value(argc, argv, "--peers"); // optional

        if (!nodeid || !leader_id || !listen || !log_path || !pub_path || !priv_path) {
            fprintf(stderr, "missing at least one required flag for node\n");
            // print usage...
            print_usage();
            return 1;
        }

        uint32_t node_id = 0;
        if (parse_u32(nodeid, &node_id) != 0) {
            fprintf(stderr, "invalid --node-id\n");
            print_usage();
            return 1;
        }

        uint32_t leader_node_id = 0;
        if (parse_u32(leader_id, &leader_node_id) != 0) {
            fprintf(stderr, "invalid --leader-id\n");
            print_usage();
            return 1;
        }

        char host[128];
        uint16_t port = 0;
        if (parse_hostport(listen, host, sizeof(host), &port) != 0) {
            fprintf(stderr, "invalid --listen (expected host:port)\n");
            print_usage();
            return 1;
        }

        NodeConfig cfg = {0};
        cfg.node_id = node_id;
        cfg.leader_id = leader_node_id;
        cfg.listen_host = host;      // careful: host is stack; copy below
        cfg.listen_port = port;
        cfg.log_path = log_path;
        cfg.pub_path = pub_path;
        cfg.priv_path = priv_path;
        cfg.peers_conf_path = peers_path;

        // NOTE: cfg.listen_host must remain valid after this function returns.
        // Easiest: duplicate it.
        char *host_dup = strdup(host);
        if (!host_dup) {
            fprintf(stderr, "strdup failed for listen host\n");
            return 1;
        }
        cfg.listen_host = host_dup;

        Node *n = node_create(&cfg);
        if (!n) {
            fprintf(stderr, "node_create failed\n");
            free(host_dup);
            return 1;
        }

        // node_run blocks forever
        int rc = node_run(n);

        node_destroy(n);
        free(host_dup);
        return (rc == 0) ? 0 : 1;
    }

    //
    // -------------------------------
    // Command: CLIENT SUBMIT
    // -------------------------------
    //
    else if (strcmp(cmd, "submit") == 0) {
        const char *host = get_flag_value(argc, argv, "--host");
        const char *port_str = get_flag_value(argc, argv, "--port");
        uint16_t port = 0;
        if (!host) {
            fprintf(stderr, "submit requires --host\n");
            print_usage();
            return 1;
        }
        if (parse_u16(port_str, &port) != 0) {
            fprintf(stderr, "invalid --port\n");
            print_usage();
            return 1;
        }

        const char *event_str = get_flag_value(argc, argv, "--event");
        const char *player_str = get_flag_value(argc, argv, "--player");
        const char *desc = get_flag_value(argc, argv, "--desc");

        if (!event_str || !player_str || !desc) {
            fprintf(stderr, "submit requires --event --player --desc\n");
            print_usage();
            return 1;
        }

        EventType et = parse_event_type(event_str);
        if (et == EVENT_UNKNOWN) {
            fprintf(stderr, "unknown event: %s\n", event_str);
            print_usage();
            return 1;
        }

        uint32_t player_id = (uint32_t)strtoul(player_str, NULL, 10);

        // REMOVING THIS because already parsed earlier in main()
        // uint64_t nonce = 0;
        // const char *nonce_s = get_flag_value(argc, argv, "--nonce");
        // if (nonce_s) {
        //     if (parse_u64(nonce_s, &nonce) != 0) {
        //         fprintf(stderr, "Invalid --nonce value: %s\n", nonce_s);
        //         return 1;
        //     }
        // }
        // else {
        //     // quick nonce: random 64-bit
        //     fprintf(stderr, "No --nonce provided; generating random nonce\n");
        //     randombytes_buf(&nonce, sizeof(nonce));
        // }

        uint8_t hash[HASH_SIZE];
        if (client_submit(host, port, (uint32_t)et, player_id,
                        desc, (uint16_t)strlen(desc),
                        nonce, hash) != 0)
        {
            fprintf(stderr, "client_submit failed\n");
            return 1;
        }

        printf("OK nonce=%llu hash=", (unsigned long long)nonce);
        util_print_hex(hash, HASH_SIZE);
        return 0;
    }

    //
    // -------------------------------
    // Command: VERIFY PEERS
    // -------------------------------
    //
    else if (strcmp(cmd, "verify-peers") == 0) {

        const char *logfile = get_flag_value(argc, argv, "--log");
        const char *peers   = get_flag_value(argc, argv, "--peers");

        if (!logfile) {
            fprintf(stderr, "No --log provided; defaulting to data/game.log\n");
            logfile = "data/game.log";
        }

        if (!peers) {
            fprintf(stderr, "verify-peers requires --peers <peers.conf>\n\n");
            print_usage();
            return 1;
        }

        int rc = logger_verify_peers(logfile, peers);
        if (rc == 0) {
            printf("Log verified (peers): OK.\n");
        }
        else {
            printf("Log verification (peers) FAILED.\n");
        }

        return (rc == 0) ? 0 : 1;
    }

    //
    // -------------------------------
    // Command: SHOW PUBKEY
    // -------------------------------
    //
    else if (strcmp(cmd, "show-pub") == 0) {
        const char *pub_path = get_flag_value(argc, argv, "--pub");
        const char *host = get_flag_value(argc, argv, "--host");
        const char *port_s = get_flag_value(argc, argv, "--port");

        // Local mode: --pub
        if (pub_path) {
            // local file version with path specified ... no node network request
            FILE *f = fopen(pub_path, "rb");
            if (!f) {
                fprintf(stderr, "show-pub: failed to open %s\n", pub_path);
                return 1;
            }
            uint8_t pub[crypto_sign_PUBLICKEYBYTES];
            size_t n = fread(pub, 1, sizeof(pub), f);
            fclose(f);
            if (n != sizeof(pub)) {
                fprintf(stderr, "show-pub: expected %zu bytes, got %zu\n",
                        (size_t)sizeof(pub), n);
                return 1;
            }
            util_print_hex_compact(pub, sizeof(pub));
            return 0;
        }

        // Remote mode: --host --port
        if (!host || !port_s) {
            fprintf(stderr, "usage:\n");
            fprintf(stderr, "  logger show-pub --pub <path>\n");
            fprintf(stderr, "  logger show-pub --host <host> --port <port>\n");
            return 1;
        }

        uint16_t port = (uint16_t)strtoul(port_s, NULL, 10);

        int fd = net_connect_tcp(host, port);
        if (fd < 0) {
            fprintf(stderr, "show-pub: connect failed\n");
            return 1;
        }

        if (msg_send(fd, MSG_PUBKEY_REQ, NULL, 0) != 0) {
            net_close(&fd);
            fprintf(stderr, "show-pub: send failed\n");
            return 1;
        }

        uint8_t type=0, ver=0;
        uint8_t *payload=NULL;
        size_t payload_len=0;

        MsgResult r = msg_recv(fd, &type, &ver, &payload, &payload_len);
        net_close(&fd);

        if (r != MSG_OK || ver != MSG_VERSION || type != MSG_PUBKEY_RESP) {
            free(payload);
            fprintf(stderr, "show-pub: bad response\n");
            return 1;
        }

        if (payload_len != 4 + crypto_sign_PUBLICKEYBYTES) {
            free(payload);
            fprintf(stderr, "show-pub: wrong payload length\n");
            return 1;
        }

        uint32_t node_id = read_u32_le(payload);
        uint8_t *pub = payload + 4;

        // Print in peers.conf-ready form:
        // node_id host port pubhex
        printf("%u %s %u ", node_id, host, (unsigned)port);
        util_print_hex_compact(pub, crypto_sign_PUBLICKEYBYTES);

        free(payload);
        return 0;
    }


    //
    // -------------------------------
    // Command: PRINT
    // -------------------------------
    //
    else if (strcmp(cmd, "print") == 0) {

        const char *pos_logfile = get_arg(argc, argv, 2);
        if (pos_logfile) log_path = pos_logfile;

        return logger_print(log_path);
    }

    //
    // -------------------------------
    // Unknown command
    // -------------------------------
    //
    else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_usage();
        return 1;
    }
}
