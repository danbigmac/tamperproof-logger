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

static uint64_t random_nonce_u64(void)
{
    uint64_t x = 0;
    randombytes_buf(&x, sizeof(x));
    return x;
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
