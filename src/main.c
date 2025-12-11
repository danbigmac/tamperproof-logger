#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "event_type.h" // parse_event_type, EventType
#include "logger.h"   // logger_add, logger_verify, logger_print
#include "util.h"     // get_arg
#include "crypto.h"   // load_or_create_keys

static void print_usage(void)
{
    printf("Usage:\n");
    printf("  logger add <event_type> <player_id> <description>\n");
    printf("  logger verify <logfile>\n");
    printf("  logger print <logfile>\n");
}

int main(int argc, char **argv)
{
    // Always initialize libsodium early and once.
    if (sodium_init() == -1) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char *cmd = argv[1];

    //
    // -------------------------------
    // Command: ADD
    // -------------------------------
    //
    if (strcmp(cmd, "add") == 0) {

        // Load or generate keys
        if (load_or_create_keys("data/public.key", "data/private.key") != 0) {
            fprintf(stderr, "Could not load or create keypair\n");
            return 1;
        }

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

        uint32_t player_id  = (uint32_t)atoi(player_id_str);

        int rc = logger_add("data/game.log", etype, player_id, description);
        if (rc != 0) {
            fprintf(stderr, "logger_add failed\n");
            return 1;
        }

        printf("Entry added.\n");
        return 0;
    }

    //
    // -------------------------------
    // Command: VERIFY
    // -------------------------------
    //
    else if (strcmp(cmd, "verify") == 0) {

        // Load or generate keys
        if (load_or_create_keys("data/public.key", "data/private.key") != 0) {
            fprintf(stderr, "Could not load or create keypair\n");
            return 1;
        }

        const char *logfile = get_arg(argc, argv, 2);
        if (!logfile) logfile = "data/game.log";

        int rc = logger_verify(logfile);
        if (rc == 0)
            printf("Log verified: OK.\n");
        else
            printf("Log verification FAILED.\n");

        return rc;
    }

    //
    // -------------------------------
    // Command: PRINT
    // -------------------------------
    //
    else if (strcmp(cmd, "print") == 0) {

        const char *logfile = get_arg(argc, argv, 2);
        if (!logfile) logfile = "data/game.log";

        int rc = logger_print(logfile);
        return rc;
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

    return 0;
}
