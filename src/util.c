#include <time.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

uint64_t util_timestamp_now(void)
{
    return (uint64_t)time(NULL);
}

void util_print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i + 1 < len) printf(" ");
    }
    printf("\n");
}

// Returns argv[i] if it exists, otherwise NULL.
const char *get_arg(int argc, char **argv, int index)
{
    if (index < argc) {
        return argv[index];
    }
    return NULL;
}

int has_flag(int argc, char **argv, const char *flag)
{
    if (!flag) {
        fprintf(stderr, "has_flag: NULL flag\n");
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], flag) == 0) return 1;
    }
    return 0;
}

const char *get_flag_value(int argc, char **argv, const char *flag)
{
    if (!flag) {
        fprintf(stderr, "get_flag_value: NULL flag\n");
        return NULL;
    }

    size_t flen = strlen(flag);

    for (int i = 1; i < argc; i++) {
        // Exact match: --flag value
        if (strcmp(argv[i], flag) == 0) {
            if (i + 1 < argc) {
                // If next token looks like another flag, treat as missing value
                if (argv[i + 1][0] == '-') {
                    fprintf(stderr, "get_flag_value: Missing value for flag '%s'\n", flag);
                    return NULL;
                }
                return argv[i + 1];
            }
            fprintf(stderr, "get_flag_value: Missing value for flag '%s'\n", flag);
            return NULL;
        }
        // Equals match: --flag=value
        if (strncmp(argv[i], flag, flen) == 0 && argv[i][flen] == '=') {
            const char *v = argv[i] + flen + 1;
            return (*v != '\0') ? v : NULL;
        }
    }

    return NULL;
}

int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int decode_pubkey_hex(uint8_t *out, size_t out_max,
                      const char *in, size_t in_len)
{
    if (in_len % 2 != 0) return -1;
    size_t bytes = in_len / 2;

    if (bytes > out_max) return -1;

    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_nibble(in[2*i]);
        int lo = hex_nibble(in[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return (int)bytes;
}

int encode_pubkey_hex(char *out, size_t out_max,
                      const uint8_t *pub, size_t pub_len)
{
    // needs 2 chars per byte
    size_t needed = pub_len * 2;
    if (out_max < needed) return -1;

    static const char HEX[] = "0123456789abcdef";

    for (size_t i = 0; i < pub_len; i++) {
        out[2*i]     = HEX[(pub[i] >> 4) & 0xF];
        out[2*i + 1] = HEX[pub[i] & 0xF];
    }

    return 0;
}

void write_u64_le(uint8_t *buf, uint64_t v) {
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)((v >> (8*i)) & 0xFF);
}

void write_u32_le(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8) & 0xFF);
    buf[2] = (uint8_t)((v >> 16) & 0xFF);
    buf[3] = (uint8_t)((v >> 24) & 0xFF);
}

void write_u16_le(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8) & 0xFF);
}

uint64_t read_u64_le(const uint8_t *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)buf[i]) << (8*i);
    return v;
}

uint32_t read_u32_le(const uint8_t *buf) {
    return (uint32_t)buf[0]
         | (uint32_t)buf[1]<<8
         | (uint32_t)buf[2]<<16
         | (uint32_t)buf[3]<<24;
}

uint16_t read_u16_le(const uint8_t *buf) {
    return (uint16_t)buf[0] | (uint16_t)buf[1] << 8;
}
