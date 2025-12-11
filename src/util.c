#include <time.h>
#include <stdio.h>
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

void write_u64_le(uint8_t *buf, uint64_t v) {
    for (int i = 0; i < 8; i++)
        buf[i] = (v >> (8*i)) & 0xFF;
}

void write_u32_le(uint8_t *buf, uint32_t v) {
    buf[0] = v & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF;
    buf[3] = (v >> 24) & 0xFF;
}

void write_u16_le(uint8_t *buf, uint16_t v) {
    buf[0] = v & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
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
