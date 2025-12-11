#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <time.h>

/* Returns current timestamp as uint64 */
uint64_t util_timestamp_now(void);

/* Converts binary hash to hex string */
void util_hex(const uint8_t *data, size_t len, char *out_hex);

/* Returns argv[i] if it exists, otherwise NULL. */
const char *get_arg(int argc, char **argv, int index);

void util_print_hex(const uint8_t *data, size_t len);

void write_u64_le(uint8_t *buf, uint64_t v);

void write_u32_le(uint8_t *buf, uint32_t v);

void write_u16_le(uint8_t *buf, uint16_t v);

uint64_t read_u64_le(const uint8_t *buf);

uint32_t read_u32_le(const uint8_t *buf);

uint16_t read_u16_le(const uint8_t *buf);

#endif
