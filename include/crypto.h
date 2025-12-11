#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Load or generate persistent keypair */
int load_or_create_keys(const char *pub_path, const char *priv_path);

/* Accessors for global static keys */
const uint8_t *get_public_key(void);
const uint8_t *get_private_key(void);

/* Hashing (SHA-256) */
int do_hash(const uint8_t *msg, size_t msg_len, uint8_t out_hash[32]);
/* Signing & verification */
int do_sign(const uint8_t hash[32], uint8_t sig_out[64]);
int do_verify(const uint8_t hash[32], const uint8_t sig[64]);

#endif
