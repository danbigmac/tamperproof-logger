#include <sys/stat.h>
#include <sodium.h>
#include "crypto.h"

static uint8_t PUBLIC_KEY[crypto_sign_PUBLICKEYBYTES];
static uint8_t PRIVATE_KEY[crypto_sign_SECRETKEYBYTES];

static int load_key_file(const char *path, uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t n = fread(buf, 1, len, f);
    fclose(f);

    return (n == len) ? 0 : -1;
}

static int write_key_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    size_t n = fwrite(buf, 1, len, f);
    fclose(f);

    return (n == len) ? 0 : -1;
}

int load_or_create_keys(const char *pub_path, const char *priv_path)
{
    // Try to load both keys from disk
    int pub_ok  = (load_key_file(pub_path,  PUBLIC_KEY,  crypto_sign_PUBLICKEYBYTES)  == 0);
    int priv_ok = (load_key_file(priv_path, PRIVATE_KEY, crypto_sign_SECRETKEYBYTES) == 0);

    if (pub_ok && priv_ok) {
        return 0;  // keys loaded successfully
    }

    // Not found - generate new keypair
    if (crypto_sign_keypair(PUBLIC_KEY, PRIVATE_KEY) != 0) {
        return -1;
    }

    // Write them to disk
    if (write_key_file(pub_path,  PUBLIC_KEY,  crypto_sign_PUBLICKEYBYTES) != 0) return -1;
    if (write_key_file(priv_path, PRIVATE_KEY, crypto_sign_SECRETKEYBYTES) != 0) return -1;

    // Important: protect private key file
    chmod(priv_path, 0600);

    return 0;
}

const uint8_t *get_public_key(void)
{
    return PUBLIC_KEY;
}

const uint8_t *get_private_key(void)
{
    return PRIVATE_KEY;
}

int do_hash(const uint8_t *msg, size_t msg_len, uint8_t out_hash[32])
{
    return crypto_hash_sha256(out_hash, msg, msg_len);
    //return 0;
}

int do_sign(const uint8_t hash[32], uint8_t sig_out[64])
{
    return crypto_sign_detached(sig_out, NULL, hash, 32, PRIVATE_KEY);
    //return 0;
}

int do_verify(const uint8_t hash[32], const uint8_t sig[64])
{
    return crypto_sign_verify_detached(sig, hash, 32, PUBLIC_KEY);
}
