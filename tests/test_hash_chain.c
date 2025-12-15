#include "../include/logger.h"
#include "../include/fileio.h"
#include "../include/crypto.h"
#include "../include/util.h"
#include "test.h"

void test_hash_chain(void)
{
    const char *path = "data/test_chain.log";
    remove(path);

    logger_add(path, 1, 11, "alpha");
    logger_add(path, 2, 22, "beta");
    logger_add(path, 3, 33, "gamma");

    // Should verify successfully
    TEST_ASSERT(logger_verify(path) == 0);

    // Tamper with file: flip a byte
    FILE *f = fopen(path, "r+b");
    TEST_ASSERT(f != NULL);
    fseek(f, 70, SEEK_SET);
    fputc(0xFF, f);
    fclose(f);

    // Verification MUST fail
    TEST_ASSERT(logger_verify(path) != 0);

    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) return 1;
    load_or_create_keys("data/test_pub.key", "data/test_priv.key");
    test_hash_chain();
}
