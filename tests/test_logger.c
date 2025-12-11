#include "../include/logger.h"
#include "../include/util.h"
#include "../include/crypto.h"
#include "test.h"
#include <sodium.h>

void test_logger(void)
{
    const char *path = "data/test_logger.log";
    remove(path);

    TEST_ASSERT(logger_add(path, 1, 5, "hello") == 0);
    TEST_ASSERT(logger_add(path, 2, 9, "world") == 0);

    TEST_ASSERT(logger_verify(path) == 0);

    // smoke test for print (won't assert output)
    TEST_ASSERT(logger_print(path) == 0);

    TEST_PASS();
}

int main(void)
{
    if (sodium_init() == -1) return 1;
    load_or_create_keys("data/test_pub.key", "data/test_priv.key");
    test_logger();
}
