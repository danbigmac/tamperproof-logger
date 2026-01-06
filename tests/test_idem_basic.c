#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "idem.h"

static void fill32(uint8_t out[32], uint8_t v) {
    for (int i = 0; i < 32; i++) out[i] = v;
}

int main(void)
{
    IdemTable t;
    assert(idem_init(&t, 1024) == 0);

    uint8_t h1[32], h2[32], out[32];
    fill32(h1, 0x11);
    fill32(h2, 0x22);

    // not found
    assert(idem_get(&t, 7, 123, out) == 0);

    // insert
    assert(idem_put(&t, 7, 123, h1) == 0);

    // now found
    memset(out, 0, sizeof(out));
    assert(idem_get(&t, 7, 123, out) == 1);
    assert(memcmp(out, h1, 32) == 0);

    // update existing key
    assert(idem_put(&t, 7, 123, h2) == 0);
    memset(out, 0, sizeof(out));
    assert(idem_get(&t, 7, 123, out) == 1);
    assert(memcmp(out, h2, 32) == 0);

    // different nonce not found
    assert(idem_get(&t, 7, 124, out) == 0);

    // different author not found
    assert(idem_get(&t, 8, 123, out) == 0);

    idem_free(&t);
    printf("PASS test_idem_basic\n");
    return 0;
}
