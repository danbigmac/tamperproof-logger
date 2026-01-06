#include "idem.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static uint64_t mix64(uint64_t x)
{
    // SplitMix64-ish mixing
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static uint64_t key_hash(uint32_t author, uint64_t nonce)
{
    uint64_t x = ((uint64_t)author << 32) ^ nonce;
    return mix64(x);
}

static int is_pow2(size_t x) { return x && ((x & (x - 1)) == 0); }

int idem_init(IdemTable *t, size_t cap)
{
    if (!t || !is_pow2(cap) || cap < 8){
        fprintf(stderr, "idem_init: capacity must be power of 2 and >= 8\n");
        return -1;
    }
    t->slots = (IdemSlot *)calloc(cap, sizeof(IdemSlot));
    if (!t->slots){
        fprintf(stderr, "idem_init: calloc for slots failed\n");
        return -1;
    }
    t->cap = cap;
    t->used = 0;
    return 0;
}

void idem_free(IdemTable *t)
{
    if (!t) {
        fprintf(stderr, "idem_free: null table pointer\n");
        return;
    }
    free(t->slots);
    t->slots = NULL;
    t->cap = 0;
    t->used = 0;
}

void idem_clear(IdemTable *t)
{
    if (!t || !t->slots) {
        fprintf(stderr, "idem_clear: null table pointer or slots\n");
        return;
    }
    memset(t->slots, 0, t->cap * sizeof(IdemSlot));
    t->used = 0;
}

static int keys_equal(const IdemSlot *s, uint32_t author, uint64_t nonce)
{
    return (s->author == author) && (s->nonce == nonce);
}

int idem_get(const IdemTable *t, uint32_t author, uint64_t nonce,
             uint8_t out_hash[IDEM_HASH_SIZE])
{
    if (!t || !t->slots || t->cap == 0) {
        fprintf(stderr, "idem_get: null table pointer or slots, or cap is 0.\n");
        return -1;
    }

    uint64_t h = key_hash(author, nonce);
    size_t mask = t->cap - 1;
    size_t idx = (size_t)h & mask;

    for (size_t probe = 0; probe < t->cap; probe++) {
        const IdemSlot *s = &t->slots[idx];

        if (s->state == 0) {
            return 0; // empty means not present
        }
        if (s->state == 1 && keys_equal(s, author, nonce)) {
            if (out_hash) memcpy(out_hash, s->entry_hash, IDEM_HASH_SIZE);
            return 1;
        }
        idx = (idx + 1) & mask;
    }

    // table full and no empty slots -> treat as not found
    return 0;
}

static int idem_put_noresize(IdemTable *t, uint32_t author, uint64_t nonce,
                             const uint8_t entry_hash[IDEM_HASH_SIZE])
{
    uint64_t h = key_hash(author, nonce);
    size_t mask = t->cap - 1;
    size_t idx = (size_t)h & mask;

    size_t first_tomb = (size_t)-1;

    for (size_t probe = 0; probe < t->cap; probe++) {
        IdemSlot *s = &t->slots[idx];

        if (s->state == 0) {
            // insert here (prefer tombstone if found)
            if (first_tomb != (size_t)-1) {
                s = &t->slots[first_tomb];
            }
            s->author = author;
            s->nonce = nonce;
            memcpy(s->entry_hash, entry_hash, IDEM_HASH_SIZE);
            s->state = 1;
            t->used++;
            return 0;
        }

        if (s->state == 2 && first_tomb == (size_t)-1) {
            first_tomb = idx;
        } else if (s->state == 1 && keys_equal(s, author, nonce)) {
            // update existing
            memcpy(s->entry_hash, entry_hash, IDEM_HASH_SIZE);
            return 0;
        }

        idx = (idx + 1) & mask;
    }

    return -1; // no place to insert
}

static int idem_resize(IdemTable *t, size_t new_cap)
{
    IdemSlot *old = t->slots;
    size_t old_cap = t->cap;

    IdemSlot *ns = (IdemSlot *)calloc(new_cap, sizeof(IdemSlot));
    if (!ns) {
        fprintf(stderr, "idem_resize: calloc failed\n");
        return -1;
    }

    t->slots = ns;
    t->cap = new_cap;
    t->used = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].state == 1) {
            (void)idem_put_noresize(t, old[i].author, old[i].nonce, old[i].entry_hash);
        }
    }

    free(old);
    return 0;
}

int idem_put(IdemTable *t, uint32_t author, uint64_t nonce,
             const uint8_t entry_hash[IDEM_HASH_SIZE])
{
    if (!t || !t->slots || t->cap == 0 || !entry_hash) {
        fprintf(stderr, "idem_put: null table pointer or slots, or cap is 0, or null entry_hash.\n");
        return -1;
    }

    // If load factor > ~0.70, grow (until a max), else clear as fallback.
    if (t->used * 10 >= t->cap * 7) {
        size_t new_cap = t->cap * 2;
        if (new_cap <= (1u << 20)) { // cap max ~1,048,576 slots (tune)
            if (idem_resize(t, new_cap) != 0) {
                // if resize fails, best-effort clear
                fprintf(stderr, "idem_put: resize failed, clearing table instead\n");
                idem_clear(t);
            }
        } else {
            // too big; best-effort clear
            idem_clear(t);
        }
    }

    return idem_put_noresize(t, author, nonce, entry_hash);
}
