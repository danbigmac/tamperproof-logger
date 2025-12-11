#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <stdlib.h>

#define TEST_ASSERT(cond)                                                \
    do { if (!(cond)) {                                                  \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1);                                                         \
    }} while (0)

#define TEST_PASS()                                                      \
    do {                                                                 \
        printf("PASS: %s\n", __func__);                                  \
        return;                                                          \
    } while (0)

#endif
