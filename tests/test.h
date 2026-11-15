/* test.h - minimal assertion harness (no external dependencies). */
#ifndef PS_TEST_H
#define PS_TEST_H

#include <stdio.h>
#include <string.h>

static int t_failures;
static int t_checks;
static const char *t_current = "";

#define RUN(fn)                                                                                    \
    do {                                                                                           \
        t_current = #fn;                                                                           \
        printf("  %-28s ", #fn);                                                                   \
        fn();                                                                                      \
        printf("ok\n");                                                                            \
    } while (0)

#define FAILF(...)                                                                                 \
    do {                                                                                           \
        printf("\n    FAIL [%s] ", t_current);                                                     \
        printf(__VA_ARGS__);                                                                       \
        printf("\n    at %s:%d\n", __FILE__, __LINE__);                                            \
        t_failures++;                                                                              \
    } while (0)

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        t_checks++;                                                                                \
        if (!(cond)) {                                                                             \
            FAILF("expected %s", #cond);                                                           \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(a, b)                                                                             \
    do {                                                                                           \
        t_checks++;                                                                                \
        long long _a = (long long)(a), _b = (long long)(b);                                        \
        if (_a != _b) {                                                                            \
            FAILF("%s == %s (%lld vs %lld)", #a, #b, _a, _b);                                      \
        }                                                                                          \
    } while (0)

#define CHECK_STR(a, b)                                                                            \
    do {                                                                                           \
        t_checks++;                                                                                \
        const char *_a = (a), *_b = (b);                                                            \
        if (!_a || strcmp(_a, _b) != 0) {                                                          \
            FAILF("%s == \"%s\" (got \"%s\")", #a, _b, _a ? _a : "(null)");                         \
        }                                                                                          \
    } while (0)

#define CHECK_MEM(a, b, n)                                                                         \
    do {                                                                                           \
        t_checks++;                                                                                \
        if (memcmp((a), (b), (n)) != 0) {                                                          \
            FAILF("%s matches %s (%zu bytes)", #a, #b, (size_t)(n));                                \
        }                                                                                          \
    } while (0)

static inline int test_report(void) {
    printf("%d checks, %d failures\n", t_checks, t_failures);
    return t_failures == 0 ? 0 : 1;
}

#endif /* PS_TEST_H */
