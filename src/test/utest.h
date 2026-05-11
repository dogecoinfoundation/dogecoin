/* utest.h compat shim for the libdogecoin Raccoon-G unit tests.
 *
 * The libdogecoin test drivers under src/test/raccoong_*_tests.c are kept
 * verbatim. They use the minunit-style u_assert_* macros declared in
 * libdogecoin's <test/utest.h>. Here we redefine those macros so each
 * assertion failure flips a process-wide flag and prints a diagnostic; the
 * Boost wrapper in pqc_raccoong_kat_tests.cpp checks the flag after each
 * driver runs and converts it into a BOOST_FAIL.
 */
#ifndef DOGECOIN_TEST_UTEST_H
#define DOGECOIN_TEST_UTEST_H

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int U_TESTS_RUN;
extern int U_TESTS_FAIL;

#ifdef __cplusplus
}
#endif

#define u_assert_true(R)                                                       \
    do {                                                                       \
        if (!(R)) {                                                            \
            fprintf(stderr,                                                    \
                    "ASSERT FAIL: %s:%d: u_assert_true(%s)\n",                 \
                    __FILE__, __LINE__, #R);                                   \
            U_TESTS_FAIL++;                                                    \
            return;                                                            \
        }                                                                      \
    } while (0)

#define u_assert_int_eq(R, E)                                                  \
    do {                                                                       \
        long long _r = (long long)(R);                                         \
        long long _e = (long long)(E);                                         \
        if (_r != _e) {                                                        \
            fprintf(stderr,                                                    \
                    "ASSERT FAIL: %s:%d: u_assert_int_eq(%s=%lld, %s=%lld)\n", \
                    __FILE__, __LINE__, #R, _r, #E, _e);                       \
            U_TESTS_FAIL++;                                                    \
            return;                                                            \
        }                                                                      \
    } while (0)

#define u_assert_uint32_eq(R, E)     u_assert_int_eq((uint32_t)(R), (uint32_t)(E))
#define u_assert_uint32_not_eq(R, E) u_assert_true((uint32_t)(R) != (uint32_t)(E))
#define u_assert_uint64_eq(R, E)     u_assert_int_eq((uint64_t)(R), (uint64_t)(E))
#define u_assert_uint64_not_eq(R, E) u_assert_true((uint64_t)(R) != (uint64_t)(E))

#define u_assert_mem_eq(R, E, L)                                               \
    do {                                                                       \
        if (memcmp((R), (E), (L)) != 0) {                                      \
            fprintf(stderr,                                                    \
                    "ASSERT FAIL: %s:%d: u_assert_mem_eq(%s,%s,%zu)\n",        \
                    __FILE__, __LINE__, #R, #E, (size_t)(L));                  \
            U_TESTS_FAIL++;                                                    \
            return;                                                            \
        }                                                                      \
    } while (0)

#define u_assert_mem_not_eq(R, E, L) u_assert_true(memcmp((R), (E), (L)) != 0)
#define u_assert_str_eq(R, E)        u_assert_true(strcmp((R), (E)) == 0)
#define u_assert_str_not_eq(R, E)    u_assert_true(strcmp((R), (E)) != 0)
#define u_assert_is_null(R)          u_assert_true((R) == NULL)
#define u_assert_not_null(R)         u_assert_true((R) != NULL)

#define u_run_test(T)                                                          \
    do {                                                                       \
        U_TESTS_RUN++;                                                         \
        T();                                                                   \
    } while (0)

#endif /* DOGECOIN_TEST_UTEST_H */
