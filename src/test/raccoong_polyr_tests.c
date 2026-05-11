/*

 The MIT License (MIT)

 Copyright (c) 2026 edtubbs
 Copyright (c) 2026 The Dogecoin Foundation

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

/*
 * test_raccoong_polyr — byte-exact gate against upstream
 * p-11/lattice-hd-wallets (commit pinned in the fixture header).
 *
 * Each operation in src/raccoon_g/polyr.c is run on the input vectors
 * raccoong_polyr_input_a / _b and compared coefficient-for-coefficient with
 * the upstream-generated expected vectors. Any divergence fails the test.
 */

#include <stdint.h>
#include <stdio.h>

#include <test/utest.h>

#include "raccoon_g/polyr.h"
#include "test/data/raccoong_polyr_vectors.h"

static void load(polyr* p, const uint64_t* src)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        p->coeffs[i] = src[i];
    }
}

static int coeffs_match_u64(const polyr* got, const uint64_t* want)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (got->coeffs[i] != want[i]) {
            fprintf(stderr,
                    "raccoong_polyr coeff %zu mismatch: got %llu, want %llu\n",
                    i, (unsigned long long)got->coeffs[i],
                    (unsigned long long)want[i]);
            return 0;
        }
    }
    return 1;
}

static int coeffs_match_i64(const int64_t* got, const int64_t* want)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (got[i] != want[i]) {
            fprintf(stderr,
                    "raccoong_polyr center coeff %zu mismatch: got %lld, want %lld\n",
                    i, (long long)got[i], (long long)want[i]);
            return 0;
        }
    }
    return 1;
}

void test_raccoong_polyr(void)
{
    /* Sanity: parameters match upstream. */
    u_assert_uint64_eq((uint64_t)RACCOONG_N, 256);
    u_assert_uint64_eq(RACCOONG_Q, 562949953438721ULL);
    u_assert_uint64_eq(RACCOONG_NI, 560750930183101ULL);

    polyr a, b, r;
    load(&a, raccoong_polyr_input_a);
    load(&b, raccoong_polyr_input_b);

    /* Inputs must already be in [0, q). */
    u_assert_true(polyr_is_normalized(&a));
    u_assert_true(polyr_is_normalized(&b));

    /* add */
    u_assert_true(polyr_add(&r, &a, &b));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_add));

    /* sub */
    u_assert_true(polyr_sub(&r, &a, &b));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_sub));

    /* mul_pointwise (= upstream mul_ntt) */
    u_assert_true(polyr_mul_pointwise(&r, &a, &b));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_mul_pointwise));

    /* scale */
    u_assert_true(polyr_scale(&r, RACCOONG_POLYR_TEST_SCALAR, &a));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_scale));

    /* lshift */
    u_assert_true(polyr_lshift(&r, &a, RACCOONG_POLYR_TEST_LSHIFT));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_lshift));

    /* rshift */
    u_assert_true(polyr_rshift(&r, &a, RACCOONG_POLYR_TEST_RSHIFT));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match_u64(&r, raccoong_polyr_expected_rshift));

    /* center */
    int64_t centered[RACCOONG_N];
    u_assert_true(polyr_center(centered, &a));
    u_assert_true(coeffs_match_i64(centered, raccoong_polyr_expected_center));

    /* Aliasing: r aliases first operand. */
    polyr c;
    polyr_copy(&c, &a);
    u_assert_true(polyr_add(&c, &c, &b));
    u_assert_true(coeffs_match_u64(&c, raccoong_polyr_expected_add));

    /* Aliasing: r aliases second operand. */
    polyr_copy(&c, &b);
    u_assert_true(polyr_add(&c, &a, &c));
    u_assert_true(coeffs_match_u64(&c, raccoong_polyr_expected_add));

    /* Heap helpers — polyr_alloc returns false on OOM and sets *out to NULL. */
    polyr* hp = NULL;
    u_assert_true(polyr_alloc(&hp));
    polyr_copy(hp, &a);
    u_assert_true(polyr_equal(hp, &a));
    polyr_set_zero(hp);
    polyr zero;
    polyr_set_zero(&zero);
    u_assert_true(polyr_equal(hp, &zero));
    polyr_free(hp);

    /* Defensive: NULL inputs return false. */
    u_assert_int_eq((int)polyr_add(NULL, &a, &b), 0);
    u_assert_int_eq((int)polyr_add(&r, NULL, &b), 0);
    u_assert_int_eq((int)polyr_lshift(&r, &a, 64), 0);
    u_assert_int_eq((int)polyr_rshift(&r, &a, 0), 0);
}
