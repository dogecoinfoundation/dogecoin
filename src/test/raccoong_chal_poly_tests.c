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
 * Byte-exact gate for raccoong_chal_poly.
 *
 * Drives upstream `ThRc_Core._chal_poly` (Raccoon-G-44, kappa=128, tau=23)
 * pinned at lattice-hd-wallets@461a5ed9.
 *
 * Covers:
 *   (1) byte-exact: raccoong_chal_poly(c_hash) == fixture polynomial,
 *       coefficient-by-coefficient, for several distinct c_hash inputs;
 *   (2) structural: every output is in {-1, 0, +1} and the L1-weight
 *       (number of non-zero coefficients) equals RACCOONG_TAU = 23;
 *   (3) reject:     null arguments are rejected without writing.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/thrc.h"
#include "test/data/raccoong_chal_poly_vectors.h"

/* `_Static_assert` is C11 only; use a -pedantic-friendly typedef trick. */
#define RACCOONG_CHAL_STATIC_ASSERT2(cond, line) \
    typedef char raccoong_chal_static_assert_##line[(cond) ? 1 : -1]
#define RACCOONG_CHAL_STATIC_ASSERT1(cond, line) RACCOONG_CHAL_STATIC_ASSERT2(cond, line)
#define RACCOONG_CHAL_STATIC_ASSERT(cond) RACCOONG_CHAL_STATIC_ASSERT1(cond, __LINE__)
RACCOONG_CHAL_STATIC_ASSERT(RACCOONG_TAU == RACCOONG_CHAL_POLY_FIXTURE_TAU);
RACCOONG_CHAL_STATIC_ASSERT(256 == RACCOONG_CHAL_POLY_FIXTURE_N);

void test_raccoong_chal_poly()
{
    /* (3) Null-argument guards. */
    int8_t out[256];
    uint8_t c_hash[RACCOONG_C_HASH_BYTES] = {0};
    u_assert_int_eq(raccoong_chal_poly(NULL, c_hash), 0);
    u_assert_int_eq(raccoong_chal_poly(out, NULL), 0);

    /* (1) + (2) Byte-exact + structural for every fixture case. */
    for (size_t f = 0; f < RACCOONG_CHAL_POLY_FIXTURE_COUNT; ++f) {
        const raccoong_chal_poly_fixture_t* fix =
            &kRaccoongChalPolyFixtures[f];

        /* Pre-fill `out` with a sentinel to ensure the call rewrites it. */
        memset(out, 0x55, sizeof(out));
        u_assert_int_eq(raccoong_chal_poly(out, fix->c_hash), 1);

        /* (1) Componentwise byte-exact match against upstream. */
        for (size_t i = 0; i < 256u; ++i) {
            if (out[i] != fix->expected[i]) {
                printf("chal_poly mismatch case=%zu coeff=%zu: "
                       "got %d expected %d\n",
                       f, i, (int)out[i], (int)fix->expected[i]);
                u_assert_int_eq(out[i], fix->expected[i]);
            }
        }

        /* (2) Structural: ternary, exact tau weight. */
        unsigned weight = 0;
        for (size_t i = 0; i < 256u; ++i) {
            int v = out[i];
            u_assert_int_eq(v >= -1 && v <= 1, 1);
            if (v != 0) weight++;
        }
        u_assert_int_eq((int)weight, (int)RACCOONG_TAU);
    }
}
