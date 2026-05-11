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
 * Byte-exact gate for raccoong_keygen_t_unrounded — composes ExpandA,
 * the seeded gaussian sampler at sigma_t^2 = 2^14, vec_ntt /
 * mul_mat_vec_ntt / vec_intt, and vec_add to reproduce upstream
 * `_keygen_unrounded(raccoon, key)`.
 *
 * Tiered to localize any regression:
 *   (1) seeded-gaussian gate at sigma_t^2 on s[0] and e1[0];
 *   (2) A_seed = SHAKE256(_hdr8('A') + key, 16);
 *   (3) full 9 * 256 unrounded t vector.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/gaussian.h"
#include "raccoon_g/polyr.h"
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_keygen_t_vectors.h"

static int first_i64_mismatch(const int64_t* got, const int64_t* want,
                              size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != want[i]) return (int)i;
    }
    return -1;
}

void test_raccoong_keygen_t(void)
{
    /* --- (1) Seeded gaussian byte-exactness on s[0] and e1[0]. --- */
    int64_t samples[RACCOONG_N];

    uint8_t seed_s0[8 + 32];
    raccoong_hdr8(seed_s0, 's', 0, 0, 0, 0, 0, 0, 0);
    memcpy(seed_s0 + 8, raccoong_keygen_t_key, 32);
    u_assert_true(gaussian_sample_seed(samples, RACCOONG_N,
                                       RACCOONG_LG_SIGMA_T2,
                                       seed_s0, sizeof(seed_s0)));
    int s0_idx = first_i64_mismatch(samples,
                                    raccoong_keygen_t_s0_expected,
                                    RACCOONG_N);
    if (s0_idx >= 0) {
        fprintf(stderr,
                "keygen-t s[0]: first mismatch at %d "
                "(got %lld, want %lld)\n",
                s0_idx,
                (long long)samples[s0_idx],
                (long long)raccoong_keygen_t_s0_expected[s0_idx]);
    }
    u_assert_int_eq(s0_idx, -1);

    uint8_t seed_e10[8 + 32];
    raccoong_hdr8(seed_e10, 'e', 0, 1, 0, 0, 0, 0, 0);
    memcpy(seed_e10 + 8, raccoong_keygen_t_key, 32);
    u_assert_true(gaussian_sample_seed(samples, RACCOONG_N,
                                       RACCOONG_LG_SIGMA_T2,
                                       seed_e10, sizeof(seed_e10)));
    int e0_idx = first_i64_mismatch(samples,
                                    raccoong_keygen_t_e1_0_expected,
                                    RACCOONG_N);
    if (e0_idx >= 0) {
        fprintf(stderr,
                "keygen-t e1[0]: first mismatch at %d "
                "(got %lld, want %lld)\n",
                e0_idx,
                (long long)samples[e0_idx],
                (long long)raccoong_keygen_t_e1_0_expected[e0_idx]);
    }
    u_assert_int_eq(e0_idx, -1);

    /* --- (2) + (3) Full keygen-t. --- */
    uint8_t A_seed[RACCOONG_A_SEED_BYTES];
    static polyr t[RACCOONG_K];
    u_assert_true(raccoong_keygen_t_unrounded(
        raccoong_keygen_t_key, A_seed, t, /*s_out=*/NULL));

    /* A_seed gate. */
    u_assert_int_eq(memcmp(A_seed, raccoong_keygen_t_A_seed_expected,
                           RACCOONG_A_SEED_BYTES), 0);

    /* t gate. */
    int row = -1, col = -1;
    for (unsigned i = 0; i < RACCOONG_K && row < 0; ++i) {
        u_assert_true(polyr_is_normalized(&t[i]));
        for (size_t k = 0; k < RACCOONG_N; ++k) {
            uint64_t want =
                raccoong_keygen_t_expected[(size_t)i * RACCOONG_N + k];
            if (t[i].coeffs[k] != want) {
                row = (int)i;
                col = (int)k;
                break;
            }
        }
    }
    if (row >= 0) {
        fprintf(stderr,
                "keygen-t: first mismatch at row %d col %d "
                "(got %llu, want %llu)\n",
                row, col,
                (unsigned long long)t[row].coeffs[col],
                (unsigned long long)raccoong_keygen_t_expected[
                    (size_t)row * RACCOONG_N + (size_t)col]);
    }
    u_assert_int_eq(row, -1);

    /* Defensive paths. */
    u_assert_int_eq((int)raccoong_keygen_t_unrounded(
        NULL, A_seed, t, NULL), 0);
    u_assert_int_eq((int)raccoong_keygen_t_unrounded(
        raccoong_keygen_t_key, NULL, t, NULL), 0);
    u_assert_int_eq((int)raccoong_keygen_t_unrounded(
        raccoong_keygen_t_key, A_seed, NULL, NULL), 0);
}
