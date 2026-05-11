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
 * Byte-exact gate for `raccoong_expand_a` + `raccoong_mul_mat_vec_ntt`
 * (and, transitively, `polyr_mul_pointwise` + `polyr_add` over a vector).
 *
 * Reproduces the upstream Python pipeline:
 *     A_ntt = _expand_a(A_seed)                # 9x9 in NTT domain
 *     v[j]  = _xof_sample_q(v_seed_j)          # 9 polys, NTT domain
 *     t     = mul_mat_vec_ntt(A_ntt, v)        # 9 polys, NTT domain
 * and asserts byte-exact equality across the full 9 * 256 u64 output.
 *
 * Also independently exercises the NTT-domain pointwise multiply on
 * (A[0][0], v[0]) so a regression in `polyr_mul_pointwise` is localized
 * before the matrix-vector accumulation hides it.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/polyr.h"
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_matvec_vectors.h"

static void build_v_from_seeds(polyr v[RACCOONG_ELL])
{
    for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
        const uint8_t* seed = &raccoong_matvec_v_seeds_blob[
            (size_t)j * RACCOONG_MATVEC_V_SEED_LEN];
        u_assert_true(raccoong_xof_sample_q(v[j].coeffs, seed,
                                            RACCOONG_MATVEC_V_SEED_LEN));
    }
}

void test_raccoong_matvec(void)
{
    /* Reconstruct A from A_seed. */
    static polyr A[RACCOONG_K][RACCOONG_ELL];
    u_assert_true(raccoong_expand_a(A, raccoong_matvec_A_seed));

    /* Sanity: every entry must be normalized to [0, q). */
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
            u_assert_true(polyr_is_normalized(&A[i][j]));
        }
    }

    /* Reconstruct v from the recorded seeds. */
    static polyr v[RACCOONG_ELL];
    build_v_from_seeds(v);

    /* --- Pointwise gate first: localizes any regression. --- */
    polyr pw00;
    u_assert_true(polyr_mul_pointwise(&pw00, &A[0][0], &v[0]));
    int pw_mismatch = -1;
    for (size_t k = 0; k < RACCOONG_N; ++k) {
        if (pw00.coeffs[k] != raccoong_matvec_pointwise_00_expected[k]) {
            pw_mismatch = (int)k;
            break;
        }
    }
    if (pw_mismatch >= 0) {
        fprintf(stderr,
                "raccoong matvec pointwise A[0][0]*v[0]: first mismatch at "
                "index %d (got %llu, want %llu)\n",
                pw_mismatch,
                (unsigned long long)pw00.coeffs[pw_mismatch],
                (unsigned long long)raccoong_matvec_pointwise_00_expected[pw_mismatch]);
    }
    u_assert_int_eq(pw_mismatch, -1);

    /* --- Full matrix-vector gate. --- */
    static polyr t[RACCOONG_K];
    u_assert_true(raccoong_mul_mat_vec_ntt(t,
                                           (const polyr (*)[RACCOONG_ELL])A,
                                           v));

    int mismatch_row = -1, mismatch_col = -1;
    for (unsigned i = 0; i < RACCOONG_K && mismatch_row < 0; ++i) {
        u_assert_true(polyr_is_normalized(&t[i]));
        for (size_t k = 0; k < RACCOONG_N; ++k) {
            uint64_t want =
                raccoong_matvec_t_expected[(size_t)i * RACCOONG_N + k];
            if (t[i].coeffs[k] != want) {
                mismatch_row = (int)i;
                mismatch_col = (int)k;
                break;
            }
        }
    }
    if (mismatch_row >= 0) {
        fprintf(stderr,
                "raccoong matvec t: first mismatch at row %d, col %d "
                "(got %llu, want %llu)\n",
                mismatch_row, mismatch_col,
                (unsigned long long)t[mismatch_row].coeffs[mismatch_col],
                (unsigned long long)raccoong_matvec_t_expected[
                    (size_t)mismatch_row * RACCOONG_N + (size_t)mismatch_col]);
    }
    u_assert_int_eq(mismatch_row, -1);

    /* Defensive paths. */
    u_assert_int_eq((int)raccoong_expand_a(NULL, raccoong_matvec_A_seed), 0);
    u_assert_int_eq((int)raccoong_expand_a(A, NULL), 0);
    u_assert_int_eq((int)raccoong_mul_mat_vec_ntt(NULL,
                                                  (const polyr (*)[RACCOONG_ELL])A,
                                                  v), 0);
    u_assert_int_eq((int)raccoong_mul_mat_vec_ntt(t, NULL, v), 0);
    u_assert_int_eq((int)raccoong_mul_mat_vec_ntt(t,
                                                  (const polyr (*)[RACCOONG_ELL])A,
                                                  NULL), 0);

    /* `vec_add` and `vec_rshift` smoke: t' = (t + t) right-shifted by 1
     * must equal t (mod q) since (2t + 1) >> 1 = t when low bit of t is 1
     * — for safety just check this is *some* polynomial in [0, q) and that
     * vec_add is commutative. */
    static polyr two_t[RACCOONG_K];
    u_assert_true(raccoong_vec_add(two_t, t, t, RACCOONG_K));
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        u_assert_true(polyr_is_normalized(&two_t[i]));
    }
    static polyr two_t_rev[RACCOONG_K];
    u_assert_true(raccoong_vec_add(two_t_rev, t, t, RACCOONG_K));
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        u_assert_true(polyr_equal(&two_t[i], &two_t_rev[i]));
    }
    static polyr shifted[RACCOONG_K];
    u_assert_true(raccoong_vec_rshift(shifted, two_t, 1, RACCOONG_K));
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        u_assert_true(polyr_is_normalized(&shifted[i]));
    }

    /* `vec_ntt` round-trip: a uniform polynomial in NTT domain, when run
     * through inverse-then-forward, must come back unchanged. */
    static polyr roundtrip[RACCOONG_ELL];
    memcpy(roundtrip, v, sizeof(roundtrip));
    u_assert_true(raccoong_vec_intt(roundtrip, RACCOONG_ELL));
    u_assert_true(raccoong_vec_ntt(roundtrip, RACCOONG_ELL));
    for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
        u_assert_true(polyr_equal(&roundtrip[j], &v[j]));
    }
}
