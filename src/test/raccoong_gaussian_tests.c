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
 * test_raccoong_gaussian — byte-exact gate against upstream
 * p-11/lattice-hd-wallets `thrc_gauss.sample_rounded` (commit pinned in the
 * fixture header).
 *
 * The C kernel consumes a recorded SHAKE256 byte prefix and must produce the
 * same RACCOONG_N samples upstream produced from the same seed.  Any
 * mismatch indicates the mpmath / MPFR equivalence at 256-bit precision has
 * broken (or that the kernel logic drifted from upstream) — in which case
 * the port stops here and the failing index is reported.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/gaussian.h"
#include "raccoon_g/polyr.h"
#include "test/data/raccoong_gaussian_vectors.h"

void test_raccoong_gaussian(void)
{
    u_assert_true(gaussian_sampler_init());

    int64_t out[RACCOONG_N];
    memset(out, 0, sizeof(out));

    size_t consumed = 0;
    u_assert_true(gaussian_sample_rounded_from_xof(
        out,
        RACCOONG_N,
        RACCOONG_GAUSS_LG_SIGMA2,
        raccoong_gauss_xof_bytes,
        RACCOONG_GAUSS_XOF_LEN,
        &consumed));

    /* Byte-exact equality across all 256 samples. */
    int first_mismatch = -1;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (out[i] != raccoong_gauss_expected[i]) {
            first_mismatch = (int)i;
            break;
        }
    }
    if (first_mismatch >= 0) {
        fprintf(stderr,
                "raccoong gauss: first mismatch at index %d: "
                "got %lld, want %lld\n",
                first_mismatch,
                (long long)out[first_mismatch],
                (long long)raccoong_gauss_expected[first_mismatch]);
    }
    u_assert_int_eq(first_mismatch, -1);

    /* Stayed inside the recorded prefix and consumed an even multiple of
     * 16 bytes (each polar attempt eats two 64-bit reads). */
    u_assert_true(consumed > 0);
    u_assert_true(consumed <= RACCOONG_GAUSS_XOF_LEN);
    u_assert_int_eq((int)(consumed % 16), 0);

    /* Defensive: NULL / odd-n inputs return false. */
    u_assert_int_eq((int)gaussian_sample_rounded_from_xof(
        NULL, RACCOONG_N, RACCOONG_GAUSS_LG_SIGMA2,
        raccoong_gauss_xof_bytes, RACCOONG_GAUSS_XOF_LEN, NULL), 0);
    u_assert_int_eq((int)gaussian_sample_rounded_from_xof(
        out, RACCOONG_N, RACCOONG_GAUSS_LG_SIGMA2,
        NULL, RACCOONG_GAUSS_XOF_LEN, NULL), 0);
    u_assert_int_eq((int)gaussian_sample_rounded_from_xof(
        out, /*n=*/3, RACCOONG_GAUSS_LG_SIGMA2,
        raccoong_gauss_xof_bytes, RACCOONG_GAUSS_XOF_LEN, NULL), 0);

    /* Seed-driven public API now drives SHAKE256(seed) into the kernel.
     * Use the exact seed the fixture was recorded with: must produce the
     * same 256 samples as the byte-stream path above. */
    memset(out, 0, sizeof(out));
    u_assert_true(gaussian_sample(out, RACCOONG_N,
                                  raccoong_gauss_seed_bytes));
    int seed_mismatch = -1;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (out[i] != raccoong_gauss_expected[i]) { seed_mismatch = (int)i; break; }
    }
    if (seed_mismatch >= 0) {
        fprintf(stderr,
                "raccoong gauss (seed): first mismatch at index %d: "
                "got %lld, want %lld\n",
                seed_mismatch,
                (long long)out[seed_mismatch],
                (long long)raccoong_gauss_expected[seed_mismatch]);
    }
    u_assert_int_eq(seed_mismatch, -1);

    /* Defensive paths for the seed-driven entry. */
    u_assert_int_eq((int)gaussian_sample(NULL, RACCOONG_N,
                                         raccoong_gauss_seed_bytes), 0);
    u_assert_int_eq((int)gaussian_sample(out, /*n=*/3,
                                         raccoong_gauss_seed_bytes), 0);

    gaussian_sampler_shutdown();
}
