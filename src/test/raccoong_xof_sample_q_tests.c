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
 * Byte-exact gate for the uniform Z_q rejection sampler used by Raccoon-G
 * `ExpandA` and threshold-share generation.  Every cell in
 * `test/data/raccoong_xof_sample_q_vectors.h` must reproduce upstream
 * `_xof_sample_q` byte-for-byte across all 256 Z_q samples.
 *
 * Also independently verifies the upstream header constructors `_hdr8` /
 * `_hdr24` by reconstructing the seed prefix from `(ds, i, j, k)` and
 * comparing to the recorded seed bytes.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/polyr.h"
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_xof_sample_q_vectors.h"

void test_raccoong_xof_sample_q(void)
{
    /* Direct sampler gate: each fixture cell, all 256 samples must match. */
    for (size_t c = 0; c < RACCOONG_XOFQ_CASE_COUNT; ++c) {
        const raccoong_xofq_case_t* tc = &raccoong_xofq_cases[c];
        uint64_t out[RACCOONG_N];
        memset(out, 0xff, sizeof(out));
        u_assert_true(raccoong_xof_sample_q(out, tc->seed, tc->seed_len));

        int mismatch = -1;
        for (size_t i = 0; i < RACCOONG_N; ++i) {
            /* Sanity: must be normalized to [0, q). */
            if (out[i] >= RACCOONG_Q) { mismatch = (int)i; break; }
            if (out[i] != tc->expected[i]) { mismatch = (int)i; break; }
        }
        if (mismatch >= 0) {
            fprintf(stderr,
                    "raccoong xof_sample_q[%s]: first mismatch at index %d "
                    "(got %llu, want %llu)\n",
                    tc->name, mismatch,
                    (unsigned long long)out[mismatch],
                    (unsigned long long)tc->expected[mismatch]);
        }
        u_assert_int_eq(mismatch, -1);
    }

    /* Header-constructor gates: reconstruct the prefix from (ds, i, j, k)
     * and check against the first 8 bytes of each fixture's recorded seed. */
    uint8_t hdr[8];

    /* cell_A_0_0 → _hdr8('A', 0, 0). */
    raccoong_hdr8(hdr, 'A', 0, 0, 0, 0, 0, 0, 0);
    u_assert_mem_eq(hdr, raccoong_xofq_cell_A_0_0_seed, 8);

    /* cell_A_3_5 → _hdr8('A', 3, 5). */
    raccoong_hdr8(hdr, 'A', 3, 5, 0, 0, 0, 0, 0);
    u_assert_mem_eq(hdr, raccoong_xofq_cell_A_3_5_seed, 8);

    /* cell_A_8_8 → _hdr8('A', 8, 8). */
    raccoong_hdr8(hdr, 'A', 8, 8, 0, 0, 0, 0, 0);
    u_assert_mem_eq(hdr, raccoong_xofq_cell_A_8_8_seed, 8);

    /* cell_p_1_4 → _hdr24('p', i=1, j=4, k=0). */
    raccoong_hdr24(hdr, 'p', 1, 4, 0);
    u_assert_mem_eq(hdr, raccoong_xofq_cell_p_1_4_seed, 8);

    /* Defensive: null `out` returns false; null seed with non-zero len returns false. */
    uint64_t scratch[RACCOONG_N];
    u_assert_int_eq((int)raccoong_xof_sample_q(NULL,
                                               raccoong_xofq_cases[0].seed,
                                               raccoong_xofq_cases[0].seed_len), 0);
    u_assert_int_eq((int)raccoong_xof_sample_q(scratch, NULL, 8), 0);

    /* Empty-seed input is a well-defined SHAKE128 stream — sampler must
     * succeed and produce values in [0, q). */
    u_assert_true(raccoong_xof_sample_q(scratch, NULL, 0));
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        u_assert_true(scratch[i] < RACCOONG_Q);
    }
}
