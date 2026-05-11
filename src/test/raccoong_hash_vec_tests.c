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
 * Byte-exact gate for raccoong_hash_vec.
 *
 * Drives upstream `ThRc_Core._hash_vec` (Raccoon-G-44, kappa=128) pinned at
 * lattice-hd-wallets@461a5ed9.
 *
 * Covers:
 *   (1) byte-exact: 32-byte digest matches upstream across several
 *       (dat_len, v_len) sizes including 1, n, k*n, and 2*n coefficients;
 *   (2) reduction:  feeding coefficients with `+q` added produces the same
 *       digest, exercising the `x mod q` reduction step;
 *   (3) reject:     null `out` / null `v` (when v_len>0) / null `dat`
 *       (when dat_len>0) are rejected without writing the output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/polyr.h"     /* RACCOONG_Q */
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_hash_vec_vectors.h"

void test_raccoong_hash_vec()
{
    uint8_t out[RACCOONG_C_HASH_BYTES];

    /* (3) Null-argument guards. */
    uint64_t dummy_v = 0;
    u_assert_int_eq(raccoong_hash_vec(NULL, 'H', NULL, 0, &dummy_v, 1), 0);
    u_assert_int_eq(raccoong_hash_vec(out, 'H', NULL, 0, NULL, 1), 0);
    u_assert_int_eq(raccoong_hash_vec(out, 'H', NULL, 4, &dummy_v, 1), 0);

    for (size_t f = 0; f < RACCOONG_HASH_VEC_FIXTURE_COUNT; ++f) {
        const raccoong_hash_vec_fixture_t* fix = &kRaccoongHashVecFixtures[f];

        /* (1) Byte-exact digest match. */
        memset(out, 0x55, sizeof(out));
        u_assert_int_eq(raccoong_hash_vec(out, fix->ds,
                                          fix->dat, fix->dat_len,
                                          fix->v,   fix->v_len),
                        1);
        if (memcmp(out, fix->digest, RACCOONG_C_HASH_BYTES) != 0) {
            printf("hash_vec mismatch case=%zu\n", f);
            for (size_t i = 0; i < RACCOONG_C_HASH_BYTES; ++i) {
                printf("  [%zu] got=%02x want=%02x\n", i,
                       out[i], fix->digest[i]);
            }
            u_assert_int_eq(memcmp(out, fix->digest,
                                   RACCOONG_C_HASH_BYTES), 0);
        }

        /* (2) `x mod q` reduction: shifting every coefficient by +q must
         * produce the same digest as the unshifted vector. */
        if (fix->v_len > 0) {
            uint64_t* shifted =
                (uint64_t*)malloc(fix->v_len * sizeof(uint64_t));
            u_assert_int_eq(shifted != NULL, 1);
            for (size_t i = 0; i < fix->v_len; ++i) {
                shifted[i] = fix->v[i] + (uint64_t)RACCOONG_Q;
            }
            uint8_t out2[RACCOONG_C_HASH_BYTES];
            u_assert_int_eq(raccoong_hash_vec(out2, fix->ds,
                                              fix->dat, fix->dat_len,
                                              shifted, fix->v_len),
                            1);
            u_assert_int_eq(memcmp(out, out2,
                                   RACCOONG_C_HASH_BYTES), 0);
            free(shifted);
        }
    }
}
