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
 * Byte-exact gate for raccoong_pk_hash + raccoong_buff_mu.
 *
 * Drives upstream `TRaccoon._buff_mu` (Raccoon-G-44, kappa=128) pinned at
 * lattice-hd-wallets@461a5ed9.
 *
 * Covers:
 *   (1) byte-exact: tr  = SHAKE256(pk).read(32) matches upstream
 *                   mu  = SHAKE256(tr||msg).read(32) matches upstream
 *                   across pk_len in {0, 16, 1024, 16144} and msg_len in
 *                   {0, 14, 64, 512};
 *   (2) reject:     null-argument guards on out / tr / pk (when len>0) /
 *                   msg (when len>0).
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/thrc.h"
#include "test/data/raccoong_buff_mu_vectors.h"

void test_raccoong_buff_mu()
{
    uint8_t tr_out[RACCOONG_C_HASH_BYTES];
    uint8_t mu_out[RACCOONG_C_HASH_BYTES];
    uint8_t scratch[RACCOONG_C_HASH_BYTES] = {0};

    /* (2) Null-argument guards. */
    u_assert_int_eq(raccoong_pk_hash(NULL, scratch, 4), 0);
    u_assert_int_eq(raccoong_pk_hash(tr_out, NULL, 4), 0);
    u_assert_int_eq(raccoong_buff_mu(NULL, scratch, scratch, 4), 0);
    u_assert_int_eq(raccoong_buff_mu(mu_out, NULL, scratch, 4), 0);
    u_assert_int_eq(raccoong_buff_mu(mu_out, scratch, NULL, 4), 0);

    /* Zero-length inputs are accepted. */
    u_assert_int_eq(raccoong_pk_hash(tr_out, NULL, 0), 1);
    u_assert_int_eq(raccoong_buff_mu(mu_out, scratch, NULL, 0), 1);

    for (size_t f = 0; f < RACCOONG_BUFF_MU_FIXTURE_COUNT; ++f) {
        const raccoong_buff_mu_fixture_t* fix = &kRaccoongBuffMuFixtures[f];

        /* (1) tr = H(pk) byte-exact. */
        memset(tr_out, 0x55, sizeof(tr_out));
        u_assert_int_eq(raccoong_pk_hash(tr_out, fix->pk, fix->pk_len), 1);
        if (memcmp(tr_out, fix->tr, RACCOONG_C_HASH_BYTES) != 0) {
            printf("pk_hash mismatch case=%zu\n", f);
            u_assert_int_eq(memcmp(tr_out, fix->tr,
                                   RACCOONG_C_HASH_BYTES), 0);
        }

        /* (1) mu = H(tr || msg) byte-exact, using the C-computed tr to
         * verify the composed flow (and indirectly confirm tr too). */
        memset(mu_out, 0x55, sizeof(mu_out));
        u_assert_int_eq(raccoong_buff_mu(mu_out, tr_out,
                                         fix->msg, fix->msg_len), 1);
        if (memcmp(mu_out, fix->mu, RACCOONG_C_HASH_BYTES) != 0) {
            printf("buff_mu mismatch case=%zu\n", f);
            u_assert_int_eq(memcmp(mu_out, fix->mu,
                                   RACCOONG_C_HASH_BYTES), 0);
        }
    }
}
