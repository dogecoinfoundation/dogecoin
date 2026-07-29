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
 * Byte-exact gate for thrc_hd_derive_priv / thrc_hd_derive_pub.
 *
 * The chain-code-driven tweak_seed derivation is libdogecoin-defined
 * (see src/raccoon_g/thrc.c::hd_derive_tweak_seed); the lattice math
 * (generate_tweak_keypair_from_seed + add_{public,signing}_keys) is taken
 * from upstream p-11/lattice-hd-wallets@461a5ed9 verbatim.
 *
 * Covers:
 *   (1) non-hardened derive_priv: child pk/sk match upstream;
 *   (2) non-hardened derive_pub:  child pk matches the priv-path pk;
 *   (3) hardened   derive_priv:   child pk/sk match upstream;
 *   (4) hardened   derive_pub:    rejected (returns false).
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/raccoong.h"
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_hd_derive_vectors.h"

static int first_byte_mismatch(const uint8_t* got, const uint8_t* want, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != want[i]) return (int)i;
    }
    return -1;
}

void test_raccoong_hd_derive(void)
{
    u_assert_int_eq(RACCOONG_PK_BYTES, RACCOONG_HD_PK_BYTES);
    u_assert_int_eq(RACCOONG_SK_BYTES, RACCOONG_HD_SK_BYTES);

    static uint8_t child_pk[RACCOONG_PK_BYTES];
    static uint8_t child_sk[RACCOONG_SK_BYTES];

    /* (1) Non-hardened: derive_priv must produce the exact child pk/sk. */
    memset(child_pk, 0xff, sizeof(child_pk));
    memset(child_sk, 0xff, sizeof(child_sk));
    u_assert_int_eq(raccoong_hd_derive_priv(
                        raccoong_hd_parent_sk, sizeof(raccoong_hd_parent_sk),
                        raccoong_hd_parent_pk, sizeof(raccoong_hd_parent_pk),
                        raccoong_hd_chaincode, RACCOONG_HD_INDEX, false,
                        child_sk, sizeof(child_sk),
                        child_pk, sizeof(child_pk)),
                    1);
    int diff = first_byte_mismatch(child_pk, raccoong_hd_nh_child_pk,
                                   sizeof(child_pk));
    if (diff >= 0) {
        fprintf(stderr, "NH child_pk mismatch at byte %d\n", diff);
    }
    u_assert_int_eq(diff, -1);
    diff = first_byte_mismatch(child_sk, raccoong_hd_nh_child_sk,
                               sizeof(child_sk));
    if (diff >= 0) {
        fprintf(stderr, "NH child_sk mismatch at byte %d\n", diff);
    }
    u_assert_int_eq(diff, -1);

    /* (2) Non-hardened derive_pub yields the same child_pk. */
    static uint8_t child_pk_pubonly[RACCOONG_PK_BYTES];
    memset(child_pk_pubonly, 0xff, sizeof(child_pk_pubonly));
    u_assert_int_eq(raccoong_hd_derive_pub(
                        raccoong_hd_parent_pk, sizeof(raccoong_hd_parent_pk),
                        raccoong_hd_chaincode, RACCOONG_HD_INDEX,
                        child_pk_pubonly, sizeof(child_pk_pubonly)),
                    1);
    diff = first_byte_mismatch(child_pk_pubonly, raccoong_hd_nh_child_pk,
                               sizeof(child_pk_pubonly));
    u_assert_int_eq(diff, -1);

    /* (3) Hardened derive_priv with hardened=true. */
    memset(child_pk, 0xff, sizeof(child_pk));
    memset(child_sk, 0xff, sizeof(child_sk));
    u_assert_int_eq(raccoong_hd_derive_priv(
                        raccoong_hd_parent_sk, sizeof(raccoong_hd_parent_sk),
                        raccoong_hd_parent_pk, sizeof(raccoong_hd_parent_pk),
                        raccoong_hd_chaincode, RACCOONG_HD_INDEX, true,
                        child_sk, sizeof(child_sk),
                        child_pk, sizeof(child_pk)),
                    1);
    diff = first_byte_mismatch(child_pk, raccoong_hd_h_child_pk,
                               sizeof(child_pk));
    u_assert_int_eq(diff, -1);
    diff = first_byte_mismatch(child_sk, raccoong_hd_h_child_sk,
                               sizeof(child_sk));
    u_assert_int_eq(diff, -1);

    /* (4) Hardened pub-only path must be rejected. */
    u_assert_int_eq(raccoong_hd_derive_pub(
                        raccoong_hd_parent_pk, sizeof(raccoong_hd_parent_pk),
                        raccoong_hd_chaincode,
                        RACCOONG_HD_INDEX | 0x80000000u,
                        child_pk_pubonly, sizeof(child_pk_pubonly)),
                    0);

    /* Negative: wrong child buffer length on derive_priv. */
    u_assert_int_eq(raccoong_hd_derive_priv(
                        raccoong_hd_parent_sk, sizeof(raccoong_hd_parent_sk),
                        raccoong_hd_parent_pk, sizeof(raccoong_hd_parent_pk),
                        raccoong_hd_chaincode, RACCOONG_HD_INDEX, false,
                        child_sk, sizeof(child_sk) - 1,
                        child_pk, sizeof(child_pk)),
                    0);
}
