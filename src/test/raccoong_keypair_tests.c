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
 * Byte-exact gate for thrc_keygen_from_seed -- end-to-end seed -> (pk, sk).
 *
 * Tiered (each tier localizes the next):
 *   (1) raccoong_hkdf_sha256(seed, 48) matches drbg_seed;
 *   (2) NIST_KAT_DRBG(drbg_seed).random_bytes(32) matches drbg_key;
 *   (3) full 16144-byte pk and 32272-byte sk match upstream
 *       generate_keypair_from_seed(seed).
 *
 * Negative paths: NULL inputs and wrong-length buffers must return false.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/keygen_kdf.h"
#include "raccoon_g/thrc.h"
#include "test/data/raccoong_keypair_vectors.h"

static int first_byte_mismatch(const uint8_t* got, const uint8_t* want, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != want[i]) return (int)i;
    }
    return -1;
}

void test_raccoong_keypair(void)
{
    /* Sanity-check sizes pinned in thrc.h against the fixture. */
    u_assert_int_eq(RACCOONG_PK_BYTES, RACCOONG_KEYPAIR_PK_BYTES);
    u_assert_int_eq(RACCOONG_SK_BYTES, RACCOONG_KEYPAIR_SK_BYTES);

    /* Tier 1: HKDF-SHA256 byte-exact against pycryptodome HKDF. */
    uint8_t drbg_seed[48];
    u_assert_int_eq(raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                                         raccoong_keypair_seed,
                                         sizeof(raccoong_keypair_seed),
                                         NULL, 0, NULL, 0), 1);
    int diff = first_byte_mismatch(drbg_seed, raccoong_keypair_drbg_seed,
                                   sizeof(drbg_seed));
    if (diff >= 0) {
        fprintf(stderr,
                "HKDF mismatch at byte %d: got=0x%02x want=0x%02x\n",
                diff, drbg_seed[diff], raccoong_keypair_drbg_seed[diff]);
    }
    u_assert_int_eq(diff, -1);

    /* Tier 2: NIST_KAT_DRBG(seed=48B).random_bytes(32) byte-exact. */
    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, raccoong_keypair_drbg_seed);
    uint8_t got_key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, got_key, sizeof(got_key));
    diff = first_byte_mismatch(got_key, raccoong_keypair_drbg_key,
                               sizeof(got_key));
    if (diff >= 0) {
        fprintf(stderr,
                "DRBG mismatch at byte %d: got=0x%02x want=0x%02x\n",
                diff, got_key[diff], raccoong_keypair_drbg_key[diff]);
    }
    u_assert_int_eq(diff, -1);

    /* Tier 3: full thrc_keygen_from_seed -> pk/sk. */
    static uint8_t pk[RACCOONG_PK_BYTES];
    static uint8_t sk[RACCOONG_SK_BYTES];
    memset(pk, 0xff, sizeof(pk));
    memset(sk, 0xff, sizeof(sk));
    u_assert_int_eq(thrc_keygen_from_seed(raccoong_keypair_seed,
                                          pk, sizeof(pk),
                                          sk, sizeof(sk)), 1);

    diff = first_byte_mismatch(pk, raccoong_keypair_pk, sizeof(pk));
    if (diff >= 0) {
        fprintf(stderr,
                "pk mismatch at byte %d: got=0x%02x want=0x%02x\n",
                diff, pk[diff], raccoong_keypair_pk[diff]);
    }
    u_assert_int_eq(diff, -1);

    diff = first_byte_mismatch(sk, raccoong_keypair_sk, sizeof(sk));
    if (diff >= 0) {
        fprintf(stderr,
                "sk mismatch at byte %d: got=0x%02x want=0x%02x\n",
                diff, sk[diff], raccoong_keypair_sk[diff]);
    }
    u_assert_int_eq(diff, -1);

    /* The signing key embeds the public key as its prefix. */
    u_assert_int_eq(memcmp(sk, pk, RACCOONG_PK_BYTES), 0);

    /* Negative paths: NULL inputs / wrong sizes must return false. */
    u_assert_int_eq(thrc_keygen_from_seed(NULL, pk, sizeof(pk), sk, sizeof(sk)),
                    0);
    u_assert_int_eq(thrc_keygen_from_seed(raccoong_keypair_seed,
                                          NULL, sizeof(pk), sk, sizeof(sk)),
                    0);
    u_assert_int_eq(thrc_keygen_from_seed(raccoong_keypair_seed,
                                          pk, sizeof(pk), NULL, sizeof(sk)),
                    0);
    u_assert_int_eq(thrc_keygen_from_seed(raccoong_keypair_seed,
                                          pk, sizeof(pk) - 1, sk, sizeof(sk)),
                    0);
    u_assert_int_eq(thrc_keygen_from_seed(raccoong_keypair_seed,
                                          pk, sizeof(pk), sk, sizeof(sk) - 1),
                    0);
}
