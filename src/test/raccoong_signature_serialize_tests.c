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
 * Byte-exact gate for raccoong_serialize_signature /
 * raccoong_deserialize_signature.
 *
 * Drives the canonical 20768-byte wire format pinned by upstream
 * raccoon_primitives.serialize_signature at lattice-hd-wallets@461a5ed9.
 *
 * Covers:
 *   (1) byte-exact: serialize(fixture tuple) == fixture bytes;
 *   (2) round-trip: deserialize(serialize(t)) == t (componentwise);
 *   (3) reject:     wrong-length input, out-of-range z coefficient,
 *                   out-of-range h coefficient.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/thrc.h"
#include "test/data/raccoong_signature_serialize_vectors.h"

/* Compile-time agreement between the public C macro and the fixture.
 *
 * `_Static_assert` is C11 only and trips `-pedantic` under `-std=gnu99`;
 * use a typedef trick that is portable down to C89 and accepted by
 * `-pedantic`.  An invalid array size silences when the predicate holds. */
#define RACCOONG_SIG_STATIC_ASSERT2(cond, line) \
    typedef char raccoong_sig_static_assert_##line[(cond) ? 1 : -1]
#define RACCOONG_SIG_STATIC_ASSERT1(cond, line) RACCOONG_SIG_STATIC_ASSERT2(cond, line)
#define RACCOONG_SIG_STATIC_ASSERT(cond) RACCOONG_SIG_STATIC_ASSERT1(cond, __LINE__)
RACCOONG_SIG_STATIC_ASSERT(RACCOONG_SIG_BYTES == RACCOONG_SIG_FIXTURE_BYTES);
RACCOONG_SIG_STATIC_ASSERT(RACCOONG_ELL == RACCOONG_SIG_FIXTURE_ELL);
RACCOONG_SIG_STATIC_ASSERT(RACCOONG_K == RACCOONG_SIG_FIXTURE_K);

static void load_fixture(uint8_t c_hash[RACCOONG_C_HASH_BYTES],
                         polyr z[RACCOONG_ELL],
                         int16_t h_signed[RACCOONG_K][256])
{
    memcpy(c_hash, kRaccoongSigFixtureCHash, RACCOONG_C_HASH_BYTES);
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        for (size_t j = 0; j < 256u; ++j) {
            z[i].coeffs[j] = kRaccoongSigFixtureZFlat[i * 256u + j];
        }
    }
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < 256u; ++j) {
            h_signed[i][j] =
                kRaccoongSigFixtureHFlatSigned[i * 256u + j];
        }
    }
}

void test_raccoong_signature_serialize()
{
    uint8_t c_hash[RACCOONG_C_HASH_BYTES];
    polyr z[RACCOONG_ELL];
    int16_t h_signed[RACCOONG_K][256];
    load_fixture(c_hash, z, h_signed);

    /* (1) byte-exact serialize. */
    uint8_t out[RACCOONG_SIG_BYTES];
    size_t out_len = sizeof(out);
    u_assert_int_eq(raccoong_serialize_signature(
                        out, &out_len, c_hash, z,
                        (const int16_t (*)[256])h_signed),
                    1);
    u_assert_int_eq((int)out_len, (int)RACCOONG_SIG_BYTES);
    u_assert_int_eq(memcmp(out, kRaccoongSigFixtureSerialized,
                           RACCOONG_SIG_BYTES),
                    0);

    /* (2) round-trip. */
    uint8_t c_hash2[RACCOONG_C_HASH_BYTES];
    polyr z2[RACCOONG_ELL];
    int16_t h2[RACCOONG_K][256];
    u_assert_int_eq(raccoong_deserialize_signature(
                        c_hash2, z2, h2,
                        kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES),
                    1);
    u_assert_int_eq(memcmp(c_hash2, c_hash, RACCOONG_C_HASH_BYTES), 0);
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        u_assert_int_eq(memcmp(z2[i].coeffs, z[i].coeffs,
                               sizeof(z[i].coeffs)),
                        0);
    }
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        u_assert_int_eq(memcmp(h2[i], h_signed[i], sizeof(h_signed[i])), 0);
    }

    /* (3a) wrong length. */
    uint8_t c3[RACCOONG_C_HASH_BYTES];
    polyr z3[RACCOONG_ELL];
    int16_t h3[RACCOONG_K][256];
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, h3,
                        kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES - 1),
                    0);
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, h3,
                        kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES + 1),
                    0);

    /* (3b) out-of-range z coefficient: bump the very last byte of the
     * first z coefficient so the 7-byte LE value lands at q exactly. */
    uint8_t bad[RACCOONG_SIG_BYTES];
    memcpy(bad, kRaccoongSigFixtureSerialized, RACCOONG_SIG_BYTES);
    /* Encode RACCOONG_Q itself into the first z coefficient slot; that
     * is one above the max valid value so the decoder must reject. */
    uint64_t q = RACCOONG_Q;
    uint8_t* zp = bad + RACCOONG_C_HASH_BYTES;
    for (unsigned k = 0; k < RACCOONG_COEFF_BYTES; ++k) {
        zp[k] = (uint8_t)((q >> (8u * k)) & 0xffu);
    }
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, h3, bad, RACCOONG_SIG_BYTES),
                    0);

    /* (3c) out-of-range h coefficient: encode q_w (= 2048) which is one
     * above the max valid h value. */
    memcpy(bad, kRaccoongSigFixtureSerialized, RACCOONG_SIG_BYTES);
    uint8_t* hp = bad + RACCOONG_C_HASH_BYTES
                + (size_t)RACCOONG_ELL * 256u * RACCOONG_COEFF_BYTES;
    uint64_t qw = RACCOONG_Q_W;
    hp[0] = (uint8_t)(qw & 0xffu);
    hp[1] = (uint8_t)((qw >> 8) & 0xffu);
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, h3, bad, RACCOONG_SIG_BYTES),
                    0);

    /* (4) null-arg guards. */
    out_len = sizeof(out);
    u_assert_int_eq(raccoong_serialize_signature(
                        NULL, &out_len, c_hash, z,
                        (const int16_t (*)[256])h_signed), 0);
    u_assert_int_eq(raccoong_serialize_signature(
                        out, NULL, c_hash, z,
                        (const int16_t (*)[256])h_signed), 0);
    u_assert_int_eq(raccoong_serialize_signature(
                        out, &out_len, NULL, z,
                        (const int16_t (*)[256])h_signed), 0);
    /* Insufficient buffer. */
    out_len = RACCOONG_SIG_BYTES - 1;
    u_assert_int_eq(raccoong_serialize_signature(
                        out, &out_len, c_hash, z,
                        (const int16_t (*)[256])h_signed), 0);

    u_assert_int_eq(raccoong_deserialize_signature(
                        NULL, z3, h3, kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES), 0);
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, NULL, h3, kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES), 0);
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, NULL, kRaccoongSigFixtureSerialized,
                        RACCOONG_SIG_BYTES), 0);
    u_assert_int_eq(raccoong_deserialize_signature(
                        c3, z3, h3, NULL, RACCOONG_SIG_BYTES), 0);
}
