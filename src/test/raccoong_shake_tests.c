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
 * SHAKE256 KAT gate.  Three checks:
 *
 *  1. FIPS 202 empty-input answer (32 bytes), the universally-quoted
 *     KAT for SHAKE256(""). Pinned at
 *     `46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f`.
 *  2. SHAKE256("abc", 16 bytes), pinned at `483366601360a8771c6863080cc4114d`.
 *  3. End-to-end agreement against the pycryptodome-recorded byte stream
 *     baked into the Session-5 Gaussian fixture: the first 32 bytes of
 *     `SHAKE256(raccoong_gauss_seed_bytes)` must equal the first 32 bytes
 *     of `raccoong_gauss_xof_bytes`.  This is the tightest tie-in to the
 *     Python reference, and it is exactly the byte stream the seed-driven
 *     gaussian path consumes.
 */

#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include "raccoon_g/shake256.h"
#include "test/data/raccoong_gaussian_vectors.h"

static const uint8_t kat_empty32[32] = {
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
    0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
    0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
};

static const uint8_t kat_abc16[16] = {
    0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
    0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
};

void test_raccoong_shake(void)
{
    uint8_t out[64];

    /* KAT 1: empty input, 32-byte digest. */
    memset(out, 0, sizeof(out));
    shake256(out, 32, NULL, 0);
    u_assert_mem_eq(out, kat_empty32, 32);

    /* KAT 2: "abc", 16-byte digest. */
    memset(out, 0, sizeof(out));
    shake256(out, 16, (const uint8_t*)"abc", 3);
    u_assert_mem_eq(out, kat_abc16, 16);

    /* KAT 3: streaming/one-shot equivalence + first-32 of fixture seed. */
    uint8_t streamed[64];
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, raccoong_gauss_seed_bytes, 32);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, streamed, 32);
    u_assert_mem_eq(streamed, raccoong_gauss_xof_bytes, 32);

    /* One-shot must match the streaming variant byte for byte. */
    uint8_t oneshot[64];
    shake256(oneshot, 32, raccoong_gauss_seed_bytes, 32);
    u_assert_mem_eq(oneshot, streamed, 32);

    /* Squeezing in two pieces equals squeezing in one piece. */
    shake256_init(&ctx);
    shake256_absorb(&ctx, raccoong_gauss_seed_bytes, 32);
    shake256_finalize(&ctx);
    uint8_t piece_a[17], piece_b[15];
    shake256_squeeze(&ctx, piece_a, sizeof(piece_a));
    shake256_squeeze(&ctx, piece_b, sizeof(piece_b));
    uint8_t joined[32];
    memcpy(joined,                   piece_a, sizeof(piece_a));
    memcpy(joined + sizeof(piece_a), piece_b, sizeof(piece_b));
    u_assert_mem_eq(joined, raccoong_gauss_xof_bytes, 32);

    /* Cross-block squeeze (200 bytes spans 2 rate blocks: 136 + 64). */
    shake256_init(&ctx);
    shake256_absorb(&ctx, raccoong_gauss_seed_bytes, 32);
    shake256_finalize(&ctx);
    uint8_t long_out[200];
    shake256_squeeze(&ctx, long_out, sizeof(long_out));
    u_assert_mem_eq(long_out, raccoong_gauss_xof_bytes, sizeof(long_out));

    /* Absorbing in pieces equals absorbing in one shot.  Use a long input
     * that spans two rate blocks (136*2 = 272 bytes) to exercise the wrap. */
    uint8_t big_msg[300];
    for (size_t i = 0; i < sizeof(big_msg); ++i) big_msg[i] = (uint8_t)i;
    uint8_t ref[64];
    shake256(ref, sizeof(ref), big_msg, sizeof(big_msg));

    shake256_init(&ctx);
    shake256_absorb(&ctx, big_msg,        100);
    shake256_absorb(&ctx, big_msg + 100,  150);
    shake256_absorb(&ctx, big_msg + 250,   50);
    shake256_finalize(&ctx);
    uint8_t got[64];
    shake256_squeeze(&ctx, got, sizeof(got));
    u_assert_mem_eq(got, ref, sizeof(ref));

    /* ---- SHAKE128: same KAT discipline at rate 168. -------------------- */

    /* FIPS 202 SHAKE128 empty-input answer (first 32 bytes), pinned at
     * `7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26`. */
    static const uint8_t kat128_empty32[32] = {
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
    };
    /* SHAKE128("abc", 16) pinned at `5881092dd818bf5cf8a3ddb793fbcba7`. */
    static const uint8_t kat128_abc16[16] = {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
    };

    uint8_t out128[64];
    memset(out128, 0, sizeof(out128));
    shake128(out128, 32, NULL, 0);
    u_assert_mem_eq(out128, kat128_empty32, 32);

    memset(out128, 0, sizeof(out128));
    shake128(out128, 16, (const uint8_t*)"abc", 3);
    u_assert_mem_eq(out128, kat128_abc16, 16);

    /* Streaming/one-shot equivalence + cross-rate-block (168+) squeeze. */
    shake128_ctx ctx128;
    shake128_init(&ctx128);
    shake128_absorb(&ctx128, big_msg, sizeof(big_msg));
    shake128_finalize(&ctx128);
    uint8_t long128_a[200];
    shake128_squeeze(&ctx128, long128_a, sizeof(long128_a));

    uint8_t long128_b[200];
    shake128(long128_b, sizeof(long128_b), big_msg, sizeof(big_msg));
    u_assert_mem_eq(long128_a, long128_b, sizeof(long128_a));

    /* Piecewise absorb under SHAKE128 must equal one-shot. */
    shake128_init(&ctx128);
    shake128_absorb(&ctx128, big_msg,        100);
    shake128_absorb(&ctx128, big_msg + 100,  150);
    shake128_absorb(&ctx128, big_msg + 250,   50);
    shake128_finalize(&ctx128);
    uint8_t got128[64];
    shake128_squeeze(&ctx128, got128, sizeof(got128));
    u_assert_mem_eq(got128, long128_b, sizeof(got128));
}
