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
 * FIPS 202 Keccak-f[1600] and SHAKE256 — minimal portable C implementation.
 * Self-contained; no dependencies outside <string.h>.  Validated against the
 * FIPS 202 empty-input known answer in test/raccoong_shake_tests.c plus the
 * agreement test against pycryptodome SHAKE256 baked into
 * test/data/raccoong_gaussian_vectors.h (the seed → 8 KiB stream pinned in
 * Session 5).  See test/raccoong_gaussian_tests.c for the seed-driven path.
 *
 * Style: simple straight-line round function; no in-place 24-round unroll
 * macros.  Speed is not a concern (single SHAKE call per Gaussian sampling
 * batch); auditability is.
 */

#include "shake256.h"

#include <string.h>

/* Keccak round constants. */
static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* Rho rotation offsets, indexed by lane number (x + 5*y). */
static const unsigned keccak_rho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

/** @brief 64-bit left rotation. */
static inline uint64_t rotl64(uint64_t x, unsigned n)
{
    return (x << n) | (x >> ((64u - n) & 63u));
}

/** @brief Keccak-f[1600] permutation (24 rounds). */
static void keccak_f1600(uint64_t s[25])
{
    for (int round = 0; round < 24; ++round) {
        uint64_t C[5], D[5], B[25];
        // theta
        for (int x = 0; x < 5; ++x) {
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; ++i) {
            s[i] ^= D[i % 5];
        }
        // rho + pi
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int idx_src = x + 5 * y;
                int idx_dst = y + 5 * ((2 * x + 3 * y) % 5);
                B[idx_dst] = rotl64(s[idx_src], keccak_rho[idx_src]);
            }
        }
        // chi
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                s[x + 5 * y] =
                    B[x + 5 * y] ^
                    ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }
        // iota
        s[0] ^= keccak_rc[round];
    }
}

/** @brief XOR `len` bytes from `data` into the state at byte offset `off`. */
static void absorb_block(uint64_t state[25], const uint8_t* data,
                         size_t off, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        size_t pos = off + i;
        size_t lane = pos >> 3;
        unsigned shift = (unsigned)((pos & 7u) << 3);
        state[lane] ^= ((uint64_t)data[i]) << shift;
    }
}

/** @brief Extract `len` bytes from state at byte offset `off` into `out`. */
static void extract_bytes(const uint64_t state[25], uint8_t* out,
                          size_t off, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        size_t pos = off + i;
        size_t lane = pos >> 3;
        unsigned shift = (unsigned)((pos & 7u) << 3);
        out[i] = (uint8_t)(state[lane] >> shift);
    }
}

/** @brief Initialize SHAKE256 context. */
void shake256_init(shake256_ctx* ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_pos = 0;
    ctx->finalized = 0;
}

/** @brief Absorb data into SHAKE256. */
void shake256_absorb(shake256_ctx* ctx, const uint8_t* data, size_t len)
{
    // Reject misuse: absorbing after finalize is undefined per FIPS 202.
    if (ctx->finalized) return;

    while (len > 0) {
        size_t room = SHAKE256_RATE_BYTES - ctx->buf_pos;
        size_t take = len < room ? len : room;
        absorb_block(ctx->state, data, ctx->buf_pos, take);
        ctx->buf_pos += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == SHAKE256_RATE_BYTES) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

/** @brief Finalize absorption phase of SHAKE256. */
void shake256_finalize(shake256_ctx* ctx)
{
    if (ctx->finalized) return;
    /* SHAKE domain separator 0x1F at first padding byte, 0x80 at last byte
     * of the rate block (the two ends may coincide if buf_pos == rate-1). */
    uint8_t pad_first = 0x1f;
    uint8_t pad_last  = 0x80;
    absorb_block(ctx->state, &pad_first, ctx->buf_pos, 1);
    absorb_block(ctx->state, &pad_last,  SHAKE256_RATE_BYTES - 1, 1);
    keccak_f1600(ctx->state);
    ctx->buf_pos = 0;
    ctx->finalized = 1;
}

/** @brief Squeeze output from SHAKE256. */
void shake256_squeeze(shake256_ctx* ctx, uint8_t* out, size_t len)
{
    if (!ctx->finalized) {
        shake256_finalize(ctx);
    }
    while (len > 0) {
        size_t avail = SHAKE256_RATE_BYTES - ctx->buf_pos;
        size_t take = len < avail ? len : avail;
        extract_bytes(ctx->state, out, ctx->buf_pos, take);
        ctx->buf_pos += take;
        out += take;
        len -= take;
        if (ctx->buf_pos == SHAKE256_RATE_BYTES) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

/** @brief One-shot SHAKE256: hash `in` to `out_len` bytes. */
void shake256(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len)
{
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, in, in_len);
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, out_len);
}

/*
 * SHAKE128: identical structure with rate=168 bytes.  Sharing the same
 * keccak_f1600 / absorb_block / extract_bytes helpers above so changes to
 * the permutation flow through both variants.
 */

/** @brief Initialize SHAKE128 context. */
void shake128_init(shake128_ctx* ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->buf_pos = 0;
    ctx->finalized = 0;
}

/** @brief Absorb data into SHAKE128. */
void shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len)
{
    if (ctx->finalized) return;
    while (len > 0) {
        size_t room = SHAKE128_RATE_BYTES - ctx->buf_pos;
        size_t take = len < room ? len : room;
        absorb_block(ctx->state, data, ctx->buf_pos, take);
        ctx->buf_pos += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == SHAKE128_RATE_BYTES) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

/** @brief Finalize absorption phase of SHAKE128. */
void shake128_finalize(shake128_ctx* ctx)
{
    if (ctx->finalized) return;
    uint8_t pad_first = 0x1f;
    uint8_t pad_last  = 0x80;
    absorb_block(ctx->state, &pad_first, ctx->buf_pos, 1);
    absorb_block(ctx->state, &pad_last,  SHAKE128_RATE_BYTES - 1, 1);
    keccak_f1600(ctx->state);
    ctx->buf_pos = 0;
    ctx->finalized = 1;
}

/** @brief Squeeze output from SHAKE128. */
void shake128_squeeze(shake128_ctx* ctx, uint8_t* out, size_t len)
{
    if (!ctx->finalized) {
        shake128_finalize(ctx);
    }
    while (len > 0) {
        size_t avail = SHAKE128_RATE_BYTES - ctx->buf_pos;
        size_t take = len < avail ? len : avail;
        extract_bytes(ctx->state, out, ctx->buf_pos, take);
        ctx->buf_pos += take;
        out += take;
        len -= take;
        if (ctx->buf_pos == SHAKE128_RATE_BYTES) {
            keccak_f1600(ctx->state);
            ctx->buf_pos = 0;
        }
    }
}

/** @brief One-shot SHAKE128: hash `in` to `out_len` bytes. */
void shake128(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len)
{
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, in, in_len);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, out, out_len);
}
