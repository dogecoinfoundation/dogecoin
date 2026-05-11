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

#ifndef LIBDOGECOIN_RACCOON_G_SHAKE256_H
#define LIBDOGECOIN_RACCOON_G_SHAKE256_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief Minimal FIPS 202 SHAKE256 used by the in-tree Raccoon-G port.
 *
 * Compiled only when USE_RACCOON_G is enabled — libdogecoin's default builds
 * do not need SHAKE / Keccak-f[1600], and we deliberately avoid linking it
 * elsewhere so changes here cannot regress non-PQC code paths.
 *
 * Usage:
 *   shake256_ctx c;
 *   shake256_init(&c);
 *   shake256_absorb(&c, msg, msg_len);
 *   shake256_finalize(&c);
 *   shake256_squeeze(&c, out, out_len);   // may be called repeatedly
 */

#define SHAKE256_RATE_BYTES 136u  // (1600 - 2*256) / 8
#define SHAKE128_RATE_BYTES 168u  // (1600 - 2*128) / 8

/** @brief SHAKE256 context. */
typedef struct {
    uint64_t state[25];      // Keccak state lanes
    size_t   buf_pos;        // bytes absorbed/squeezed into current block
    int      finalized;      // 0 absorbing, 1 squeezing
} shake256_ctx;

/** @brief Initialize SHAKE256 context. */
void shake256_init(shake256_ctx* ctx);

/** @brief Absorb data into SHAKE256 context. */
void shake256_absorb(shake256_ctx* ctx, const uint8_t* data, size_t len);

/** @brief Finalize absorption phase, prepare for squeezing. */
void shake256_finalize(shake256_ctx* ctx);

/** @brief Squeeze output from SHAKE256 context. */
void shake256_squeeze(shake256_ctx* ctx, uint8_t* out, size_t len);

/** @brief One-shot helper: hash `in` to `out_len` bytes. */
void shake256(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len);

/**
 * @brief SHAKE128 — same Keccak-f[1600] permutation, same 0x1f/0x80 SHAKE pad.
 *
 * SHAKE128 — same Keccak-f[1600] permutation, same 0x1f/0x80 SHAKE pad,
 * differing only in the absorption/squeeze rate (168 bytes).  Upstream
 * raccoon-g uses SHAKE128 by default for `_xof_sample_q` at kappa=128
 * (the `ExpandA` rejection sampler), so we expose it alongside SHAKE256.
 */
typedef struct {
    uint64_t state[25];
    size_t   buf_pos;
    int      finalized;
} shake128_ctx;

/** @brief Initialize SHAKE128 context. */
void shake128_init(shake128_ctx* ctx);

/** @brief Absorb data into SHAKE128 context. */
void shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len);

/** @brief Finalize absorption phase, prepare for squeezing. */
void shake128_finalize(shake128_ctx* ctx);

/** @brief Squeeze output from SHAKE128 context. */
void shake128_squeeze(shake128_ctx* ctx, uint8_t* out, size_t len);

/** @brief One-shot helper: hash `in` to `out_len` bytes. */
void shake128(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_SHAKE256_H */
