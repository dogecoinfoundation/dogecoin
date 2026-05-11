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

#ifndef LIBDOGECOIN_RACCOON_G_POLYR_H
#define LIBDOGECOIN_RACCOON_G_POLYR_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief Z_q polynomial arithmetic for Raccoon-G-44.
 *
 * Parameters are pinned to the upstream p-11/lattice-hd-wallets reference,
 * src/raccoon/thrc-py/polyr.py at commit 461a5ed9b6d57e3bf8c381be3bb79325ab21d906.
 * See src/raccoon_g/README.md for the gate.
 *
 * Wire encoding is intentionally NOT defined at the polyr layer: upstream
 * polyr.py has no serializer either. Bit-packed encoding for keys / signatures
 * lives in higher layers (raccoon_primitives.py upstream; thrc.c here) and
 * lands in Session 6.
 */

#define RACCOONG_N     256                    // ring degree
#define RACCOONG_Q     562949953438721ULL     // 50-bit prime, q = 1 (mod 512)
#define RACCOONG_NI    560750930183101ULL     // n^-1 mod q
#define RACCOONG_LOG_Q 50                     // ceil(log2(q))

/**
 * @brief Transparent struct so that callers (and tests) can allocate on the stack.
 *
 * Transparent struct so that callers (and tests) can allocate on the stack
 * or in arrays of polynomials without paying a heap allocation per coeff
 * vector. polyr_alloc/free are provided for cases where heap is preferred.
 */
typedef struct polyr {
    uint64_t coeffs[RACCOONG_N]; // each in [0, RACCOONG_Q) after normalization
} polyr;

/**
 * @brief Heap helpers.
 *
 * polyr_alloc allocates a zero-initialized polynomial. Returns false on OOM
 * (in which case *out is set to NULL).
 */
dogecoin_bool polyr_alloc(polyr** out);
void          polyr_free(polyr* p);

/** @brief Initialization / equality. */
void          polyr_set_zero(polyr* r);
void          polyr_copy(polyr* r, const polyr* a);
dogecoin_bool polyr_equal(const polyr* a, const polyr* b);

/** @brief Validate that all coefficients lie in [0, RACCOONG_Q). Returns true if so. */
dogecoin_bool polyr_is_normalized(const polyr* a);

/**
 * @brief Modular arithmetic mirroring upstream polyr.py.
 *
 * Modular arithmetic mirroring upstream polyr.py:
 *   polyr_add           <-> poly_add
 *   polyr_sub           <-> poly_sub
 *   polyr_mul_pointwise <-> mul_ntt   (coefficient-wise multiplication, used
 *                                       when both operands are in NTT form)
 *   polyr_scale         <-> poly_scale
 *   polyr_lshift        <-> poly_lshift
 *   polyr_rshift        <-> poly_rshift  (rounding right-shift)
 *
 * All routines accept aliasing of result with operands. They return true on
 * success and false on invalid arguments (e.g., NULL inputs, shift counts
 * out of range).
 */
dogecoin_bool polyr_add(polyr* r, const polyr* a, const polyr* b);
dogecoin_bool polyr_sub(polyr* r, const polyr* a, const polyr* b);
dogecoin_bool polyr_mul_pointwise(polyr* r, const polyr* a, const polyr* b);
dogecoin_bool polyr_scale(polyr* r, uint64_t c, const polyr* a);
dogecoin_bool polyr_lshift(polyr* r, const polyr* a, unsigned shift);
dogecoin_bool polyr_rshift(polyr* r, const polyr* a, unsigned shift);

/**
 * @brief Center: out[i] = ((a[i] + q/2) mod q) - q/2, signed.
 *
 * Center: out[i] = ((a[i] + q/2) mod q) - q/2, signed.
 * The output range is [-q/2, q/2). Output array is signed and lives
 * separately from polyr because callers may need raw int64_t access.
 */
dogecoin_bool polyr_center(int64_t out[RACCOONG_N], const polyr* a);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_POLYR_H */
