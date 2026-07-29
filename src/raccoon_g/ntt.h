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

#ifndef LIBDOGECOIN_RACCOON_G_NTT_H
#define LIBDOGECOIN_RACCOON_G_NTT_H

#include <dogecoin/dogecoin.h>

#include "polyr.h"

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief Forward / inverse NTT for the Raccoon-G-44 ring R_q = Z_q[X]/(X^n + 1).
 *
 * The twiddle table is generated at init and its SHA-256 must match the value
 * recorded in src/raccoon_g/README.md (filled in Session 4).
 */

/** @brief Initialize NTT (no-op; twiddle table is static). */
dogecoin_bool ntt_init(void);

/** @brief Shut down NTT (no-op). */
void          ntt_shutdown(void);

/** @brief Apply forward NTT transform in-place. */
dogecoin_bool ntt_forward(polyr* r);

/** @brief Apply inverse NTT transform in-place. */
dogecoin_bool ntt_inverse(polyr* r);

/** @brief Pointwise multiplication in NTT domain. */
dogecoin_bool ntt_pointwise(polyr* r, const polyr* a, const polyr* b);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_NTT_H */
