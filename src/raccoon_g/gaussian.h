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

#ifndef LIBDOGECOIN_RACCOON_G_GAUSSIAN_H
#define LIBDOGECOIN_RACCOON_G_GAUSSIAN_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief Rounded Gaussian sampler for Raccoon-G-44.
 *
 * Mirrors `sample_rounded` from upstream `thrc_gauss.py` (Marsaglia polar
 * method) at mpmath/MPFR precision = 256 bits.  The math kernel is exposed
 * here so it can be exercised against a recorded XOF byte stream without
 * pulling SHAKE256 into the libdogecoin build (Sessions 1-5 stay free of
 * additional crypto primitives; the SHAKE256 wrapper that drives the kernel
 * from a 32-byte seed lands in Session 6).
 */

/** @brief Initialize the Gaussian sampler. */
dogecoin_bool gaussian_sampler_init(void);

/** @brief Shut down the Gaussian sampler and free MPFR caches. */
void          gaussian_sampler_shutdown(void);

/*
 * Default sigma^2 exponent used by the seed-driven entry point.  Matches the
 * sigma = 2^20 / sig^2 = 2^40 setting upstream `thrc_gauss.py` uses in its
 * smoke test and that the Session-5 fixture is recorded at.  The threshold
 * core (Session 7) will switch sigma per-call once the sigma_t / sigma_w
 * parameters are wired in.
 */
#define RACCOONG_GAUSS_LG_SIGMA2_DEFAULT 40u

/**
 * @brief Drive the rounded-Gaussian sampler from a pre-extracted XOF byte stream.
 *
 * Produces `n` samples in `out`, returning false if:
 *   - any pointer is NULL;
 *   - sigma^2 = 2^lg_sigma2 cannot be represented as an MPFR value (always
 *     false in practice for lg_sigma2 in [0, 60]);
 *   - the supplied stream is exhausted before `n` accepted samples are
 *     produced (callers should over-provision; 8 KiB is sufficient for n=256
 *     at sigma = 2^20 with the canonical rejection rate).
 *
 * On success, `*xof_consumed_bytes` (if non-NULL) receives the number of
 * stream bytes actually consumed; this lets callers / tests confirm they
 * stayed within the recorded prefix.
 *
 * @param[out] out                 Array to receive n samples.
 * @param[in]  n                   Number of samples (must be even).
 * @param[in]  lg_sigma2           Log base 2 of sigma squared.
 * @param[in]  xof_bytes           Pre-extracted XOF byte stream.
 * @param[in]  xof_len             Length of XOF byte stream.
 * @param[out] xof_consumed_bytes  Optional pointer to receive bytes consumed.
 *
 * @return True on success, false on error or insufficient stream.
 */
dogecoin_bool gaussian_sample_rounded_from_xof(int64_t* out,
                                               size_t n,
                                               uint32_t lg_sigma2,
                                               const uint8_t* xof_bytes,
                                               size_t xof_len,
                                               size_t* xof_consumed_bytes);

/**
 * @brief Public seed-driven entry point at default sigma.
 *
 * Returns false until Session 6 wires the SHAKE256 byte source.  Kept here so
 * the downstream `thrc.c` call sites (Session 6 and 7) can be written against
 * the final shape today.
 *
 * @param[out] out  Array to receive n samples.
 * @param[in]  n    Number of samples (must be even).
 * @param[in]  seed 32-byte seed.
 *
 * @return True on success, false on error.
 */
dogecoin_bool gaussian_sample(int64_t* out, size_t n, const uint8_t seed[32]);

/**
 * @brief Generalized seed-driven entry point with explicit sigma.
 *
 * Accepts an arbitrary-length `seed` (the upstream `sample_rounded(sig2, seed, n)` opens SHAKE256
 * on whatever bytes it is given) and an explicit `lg_sigma2` so callers can hit the sigma_t² = 2^14
 * and sigma_w² = 2^80 settings used by Raccoon-G keygen and sign.  Pre-extracts 8 KiB from SHAKE256(seed)
 * — sufficient for n=256 at the canonical ~21.5% rejection rate (≈ 7.27 bytes/sample); returns false
 * if the kernel exhausts that prefix before n samples are produced.
 *
 * @param[out] out        Array to receive n samples.
 * @param[in]  n          Number of samples (must be even).
 * @param[in]  lg_sigma2  Log base 2 of sigma squared.
 * @param[in]  seed       Arbitrary-length seed bytes.
 * @param[in]  seed_len   Length of seed.
 *
 * @return True on success, false on error.
 */
dogecoin_bool gaussian_sample_seed(int64_t* out, size_t n,
                                   uint32_t lg_sigma2,
                                   const uint8_t* seed, size_t seed_len);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_GAUSSIAN_H */
