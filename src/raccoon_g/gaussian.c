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
 * Raccoon-G-44 rounded Gaussian sampler — math kernel.
 *
 * 1:1 port of `sample_rounded` / `unif_real` from upstream
 *   p-11/lattice-hd-wallets@461a5ed9 src/raccoon/thrc-py/thrc_gauss.py
 *
 * Bit-exactness across mpmath@256 and MPFR@256 was checked offline (1000
 * randomly-sampled inputs to log/sqrt at exact 256-bit mantissas, zero
 * mismatches).  The byte-exact gate at runtime is
 * `test/raccoong_gaussian_tests.c::test_raccoong_gaussian` against the
 * recorded fixture in `test/data/raccoong_gaussian_vectors.h`.
 *
 * The seed-driven path (`gaussian_sample`) returns false in this session;
 * SHAKE256 plumbing lands in Session 6 alongside the rest of the upstream
 * XOF construction.
 *
 * SECURITY / SIDE-CHANNEL WARNING -----------------------------------------
 * This sampler intentionally drives MPFR at 256-bit precision so the
 * outputs are byte-exact against the upstream mpmath reference. MPFR is
 * NOT constant-time: it performs data-dependent malloc/free per
 * coefficient, has data-dependent rounding paths and branch counts, and
 * makes no constant-time guarantees. Because this routine consumes the
 * secret seed material used to derive the Raccoon-G-44 secret key
 * polynomials (`s`, `e1`), running it in adversarial-observer environments
 * can leak information about the secret via timing / cache side channels.
 *
 * The Raccoon-G-44 port shipped in this tree is gated as
 * `EXPERIMENTAL_FEATURE` and the README in src/raccoon_g/ documents that
 * the port is "not-for-production until audit". Removing that gate (i.e.
 * flipping Raccoon-G-44 to a production signing path) is BLOCKED on
 * replacing this MPFR-backed sampler with a constant-time integer/fixed
 * point implementation that does not branch or allocate on secret-derived
 * data.
 * -------------------------------------------------------------------------
 */

#include "gaussian.h"
#include "shake256.h"

#include <gmp.h>
#include <mpfr.h>

// mpmath precision in upstream thrc_gauss.py is 256 bits.
#define RACCOONG_GAUSS_PREC 256

// Bytes consumed per polar-method attempt: two 64-bit unif_real reads.
#define RACCOONG_GAUSS_PREC_BITS_PER_SAMPLE 64
#define RACCOONG_GAUSS_BYTES_PER_ATTEMPT \
    ((RACCOONG_GAUSS_PREC_BITS_PER_SAMPLE + 7) / 8 * 2)

/**
 * @brief Initialize the Gaussian sampler.
 *
 * Sets MPFR's default precision so all callers get the right working
 * width without having to thread it through the kernel API. Calling
 * twice is harmless.
 *
 * @return Always returns true.
 */
dogecoin_bool gaussian_sampler_init(void)
{
    mpfr_set_default_prec(RACCOONG_GAUSS_PREC);
    return true;
}

/**
 * @brief Shut down the Gaussian sampler and free MPFR caches.
 */
void gaussian_sampler_shutdown(void)
{
    mpfr_free_cache();
}

/**
 * @brief Read a 64-bit little-endian unsigned integer at `*pos`, advance `*pos`.
 *
 * @param[in]  buf     Buffer to read from.
 * @param[in]  buf_len Length of buffer.
 * @param[in,out] pos  Current position, updated on success.
 * @param[out] out     Receives the 64-bit little-endian value.
 *
 * @return True if 8 bytes were available, false otherwise.
 */
static dogecoin_bool xof_read_u64_le(const uint8_t* buf, size_t buf_len,
                                     size_t* pos, uint64_t* out)
{
    if (*pos + 8 > buf_len) {
        return false;
    }
    uint64_t v = 0;
    for (int k = 0; k < 8; ++k) {
        v |= ((uint64_t)buf[*pos + (size_t)k]) << (8 * k);
    }
    *pos += 8;
    *out = v;
    return true;
}

/**
 * @brief Convert a raw 64-bit unsigned word into a signed mpmath/MPFR value.
 *
 * Maps the raw 64-bit unsigned word to a signed mpmath/MPFR value in
 * [-1, 1 - 2^-63] following upstream `unif_real` with prec=64.
 *
 * @param[out] dst MPFR destination variable.
 * @param[in]  u   64-bit unsigned integer.
 */
static void unif_real_set_from_u64(mpfr_t dst, uint64_t u)
{
    // Two's-complement signed: if u >= 2^63, value -= 2^64.
    int64_t s;
    if (u >= ((uint64_t)1 << 63)) {
        // u - 2^64 fits in int64_t since u >= 2^63.
        s = (int64_t)(u - ((uint64_t)1 << 63)) - (int64_t)((uint64_t)1 << 63);
    } else {
        s = (int64_t)u;
    }
    // upstream: mp_scl = 2^-(prec-1) = 2^-63; result = mp_scl * s.
    mpfr_set_si(dst, (long)s, MPFR_RNDN);
    mpfr_div_2ui(dst, dst, 63, MPFR_RNDN);
}

/**
 * @brief Compute round_half_up: floor(x + 1/2).
 *
 * @param[in]  x       MPFR value to round.
 * @param[out] scratch Scratch MPFR variable.
 *
 * @return The value floor(x + 0.5) as a long.
 */
static long mp_round_half_up_to_long(mpfr_srcptr x, mpfr_t scratch)
{
    // scratch = x + 0.5 ; floor ; cast to long.
    mpfr_set_d(scratch, 0.5, MPFR_RNDN);
    mpfr_add(scratch, x, scratch, MPFR_RNDN);
    mpfr_floor(scratch, scratch);
    /* The samples never approach long range overflow at sigma=2^20
     * (|v| < ~18*sigma). MPFR_RNDD is fine since the value is already
     * an integer at this point. */
    return mpfr_get_si(scratch, MPFR_RNDD);
}

/**
 * @brief Sample rounded Gaussian values from a pre-extracted XOF byte stream.
 *
 * Drive the rounded-Gaussian sampler from a *pre-extracted* XOF byte stream
 * (i.e., the bytes that `SHAKE256(seed).read(xof_len)` would yield in the
 * upstream Python).  Produces `n` samples in `out`, returning false if:
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
                                               size_t* xof_consumed_bytes)
{
    if (!out || !xof_bytes || (n & 1u)) {
        // upstream produces samples in pairs; n must be even.
        return false;
    }

    /* Upstream:
     *   sig' = sqrt(sig^2 - 1/12); cs2 = -2 * sig'^2
     *        = -2 * (sig^2 - 1/12) = 1/6 - 2*sig^2
     */
    mpfr_t cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch;
    mpfr_inits2(RACCOONG_GAUSS_PREC, cs2, sig2_mpfr, sixth, x0, x1,
                s_acc, s_factor, t, scratch, (mpfr_ptr)0);

    // sig2 = 2^lg_sigma2 (exact).
    mpfr_set_ui_2exp(sig2_mpfr, 1, lg_sigma2, MPFR_RNDN);

    // sixth = 1/6 (rounded to 256 bits, matches mpmath fdiv(1,6)).
    mpfr_set_ui(sixth, 1, MPFR_RNDN);
    mpfr_div_ui(sixth, sixth, 6, MPFR_RNDN);

    // cs2 = sixth - ldexp(sig2, 1) = 1/6 - 2*sig2.  ldexp(sig2,1) is exact.
    mpfr_mul_2ui(t, sig2_mpfr, 1, MPFR_RNDN);
    mpfr_sub(cs2, sixth, t, MPFR_RNDN);

    size_t pos = 0;
    size_t i = 0;
    while (i < n) {
        uint64_t u0, u1;
        if (!xof_read_u64_le(xof_bytes, xof_len, &pos, &u0)) {
            goto fail;
        }
        if (!xof_read_u64_le(xof_bytes, xof_len, &pos, &u1)) {
            goto fail;
        }
        unif_real_set_from_u64(x0, u0);
        unif_real_set_from_u64(x1, u1);

        // s_acc = x0^2 + x1^2
        mpfr_sqr(t, x0, MPFR_RNDN);
        mpfr_sqr(s_acc, x1, MPFR_RNDN);
        mpfr_add(s_acc, s_acc, t, MPFR_RNDN);

        // Reject unless 0 < s_acc < 1.
        if (mpfr_sgn(s_acc) <= 0) continue;
        if (mpfr_cmp_ui(s_acc, 1) >= 0) continue;

        // s_factor = sqrt( cs2 * log(s_acc) / s_acc )
        mpfr_log(t, s_acc, MPFR_RNDN);
        mpfr_mul(t, cs2, t, MPFR_RNDN);
        mpfr_div(t, t, s_acc, MPFR_RNDN);
        mpfr_sqrt(s_factor, t, MPFR_RNDN);

        /* v[i]   = round_half_up(s_factor * x0)
         * v[i+1] = round_half_up(s_factor * x1) */
        mpfr_mul(t, s_factor, x0, MPFR_RNDN);
        out[i]     = (int64_t)mp_round_half_up_to_long(t, scratch);
        mpfr_mul(t, s_factor, x1, MPFR_RNDN);
        out[i + 1] = (int64_t)mp_round_half_up_to_long(t, scratch);

        i += 2;
    }

    if (xof_consumed_bytes) *xof_consumed_bytes = pos;

    mpfr_clears(cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch,
                (mpfr_ptr)0);
    return true;

fail:
    mpfr_clears(cs2, sig2_mpfr, sixth, x0, x1, s_acc, s_factor, t, scratch,
                (mpfr_ptr)0);
    return false;
}

/**
 * @brief Seed-driven entry point at default sigma.
 *
 * Drives the kernel from `SHAKE256(seed)` at the default sigma^2 = 2^RACCOONG_GAUSS_LG_SIGMA2_DEFAULT.
 * Byte-exact against the recorded fixture (see test/raccoong_gaussian_tests.c::test_raccoong_gaussian_seed)
 * because SHAKE256 itself is byte-exact against pycryptodome (FIPS 202 empty-input KAT + 8 KiB-of-fixture-seed
 * agreement test).
 *
 * @param[out] out  Array to receive n samples.
 * @param[in]  n    Number of samples (must be even).
 * @param[in]  seed 32-byte seed.
 *
 * @return True on success, false on error.
 */
dogecoin_bool gaussian_sample(int64_t* out, size_t n, const uint8_t seed[32])
{
    if (!out || !seed || (n & 1u)) return false;
    return gaussian_sample_seed(out, n,
                                (uint32_t)RACCOONG_GAUSS_LG_SIGMA2_DEFAULT,
                                seed, 32);
}

/**
 * @brief Generalized seed-driven entry point with explicit sigma.
 *
 * Reads the same 8 KiB SHAKE256(seed) prefix as `gaussian_sample` but accepts an arbitrary-length seed
 * (so the upstream `hdr8(ds, i) + key` 40-byte seeds for keygen / sign work) and an explicit `lg_sigma2`.
 * Byte-exact against the upstream `sample_rounded(1 << lg_sigma2, seed, n=n)` for every gate in 7c-7e.
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
                                   const uint8_t* seed, size_t seed_len)
{
    if (!out || !seed || (n & 1u)) return false;

    uint8_t xof[8192];
    shake256(xof, sizeof(xof), seed, seed_len);

    return gaussian_sample_rounded_from_xof(
        out, n, lg_sigma2,
        xof, sizeof(xof), /*xof_consumed_bytes=*/NULL);
}
