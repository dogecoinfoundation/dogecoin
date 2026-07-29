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
 * Raccoon-G-44 threshold core — skeleton. Keygen/sign/verify/HD-derive land
 * in Sessions 6-7 and must produce byte-identical output to the upstream
 * Python reference (p-11/lattice-hd-wallets) for the committed KAT seeds.
 */

#include "thrc.h"

#include <string.h>

#include <dogecoin/mem.h>
#include <dogecoin/sha2.h>

#include "gaussian.h"
#include "keygen_kdf.h"
#include "polyr.h"
#include "ntt.h"
#include "shake256.h"

void raccoong_hdr8(uint8_t out[8], char ds,
                   uint8_t b1, uint8_t b2, uint8_t b3,
                   uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7)
{
    out[0] = (uint8_t)ds;
    out[1] = b1; out[2] = b2; out[3] = b3;
    out[4] = b4; out[5] = b5; out[6] = b6; out[7] = b7;
}

void raccoong_hdr24(uint8_t out[8], char ds,
                    uint32_t i, uint32_t j, uint8_t k)
{
// Upstream layout: bytes([ord(ds), k]) + i.to_bytes(3,'little')
//                                      + j.to_bytes(3,'little').
// The 3-byte little-endian fields are the low 3 bytes of i / j.
    out[0] = (uint8_t)ds;
    out[1] = k;
    out[2] = (uint8_t)(i      );
    out[3] = (uint8_t)(i >> 8 );
    out[4] = (uint8_t)(i >> 16);
    out[5] = (uint8_t)(j      );
    out[6] = (uint8_t)(j >> 8 );
    out[7] = (uint8_t)(j >> 16);
}

/**
 * @brief Uniform Z_q rejection sampler.
 *
 * 1:1 port of upstream `ThRc_Core._xof_sample_q` (thrc_core.py) at kappa=128
 * (SHAKE128).  Reads ceil(q_bits/8) = 7 bytes per attempt, masks to q_bits=50
 * bits, accepts if the masked value is in [0, q).  Deterministic given `seed`.
 *
 * @param[out] out Output array receiving RACCOONG_N values, each in [0, RACCOONG_Q).
 * @param[in] seed Seed for deterministic generation.
 * @param[in] seed_len Length of seed in bytes.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_xof_sample_q(uint64_t out[/* RACCOONG_N */],
                                    const uint8_t* seed, size_t seed_len)
{
    if (!out || (!seed && seed_len != 0)) return false;

    // q_bits = RACCOONG_LOG_Q = 50, blen = ceil(50/8) = 7.
    const unsigned blen = (RACCOONG_LOG_Q + 7u) / 8u;             // 7
    const uint64_t mask = (RACCOONG_LOG_Q >= 64)
        ? (uint64_t)~0ULL
        : (((uint64_t)1 << RACCOONG_LOG_Q) - 1ULL);               // 2^50 - 1

    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, seed, seed_len);
    shake128_finalize(&ctx);

    size_t i = 0;
    while (i < RACCOONG_N) {
        uint8_t z[8] = {0};   /* read into low `blen` bytes; high zero */
        shake128_squeeze(&ctx, z, blen);
        uint64_t x = ((uint64_t)z[0]      ) |
                     ((uint64_t)z[1] <<  8) |
                     ((uint64_t)z[2] << 16) |
                     ((uint64_t)z[3] << 24) |
                     ((uint64_t)z[4] << 32) |
                     ((uint64_t)z[5] << 40) |
                     ((uint64_t)z[6] << 48);
        x &= mask;
        if (x < RACCOONG_Q) {
            out[i++] = x;
        }
    }
    return true;
}

/**
 * @brief Challenge-polynomial expansion.
 *
 * Maps the 32-byte challenge digest `c_hash` to a τ-weight ternary
 * polynomial in {-1, 0, +1}^256 (exactly RACCOONG_TAU non-zero
 * coefficients).  Used by both `thrc_sign` and `thrc_verify`.
 *
 * @param[out] out Output polynomial with values in {-1, 0, +1}^256.
 * @param[in] c_hash Challenge digest (32 bytes).
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_chal_poly(int8_t out[256],
                                 const uint8_t c_hash[RACCOONG_C_HASH_BYTES])
{
    if (!out || !c_hash) return false;

    /* Upstream:
     *     mask_n  = n - 1                              # = 0xff for n=256
     *     blen    = (mask_n.bit_length() + 1 + 7) // 8  # = (8+1+7)//8 = 2
     *     xof     = SHAKE256(_hdr8('c', tau) + c_hash)
     *     while wt < tau:
     *         z    = xof.read(blen)
     *         x    = int.from_bytes(z, 'little')
     *         sign = x & 1
     *         idx  = (x >> 1) & mask_n
     *         if c[idx] == 0:
     *             c[idx] = 2*sign - 1
     *             wt    += 1
     */
    memset(out, 0, 256);

    uint8_t hdr[8];
    raccoong_hdr8(hdr, 'c', (uint8_t)RACCOONG_TAU, 0, 0, 0, 0, 0, 0);

    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, hdr, sizeof(hdr));
    shake256_absorb(&ctx, c_hash, RACCOONG_C_HASH_BYTES);
    shake256_finalize(&ctx);

    unsigned wt = 0;
    while (wt < RACCOONG_TAU) {
        uint8_t z[2];
        shake256_squeeze(&ctx, z, sizeof(z));
        unsigned x   = (unsigned)z[0] | ((unsigned)z[1] << 8);
        unsigned sgn = x & 1u;
        unsigned idx = (x >> 1) & 0xffu;       // mask_n = 255 for n=256
        if (out[idx] == 0) {
            out[idx] = (int8_t)((int)(2u * sgn) - 1);   // sgn=1 -> +1, sgn=0 -> -1
            wt++;
        }
    }
    return true;
}

/**
 * @brief Vector hash function.
 *
 * Hashes a domain-separating header, an arbitrary byte string `dat`, and a
 * flat vector `v` of Z_q coefficients to a `RACCOONG_C_HASH_BYTES` (32-byte)
 * digest.  Mirrors `ThRc_Core._hash_vec(dat, vec, ds)` for Raccoon-G-44
 * (q_byt = 7), where nested vectors of polynomials are flattened before
 * being fed in.
 *
 * @param[out] out Output hash (32 bytes).
 * @param[in] ds Domain separator byte.
 * @param[in] dat Arbitrary byte string.
 * @param[in] dat_len Length of dat in bytes.
 * @param[in] v Vector of Z_q coefficients.
 * @param[in] v_len Number of coefficients in v.
 * @return true on success, false on invalid parameters.
 */
dogecoin_bool raccoong_hash_vec(uint8_t out[RACCOONG_C_HASH_BYTES],
                                char ds,
                                const uint8_t* dat, size_t dat_len,
                                const uint64_t* v, size_t v_len)
{
    if (!out) return false;
    if (dat_len != 0 && !dat) return false;
    if (v_len != 0 && !v) return false;

    /* Upstream:
     *   q_byt = (q_bits + 7) // 8                      # = 7 for Raccoon-G
     *   xof   = SHAKE256(_hdr24(ds, len(dat), q_byt * len(v)) + dat)
     *   for x in v: xof.update((x % q).to_bytes(q_byt, 'little'))
     *   return xof.read(crh)                            # 32 bytes
     *
     * The `_hdr24` "i" and "j" fields are 3-byte little-endian, so the
     * primitive only supports dat_len < 2^24 and v_len < 2^24 / 7 ≈ 2.4M
     * — well above any Raccoon-G-44 call site (largest is k*n = 2304).
     */
    const unsigned q_byt = (RACCOONG_LOG_Q + 7u) / 8u;     /* 7 */
    if (dat_len > 0xFFFFFFu) return false;
    if (v_len   > 0xFFFFFFu / q_byt) return false;

    uint8_t hdr[8];
    raccoong_hdr24(hdr, ds,
                   (uint32_t)dat_len,
                   (uint32_t)(q_byt * v_len),
                   0);

    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, hdr, sizeof(hdr));
    if (dat_len > 0) {
        shake256_absorb(&ctx, dat, dat_len);
    }
    for (size_t i = 0; i < v_len; ++i) {
        // `x % q` (Python semantics): for unsigned uint64 < 2^63 we can
        // use a plain C `%`, which matches because both operands are
        // non-negative.  Callers feeding centered representatives must
        // reduce them to [0,q) beforehand.
        uint64_t x = v[i] % RACCOONG_Q;
        uint8_t le[8] = {0};                              // q_byt <= 7
        le[0] = (uint8_t)(x      );
        le[1] = (uint8_t)(x >>  8);
        le[2] = (uint8_t)(x >> 16);
        le[3] = (uint8_t)(x >> 24);
        le[4] = (uint8_t)(x >> 32);
        le[5] = (uint8_t)(x >> 40);
        le[6] = (uint8_t)(x >> 48);
        shake256_absorb(&ctx, le, q_byt);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
    return true;
}

/**
 * @brief BUFF transcript hash.
 *
 * Computes tr = H(vk) where `vk` is the canonical serialized public key.
 * This is the first stage of the BUFF (Binding Unforgeability Framework)
 * input computation.
 *
 * @param[out] out Output transcript hash (32 bytes).
 * @param[in] pk Serialized public key bytes.
 * @param[in] pk_len Length of pk in bytes.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_pk_hash(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t* pk, size_t pk_len)
{
    if (!out) return false;
    if (pk_len != 0 && !pk) return false;

    // Upstream: tr = SHAKE256(vk_bytes).read(crh).
    shake256_ctx ctx;
    shake256_init(&ctx);
    if (pk_len > 0) {
        shake256_absorb(&ctx, pk, pk_len);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
    return true;
}

/**
 * @brief BUFF message digest.
 *
 * Computes mu = H(tr || msg), the second stage of the BUFF input computation.
 *
 * @param[out] out Output message digest (32 bytes).
 * @param[in] tr Transcript hash from raccoong_pk_hash (32 bytes).
 * @param[in] msg Message bytes.
 * @param[in] msg_len Length of msg in bytes.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_buff_mu(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t tr[RACCOONG_C_HASH_BYTES],
                               const uint8_t* msg, size_t msg_len)
{
    if (!out || !tr) return false;
    if (msg_len != 0 && !msg) return false;

    // Upstream: mu = SHAKE256(tr || msg).read(mu_sz = crh).
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, tr, RACCOONG_C_HASH_BYTES);
    if (msg_len > 0) {
        shake256_absorb(&ctx, msg, msg_len);
    }
    shake256_finalize(&ctx);
    shake256_squeeze(&ctx, out, RACCOONG_C_HASH_BYTES);
    return true;
}

/**
 * @brief Fill the public matrix A from A_seed.
 *
 * 1:1 port of upstream `ThRc_Core._expand_a`: for each (i, j) the entry is
 * `_xof_sample_q(_hdr8('A', i, j) + A_seed)`.  Upstream treats this matrix
 * as already living in NTT domain (uniform random in either basis), so the
 * output is consumable directly by `raccoong_mul_mat_vec_ntt`.
 *
 * @param[out] A Output k×ell matrix in NTT domain.
 * @param[in] A_seed Public matrix seed (16 bytes).
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_expand_a(polyr A[RACCOONG_K][RACCOONG_ELL],
                                const uint8_t A_seed[RACCOONG_A_SEED_BYTES])
{
    if (!A || !A_seed) return false;

    // Upstream: a[i][j] = _xof_sample_q(_hdr8('A', i, j) + A_seed).
    uint8_t buf[8 + RACCOONG_A_SEED_BYTES];
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
            raccoong_hdr8(buf, 'A',
                          (uint8_t)i, (uint8_t)j, 0, 0, 0, 0, 0);
            memcpy(buf + 8, A_seed, RACCOONG_A_SEED_BYTES);
            if (!raccoong_xof_sample_q(A[i][j].coeffs, buf, sizeof(buf))) {
                return false;
            }
        }
    }
    return true;
}

/**
 * @brief In-place forward NTT on vector of polynomials.
 *
 * @param[in,out] v Vector of polynomials to transform.
 * @param[in] n Number of polynomials in vector.
 * @return true on success, false on null input.
 */
dogecoin_bool raccoong_vec_ntt(polyr* v, size_t n)
{
    if (!v) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!ntt_forward(&v[i])) return false;
    }
    return true;
}

/**
 * @brief In-place inverse NTT on vector of polynomials.
 *
 * @param[in,out] v Vector of polynomials to transform.
 * @param[in] n Number of polynomials in vector.
 * @return true on success, false on null input.
 */
dogecoin_bool raccoong_vec_intt(polyr* v, size_t n)
{
    if (!v) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!ntt_inverse(&v[i])) return false;
    }
    return true;
}

/**
 * @brief Element-wise addition of polynomial vectors.
 *
 * @param[out] r Output vector r = a + b mod q.
 * @param[in] a First input vector.
 * @param[in] b Second input vector.
 * @param[in] n Number of polynomials in vectors.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_vec_add(polyr* r, const polyr* a, const polyr* b,
                               size_t n)
{
    if (!r || !a || !b) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!polyr_add(&r[i], &a[i], &b[i])) return false;
    }
    return true;
}

/**
 * @brief Right-shift of polynomial vector coefficients.
 *
 * @param[out] r Output vector with coefficients right-shifted.
 * @param[in] a Input vector.
 * @param[in] shift Number of bits to right-shift.
 * @param[in] n Number of polynomials in vectors.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_vec_rshift(polyr* r, const polyr* a, unsigned shift,
                                  size_t n)
{
    if (!r || !a) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!polyr_rshift(&r[i], &a[i], shift)) return false;
    }
    return true;
}

/**
 * @brief Matrix-vector multiplication in NTT domain.
 *
 * Computes out[i] = sum_j A[i][j] *_ntt v[j] for i in [0, k), j in [0, ell).
 * Inputs must already be in NTT domain. Output is in NTT domain.
 *
 * @param[out] out Output k-vector in NTT domain.
 * @param[in] A k×ell matrix in NTT domain.
 * @param[in] v ell-vector in NTT domain.
 * @return true on success, false on null inputs.
 */
dogecoin_bool raccoong_mul_mat_vec_ntt(polyr out[RACCOONG_K],
                                       const polyr A[RACCOONG_K][RACCOONG_ELL],
                                       const polyr v[RACCOONG_ELL])
{
    if (!out || !A || !v) return false;

    // Upstream:
    //     for i in range(k):
    //         for j in range(ell):
    //             r[i] = poly_add(r[i], mul_ntt(m[i][j], v[j]))
    // `mul_ntt` is coefficient-wise (NTT-domain) multiplication.
    polyr tmp;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        polyr_set_zero(&out[i]);
        for (unsigned j = 0; j < RACCOONG_ELL; ++j) {
            if (!polyr_mul_pointwise(&tmp, &A[i][j], &v[j])) return false;
            if (!polyr_add(&out[i], &out[i], &tmp)) return false;
        }
    }
    return true;
}

/* Reduce a signed int64_t array to a polyr in [0, RACCOONG_Q). */
static void polyr_load_signed(polyr* dst, const int64_t* src)
{
    const int64_t Q = (int64_t)RACCOONG_Q;
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        int64_t v = src[i] % Q;
        if (v < 0) v += Q;
        dst->coeffs[i] = (uint64_t)v;
    }
}

static dogecoin_bool keygen_t_unrounded_inner(const uint8_t key[32],
                                              const uint8_t A_seed_in[RACCOONG_A_SEED_BYTES],
                                              polyr t_out[RACCOONG_K],
                                              polyr s_out[RACCOONG_ELL])
{
    dogecoin_bool ok = false;

    // --- 1b. A = ExpandA(A_seed)  (already in NTT domain). ---
    static polyr A[RACCOONG_K][RACCOONG_ELL];
    if (!raccoong_expand_a(A, A_seed_in)) goto cleanup;

    // --- 2. s ~ D_t^ell, e1 ~ D_t^k via sample_rounded(2^14, hdr8 + key).
    static polyr s_poly[RACCOONG_ELL];
    static polyr e1_poly[RACCOONG_K];
    int64_t sample_buf[RACCOONG_N];

    uint8_t seed_buf[8 + 32];
    memcpy(seed_buf + 8, key, 32);

    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        raccoong_hdr8(seed_buf, 's', (uint8_t)i, 0, 0, 0, 0, 0, 0);
        if (!gaussian_sample_seed(sample_buf, RACCOONG_N,
                                  RACCOONG_LG_SIGMA_T2,
                                  seed_buf, sizeof(seed_buf))) {
            goto cleanup_locals;
        }
        polyr_load_signed(&s_poly[i], sample_buf);
    }
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        raccoong_hdr8(seed_buf, 'e', (uint8_t)i, 1, 0, 0, 0, 0, 0);
        if (!gaussian_sample_seed(sample_buf, RACCOONG_N,
                                  RACCOONG_LG_SIGMA_T2,
                                  seed_buf, sizeof(seed_buf))) {
            goto cleanup_locals;
        }
        polyr_load_signed(&e1_poly[i], sample_buf);
    }

    // Capture s in caller's signed-secret slot before we forward-NTT it.
    if (s_out) {
        for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
            polyr_copy(&s_out[i], &s_poly[i]);
        }
    }

    // --- 3. t := A * s + e1   (no rshift). ---
    static polyr s_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        polyr_copy(&s_ntt[i], &s_poly[i]);
    }
    if (!raccoong_vec_ntt(s_ntt, RACCOONG_ELL)) goto cleanup_with_sntt;

    static polyr t_ntt[RACCOONG_K];
    if (!raccoong_mul_mat_vec_ntt(t_ntt,
                                  (const polyr (*)[RACCOONG_ELL])A,
                                  s_ntt)) goto cleanup_with_sntt;

    if (!raccoong_vec_intt(t_ntt, RACCOONG_K)) goto cleanup_with_sntt;

    ok = raccoong_vec_add(t_out, t_ntt, e1_poly, RACCOONG_K);

cleanup_with_sntt:
    dogecoin_mem_zero(s_ntt, sizeof(s_ntt));
    dogecoin_mem_zero(t_ntt, sizeof(t_ntt));
cleanup_locals:
    dogecoin_mem_zero(sample_buf, sizeof(sample_buf));
    dogecoin_mem_zero(seed_buf, sizeof(seed_buf));
cleanup:
    // Wipe secret-derived BSS slots. A depends only on the public A_seed and
    // is left intact. s_poly, e1_poly, s_ntt and t_ntt (the pre-addition
    // intermediate A·s, which together with the public t reveals e1) are all
    // secret-derived and must be cleared.
    dogecoin_mem_zero(s_poly, sizeof(s_poly));
    dogecoin_mem_zero(e1_poly, sizeof(e1_poly));
    return ok;
}

/**
 * @brief Generate unrounded keygen parameters from a seed.
 *
 * Byte-exact port of upstream `raccoon_primitives._keygen_unrounded`.  Emits:
 *   - `A_seed_out` (16 bytes)        = SHAKE256(_hdr8('A') + key, 16)
 *   - `t_out[k]`  (k polyrs in [0,q)) = vec_intt(A_ntt * vec_ntt(s)) + e1
 *
 * No rshift / nu_t rounding is applied — the unrounded shape is the canonical
 * HD-wallet variant (preserves additive linearity for non-hardened child
 * derivation).
 *
 * @param[in] key 32-byte generation key.
 * @param[out] A_seed_out Public matrix seed (16 bytes).
 * @param[out] t_out k polynomials (public component).
 * @param[out] s_out ell polynomials (secret component, can be NULL).
 * @return true on success, false on null inputs or crypto failures.
 */
dogecoin_bool raccoong_keygen_t_unrounded(const uint8_t key[32],
                                          uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                          polyr t_out[RACCOONG_K],
                                          polyr s_out[RACCOONG_ELL])
{
    if (!key || !A_seed_out || !t_out) return false;

    /* --- 1. A_seed = SHAKE256(_hdr8('A') + key, 16) --- */
    uint8_t hdr_in[8 + 32];
    raccoong_hdr8(hdr_in, 'A', 0, 0, 0, 0, 0, 0, 0);
    memcpy(hdr_in + 8, key, 32);
    shake256(A_seed_out, RACCOONG_A_SEED_BYTES, hdr_in, sizeof(hdr_in));

    return keygen_t_unrounded_inner(key, A_seed_out, t_out, s_out);
}

/**
 * @brief Tweak variant of keygen reusing parent's A_seed.
 *
 * Mirrors upstream `generate_tweak_keypair_from_seed`'s middle section
 * (after the DRBG key is drawn): A_ntt = expand(parent_A_seed);
 * s/e1 ~ sample_rounded(...+key); t = A*s + e1 (unrounded).
 *
 * @param[in] key 32-byte generation key.
 * @param[in] A_seed_in Parent's public matrix seed.
 * @param[out] t_out k polynomials.
 * @param[out] s_out ell polynomials (secret component).
 * @return true on success, false on invalid inputs.
 */
static dogecoin_bool raccoong_keygen_t_with_aseed(const uint8_t key[32],
                                                  const uint8_t A_seed_in[RACCOONG_A_SEED_BYTES],
                                                  polyr t_out[RACCOONG_K],
                                                  polyr s_out[RACCOONG_ELL])
{
    if (!key || !A_seed_in || !t_out) return false;
    return keygen_t_unrounded_inner(key, A_seed_in, t_out, s_out);
}

/**
 * @brief Generate master keypair from seed.
 *
 * Generates a Raccoon-G-44 keypair from a 32-byte seed using the upstream
 * `generate_keypair_from_seed` algorithm: HKDF derivation, DRBG instantiation,
 * and byte-exact keygen.
 *
 * @param[in] seed 32-byte seed.
 * @param[out] pk_out Public key buffer (must be RACCOONG_PK_BYTES).
 * @param[in] pk_len Length of pk_out buffer.
 * @param[out] sk_out Secret key buffer (must be RACCOONG_SK_BYTES).
 * @param[in] sk_len Length of sk_out buffer.
 * @return true on success, false on parameter validation failure.
 */
dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len);

/* Forward decls for HD-derive helpers. */
static dogecoin_bool deserialize_poly_le7(polyr* dst, const uint8_t* src);
static dogecoin_bool deserialize_pk_into(const uint8_t* pk, size_t pk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K]);
static dogecoin_bool deserialize_sk_into(const uint8_t* sk, size_t sk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K],
                                         polyr s_out[RACCOONG_ELL]);
static dogecoin_bool hd_derive_tweak_seed(uint8_t tweak_seed_out[32],
                                          const uint8_t* parent_pk, size_t parent_pk_len,
                                          const uint8_t* parent_sk, size_t parent_sk_len,
                                          const uint8_t chaincode[32],
                                          uint32_t index, dogecoin_bool hardened);

    // Pack one polyr (already in [0, q)) as 256 little-endian 7-byte coeffs.
static void serialize_poly_le7(uint8_t* dst, const polyr* p)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t c = p->coeffs[i]; // normalized [0, q), q < 2^50
        dst[0] = (uint8_t)(c);
        dst[1] = (uint8_t)(c >> 8);
        dst[2] = (uint8_t)(c >> 16);
        dst[3] = (uint8_t)(c >> 24);
        dst[4] = (uint8_t)(c >> 32);
        dst[5] = (uint8_t)(c >> 40);
        dst[6] = (uint8_t)(c >> 48);
        dst += RACCOONG_COEFF_BYTES;
    }
}

void raccoong_serialize_pk(uint8_t pk_out[/*RACCOONG_PK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K])
{
    memcpy(pk_out, A_seed, RACCOONG_A_SEED_BYTES);
    uint8_t* p = pk_out + RACCOONG_A_SEED_BYTES;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        serialize_poly_le7(p, &t[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
}

void raccoong_serialize_sk(uint8_t sk_out[/*RACCOONG_SK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K],
                           const polyr s[RACCOONG_ELL])
{
    raccoong_serialize_pk(sk_out, A_seed, t);
    uint8_t* p = sk_out + RACCOONG_PK_BYTES;
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        serialize_poly_le7(p, &s[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
}

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len)
{
    if (!seed || !pk_out || !sk_out) return false;
    if (pk_len != RACCOONG_PK_BYTES) return false;
    if (sk_len != RACCOONG_SK_BYTES) return false;

    // Upstream `generate_keypair_from_seed`:
    //     drbg_seed = HKDF(seed, 48, salt=None, hashmod=SHA256)
    //     drbg = NIST_KAT_DRBG(drbg_seed)
    //     key  = drbg.random_bytes(32)
    //     (vk, s) = _keygen_unrounded(raccoon, key)
    //     return serialize_public_key(vk), serialize_signing_key((vk, s))
    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              seed, 32,
                              /*salt=*/NULL, 0,
                              /*info=*/NULL, 0)) {
        return false;
    }

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    dogecoin_mem_zero(drbg_seed, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    dogecoin_mem_zero(&drbg, sizeof(drbg));

    uint8_t A_seed[RACCOONG_A_SEED_BYTES];
    static polyr t_vec[RACCOONG_K];
    static polyr s_vec[RACCOONG_ELL];

    if (!raccoong_keygen_t_unrounded(key, A_seed, t_vec, s_vec)) {
        dogecoin_mem_zero(key, sizeof(key));
        dogecoin_mem_zero(s_vec, sizeof(s_vec));
        return false;
    }
    dogecoin_mem_zero(key, sizeof(key));

    raccoong_serialize_pk(pk_out, A_seed, t_vec);
    raccoong_serialize_sk(sk_out, A_seed, t_vec, s_vec);

    // Wipe the secret share; the caller now owns sk_out.
    dogecoin_mem_zero(s_vec, sizeof(s_vec));
    return true;
}

/**
 * @brief Serialize Raccoon-G signature.
 *
 * Pack a Raccoon-G signature tuple `(c_hash, z, h)` into RACCOONG_SIG_BYTES
 * of canonical little-endian bytes.
 *
 * @param[out] sig_out Output signature buffer.
 * @param[in,out] sig_len_inout On input: buffer size; on output: bytes written.
 * @param[in] c_hash Challenge digest (32 bytes).
 * @param[in] z ell polynomials in [0, q).
 * @param[in] h_signed k polynomials of centered hint coefficients in [-q_w/2, q_w/2).
 * @return true on success, false on invalid parameters or out-of-range coefficients.
 */
dogecoin_bool raccoong_serialize_signature(
    uint8_t* sig_out, size_t* sig_len_inout,
    const uint8_t c_hash[RACCOONG_C_HASH_BYTES],
    const polyr z[RACCOONG_ELL],
    const int16_t h_signed[RACCOONG_K][256])
{
    if (!sig_out || !sig_len_inout || !c_hash || !z || !h_signed) {
        return false;
    }
    if (*sig_len_inout < RACCOONG_SIG_BYTES) {
        return false;
    }

    // Reject malformed z up front so we never write a partial signature.
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            if (z[i].coeffs[j] >= RACCOONG_Q) {
                return false;
            }
        }
    }

    memcpy(sig_out, c_hash, RACCOONG_C_HASH_BYTES);
    uint8_t* p = sig_out + RACCOONG_C_HASH_BYTES;

    // z block: ell * n * 7 bytes, little-endian, value already in [0, q).
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        serialize_poly_le7(p, &z[i]);
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }

    // h block: k * n * 2 bytes. Upstream encodes (coeff % q_w) so a signed
    // coefficient and its (coeff + q_w) representative produce the same
    // wire bytes; we just reduce into [0, q_w) here. q_w == 2048 fits in
    // a 16-bit int with room to spare so the modular add never overflows.
    const uint64_t qw = RACCOONG_Q_W;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            int32_t v = (int32_t)h_signed[i][j];
            uint64_t u = (uint64_t)((int64_t)v % (int64_t)qw);
            // C99 % can return negative for negative v; normalize.
            if ((int64_t)u < 0) {
                u = (uint64_t)((int64_t)u + (int64_t)qw);
            }
            p[0] = (uint8_t)(u & 0xffu);
            p[1] = (uint8_t)((u >> 8) & 0xffu);
            p += RACCOONG_H_COEFF_BYTES;
        }
    }

    *sig_len_inout = RACCOONG_SIG_BYTES;
    return true;
}

/**
 * @brief Deserialize Raccoon-G signature.
 *
 * Unpack a canonical Raccoon-G signature. Mirrors upstream `deserialize_signature`:
 * validates that z coefficients are in [0, q) and h coefficients are in [0, q_w),
 * then centers h to [-q_w/2, q_w/2).
 *
 * @param[out] c_hash_out Challenge digest (32 bytes).
 * @param[out] z_out ell polynomials (output).
 * @param[out] h_signed_out k polynomials of centered h values.
 * @param[in] sig Canonical signature bytes.
 * @param[in] sig_len Length of sig (must equal RACCOONG_SIG_BYTES).
 * @return true on success, false on invalid parameters or out-of-range coefficients.
 */
dogecoin_bool raccoong_deserialize_signature(
    uint8_t c_hash_out[RACCOONG_C_HASH_BYTES],
    polyr z_out[RACCOONG_ELL],
    int16_t h_signed_out[RACCOONG_K][256],
    const uint8_t* sig, size_t sig_len)
{
    if (!c_hash_out || !z_out || !h_signed_out || !sig) {
        return false;
    }
    if (sig_len != RACCOONG_SIG_BYTES) {
        return false;
    }

    memcpy(c_hash_out, sig, RACCOONG_C_HASH_BYTES);
    const uint8_t* p = sig + RACCOONG_C_HASH_BYTES;

    // z block: 7-byte LE, must be < q.
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!deserialize_poly_le7(&z_out[i], p)) {
            return false;
        }
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }

    // h block: 2-byte LE in [0, q_w), centered to [-q_w/2, q_w/2).
    const uint64_t qw = RACCOONG_Q_W;
    const int32_t half_qw = (int32_t)(qw >> 1);
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            uint32_t u = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
            if ((uint64_t)u >= qw) {
                return false;
            }
            int32_t centered = (int32_t)u;
            if (centered > half_qw) {
                centered -= (int32_t)qw;
            }
            h_signed_out[i][j] = (int16_t)centered;
            p += RACCOONG_H_COEFF_BYTES;
        }
    }
    return true;
}

/* ------------------------------------------------------------------
 *  Algorithm 2 (Sign) / Algorithm 3 (Verify) for Raccoon-G-44
 *
 *  1:1 ports of upstream `ThRc_Core.plain_sign` / `verify` (thrc_core.py).
 *  All polynomials live in static storage so the working set stays off
 *  the stack (~165 KB for the matrix A alone); this mirrors the existing
 *  `raccoong_keygen_t_unrounded` style and is not thread safe.
 *
 *  Secret residue: the static buffers used by `thrc_sign_internal` (r_vec,
 *  e2_vec, r_ntt, s_ntt, z_ntt, z_vec, w_vec, and the local challenge poly
 *  c / c_ntt) are explicitly zeroized on every exit path via the `cleanup:`
 *  label so that no secret-derived material persists in BSS between calls
 *  (e.g. across a process-crash core dump or a /proc/<pid>/mem read). The
 *  verify path's static buffers are derived from public inputs only and do
 *  not require wiping.
 *
 *  Known limitation: the Marsaglia-polar Gaussian sampler reached via
 *  `sample_w_gaussian` uses MPFR mpfr_log/mpfr_sqrt in a secret-dependent
 *  rejection loop, so sign time is not constant in the seed bits. Replacing
 *  that sampler is a deliberate follow-up because it would invalidate every
 *  byte-exact KAT in test/raccoong_*; the KAT fixtures must be regenerated
 *  together with the sampler swap.
 * ------------------------------------------------------------------ */

#include <math.h>
#include <dogecoin/random.h>

/* B2_z bound for kappa=128, max_derivation_depth=1000 (upstream
 * `_compute_b2_bound`).  Computed at first use; the formula is purely
 * deterministic so any caller observes the same value. */
static double raccoong_b2_bound(void)
{
    static int initialized = 0;
    static double b2;
    if (!initialized) {
        const double sqrt_depth = sqrt(1000.0);
        const double sigma_t    = ldexp(1.0, RACCOONG_LG_ST);   /* 2^7  */
        const double sigma_w    = ldexp(1.0, RACCOONG_LG_SWT);  /* 2^40 */
        const double n_kp_ell   = (double)RACCOONG_N *
                                  (double)(RACCOONG_K + RACCOONG_ELL);
        const double n_k        = (double)RACCOONG_N * (double)RACCOONG_K;
        const double term1      = exp(0.25) *
            ((double)RACCOONG_TAU * sigma_t * sqrt_depth + sigma_w) *
            sqrt(n_kp_ell);
        const double term2      =
            ((double)RACCOONG_TAU * ldexp(1.0, RACCOONG_NU_T) +
             ldexp(1.0, RACCOONG_NU_W + 1u)) *
            sqrt(n_k);
        b2 = term1 + term2;
        initialized = 1;
    }
    return b2;
}

// Round-half-up shift to the q_w domain: out[i] = ((x + 2^(nu-1)) >> nu) % q_w.
static void rshift_to_qw(uint16_t out[RACCOONG_N], const polyr* in)
{
    const uint64_t mid = (uint64_t)1 << (RACCOONG_NU_W - 1u);
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t v = (in->coeffs[i] + mid) >> RACCOONG_NU_W;
        out[i] = (uint16_t)(v % (uint64_t)RACCOONG_Q_W);
    }
}

// Centered representative in [-q/2, q/2] of an unsigned coefficient mod q.
static int64_t center_q(uint64_t x)
{
    int64_t v = (int64_t)x;
    const int64_t Q = (int64_t)RACCOONG_Q;
    const int64_t half = Q >> 1;
    if (v > half) v -= Q;
    return v;
}

// Centered representative in [-q_w/2, q_w/2) of an unsigned coefficient mod q_w.
static int32_t center_qw(uint16_t x)
{
    int32_t v = (int32_t)x;
    const int32_t Qw = (int32_t)RACCOONG_Q_W;
    const int32_t half = Qw >> 1;
    if (v > half) v -= Qw;
    return v;
}

// `_check_bounds(z, h)` from upstream: ||(z, 2^nu_w · h)||_2 <= B2_z.
static dogecoin_bool check_bounds(const polyr z[RACCOONG_ELL],
                                  const uint16_t h[RACCOONG_K][RACCOONG_N])
{
    double s2z = 0.0;
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            const double v = (double)center_q(z[i].coeffs[j]);
            s2z += v * v;
        }
    }
    double s2h = 0.0;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            const double v = (double)center_qw(h[i][j]);
            s2h += v * v;
        }
    }
    // sum + (2^nu_w)^2 · s2h, then sqrt and compare to B2.
    const double n2 = sqrt(s2z + ldexp(s2h, 2 * RACCOONG_NU_W));
    return (n2 <= raccoong_b2_bound()) ? true : false;
}

// HD-wallet sign/verify (upstream `_sign_with_unrounded_public_key`):
//
// Replace `lshift(t, nu_t)` with `lshift(round(t, nu_t), nu_t)`, i.e.
//   t̂ = (t + 2^(nu_t-1)) >> nu_t  (mod q_t),  then  t̂ << nu_t  (mod q).
//
// Since q_t = q >> nu_t = 16383 < 2^14 and nu_t = 35, the lshifted value is
// < 2^49 < q, so no further mod-q reduction is needed after the shift.
static void round_and_lshift_nu_t(polyr* dst, const polyr* src)
{
    const uint64_t mid = (uint64_t)1 << (RACCOONG_NU_T - 1u);
    const uint64_t q_t = (uint64_t)RACCOONG_Q >> RACCOONG_NU_T; /* 16383 */
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t rounded = ((src->coeffs[i] + mid) >> RACCOONG_NU_T) % q_t;
        dst->coeffs[i] = rounded << RACCOONG_NU_T;
    }
}

// Sample r_i (i in [0, ell)) or e2_i (i in [0, k)) via gaussian_sample_seed
// at sigma_w^2 = 2^80, then reduce mod q into polyr storage.
static dogecoin_bool sample_w_gaussian(polyr* dst, char ds,
                                       uint8_t idx, uint8_t b2,
                                       const uint8_t key[32])
{
    uint8_t seed_buf[8 + 32];
    raccoong_hdr8(seed_buf, ds, idx, b2, 0, 0, 0, 0, 0);
    memcpy(seed_buf + 8, key, 32);
    int64_t sample_buf[RACCOONG_N];
    if (!gaussian_sample_seed(sample_buf, RACCOONG_N,
                              RACCOONG_LG_SIGMA_W2,
                              seed_buf, sizeof(seed_buf))) {
        memset(seed_buf, 0, sizeof(seed_buf));
        return false;
    }
    memset(seed_buf, 0, sizeof(seed_buf));
    polyr_load_signed(dst, sample_buf);
    memset(sample_buf, 0, sizeof(sample_buf));
    return true;
}

// Encode an `int8_t` challenge polynomial (values in {-1, 0, +1}^N) as a
// polyr in [0, q): -1 maps to q-1.
static void chal_to_polyr(polyr* dst, const int8_t c[RACCOONG_N])
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        int v = c[i];
        if (v < 0) {
            dst->coeffs[i] = (uint64_t)((int64_t)RACCOONG_Q + (int64_t)v);
        } else {
            dst->coeffs[i] = (uint64_t)v;
        }
    }
}

// Flatten a `uint16_t v[K][N]` (q_w domain) into a `uint64_t[K*N]` for
// `raccoong_hash_vec`.  Coefficients in [0, q_w) are already < q so the
// 7-byte LE encoding agrees with `int(x % q).to_bytes(7, 'little')`.
static void qw_vec_to_u64(uint64_t out[RACCOONG_K * RACCOONG_N],
                          const uint16_t v[RACCOONG_K][RACCOONG_N])
{
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            out[i * RACCOONG_N + j] = (uint64_t)v[i][j];
        }
    }
}

/**
 * @brief Internal threshold signature generation.
 *
 * Core Algorithm 2 (Sign) implementation for Raccoon-G-44. A 1:1 port of
 * upstream `ThRc_Core.plain_sign` (thrc_core.py). Generates the signature
 * components (c_hash, z, h) given the key material and message digest.
 *
 * @param[out] c_hash_out Challenge digest.
 * @param[out] z_out ell-vector signature component.
 * @param[out] h_signed_out k-vector hint component (centered).
 * @param[in] A_seed Public matrix seed.
 * @param[in] t Public key polynomials.
 * @param[in] s Secret key polynomials.
 * @param[in] mu Message digest (BUFF input).
 * @param[in] master_random Master randomness (32 bytes).
 * @return true on success, false on invalid inputs.
 */
static dogecoin_bool thrc_sign_internal(uint8_t c_hash_out[RACCOONG_C_HASH_BYTES],
                                        polyr z_out[RACCOONG_ELL],
                                        int16_t h_signed_out[RACCOONG_K][RACCOONG_N],
                                        const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                                        const polyr t[RACCOONG_K],
                                        const polyr s[RACCOONG_ELL],
                                        const uint8_t mu[RACCOONG_C_HASH_BYTES],
                                        const uint8_t master_random[32])
{
    dogecoin_bool ok = false;

    // --- 0. ExpandA.
    static polyr A_ntt[RACCOONG_K][RACCOONG_ELL];
    if (!raccoong_expand_a(A_ntt, A_seed)) goto cleanup;

    // --- 1. r ~ D_w^ell,  e2 ~ D_w^k  (sigma_w^2 = 2^80).
    static polyr r_vec[RACCOONG_ELL];
    static polyr e2_vec[RACCOONG_K];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!sample_w_gaussian(&r_vec[i], 'r', (uint8_t)i, 0, master_random)) {
            goto cleanup;
        }
    }
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        if (!sample_w_gaussian(&e2_vec[i], 'e', (uint8_t)i, 2, master_random)) {
            goto cleanup;
        }
    }

    // --- 2. w = [A * r + e2]_nu_w   (mod q_w).
    static polyr r_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) polyr_copy(&r_ntt[i], &r_vec[i]);
    if (!raccoong_vec_ntt(r_ntt, RACCOONG_ELL)) goto cleanup;

    static polyr w_vec[RACCOONG_K];
    if (!raccoong_mul_mat_vec_ntt(w_vec,
                                  (const polyr (*)[RACCOONG_ELL])A_ntt,
                                  r_ntt)) goto cleanup;
    if (!raccoong_vec_intt(w_vec, RACCOONG_K)) goto cleanup;
    if (!raccoong_vec_add(w_vec, w_vec, e2_vec, RACCOONG_K)) goto cleanup;

    static uint16_t w_qw[RACCOONG_K][RACCOONG_N];
    for (unsigned i = 0; i < RACCOONG_K; ++i) rshift_to_qw(w_qw[i], &w_vec[i]);

    // --- 3. c_hash = H(mu, w_qw);  c = chal_poly(c_hash);  c_ntt = NTT(c).
    static uint64_t hash_flat[RACCOONG_K * RACCOONG_N];
    qw_vec_to_u64(hash_flat, (const uint16_t (*)[RACCOONG_N])w_qw);
    if (!raccoong_hash_vec(c_hash_out, 'H', mu, RACCOONG_C_HASH_BYTES,
                           hash_flat, (size_t)RACCOONG_K * RACCOONG_N)) {
        goto cleanup;
    }
    int8_t c[RACCOONG_N];
    if (!raccoong_chal_poly(c, c_hash_out)) {
        dogecoin_mem_zero(c, sizeof(c));
        goto cleanup;
    }
    polyr c_ntt;
    chal_to_polyr(&c_ntt, c);
    if (!ntt_forward(&c_ntt)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        goto cleanup;
    }

    // --- 4. z_ntt = c_ntt * NTT(s) + r_ntt;  z = INTT(z_ntt).
    static polyr s_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) polyr_copy(&s_ntt[i], &s[i]);
    if (!raccoong_vec_ntt(s_ntt, RACCOONG_ELL)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        goto cleanup;
    }

    static polyr z_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!polyr_mul_pointwise(&z_ntt[i], &c_ntt, &s_ntt[i])) {
            dogecoin_mem_zero(c, sizeof(c));
            dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
            goto cleanup;
        }
        if (!polyr_add(&z_ntt[i], &z_ntt[i], &r_ntt[i])) {
            dogecoin_mem_zero(c, sizeof(c));
            dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
            goto cleanup;
        }
    }
    static polyr z_vec[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) polyr_copy(&z_vec[i], &z_ntt[i]);
    if (!raccoong_vec_intt(z_vec, RACCOONG_ELL)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        goto cleanup;
    }

    // --- 5. y = [A * z_ntt - 2^nu_t · c_ntt · NTT(t)]_nu_w.
    static polyr y_vec[RACCOONG_K];
    if (!raccoong_mul_mat_vec_ntt(y_vec,
                                  (const polyr (*)[RACCOONG_ELL])A_ntt,
                                  z_ntt)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        goto cleanup;
    }
    static polyr t_shift[RACCOONG_K];
    // HD-wallet variant: round t to nu_t first, then shift back.
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        round_and_lshift_nu_t(&t_shift[i], &t[i]);
    }
    if (!raccoong_vec_ntt(t_shift, RACCOONG_K)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        goto cleanup;
    }
    polyr tmp;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        if (!polyr_mul_pointwise(&tmp, &c_ntt, &t_shift[i])) {
            dogecoin_mem_zero(c, sizeof(c));
            dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
            dogecoin_mem_zero(&tmp, sizeof(tmp));
            goto cleanup;
        }
        if (!polyr_sub(&y_vec[i], &y_vec[i], &tmp)) {
            dogecoin_mem_zero(c, sizeof(c));
            dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
            dogecoin_mem_zero(&tmp, sizeof(tmp));
            goto cleanup;
        }
    }
    if (!raccoong_vec_intt(y_vec, RACCOONG_K)) {
        dogecoin_mem_zero(c, sizeof(c));
        dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
        dogecoin_mem_zero(&tmp, sizeof(tmp));
        goto cleanup;
    }
    static uint16_t y_qw[RACCOONG_K][RACCOONG_N];
    for (unsigned i = 0; i < RACCOONG_K; ++i) rshift_to_qw(y_qw[i], &y_vec[i]);

    // --- 6. h = w_qw - y_qw  (mod q_w);  then center to [-q_w/2, q_w/2).
    const int32_t Qw = (int32_t)RACCOONG_Q_W;
    const int32_t Qw_half = Qw >> 1;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            int32_t d = (int32_t)w_qw[i][j] - (int32_t)y_qw[i][j];
            d %= Qw;
            if (d < 0) d += Qw;
            // Centered for signature serialization (see signature wire fmt).
            if (d > Qw_half) d -= Qw;
            h_signed_out[i][j] = (int16_t)d;
        }
    }

    // --- 7. emit z.
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) polyr_copy(&z_out[i], &z_vec[i]);

    // Wipe stack-resident challenge poly / local NTT scratch.
    dogecoin_mem_zero(c, sizeof(c));
    dogecoin_mem_zero(&c_ntt, sizeof(c_ntt));
    dogecoin_mem_zero(&tmp, sizeof(tmp));
    ok = true;

cleanup:
    // Wipe every BSS slot that may carry secret-derived residue. Buffers
    // derived solely from public inputs (A_ntt, w_qw, y_vec, y_qw, t_shift,
    // hash_flat) are not zeroized because they cannot leak the secret r/s.
    dogecoin_mem_zero(r_vec, sizeof(r_vec));
    dogecoin_mem_zero(e2_vec, sizeof(e2_vec));
    dogecoin_mem_zero(r_ntt, sizeof(r_ntt));
    dogecoin_mem_zero(w_vec, sizeof(w_vec));
    dogecoin_mem_zero(s_ntt, sizeof(s_ntt));
    dogecoin_mem_zero(z_ntt, sizeof(z_ntt));
    dogecoin_mem_zero(z_vec, sizeof(z_vec));
    return ok;
}

/**
 * @brief Internal threshold signature verification.
 *
 * Core Algorithm 3 (Verify) implementation for Raccoon-G-44. A 1:1 port of
 * upstream `ThRc_Core.verify` (thrc_core.py). Verifies signature components
 * against the public key and message digest.
 *
 * @param[in] A_seed Public matrix seed.
 * @param[in] t Public key polynomials.
 * @param[in] c_hash Challenge digest.
 * @param[in] z Signature z component.
 * @param[in] h_signed Signature h component (centered).
 * @param[in] mu Message digest (BUFF input).
 * @return true if signature is valid, false otherwise.
 */
static dogecoin_bool thrc_verify_internal(const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                                          const polyr t[RACCOONG_K],
                                          const uint8_t c_hash[RACCOONG_C_HASH_BYTES],
                                          const polyr z[RACCOONG_ELL],
                                          const int16_t h_signed[RACCOONG_K][RACCOONG_N],
                                          const uint8_t mu[RACCOONG_C_HASH_BYTES])
{
    // --- 1. c = chal_poly(c_hash);  c_ntt = NTT(c).
    int8_t c[RACCOONG_N];
    if (!raccoong_chal_poly(c, c_hash)) return false;
    polyr c_ntt;
    chal_to_polyr(&c_ntt, c);
    if (!ntt_forward(&c_ntt)) return false;

    // --- 2. w = [A z_ntt - 2^nu_t c_ntt NTT(t)]_nu_w + h  (mod q_w).
    static polyr A_ntt[RACCOONG_K][RACCOONG_ELL];
    if (!raccoong_expand_a(A_ntt, A_seed)) return false;

    static polyr z_ntt[RACCOONG_ELL];
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) polyr_copy(&z_ntt[i], &z[i]);
    if (!raccoong_vec_ntt(z_ntt, RACCOONG_ELL)) return false;

    static polyr w_vec[RACCOONG_K];
    if (!raccoong_mul_mat_vec_ntt(w_vec,
                                  (const polyr (*)[RACCOONG_ELL])A_ntt,
                                  z_ntt)) return false;
    static polyr t_shift[RACCOONG_K];
    // HD-wallet variant: round t to nu_t first, then shift back.
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        round_and_lshift_nu_t(&t_shift[i], &t[i]);
    }
    if (!raccoong_vec_ntt(t_shift, RACCOONG_K)) return false;
    polyr tmp;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        if (!polyr_mul_pointwise(&tmp, &c_ntt, &t_shift[i])) return false;
        if (!polyr_sub(&w_vec[i], &w_vec[i], &tmp)) return false;
    }
    if (!raccoong_vec_intt(w_vec, RACCOONG_K)) return false;

    static uint16_t w_qw[RACCOONG_K][RACCOONG_N];
    const int32_t Qw = (int32_t)RACCOONG_Q_W;
    static uint16_t h_unsigned[RACCOONG_K][RACCOONG_N];
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        rshift_to_qw(w_qw[i], &w_vec[i]);
        for (size_t j = 0; j < RACCOONG_N; ++j) {
            int32_t hv = (int32_t)h_signed[i][j];
            hv %= Qw;
            if (hv < 0) hv += Qw;
            h_unsigned[i][j] = (uint16_t)hv;
            int32_t sum = (int32_t)w_qw[i][j] + hv;
            if (sum >= Qw) sum -= Qw;
            w_qw[i][j] = (uint16_t)sum;
        }
    }

    static uint64_t hash_flat[RACCOONG_K * RACCOONG_N];
    qw_vec_to_u64(hash_flat, (const uint16_t (*)[RACCOONG_N])w_qw);
    uint8_t c_hash2[RACCOONG_C_HASH_BYTES];
    if (!raccoong_hash_vec(c_hash2, 'H', mu, RACCOONG_C_HASH_BYTES,
                           hash_flat, (size_t)RACCOONG_K * RACCOONG_N)) {
        return false;
    }

    // --- 3. accept iff c_hash matches and the norm bound holds.
    if (memcmp(c_hash, c_hash2, RACCOONG_C_HASH_BYTES) != 0) return false;
    return check_bounds(z, (const uint16_t (*)[RACCOONG_N])h_unsigned);
}

/**
 * @brief Threshold signature with caller-supplied randomness.
 *
 * Deterministic signing variant for byte-exact KAT. Equivalent to `thrc_sign`
 * but takes a caller-supplied 32-byte master randomness blob instead of pulling
 * from the libdogecoin RNG.  Mirrors upstream `ThRc_Core.plain_sign(vk, sk, mu)`.
 *
 * @param[in] sk Serialized secret key (RACCOONG_SK_BYTES).
 * @param[in] sk_len Length of sk buffer.
 * @param[in] msg Message bytes.
 * @param[in] msg_len Length of msg in bytes.
 * @param[in] master_random Master randomness seed (32 bytes).
 * @param[out] sig_out Output signature buffer.
 * @param[in,out] sig_len_inout On input: buffer size; on output: bytes written.
 * @return true on success, false on invalid parameters or signing failure.
 */
dogecoin_bool thrc_sign_with_random(const uint8_t* sk, size_t sk_len,
                                    const uint8_t* msg, size_t msg_len,
                                    const uint8_t master_random[RACCOONG_KG_SEED_BYTES],
                                    uint8_t* sig_out, size_t* sig_len_inout)
{
    if (!sk || !sig_out || !sig_len_inout || !master_random) return false;
    if (msg_len != 0 && !msg) return false;
    if (*sig_len_inout < RACCOONG_SIG_BYTES) return false;

    dogecoin_bool ok = false;

    // Deserialize sk = (A_seed, t, s).
    uint8_t A_seed[RACCOONG_A_SEED_BYTES];
    static polyr t_vec[RACCOONG_K];
    static polyr s_vec[RACCOONG_ELL];
    if (!deserialize_sk_into(sk, sk_len, A_seed, t_vec, s_vec)) goto out;

    // BUFF: tr = H(pk); mu = H(tr || msg).  pk = first PK_BYTES of sk.
    uint8_t tr[RACCOONG_C_HASH_BYTES];
    if (!raccoong_pk_hash(tr, sk, RACCOONG_PK_BYTES)) goto out;
    uint8_t mu[RACCOONG_C_HASH_BYTES];
    if (!raccoong_buff_mu(mu, tr, msg, msg_len)) goto out;

    uint8_t c_hash[RACCOONG_C_HASH_BYTES];
    static polyr z_vec[RACCOONG_ELL];
    static int16_t h_signed[RACCOONG_K][RACCOONG_N];
    if (!thrc_sign_internal(c_hash, z_vec, h_signed,
                            A_seed, t_vec, s_vec, mu, master_random)) {
        goto out;
    }

    size_t out_len = *sig_len_inout;
    if (!raccoong_serialize_signature(sig_out, &out_len,
                                      c_hash, z_vec,
                                      (const int16_t (*)[256])h_signed)) {
        goto out;
    }
    *sig_len_inout = out_len;
    ok = true;

out:
    // s_vec is secret and must always be wiped. z_vec / h_signed are the
    // public signature components; clearing them avoids leaving correlated
    // intermediate material in BSS between calls. t_vec, A_seed, tr, mu and
    // c_hash are all public.
    dogecoin_mem_zero(s_vec, sizeof(s_vec));
    dogecoin_mem_zero(z_vec, sizeof(z_vec));
    dogecoin_mem_zero(h_signed, sizeof(h_signed));
    return ok;
}

/**
 * @brief Threshold signature generation.
 *
 * Generates a Raccoon-G-44 signature from a secret key and message. Uses the
 * libdogecoin RNG to generate master randomness internally.
 *
 * @param[in] sk Serialized secret key (RACCOONG_SK_BYTES).
 * @param[in] sk_len Length of sk buffer.
 * @param[in] msg Message bytes.
 * @param[in] msg_len Length of msg in bytes.
 * @param[out] sig_out Output signature buffer.
 * @param[in,out] sig_len_inout On input: buffer size; on output: bytes written.
 * @return true on success, false on invalid parameters or signing failure.
 */
dogecoin_bool thrc_sign(const uint8_t* sk, size_t sk_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t* sig_out, size_t* sig_len_inout)
{
    uint8_t master_random[RACCOONG_KG_SEED_BYTES];
    if (!dogecoin_random_bytes(master_random, sizeof(master_random), 0)) {
        return false;
    }
    dogecoin_bool ok = thrc_sign_with_random(sk, sk_len, msg, msg_len,
                                             master_random,
                                             sig_out, sig_len_inout);
    dogecoin_mem_zero(master_random, sizeof(master_random));
    return ok;
}

/**
 * @brief Threshold signature verification.
 *
 * Verifies a Raccoon-G-44 signature against a public key and message.
 *
 * @param[in] pk Serialized public key (RACCOONG_PK_BYTES).
 * @param[in] pk_len Length of pk buffer.
 * @param[in] msg Message bytes.
 * @param[in] msg_len Length of msg in bytes.
 * @param[in] sig Signature bytes (RACCOONG_SIG_BYTES).
 * @param[in] sig_len Length of sig buffer.
 * @return true if signature is valid, false otherwise.
 */
dogecoin_bool thrc_verify(const uint8_t* pk, size_t pk_len,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t* sig, size_t sig_len)
{
    if (!pk || !sig) return false;
    if (msg_len != 0 && !msg) return false;
    if (sig_len != RACCOONG_SIG_BYTES) return false;

    uint8_t A_seed[RACCOONG_A_SEED_BYTES];
    static polyr t_vec[RACCOONG_K];
    if (!deserialize_pk_into(pk, pk_len, A_seed, t_vec)) return false;

    uint8_t c_hash[RACCOONG_C_HASH_BYTES];
    static polyr z_vec[RACCOONG_ELL];
    static int16_t h_signed[RACCOONG_K][RACCOONG_N];
    if (!raccoong_deserialize_signature(c_hash, z_vec, h_signed,
                                        sig, sig_len)) {
        return false;
    }

    uint8_t tr[RACCOONG_C_HASH_BYTES];
    if (!raccoong_pk_hash(tr, pk, pk_len)) return false;
    uint8_t mu[RACCOONG_C_HASH_BYTES];
    if (!raccoong_buff_mu(mu, tr, msg, msg_len)) return false;

    return thrc_verify_internal(A_seed, t_vec, c_hash, z_vec,
                                (const int16_t (*)[RACCOONG_N])h_signed, mu);
}

/**
 * @brief BIP-32 style private key derivation.
 *
 * Derives a child private key from a parent keypair using BIP-32 style
 * hardened or non-hardened child key derivation with chaincode.
 *
 * @param[in] parent_sk Serialized parent secret key.
 * @param[in] parent_sk_len Length of parent_sk.
 * @param[in] parent_pk Serialized parent public key.
 * @param[in] parent_pk_len Length of parent_pk.
 * @param[in] chaincode Chaincode (32 bytes).
 * @param[in] index Child index.
 * @param[in] hardened Whether to use hardened derivation.
 * @param[out] child_sk_out Child secret key buffer (RACCOONG_SK_BYTES).
 * @param[in] child_sk_len Length of child_sk_out buffer.
 * @param[out] child_pk_out Child public key buffer (RACCOONG_PK_BYTES).
 * @param[in] child_pk_len Length of child_pk_out buffer.
 * @return true on success, false on invalid parameters or derivation failure.
 */
dogecoin_bool thrc_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                  const uint8_t* parent_pk, size_t parent_pk_len,
                                  const uint8_t chaincode[32],
                                  uint32_t index, dogecoin_bool hardened,
                                  uint8_t* child_sk_out, size_t child_sk_len,
                                  uint8_t* child_pk_out, size_t child_pk_len)
{
    if (!parent_sk || !parent_pk || !chaincode ||
        !child_sk_out || !child_pk_out) {
        return false;
    }
    if (child_sk_len != RACCOONG_SK_BYTES) return false;
    if (child_pk_len != RACCOONG_PK_BYTES) return false;

    // 1. Deserialize parent sk = (A_seed, t, s); cross-check A_seed against pk.
    // NOTE: these vectors hold secret-key material. They MUST NOT be marked
    // `static` (the previous implementation did, racing two callers and
    // leaking `s` across calls). Allocate on the heap so we own a fresh,
    // private copy per call and can explicitly zeroize it on every exit path.
    uint8_t parent_A_seed[RACCOONG_A_SEED_BYTES];
    uint8_t parent_pk_A_seed[RACCOONG_A_SEED_BYTES];
    polyr* parent_t = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    polyr* parent_s = (polyr*)dogecoin_calloc(RACCOONG_ELL, sizeof(polyr));
    polyr* tweak_t  = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    polyr* tweak_s  = (polyr*)dogecoin_calloc(RACCOONG_ELL, sizeof(polyr));
    polyr* child_t  = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    polyr* child_s  = (polyr*)dogecoin_calloc(RACCOONG_ELL, sizeof(polyr));
    dogecoin_bool ok = false;
    if (!parent_t || !parent_s || !tweak_t || !tweak_s || !child_t || !child_s) {
        goto cleanup;
    }
    if (!deserialize_sk_into(parent_sk, parent_sk_len, parent_A_seed,
                             parent_t, parent_s)) {
        goto cleanup;
    }
    if (!deserialize_pk_into(parent_pk, parent_pk_len, parent_pk_A_seed,
                             /*t_out=*/NULL)) {
        goto cleanup;
    }
    if (memcmp(parent_A_seed, parent_pk_A_seed, RACCOONG_A_SEED_BYTES) != 0) {
        goto cleanup;
    }

    // 2. tweak_seed = HMAC-SHA512(chaincode, tag || sha256(parent_key) || idx_BE)[:32]
    //    tag is 'p' for non-hardened (uses parent_pk hash) or 'S' for hardened
    //    (uses parent_sk hash). This mirrors the liboqs-side derive_hd_bytes
    //    domain separator tags.
    {
    uint8_t tweak_seed[32];
    if (!hd_derive_tweak_seed(tweak_seed, parent_pk, parent_pk_len,
                              parent_sk, parent_sk_len, chaincode,
                              index, hardened)) {
        dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));
        goto cleanup;
    }

    // 3. drbg_seed = HKDF-SHA256(tweak_seed, 48); drbg.random_bytes(32) = key.
    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              tweak_seed, sizeof(tweak_seed),
                              NULL, 0, NULL, 0)) {
        dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));
        dogecoin_mem_zero(drbg_seed, sizeof(drbg_seed));
        goto cleanup;
    }
    dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    dogecoin_mem_zero(drbg_seed, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    dogecoin_mem_zero(&drbg, sizeof(drbg));

    // 4. tweak keygen reusing parent A_seed.
    if (!raccoong_keygen_t_with_aseed(key, parent_A_seed, tweak_t, tweak_s)) {
        dogecoin_mem_zero(key, sizeof(key));
        goto cleanup;
    }
    dogecoin_mem_zero(key, sizeof(key));
    }

    // 5. child_t = parent_t + tweak_t (mod q); child_s = parent_s + tweak_s (mod q).
    if (!raccoong_vec_add(child_t, parent_t, tweak_t, RACCOONG_K)) {
        goto cleanup;
    }
    if (!raccoong_vec_add(child_s, parent_s, tweak_s, RACCOONG_ELL)) {
        goto cleanup;
    }

    raccoong_serialize_pk(child_pk_out, parent_A_seed, child_t);
    raccoong_serialize_sk(child_sk_out, parent_A_seed, child_t, child_s);
    ok = true;

cleanup:
    /* Wipe transient secrets on EVERY exit path (success or any failure). */
    if (parent_s) { dogecoin_mem_zero(parent_s, RACCOONG_ELL * sizeof(polyr)); dogecoin_free(parent_s); }
    if (parent_t) { dogecoin_mem_zero(parent_t, RACCOONG_K   * sizeof(polyr)); dogecoin_free(parent_t); }
    if (tweak_s)  { dogecoin_mem_zero(tweak_s,  RACCOONG_ELL * sizeof(polyr)); dogecoin_free(tweak_s); }
    if (tweak_t)  { dogecoin_mem_zero(tweak_t,  RACCOONG_K   * sizeof(polyr)); dogecoin_free(tweak_t); }
    if (child_s)  { dogecoin_mem_zero(child_s,  RACCOONG_ELL * sizeof(polyr)); dogecoin_free(child_s); }
    if (child_t)  { dogecoin_mem_zero(child_t,  RACCOONG_K   * sizeof(polyr)); dogecoin_free(child_t); }
    dogecoin_mem_zero(parent_A_seed, sizeof(parent_A_seed));
    dogecoin_mem_zero(parent_pk_A_seed, sizeof(parent_pk_A_seed));
    return ok;
}

/**
 * @brief BIP-32 style public key derivation.
 *
 * Derives a child public key from a parent public key using BIP-32 style
 * non-hardened child key derivation with chaincode.
 *
 * @param[in] parent_pk Serialized parent public key.
 * @param[in] parent_pk_len Length of parent_pk.
 * @param[in] chaincode Chaincode (32 bytes).
 * @param[in] index Child index (hardened bits must be 0).
 * @param[out] child_pk_out Child public key buffer (RACCOONG_PK_BYTES).
 * @param[in] child_pk_len Length of child_pk_out buffer.
 * @return true on success, false on invalid parameters or derivation failure.
 */
dogecoin_bool thrc_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                 const uint8_t chaincode[32],
                                 uint32_t index,
                                 uint8_t* child_pk_out, size_t child_pk_len)
{
    if (!parent_pk || !chaincode || !child_pk_out) return false;
    if (child_pk_len != RACCOONG_PK_BYTES) return false;
    // Hardened derivation needs the secret key.
    if (index & 0x80000000U) return false;

    uint8_t parent_A_seed[RACCOONG_A_SEED_BYTES];
    polyr* parent_t = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    polyr* tweak_t  = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    polyr* child_t  = (polyr*)dogecoin_calloc(RACCOONG_K, sizeof(polyr));
    dogecoin_bool ok = false;
    if (!parent_t || !tweak_t || !child_t) {
        goto cleanup_pub;
    }
    if (!deserialize_pk_into(parent_pk, parent_pk_len, parent_A_seed, parent_t)) {
        goto cleanup_pub;
    }

    {
    uint8_t tweak_seed[32];
    if (!hd_derive_tweak_seed(tweak_seed, parent_pk, parent_pk_len,
                              /*parent_sk=*/NULL, 0, chaincode,
                              index, /*hardened=*/false)) {
        dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));
        goto cleanup_pub;
    }

    uint8_t drbg_seed[48];
    if (!raccoong_hkdf_sha256(drbg_seed, sizeof(drbg_seed),
                              tweak_seed, sizeof(tweak_seed),
                              NULL, 0, NULL, 0)) {
        dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));
        dogecoin_mem_zero(drbg_seed, sizeof(drbg_seed));
        goto cleanup_pub;
    }
    dogecoin_mem_zero(tweak_seed, sizeof(tweak_seed));

    raccoong_nist_kat_drbg drbg;
    raccoong_nist_kat_drbg_init(&drbg, drbg_seed);
    dogecoin_mem_zero(drbg_seed, sizeof(drbg_seed));

    uint8_t key[32];
    raccoong_nist_kat_drbg_random_bytes(&drbg, key, sizeof(key));
    dogecoin_mem_zero(&drbg, sizeof(drbg));

    if (!raccoong_keygen_t_with_aseed(key, parent_A_seed, tweak_t, NULL)) {
        dogecoin_mem_zero(key, sizeof(key));
        goto cleanup_pub;
    }
    dogecoin_mem_zero(key, sizeof(key));
    }

    if (!raccoong_vec_add(child_t, parent_t, tweak_t, RACCOONG_K)) {
        goto cleanup_pub;
    }

    raccoong_serialize_pk(child_pk_out, parent_A_seed, child_t);
    ok = true;

cleanup_pub:
    if (parent_t) { dogecoin_mem_zero(parent_t, RACCOONG_K * sizeof(polyr)); dogecoin_free(parent_t); }
    if (tweak_t)  { dogecoin_mem_zero(tweak_t,  RACCOONG_K * sizeof(polyr)); dogecoin_free(tweak_t); }
    if (child_t)  { dogecoin_mem_zero(child_t,  RACCOONG_K * sizeof(polyr)); dogecoin_free(child_t); }
    dogecoin_mem_zero(parent_A_seed, sizeof(parent_A_seed));
    return ok;
}

/*
 * Deserialization helpers + chain-code-driven tweak derivation.
 */

/**
 * @brief Deserialize a polynomial from little-endian 7-byte encoding.
 *
 * @param[out] dst Output polynomial.
 * @param[in] src 256 * 7 bytes of little-endian encoded coefficients.
 * @return true if all coefficients are in [0, q), false otherwise.
 */

static dogecoin_bool deserialize_poly_le7(polyr* dst, const uint8_t* src)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t c =
              ((uint64_t)src[0])
            | ((uint64_t)src[1] << 8)
            | ((uint64_t)src[2] << 16)
            | ((uint64_t)src[3] << 24)
            | ((uint64_t)src[4] << 32)
            | ((uint64_t)src[5] << 40)
            | ((uint64_t)src[6] << 48);
        if (c >= RACCOONG_Q) return false;
        dst->coeffs[i] = c;
        src += RACCOONG_COEFF_BYTES;
    }
    return true;
}

/**
 * @brief Deserialize public key into components.
 *
 * @param[in] pk Serialized public key (RACCOONG_PK_BYTES).
 * @param[in] pk_len Length of pk buffer.
 * @param[out] A_seed_out Public matrix seed (16 bytes).
 * @param[out] t_out k polynomials (can be NULL).
 * @return true on success, false on invalid parameters.
 */
static dogecoin_bool deserialize_pk_into(const uint8_t* pk, size_t pk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K])
{
    if (!pk || pk_len != RACCOONG_PK_BYTES) return false;
    memcpy(A_seed_out, pk, RACCOONG_A_SEED_BYTES);
    if (!t_out) return true;
    const uint8_t* p = pk + RACCOONG_A_SEED_BYTES;
    for (unsigned i = 0; i < RACCOONG_K; ++i) {
        if (!deserialize_poly_le7(&t_out[i], p)) return false;
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
    return true;
}

/**
 * @brief Deserialize secret key into components.
 *
 * @param[in] sk Serialized secret key (RACCOONG_SK_BYTES).
 * @param[in] sk_len Length of sk buffer.
 * @param[out] A_seed_out Public matrix seed (16 bytes).
 * @param[out] t_out k polynomials.
 * @param[out] s_out ell polynomials (can be NULL).
 * @return true on success, false on invalid parameters.
 */
static dogecoin_bool deserialize_sk_into(const uint8_t* sk, size_t sk_len,
                                         uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                         polyr t_out[RACCOONG_K],
                                         polyr s_out[RACCOONG_ELL])
{
    if (!sk || sk_len != RACCOONG_SK_BYTES) return false;
    if (!deserialize_pk_into(sk, RACCOONG_PK_BYTES, A_seed_out, t_out)) {
        return false;
    }
    if (!s_out) return true;
    const uint8_t* p = sk + RACCOONG_PK_BYTES;
    for (unsigned i = 0; i < RACCOONG_ELL; ++i) {
        if (!deserialize_poly_le7(&s_out[i], p)) return false;
        p += (size_t)RACCOONG_N * RACCOONG_COEFF_BYTES;
    }
    return true;
}

/**
 * @brief Derive tweak seed using chaincode and parent key hash.
 *
 * Derives a tweak seed for BIP-32 style hierarchical key derivation.
 * Computes: tweak_seed = HMAC-SHA512(chaincode, tag || sha256(parent_key) || index_BE)[:32]
 * where tag is 'p' for non-hardened (parent_pk) or 'S' for hardened (parent_sk).
 *
 * @param[out] tweak_seed_out Derived tweak seed (32 bytes).
 * @param[in] parent_pk Parent public key bytes.
 * @param[in] parent_pk_len Length of parent_pk.
 * @param[in] parent_sk Parent secret key bytes (NULL for non-hardened).
 * @param[in] parent_sk_len Length of parent_sk.
 * @param[in] chaincode Chaincode (32 bytes).
 * @param[in] index Derivation index.
 * @param[in] hardened Whether to use hardened derivation.
 * @return true on success, false on invalid inputs.
 */
static dogecoin_bool hd_derive_tweak_seed(uint8_t tweak_seed_out[32],
                                          const uint8_t* parent_pk, size_t parent_pk_len,
                                          const uint8_t* parent_sk, size_t parent_sk_len,
                                          const uint8_t chaincode[32],
                                          uint32_t index, dogecoin_bool hardened)
{
    uint8_t data[1 + 32 + 4];
    uint8_t digest[32];

    uint32_t encoded_index = hardened ? (index | 0x80000000u) : index;
    if (hardened) {
        if (!parent_sk || parent_sk_len != RACCOONG_SK_BYTES) return false;
        data[0] = 'S';
        sha256_raw(parent_sk, parent_sk_len, digest);
    } else {
        if (!parent_pk || parent_pk_len != RACCOONG_PK_BYTES) return false;
        data[0] = 'p';
        sha256_raw(parent_pk, parent_pk_len, digest);
    }
    memcpy(data + 1, digest, 32);
    data[33] = (uint8_t)(encoded_index >> 24);
    data[34] = (uint8_t)(encoded_index >> 16);
    data[35] = (uint8_t)(encoded_index >> 8);
    data[36] = (uint8_t)(encoded_index);

    uint8_t I[64];
    hmac_sha512(chaincode, 32, data, sizeof(data), I);
    memcpy(tweak_seed_out, I, 32);
    memset(I, 0, sizeof(I));
    memset(data, 0, sizeof(data));
    return true;
}
