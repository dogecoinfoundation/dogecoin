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

#ifndef LIBDOGECOIN_RACCOON_G_THRC_H
#define LIBDOGECOIN_RACCOON_G_THRC_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

#include "polyr.h"

LIBDOGECOIN_BEGIN_DECL

// Raccoon-G-44 threshold core dimensions (mirrors upstream `ThRc_Core` defaults
// for HD-wallet sigs at #sigs 2^60: k = ell = 9).
#define RACCOONG_K   9u
#define RACCOONG_ELL 9u

// Size of `A_seed` (the public-matrix seed, "as_sz" upstream).
#define RACCOONG_A_SEED_BYTES 16u

/*
 * Threshold core ("thrc") for Raccoon-G-44: keygen, sign, verify, and BIP-32
 * style child derivation. Glue around polyr / ntt / gaussian. All routines
 * are byte-deterministic with respect to their inputs (seed, message, etc.)
 * to allow byte-exact KAT comparison against the upstream Python reference.
 */

/*
 * Canonical Raccoon-G-44 serialization sizes (mirrors upstream
 * `raccoon_primitives._PUBLIC_KEY_SIZE` / `_SIGNING_KEY_SIZE`):
 *   q is 50-bit so each coefficient packs into 7 little-endian bytes.
 *   pk = A_seed (16 B) || t (k * n * 7 B)               = 16144 B
 *   sk = pk || s (ell * n * 7 B)                        = 32272 B
 */
#define RACCOONG_COEFF_BYTES 7u
#define RACCOONG_PK_BYTES \
    (RACCOONG_A_SEED_BYTES + (size_t)RACCOONG_K * 256u * RACCOONG_COEFF_BYTES)
#define RACCOONG_SK_BYTES \
    (RACCOONG_PK_BYTES + (size_t)RACCOONG_ELL * 256u * RACCOONG_COEFF_BYTES)

dogecoin_bool thrc_keygen_from_seed(const uint8_t seed[32],
                                    uint8_t* pk_out, size_t pk_len,
                                    uint8_t* sk_out, size_t sk_len);

/*
 * Canonical little-endian serialization helpers (mirror
 * upstream `serialize_public_key` / `serialize_signing_key`).
 * `pk_out` must point to RACCOONG_PK_BYTES of writable storage; `sk_out`
 * to RACCOONG_SK_BYTES.  Secret coefficients are stored as `c mod q` to
 * match the upstream `int(coefficient % _Q).to_bytes(_COEFF_BYTES, "little")`
 * convention, so freshly-sampled negative gaussians round-trip cleanly.
 */
void raccoong_serialize_pk(uint8_t pk_out[/*RACCOONG_PK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K]);

void raccoong_serialize_sk(uint8_t sk_out[/*RACCOONG_SK_BYTES*/],
                           const uint8_t A_seed[RACCOONG_A_SEED_BYTES],
                           const polyr t[RACCOONG_K],
                           const polyr s[RACCOONG_ELL]);

// Master randomness blob size for signing (kg_sz = 32 B in upstream).
#define RACCOONG_KG_SEED_BYTES 32u

dogecoin_bool thrc_sign(const uint8_t* sk, size_t sk_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t* sig_out, size_t* sig_len_inout);

/*
 * `thrc_sign_with_random` - deterministic signing for byte-exact KAT.
 *
 * Equivalent to `thrc_sign` but takes a caller-supplied 32-byte master
 * randomness blob (`master_random`) instead of pulling from the
 * libdogecoin RNG.  Mirrors upstream `ThRc_Core.plain_sign(vk, sk, mu)`
 * where the `random_bytes(kg_sz)` call is replaced by a deterministic
 * source.  Used by the byte-exact KAT in `test/raccoong_sign_tests.c`;
 * production callers should prefer `thrc_sign`.
 */
dogecoin_bool thrc_sign_with_random(const uint8_t* sk, size_t sk_len,
                                    const uint8_t* msg, size_t msg_len,
                                    const uint8_t master_random[RACCOONG_KG_SEED_BYTES],
                                    uint8_t* sig_out, size_t* sig_len_inout);

dogecoin_bool thrc_verify(const uint8_t* pk, size_t pk_len,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t* sig, size_t sig_len);

/*
 * Thread safety note for the HD derivation routines below: the per-call
 * scratch for secret-key polynomials in these routines is heap-allocated
 * and wiped on every exit, so the HD derive wrappers do not themselves
 * leak parent-secret material across concurrent calls on different
 * (parent_sk, parent_pk) pairs.
 *
 * However, these routines internally invoke `raccoong_keygen_t_with_aseed`
 * (and, for verification paths, the keygen / sign primitives in this
 * translation unit) which still use file-scope `static polyr` scratch for
 * lattice keygen and signing state. As a result the guarantee above only
 * holds provided no other thread is concurrently calling any other thrc
 * primitive (HD derive, keygen, sign, or verify) in this process. Callers
 * that may run thrc primitives from multiple threads MUST serialize all
 * such calls with an external lock; the same applies to any shared output
 * buffer.
 */
dogecoin_bool thrc_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                  const uint8_t* parent_pk, size_t parent_pk_len,
                                  const uint8_t chaincode[32],
                                  uint32_t index, dogecoin_bool hardened,
                                  uint8_t* child_sk_out, size_t child_sk_len,
                                  uint8_t* child_pk_out, size_t child_pk_len);

dogecoin_bool thrc_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                 const uint8_t chaincode[32],
                                 uint32_t index,
                                 uint8_t* child_pk_out, size_t child_pk_len);

/*
 * `_xof_sample_q` — uniform Z_q rejection sampler.  1:1 port of upstream
 * `ThRc_Core._xof_sample_q` (thrc_core.py) at kappa=128 (SHAKE128).  Reads
 * ceil(q_bits/8) = 7 bytes per attempt, masks to q_bits=50 bits, accepts
 * if the masked value is in [0, q).  Deterministic given `seed`.
 *
 * `out` receives RACCOONG_N values, each in [0, RACCOONG_Q).  Returns
 * false on null inputs.  Used by ExpandA and threshold-share generation.
 */
dogecoin_bool raccoong_xof_sample_q(uint64_t out[/* RACCOONG_N */],
                                    const uint8_t* seed, size_t seed_len);

/*
 * Upstream domain-separation header constructors.  Verbatim ports of
 * `_hdr8` / `_hdr24` from thrc_core.py.  Output buffer must be >= 8 / 16
 * bytes respectively.
 */
void raccoong_hdr8(uint8_t out[8], char ds,
                   uint8_t b1, uint8_t b2, uint8_t b3,
                   uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7);
void raccoong_hdr24(uint8_t out[8], char ds,
                    uint32_t i, uint32_t j, uint8_t k);

/*
 * `_expand_a` — fill the public k×ell matrix A from `A_seed`.
 *
 * 1:1 port of upstream `ThRc_Core._expand_a`: for each (i, j) the entry is
 * `_xof_sample_q(_hdr8('A', i, j) + A_seed)`.  Upstream treats this matrix
 * as already living in NTT domain (uniform random in either basis), so the
 * output is consumable directly by `raccoong_mul_mat_vec_ntt`.
 *
 * Returns false on null inputs.
 */
dogecoin_bool raccoong_expand_a(polyr A[RACCOONG_K][RACCOONG_ELL],
                                const uint8_t A_seed[RACCOONG_A_SEED_BYTES]);

/*
 * Vector / matrix-vector helpers over the ring R_q = Z_q[X]/(X^n+1).
 * Mirrors upstream polyr.py functions of the same shape.  All routines
 * return false on null inputs.  Aliasing rules match the underlying
 * `polyr_*` and `ntt_*` calls.
 */
dogecoin_bool raccoong_vec_ntt(polyr* v, size_t n);    // in-place forward
dogecoin_bool raccoong_vec_intt(polyr* v, size_t n);   // in-place inverse

dogecoin_bool raccoong_vec_add(polyr* r, const polyr* a, const polyr* b,
                               size_t n);
dogecoin_bool raccoong_vec_rshift(polyr* r, const polyr* a, unsigned shift,
                                  size_t n);

/*
 * out[i] = sum_j A[i][j] *_ntt v[j]   for i in [0, k), j in [0, ell).
 * Inputs must already be in NTT domain.  Output is in NTT domain.
 */
dogecoin_bool raccoong_mul_mat_vec_ntt(polyr out[RACCOONG_K],
                                       const polyr A[RACCOONG_K][RACCOONG_ELL],
                                       const polyr v[RACCOONG_ELL]);

/*
 * `_keygen_unrounded(key)` — byte-exact port of upstream
 * `raccoon_primitives._keygen_unrounded`.  Emits:
 *   - `A_seed_out` (16 bytes)        = SHAKE256(_hdr8('A') + key, 16)
 *   - `t_out[k]`  (k polyrs in [0,q)) = vec_intt(A_ntt * vec_ntt(s)) + e1
 *
 * No rshift / nu_t rounding is applied — the unrounded shape is the
 * canonical HD-wallet variant (preserves additive linearity for non-
 * hardened child derivation, see upstream docstring).
 *
 * `s_out` (ell polyrs in [0,q)) may be NULL when only the public vk is
 * needed; supplying it lets the caller assemble the full signing key
 * sk = (vk, s).  Returns false on null A_seed_out / t_out / key, or if
 * the gaussian/NTT primitives reject any input.
 */
dogecoin_bool raccoong_keygen_t_unrounded(const uint8_t key[32],
                                          uint8_t A_seed_out[RACCOONG_A_SEED_BYTES],
                                          polyr t_out[RACCOONG_K],
                                          polyr s_out[RACCOONG_ELL]);

// Upstream `lg_st = 7` ⇒ sigma_t² = 2^14.
#define RACCOONG_LG_ST       7u
#define RACCOONG_LG_SIGMA_T2 14u

// Upstream `lg_swt = 40` ⇒ sigma_w² = 2^80.
#define RACCOONG_LG_SWT      40u
#define RACCOONG_LG_SIGMA_W2 80u

// Upstream `nu_t = 35`; q_t = q >> nu_t.
#define RACCOONG_NU_T        35u

/*
 * Signature wire format (mirrors upstream `serialize_signature`).
 *
 *   nu_w = 38, q_w = q >> nu_w = 2048 (12-bit), so each h coefficient packs
 *   into 2 little-endian bytes. nu_t / q_t are unused on the wire because the
 *   HD-wallet variant signs against the unrounded `t` (preserves additive
 *   linearity). z coefficients use the full 7-byte modulo-q encoding.
 *
 *   sig = c_hash (32 B)
 *      || z (ell * n * 7 B = 16128 B)
 *      || h (k   * n * 2 B =  4608 B)
 *      = 20768 B  fixed.
 *
 * Pinned in src/raccoon_g/raccoong.c::raccoong_sig_max_len(); a static
 * assertion in test/raccoong_signature_serialize_tests.c keeps the macros
 * locked to the upstream Python constants via the byte-exact fixture.
 */
#define RACCOONG_NU_W 38u
#define RACCOONG_Q_W ((uint64_t)RACCOONG_Q >> RACCOONG_NU_W)   // 2048
#define RACCOONG_H_COEFF_BYTES 2u
#define RACCOONG_C_HASH_BYTES 32u
#define RACCOONG_SIG_BYTES \
    (RACCOONG_C_HASH_BYTES \
     + (size_t)RACCOONG_ELL * 256u * RACCOONG_COEFF_BYTES \
     + (size_t)RACCOONG_K   * 256u * RACCOONG_H_COEFF_BYTES)

/*
 * `raccoong_serialize_signature` — pack a Raccoon-G signature tuple
 * `(c_hash, z, h)` into `RACCOONG_SIG_BYTES` of canonical bytes.
 *
 * Inputs:
 *   c_hash   - challenge digest (32 bytes).
 *   z        - ell polynomials in [0, q).  Aliasing with sig_out is illegal.
 *   h_signed - k polynomials of centered hint coefficients in
 *              [-q_w/2, q_w/2).  Each coefficient is reduced modulo q_w
 *              before being written, so the signed and unsigned representa-
 *              tions encode to the same bytes.
 *
 * Returns false on null inputs / sig_len_inout < RACCOONG_SIG_BYTES, or if
 * any z coefficient is out of [0, q).  On success `*sig_len_inout` is set
 * to RACCOONG_SIG_BYTES.
 */
dogecoin_bool raccoong_serialize_signature(
    uint8_t* sig_out, size_t* sig_len_inout,
    const uint8_t c_hash[RACCOONG_C_HASH_BYTES],
    const polyr z[RACCOONG_ELL],
    const int16_t h_signed[RACCOONG_K][256]);

/*
 * `raccoong_deserialize_signature` — unpack a canonical Raccoon-G
 * signature.  Mirrors upstream `deserialize_signature`:
 *   - z coefficients are read as little-endian 7-byte unsigned values in
 *     [0, q); a value >= q is rejected (returns false).
 *   - h coefficients are read as little-endian 2-byte unsigned values in
 *     [0, q_w); a value >= q_w is rejected.  They are then centered into
 *     `h_signed_out` ∈ [-q_w/2, q_w/2).
 *
 * Returns false on null inputs, sig_len != RACCOONG_SIG_BYTES, or
 * out-of-range coefficient.
 */
dogecoin_bool raccoong_deserialize_signature(
    uint8_t c_hash_out[RACCOONG_C_HASH_BYTES],
    polyr z_out[RACCOONG_ELL],
    int16_t h_signed_out[RACCOONG_K][256],
    const uint8_t* sig, size_t sig_len);

/*
 * Challenge-polynomial expansion (`_chal_poly` upstream).
 *
 * Maps the 32-byte challenge digest `c_hash` to a τ-weight ternary
 * polynomial in {-1, 0, +1}^256 (exactly RACCOONG_TAU non-zero
 * coefficients).  Used by both `thrc_sign` and `thrc_verify`.
 *
 * Algorithm (byte-exact with `ThRc_Core._chal_poly`):
 *   xof = SHAKE256(_hdr8('c', τ) || c_hash)
 *   while weight < τ:
 *       z    = xof.read(blen=2)            # 9 bits needed, blen=ceil(9/8)
 *       x    = u16_le(z)
 *       sign = x & 1
 *       idx  = (x >> 1) & 0xff
 *       if c[idx] == 0:
 *           c[idx] = 2*sign - 1
 *           weight += 1
 *
 * `out` is written iff the call returns true (which it always does for
 * valid arguments — SHAKE256 is unbounded so the rejection loop always
 * terminates within a few hundred reads).  Returns false only on null
 * arguments.
 */
#define RACCOONG_TAU 23u

dogecoin_bool raccoong_chal_poly(int8_t out[256],
                                 const uint8_t c_hash[RACCOONG_C_HASH_BYTES]);

/*
 * Vector hash (`_hash_vec` upstream).
 *
 * Hashes a domain-separating header, an arbitrary byte string `dat`, and a
 * flat vector `v` of Z_q coefficients to a `RACCOONG_C_HASH_BYTES` (32-byte)
 * digest.  Mirrors `ThRc_Core._hash_vec(dat, vec, ds)` for Raccoon-G-44
 * (q_byt = 7), where nested vectors of polynomials are flattened before
 * being fed in.
 *
 * Algorithm (byte-exact with upstream):
 *   xof = SHAKE256(_hdr24(ds, len(dat), 7 * v_len) || dat)
 *   for x in v:
 *       xof.update((x mod q).to_bytes(7, 'little'))
 *   out = xof.read(32)
 *
 * `ds` is a single ASCII byte ('H' for the canonical `Hash` use, but the
 * primitive is parameterized to also serve `Hcom` ('H') and future glue).
 * Coefficients are reduced mod RACCOONG_Q before encoding, matching the
 * upstream `int(x % RACC_Q).to_bytes(...)` convention so signed/centered
 * representatives round-trip cleanly.
 *
 * Returns false only on null `out`/`v` (when v_len > 0) or null `dat`
 * (when dat_len > 0); `dat_len` and `v_len` are otherwise unconstrained.
 */
dogecoin_bool raccoong_hash_vec(uint8_t out[RACCOONG_C_HASH_BYTES],
                                char ds,
                                const uint8_t* dat, size_t dat_len,
                                const uint64_t* v, size_t v_len);

/*
 * BUFF transcript hash `tr = H(vk)` (upstream `decode_vk` /
 * `_buff_mu` first stage).
 *
 * Algorithm (byte-exact with upstream):
 *   tr = SHAKE256(pk_bytes).read(crh)
 *
 * Where `pk_bytes` is the canonical serialized public key (length
 * RACCOONG_PK_BYTES = 16144 B for Raccoon-G-44) and `crh` is
 * RACCOONG_C_HASH_BYTES (32 B).  The `pk_len` parameter accepts any
 * length so callers can pre-compute `tr` over fragments or test
 * vectors, but production callers should pass the full serialized vk.
 *
 * Returns false only on null `out` or null `pk` (when pk_len > 0).
 */
dogecoin_bool raccoong_pk_hash(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t* pk, size_t pk_len);

/*
 * BUFF message digest `mu = H(tr || msg)` (upstream `_buff_mu`).
 *
 * Algorithm (byte-exact with upstream `ThRc_Api._buff_mu`):
 *   mu = SHAKE256(tr || msg).read(mu_sz)
 *
 * Where `tr` is the 32-byte transcript from `raccoong_pk_hash` and
 * `mu_sz = crh = RACCOONG_C_HASH_BYTES = 32`.  Together these compose
 * the BUFF (Binding Unforgeability Framework) input to the inner
 * signature: callers should pass `mu` to `thrc_sign` / `thrc_verify`
 * rather than the raw message.
 *
 * Returns false only on null `out` / null `tr` or null `msg`
 * (when msg_len > 0).
 */
dogecoin_bool raccoong_buff_mu(uint8_t out[RACCOONG_C_HASH_BYTES],
                               const uint8_t tr[RACCOONG_C_HASH_BYTES],
                               const uint8_t* msg, size_t msg_len);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_THRC_H */
