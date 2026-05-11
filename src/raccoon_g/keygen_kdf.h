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

#ifndef LIBDOGECOIN_RACCOON_G_KEYGEN_KDF_H
#define LIBDOGECOIN_RACCOON_G_KEYGEN_KDF_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief RFC 5869 HKDF-SHA256.
 *
 * `salt` may be NULL (zeros of HashLen are used, per RFC 5869 §2.2).  `info` may be NULL (treated as empty).
 * `out_len` must satisfy `out_len <= 255 * HashLen` (= 8160 bytes).  Returns false on null `out`, oversize
 * output, or zero-length IKM (defensive).
 *
 * Byte-exact against pycryptodome `Crypto.Protocol.KDF.HKDF(ikm, out_len, salt=None, hashmod=SHA256)`,
 * which is what upstream `raccoon_primitives._drbg_seed_from_entropy` calls.
 *
 * @param[out] out      Output buffer for derived key material.
 * @param[in]  out_len  Length of output (must be <= 8160 bytes).
 * @param[in]  ikm      Input keying material.
 * @param[in]  ikm_len  Length of IKM.
 * @param[in]  salt     Optional salt (may be NULL).
 * @param[in]  salt_len Length of salt.
 * @param[in]  info     Optional info string (may be NULL).
 * @param[in]  info_len Length of info.
 *
 * @return True on success, false on invalid arguments.
 */
dogecoin_bool raccoong_hkdf_sha256(uint8_t* out, size_t out_len,
                                   const uint8_t* ikm, size_t ikm_len,
                                   const uint8_t* salt, size_t salt_len,
                                   const uint8_t* info, size_t info_len);

/**
 * @brief NIST KAT AES-256-CTR DRBG.
 *
 * The variant used by the upstream `nist_kat_drbg.py`.  Deterministic given a 48-byte seed;
 * produces arbitrary-length pseudo-random bytes via `random_bytes`.  Each `random_bytes` call
 * refreshes the (key, ctr) pair from the AES-CTR stream itself.
 *
 * This DRBG is NOT cryptographically suitable as a general PRNG — its sole role here is to
 * reproduce upstream KATs.  Callers that need entropy must use `dogecoin_random_bytes` instead.
 */
typedef struct {
    uint8_t key[32];
    uint8_t ctr[16];
} raccoong_nist_kat_drbg;

/**
 * @brief Initialize the NIST KAT DRBG.
 *
 * @param[out] ctx  DRBG context to initialize.
 * @param[in]  seed 48-byte seed.
 */
void raccoong_nist_kat_drbg_init(raccoong_nist_kat_drbg* ctx,
                                 const uint8_t seed[48]);

/**
 * @brief Generate random bytes from the NIST KAT DRBG.
 *
 * @param[in,out] ctx       DRBG context.
 * @param[out]    out       Output buffer.
 * @param[in]     num_bytes Number of bytes to generate.
 */
void raccoong_nist_kat_drbg_random_bytes(raccoong_nist_kat_drbg* ctx,
                                         uint8_t* out, size_t num_bytes);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_KEYGEN_KDF_H */
