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
 * Key-derivation primitives used by Raccoon-G-44 seeded keygen.
 *
 * - HKDF-SHA256 (RFC 5869) on top of the in-tree `hmac_sha256` so we keep
 *   the only crypto dependency on the existing libdogecoin SHA-256.
 *
 * - NIST_KAT_DRBG (AES-256-CTR) mirroring upstream
 *   `p-11/lattice-hd-wallets@461a5ed9 src/raccoon/thrc-py/nist_kat_drbg.py`,
 *   on top of the existing constant-time AES from `src/ctaes.c`.
 *
 * Both helpers are deterministic given their seed inputs and are used
 * solely to reproduce upstream KAT byte streams; they MUST NOT be used as
 * general-purpose RNGs (call `dogecoin_random_bytes` for that).
 */

#include "keygen_kdf.h"

#include <string.h>

#include <dogecoin/ctaes.h>
#include <dogecoin/sha2.h>

#define HKDF_HASH_LEN 32u

/**
 * @brief RFC 5869 HKDF-SHA256.
 *
 * Byte-exact against pycryptodome `Crypto.Protocol.KDF.HKDF(ikm, out_len,
 * salt=None, hashmod=SHA256)`, which is what upstream
 * `raccoon_primitives._drbg_seed_from_entropy` calls.
 *
 * @param[out] out      Output buffer for derived key material.
 * @param[in]  out_len  Length of output (must be <= 255 * 32 = 8160 bytes).
 * @param[in]  ikm      Input keying material.
 * @param[in]  ikm_len  Length of IKM (must be > 0).
 * @param[in]  salt     Optional salt (may be NULL, in which case HashLen zero bytes are used).
 * @param[in]  salt_len Length of salt.
 * @param[in]  info     Optional info string (may be NULL if info_len == 0).
 * @param[in]  info_len Length of info.
 *
 * @return True on success, false on null out, oversize output, or zero-length IKM.
 */
dogecoin_bool raccoong_hkdf_sha256(uint8_t* out, size_t out_len,
                                   const uint8_t* ikm, size_t ikm_len,
                                   const uint8_t* salt, size_t salt_len,
                                   const uint8_t* info, size_t info_len)
{
    /* Defensive: HKDF is unsafe with empty IKM and the upstream caller
     * (`_drbg_seed_from_entropy`) always passes 32-byte entropy. */
    if (!out || ikm_len == 0 || !ikm) return false;
    if (out_len == 0) return true;
    if (out_len > 255u * HKDF_HASH_LEN) return false;
    if (info_len != 0 && !info) return false;

    // RFC 5869 §2.2: if salt is empty, use HashLen zero bytes.
    uint8_t zero_salt[HKDF_HASH_LEN];
    if (!salt || salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    // HKDF-Extract: prk = HMAC-SHA256(salt, ikm).
    uint8_t prk[HKDF_HASH_LEN];
    hmac_sha256(salt, (uint32_t)salt_len, ikm, ikm_len, prk);

    // HKDF-Expand: T(i) = HMAC-SHA256(prk, T(i-1) || info || i).
    uint8_t t_block[HKDF_HASH_LEN];
    size_t t_block_len = 0; // 0 on first iteration, HASH_LEN thereafter
    size_t produced = 0;
    for (uint8_t counter = 1; produced < out_len; ++counter) {
        hmac_sha256_context hctx;
        hmac_sha256_init(&hctx, prk, sizeof(prk));
        if (t_block_len) {
            hmac_sha256_write(&hctx, t_block, (uint32_t)t_block_len);
        }
        if (info_len) {
            hmac_sha256_write(&hctx, info, (uint32_t)info_len);
        }
        hmac_sha256_write(&hctx, &counter, 1);
        hmac_sha256_finalize(&hctx, t_block);
        t_block_len = HKDF_HASH_LEN;

        size_t take = out_len - produced;
        if (take > HKDF_HASH_LEN) take = HKDF_HASH_LEN;
        memcpy(out + produced, t_block, take);
        produced += take;

        // HKDF-Expand bound: counter <= ceil(L / HashLen) <= 255.
        if (counter == 255 && produced < out_len) {
            memset(prk, 0, sizeof(prk));
            memset(t_block, 0, sizeof(t_block));
            return false;
        }
    }

    memset(prk, 0, sizeof(prk));
    memset(t_block, 0, sizeof(t_block));
    return true;
}

/**
 * @brief Big-endian +1 on the 16-byte counter.
 *
 * Matching upstream's `int(...,'big')+1`.
 *
 * @param[in,out] ctr 16-byte counter to increment.
 */
static void drbg_increment_ctr(uint8_t ctr[16])
{
    for (int i = 15; i >= 0; --i) {
        if (++ctr[i] != 0) return;
    }
}

/**
 * @brief Internal: fill `out` with `num_bytes` AES-256-ECB(ctr++) bytes.
 *
 * Does not perform the trailing key+ctr refresh that `random_bytes` performs.
 * Matches upstream `NIST_KAT_DRBG.get_bytes`.
 *
 * @param[in,out] key       32-byte AES-256 key.
 * @param[in,out] ctr       16-byte counter.
 * @param[out]    out       Output buffer.
 * @param[in]     num_bytes Number of bytes to produce.
 */
static void drbg_get_bytes(uint8_t key[32], uint8_t ctr[16],
                           uint8_t* out, size_t num_bytes)
{
    AES256_ctx aes;
    AES256_init(&aes, key);
    size_t written = 0;
    uint8_t block[16];
    while (written < num_bytes) {
        drbg_increment_ctr(ctr);
        AES256_encrypt(&aes, 1, block, ctr);
        size_t take = num_bytes - written;
        if (take > 16) take = 16;
        memcpy(out + written, block, take);
        written += take;
    }
    memset(block, 0, sizeof(block));
    memset(&aes, 0, sizeof(aes));
}

/**
 * @brief Initialize the NIST KAT DRBG from a 48-byte seed.
 *
 * Upstream `__init__`:
 *   update = self.get_bytes(48)            # 48 bytes under (0, 0)
 *   update = update XOR seed
 *   self.key, self.ctr = update[:32], update[32:]
 *
 * @param[out] ctx  DRBG context to initialize.
 * @param[in]  seed 48-byte seed.
 */
void raccoong_nist_kat_drbg_init(raccoong_nist_kat_drbg* ctx,
                                 const uint8_t seed[48])
{
    memset(ctx->key, 0, sizeof(ctx->key));
    memset(ctx->ctr, 0, sizeof(ctx->ctr));

    uint8_t update[48];
    drbg_get_bytes(ctx->key, ctx->ctr, update, sizeof(update));
    for (size_t i = 0; i < sizeof(update); ++i) update[i] ^= seed[i];
    memcpy(ctx->key, update, 32);
    memcpy(ctx->ctr, update + 32, 16);
    memset(update, 0, sizeof(update));
}

/**
 * @brief Generate random bytes from the NIST KAT DRBG.
 *
 * Upstream `random_bytes`:
 *   output = self.get_bytes(num_bytes)
 *   update = self.get_bytes(48)
 *   self.key, self.ctr = update[:32], update[32:]
 *
 * @param[in,out] ctx       DRBG context.
 * @param[out]    out       Output buffer.
 * @param[in]     num_bytes Number of bytes to generate.
 */
void raccoong_nist_kat_drbg_random_bytes(raccoong_nist_kat_drbg* ctx,
                                         uint8_t* out, size_t num_bytes)
{
    if (out && num_bytes) {
        drbg_get_bytes(ctx->key, ctx->ctr, out, num_bytes);
    }
    uint8_t update[48];
    drbg_get_bytes(ctx->key, ctx->ctr, update, sizeof(update));
    memcpy(ctx->key, update, 32);
    memcpy(ctx->ctr, update + 32, 16);
    memset(update, 0, sizeof(update));
}
