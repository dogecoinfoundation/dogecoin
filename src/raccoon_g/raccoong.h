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

#ifndef LIBDOGECOIN_RACCOON_G_RACCOONG_H
#define LIBDOGECOIN_RACCOON_G_RACCOONG_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/**
 * @brief Raccoon-G-44 parameter set.
 *
 * These constants must agree byte-for-byte with the upstream Python reference
 * (p-11/lattice-hd-wallets, see src/raccoon_g/README.md for the pinned commit).
 * They are intentionally NOT yet defined in this skeleton commit; defining them
 * before the polyr/ntt port lands would risk encoding wrong values into headers
 * that downstream code starts to depend on. They are filled in Session 3 along
 * with the polynomial arithmetic.
 *
 * Public sizes that the libdogecoin API already exposes (DOGECOIN_PQC_RACCOON_*
 * in include/dogecoin/pqc_raccoon.h) are unchanged.
 */

/** @brief Backend availability probe. Returns true once the in-tree implementation is complete. */
dogecoin_bool raccoong_is_ready(void);

/** @brief Seed-deterministic keypair generation. seed must be 32 bytes. */
dogecoin_bool raccoong_keygen_from_seed(const uint8_t seed[32],
                                        uint8_t* pk_out, size_t pk_len,
                                        uint8_t* sk_out, size_t sk_len);

/** @brief Sign a message. */
dogecoin_bool raccoong_sign(const uint8_t* sk, size_t sk_len,
                            const uint8_t* msg, size_t msg_len,
                            uint8_t* sig_out, size_t* sig_len_inout);

/** @brief Verify a signature. */
dogecoin_bool raccoong_verify(const uint8_t* pk, size_t pk_len,
                              const uint8_t* msg, size_t msg_len,
                              const uint8_t* sig, size_t sig_len);

/** @brief BIP-32 style hierarchical derivation (HMAC-SHA512 keyed by chaincode). */
dogecoin_bool raccoong_hd_derive_priv(const uint8_t* parent_sk, size_t parent_sk_len,
                                      const uint8_t* parent_pk, size_t parent_pk_len,
                                      const uint8_t chaincode[32],
                                      uint32_t index, dogecoin_bool hardened,
                                      uint8_t* child_sk_out, size_t child_sk_len,
                                      uint8_t* child_pk_out, size_t child_pk_len);

/** @brief Derive public child key (unhardened only). */
dogecoin_bool raccoong_hd_derive_pub(const uint8_t* parent_pk, size_t parent_pk_len,
                                     const uint8_t chaincode[32],
                                     uint32_t index,
                                     uint8_t* child_pk_out, size_t child_pk_len);

/** @brief Reported wire sizes. Return 0 until the parameter set is finalized. */
size_t raccoong_pk_len(void);
size_t raccoong_sk_len(void);
size_t raccoong_sig_max_len(void);

LIBDOGECOIN_END_DECL

#endif /* LIBDOGECOIN_RACCOON_G_RACCOONG_H */
