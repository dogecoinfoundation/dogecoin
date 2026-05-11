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

#include <test/utest.h>

#include <stdlib.h>
#include <string.h>

#include "raccoon_g/thrc.h"

#include "test/data/raccoong_sign_vectors.h"

void test_raccoong_sign(void)
{
    /* Derive the keypair from the pinned kg_seed; must agree with the
     * existing byte-exact keypair fixture (Session 7d). */
    uint8_t* pk = (uint8_t*)malloc(RACCOONG_PK_BYTES);
    uint8_t* sk = (uint8_t*)malloc(RACCOONG_SK_BYTES);
    u_assert_true(pk && sk);
    u_assert_true(thrc_keygen_from_seed(kRaccoongSignKgSeed,
                                        pk, RACCOONG_PK_BYTES,
                                        sk, RACCOONG_SK_BYTES));

    /* --- 1. Byte-exact sign against the upstream fixture. */
    uint8_t* sig = (uint8_t*)malloc(RACCOONG_SIG_BYTES);
    u_assert_true(sig != NULL);
    size_t sig_len = RACCOONG_SIG_BYTES;
    u_assert_true(thrc_sign_with_random(sk, RACCOONG_SK_BYTES,
                                        kRaccoongSignMsg,
                                        RACCOONG_SIGN_MSG_LEN,
                                        kRaccoongSignMasterRandom,
                                        sig, &sig_len));
    u_assert_int_eq((int)sig_len, (int)RACCOONG_SIG_BYTES);
    u_assert_int_eq((int)RACCOONG_SIGN_EXPECTED_SIG_LEN, (int)RACCOONG_SIG_BYTES);
    u_assert_int_eq(memcmp(sig, kRaccoongSignExpectedSig,
                           RACCOONG_SIG_BYTES), 0);

    /* --- 2. Verify accepts the freshly produced signature. */
    u_assert_true(thrc_verify(pk, RACCOONG_PK_BYTES,
                              kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                              sig, RACCOONG_SIG_BYTES));

    /* --- 3. Verify accepts the checked-in expected bytes too. */
    u_assert_true(thrc_verify(pk, RACCOONG_PK_BYTES,
                              kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                              kRaccoongSignExpectedSig, RACCOONG_SIG_BYTES));

    /* --- 4. Tampered-signature rejection.  Flip a bit in each region. */
    {
        /* (a) corrupt c_hash. */
        uint8_t* tampered = (uint8_t*)malloc(RACCOONG_SIG_BYTES);
        u_assert_true(tampered != NULL);
        memcpy(tampered, sig, RACCOONG_SIG_BYTES);
        tampered[0] ^= 0x01;
        u_assert_int_eq((int)thrc_verify(pk, RACCOONG_PK_BYTES,
                                         kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                                         tampered, RACCOONG_SIG_BYTES), 0);

        /* (b) corrupt a z coefficient near the start of the z region. */
        memcpy(tampered, sig, RACCOONG_SIG_BYTES);
        tampered[RACCOONG_C_HASH_BYTES] ^= 0x01;
        u_assert_int_eq((int)thrc_verify(pk, RACCOONG_PK_BYTES,
                                         kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                                         tampered, RACCOONG_SIG_BYTES), 0);

        /* (c) corrupt the last byte of h. */
        memcpy(tampered, sig, RACCOONG_SIG_BYTES);
        tampered[RACCOONG_SIG_BYTES - 1] ^= 0x80;
        u_assert_int_eq((int)thrc_verify(pk, RACCOONG_PK_BYTES,
                                         kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                                         tampered, RACCOONG_SIG_BYTES), 0);

        free(tampered);
    }

    /* --- 5. Verify rejects on wrong message. */
    {
        uint8_t wrong_msg[RACCOONG_SIGN_MSG_LEN];
        memcpy(wrong_msg, kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN);
        wrong_msg[0] ^= 0x01;
        u_assert_int_eq((int)thrc_verify(pk, RACCOONG_PK_BYTES,
                                         wrong_msg, RACCOONG_SIGN_MSG_LEN,
                                         sig, RACCOONG_SIG_BYTES), 0);
    }

    /* --- 6. Null / length-mismatch guards. */
    {
        size_t sl = RACCOONG_SIG_BYTES;
        u_assert_int_eq((int)thrc_sign_with_random(NULL, RACCOONG_SK_BYTES,
                                                    kRaccoongSignMsg,
                                                    RACCOONG_SIGN_MSG_LEN,
                                                    kRaccoongSignMasterRandom,
                                                    sig, &sl), 0);
        sl = RACCOONG_SIG_BYTES;
        u_assert_int_eq((int)thrc_sign_with_random(sk, RACCOONG_SK_BYTES,
                                                    kRaccoongSignMsg,
                                                    RACCOONG_SIGN_MSG_LEN,
                                                    NULL,
                                                    sig, &sl), 0);
        sl = RACCOONG_SIG_BYTES - 1; /* too small */
        u_assert_int_eq((int)thrc_sign_with_random(sk, RACCOONG_SK_BYTES,
                                                    kRaccoongSignMsg,
                                                    RACCOONG_SIGN_MSG_LEN,
                                                    kRaccoongSignMasterRandom,
                                                    sig, &sl), 0);

        u_assert_int_eq((int)thrc_verify(NULL, RACCOONG_PK_BYTES,
                                          kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                                          sig, RACCOONG_SIG_BYTES), 0);
        u_assert_int_eq((int)thrc_verify(pk, RACCOONG_PK_BYTES,
                                          kRaccoongSignMsg, RACCOONG_SIGN_MSG_LEN,
                                          sig, RACCOONG_SIG_BYTES - 1), 0);
    }

    free(sig);
    free(pk);
    free(sk);
}
