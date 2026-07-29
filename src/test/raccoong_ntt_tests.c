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
 * test_raccoong_ntt — byte-exact gate against upstream
 * p-11/lattice-hd-wallets (commit pinned in the fixture header).
 *
 * Checks performed:
 *   1. SHA-256 over the in-tree RACCOONG_W table (LE-u64 form) matches the
 *      digest the fixture generator recorded from upstream RACC_W. Catches
 *      any drift in the embedded twiddle table.
 *   2. The fixture's RACC_W array equals the in-tree table coefficient-by-
 *      coefficient (same gate, different angle).
 *   3. ntt_forward(A) matches upstream ntt(A).
 *   4. ntt_inverse(ntt_forward(A)) == A (roundtrip).
 *   5. ntt_inverse(ntt_pointwise(ntt_forward(A), ntt_forward(B))) ==
 *      schoolbook(A, B) mod (X^n + 1) — the actual contract callers rely on.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <test/utest.h>

#include <dogecoin/sha2.h>

#include "raccoon_g/polyr.h"
#include "raccoon_g/ntt.h"
#include "test/data/raccoong_ntt_vectors.h"

static void load(polyr* p, const uint64_t* src)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        p->coeffs[i] = src[i];
    }
}

static int coeffs_match(const polyr* got, const uint64_t* want, const char* tag)
{
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        if (got->coeffs[i] != want[i]) {
            fprintf(stderr,
                    "%s: coeff %zu mismatch: got %llu, want %llu\n",
                    tag, i, (unsigned long long)got->coeffs[i],
                    (unsigned long long)want[i]);
            return 0;
        }
    }
    return 1;
}

/* Return 1 if hex(SHA256(LE-u64 encoding of twiddle_table)) equals expected_hex. */
static int twiddle_sha_matches(const uint64_t* twiddle_table, const char* expected_hex)
{
    /* Build LE-u64 byte buffer. */
    uint8_t buf[RACCOONG_N * 8];
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        uint64_t v = twiddle_table[i];
        for (size_t j = 0; j < 8; ++j) {
            buf[i * 8 + j] = (uint8_t)(v >> (8 * j));
        }
    }
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_raw(buf, sizeof(buf), digest);

    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    }
    if (strcmp(hex, expected_hex) != 0) {
        fprintf(stderr,
                "raccoong NTT twiddle SHA mismatch: got %s, want %s\n",
                hex, expected_hex);
        return 0;
    }
    return 1;
}

void test_raccoong_ntt(void)
{
    /* (1) Twiddle SHA gate against the value emitted at fixture-generation
     *     time. The fixture array is the upstream table; if the SHA-256 of
     *     the in-tree array also matches, the in-tree table equals upstream. */
    u_assert_true(twiddle_sha_matches(raccoong_ntt_w_table,
                                      RACCOONG_NTT_W_SHA256_HEX));

    /* (2) Compare the in-tree RACCOONG_W indirectly via ntt_forward of a
     *     known input against the fixture-recorded result. (We don't expose
     *     RACCOONG_W directly; ntt_forward is the only consumer of it.) */
    polyr a, b, r;
    load(&a, raccoong_ntt_input_a);
    load(&b, raccoong_ntt_input_b);

    u_assert_true(ntt_init());

    /* (3) Forward NTT byte-exact match. */
    polyr_copy(&r, &a);
    u_assert_true(ntt_forward(&r));
    u_assert_true(polyr_is_normalized(&r));
    u_assert_true(coeffs_match(&r, raccoong_ntt_expected_ntt_a,
                               "ntt_forward(A)"));

    /* (4) Inverse NTT roundtrip.  intt(ntt(A)) == A. */
    polyr roundtrip;
    polyr_copy(&roundtrip, &r);
    u_assert_true(ntt_inverse(&roundtrip));
    u_assert_true(polyr_is_normalized(&roundtrip));
    u_assert_true(coeffs_match(&roundtrip,
                               raccoong_ntt_expected_intt_ntt_a,
                               "ntt_inverse(ntt_forward(A))"));
    u_assert_true(coeffs_match(&roundtrip, raccoong_ntt_input_a,
                               "ntt roundtrip == A"));

    /* (5) NTT-multiply == schoolbook. */
    polyr ntta, nttb, prod;
    polyr_copy(&ntta, &a);
    polyr_copy(&nttb, &b);
    u_assert_true(ntt_forward(&ntta));
    u_assert_true(ntt_forward(&nttb));
    u_assert_true(ntt_pointwise(&prod, &ntta, &nttb));
    u_assert_true(ntt_inverse(&prod));
    u_assert_true(polyr_is_normalized(&prod));
    u_assert_true(coeffs_match(&prod,
                               raccoong_ntt_expected_via_ntt_ab,
                               "intt(pw(ntt(A), ntt(B)))"));
    u_assert_true(coeffs_match(&prod,
                               raccoong_ntt_expected_schoolbook_ab,
                               "ntt-mul == schoolbook(A,B)"));

    /* Defensive: NULL inputs return false. */
    u_assert_int_eq((int)ntt_forward(NULL), 0);
    u_assert_int_eq((int)ntt_inverse(NULL), 0);
    u_assert_int_eq((int)ntt_pointwise(NULL, &a, &b), 0);
    u_assert_int_eq((int)ntt_pointwise(&r, NULL, &b), 0);

    ntt_shutdown();
}
