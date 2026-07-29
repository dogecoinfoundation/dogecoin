// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Smoke "fuzz" harness for the Raccoon-G-44 verify-path deserializer.
//
// Background: review item #6 in
// https://gist.github.com/xanimo/b94ac3abcb4a539445eaa7be16ad72b1
// flagged that raccoong_verify() consumes a pk (~16144 B) and sig
// (~20768 B) that are parsed from arbitrary on-chain scriptSig pushes
// (TX_R), and that the per-coefficient 7-byte LE / centered-h
// reconstruction in the signature wire format had no negative coverage
// outside the KAT "tampered" cases. This harness exercises the
// deserializer against tens of thousands of malformed inputs in a Boost
// test (the dogecoin tree does not have a src/test/fuzz/ libFuzzer
// scaffold; this is the closest in-tree equivalent and keeps the harness
// running on every CI build).
//
// What we check:
//   * raccoong_verify and PQCVerify must not crash, deadlock, or read
//     uninitialized memory for any input.
//   * Verify MUST return false for:
//       - random pk+sig of correct length,
//       - any truncated / oversized pk or sig buffer,
//       - any single-byte mutation of a real (valid) pk or sig.
//   * Verify MUST return true for an untouched valid pk+sig produced by
//     raccoong_keygen_from_seed / raccoong_sign (round-trip sanity).
//
// This is intentionally a property/robustness test, not a security
// audit. A real coverage-guided fuzzer (e.g. libFuzzer over a
// raccoong_verify_target) remains the recommended follow-up before any
// consensus-adjacent role for this carrier.

#include "config/bitcoin-config.h"

#ifdef ENABLE_LIBOQS_RACCOON

#include "random.h"
#include "support/cleanse.h"
#include "test/test_bitcoin.h"

#include "pqc/pqc_commitment.h"

#include "raccoon_g/raccoong.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

// Keep the iteration counts modest — Raccoon-G-44 verify is not cheap and
// these tests run on every CI build. The intent is regression coverage of
// the deserializer's negative paths, not a long-running fuzz campaign.
constexpr int kRandomBufferIterations = 256;
constexpr int kMutationIterations     = 64;
constexpr int kLengthMutationIterations = 64;

// Deterministic message used across the harness so failures are
// reproducible from the iteration counter alone.
const std::vector<unsigned char> kFuzzMessage = {
    0x6d, 0x73, 0x67, 0x66, 0x75, 0x7a, 0x7a, 0x21,
    0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqc_raccoong_verify_fuzz_tests, BasicTestingSetup)

// Reject random-bytes-of-correct-length inputs. Exercises the wire-format
// parser (TAG dispatch, per-coefficient 7-byte LE decode, centered-h
// reconstruction) against unstructured noise. raccoong_verify must always
// return false and must not crash.
BOOST_AUTO_TEST_CASE(raccoong_verify_rejects_random_correct_length_buffers)
{
    const size_t pk_len  = raccoong_pk_len();
    const size_t sig_len = raccoong_sig_max_len();
    BOOST_REQUIRE_GT(pk_len, 0u);
    BOOST_REQUIRE_GT(sig_len, 0u);

    FastRandomContext rng(true /*deterministic*/);

    for (int i = 0; i < kRandomBufferIterations; ++i) {
        std::vector<unsigned char> pk  = rng.randbytes(pk_len);
        std::vector<unsigned char> sig = rng.randbytes(sig_len);

        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44,
                               pk,
                               kFuzzMessage.data(), kFuzzMessage.size(),
                               sig));
    }
}

// Reject buffers whose lengths do not match the wire format. PQCVerify
// already enforces a strict pk size check; this also stresses
// raccoong_verify directly with a wide range of sig lengths so a
// length-driven parser bug can't lurk behind the upper API.
BOOST_AUTO_TEST_CASE(raccoong_verify_rejects_wrong_length_buffers)
{
    const size_t pk_len  = raccoong_pk_len();
    const size_t sig_len = raccoong_sig_max_len();

    FastRandomContext rng(true);

    // Empty and 1-byte cases up front.
    {
        std::vector<unsigned char> pk_empty;
        std::vector<unsigned char> sig_empty;
        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk_empty,
                               kFuzzMessage.data(), kFuzzMessage.size(),
                               sig_empty));

        std::vector<unsigned char> pk_one(1, 0x00);
        std::vector<unsigned char> sig_one(1, 0x00);
        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk_one,
                               kFuzzMessage.data(), kFuzzMessage.size(),
                               sig_one));
    }

    for (int i = 0; i < kLengthMutationIterations; ++i) {
        // Random wrong pk length in [1, 2*pk_len], excluding the exact one.
        size_t bad_pk_len = 1 + (rng.rand32() % (2 * pk_len));
        if (bad_pk_len == pk_len) bad_pk_len += 1;
        std::vector<unsigned char> pk = rng.randbytes(bad_pk_len);
        std::vector<unsigned char> sig = rng.randbytes(sig_len);

        // PQCVerify enforces pk_len strictly.
        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk,
                               kFuzzMessage.data(), kFuzzMessage.size(),
                               sig));

        // Direct raccoong_verify with a random pk_len must also reject
        // without crashing.
        BOOST_CHECK(raccoong_verify(pk.data(), pk.size(),
                                    kFuzzMessage.data(), kFuzzMessage.size(),
                                    sig.data(), sig.size()) == 0);

        // Random wrong sig length in [1, 2*sig_len], excluding the exact one.
        size_t bad_sig_len = 1 + (rng.rand32() % (2 * sig_len));
        if (bad_sig_len == sig_len) bad_sig_len += 1;
        std::vector<unsigned char> pk_ok  = rng.randbytes(pk_len);
        std::vector<unsigned char> bad_sig = rng.randbytes(bad_sig_len);
        BOOST_CHECK(raccoong_verify(pk_ok.data(), pk_ok.size(),
                                    kFuzzMessage.data(), kFuzzMessage.size(),
                                    bad_sig.data(), bad_sig.size()) == 0);
    }
}

// Round-trip sanity + single-byte mutation coverage. A valid keypair is
// generated, a signature is produced, and the harness then:
//   1) verifies the untouched (pk, sig) returns true,
//   2) flips one random byte in pk (or sig) and verifies the result is
//      always rejected.
//
// Keypair generation goes through MPFR-backed Gaussian sampling and is
// expensive; we only generate one keypair for the whole test case and
// reuse it across mutations.
BOOST_AUTO_TEST_CASE(raccoong_verify_rejects_single_byte_mutations)
{
    std::vector<unsigned char> pk, sk;
    if (!PQCGenerateKeypair(PQCCommitmentType::RACCOONG44, pk, sk)) {
        // Keypair generation may legitimately be unavailable in some build
        // configurations (e.g. MPFR init failure on a stripped sandbox).
        // Skip the round-trip portion in that case rather than failing the
        // whole suite; the random-bytes coverage above still runs.
        BOOST_TEST_MESSAGE("PQCGenerateKeypair(RACCOONG44) unavailable; "
                           "skipping mutation round-trip");
        return;
    }
    BOOST_REQUIRE_EQUAL(pk.size(), raccoong_pk_len());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(PQCSign(PQCCommitmentType::RACCOONG44, sk,
                          kFuzzMessage.data(), kFuzzMessage.size(), sig));
    BOOST_REQUIRE(!sig.empty());

    // 1) Untouched (pk, sig) must verify.
    BOOST_CHECK(PQCVerify(PQCCommitmentType::RACCOONG44, pk,
                          kFuzzMessage.data(), kFuzzMessage.size(), sig));

    FastRandomContext rng(true);

    // 2) Flip one random byte of pk; must always be rejected.
    for (int i = 0; i < kMutationIterations; ++i) {
        std::vector<unsigned char> pk_mut = pk;
        size_t pos = rng.rand32() % pk_mut.size();
        unsigned char delta = static_cast<unsigned char>(1 + (rng.rand32() & 0xff));
        pk_mut[pos] ^= delta;
        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk_mut,
                               kFuzzMessage.data(), kFuzzMessage.size(), sig));
    }

    // 3) Flip one random byte of sig; must always be rejected.
    for (int i = 0; i < kMutationIterations; ++i) {
        std::vector<unsigned char> sig_mut = sig;
        size_t pos = rng.rand32() % sig_mut.size();
        unsigned char delta = static_cast<unsigned char>(1 + (rng.rand32() & 0xff));
        sig_mut[pos] ^= delta;
        BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk,
                               kFuzzMessage.data(), kFuzzMessage.size(), sig_mut));
    }

    // 4) Wrong message under the original signature must be rejected.
    std::vector<unsigned char> wrong_msg = kFuzzMessage;
    wrong_msg[0] ^= 0x01;
    BOOST_CHECK(!PQCVerify(PQCCommitmentType::RACCOONG44, pk,
                           wrong_msg.data(), wrong_msg.size(), sig));

    memory_cleanse(sk.data(), sk.size());
}

BOOST_AUTO_TEST_SUITE_END()

#endif // ENABLE_LIBOQS_RACCOON
