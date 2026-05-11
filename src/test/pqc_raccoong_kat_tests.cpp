// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license.
//
// Boost-test wrapper that drives the byte-exact Raccoon-G-44 KAT suite
// vendored verbatim from edtubbs/libdogecoin@0.1.5-dev-pqc-carrier. Each
// libdogecoin test driver (src/test/raccoong_*_tests.c) registers its
// failures through the U_TESTS_RUN / U_TESTS_FAIL counters declared in
// src/test/utest.h. Here we wire them into the existing Boost test suite
// so the carrier-level Raccoon-G implementation cannot ship without the
// upstream gate.

#include "config/bitcoin-config.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

// Counters consumed by the u_assert_* macros in src/test/utest.h.
extern "C" int U_TESTS_RUN = 0;
extern "C" int U_TESTS_FAIL = 0;

// Forward-declarations of the libdogecoin-style test drivers (kept verbatim
// under src/test/raccoong_*_tests.c).
extern "C" {
void test_raccoong_polyr(void);
void test_raccoong_ntt(void);
void test_raccoong_gaussian(void);
void test_raccoong_shake(void);
void test_raccoong_xof_sample_q(void);
void test_raccoong_matvec(void);
void test_raccoong_keygen_t(void);
void test_raccoong_keypair(void);
void test_raccoong_hd_derive(void);
void test_raccoong_signature_serialize(void);
void test_raccoong_hash_vec(void);
void test_raccoong_chal_poly(void);
void test_raccoong_buff_mu(void);
void test_raccoong_sign(void);
}

namespace {
struct ScopedRaccoongCounters {
    int run_before;
    int fail_before;
    ScopedRaccoongCounters() : run_before(U_TESTS_RUN), fail_before(U_TESTS_FAIL) {}
    int failures() const { return U_TESTS_FAIL - fail_before; }
};
} // namespace

#define RUN_RACCOONG_KAT(name)                                                  \
    do {                                                                        \
        ScopedRaccoongCounters _g;                                              \
        U_TESTS_RUN++;                                                          \
        test_##name();                                                          \
        BOOST_CHECK_EQUAL(_g.failures(), 0);                                    \
    } while (0)

BOOST_FIXTURE_TEST_SUITE(pqc_raccoong_kat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(raccoong_polyr_kat)         { RUN_RACCOONG_KAT(raccoong_polyr); }
BOOST_AUTO_TEST_CASE(raccoong_ntt_kat)           { RUN_RACCOONG_KAT(raccoong_ntt); }
BOOST_AUTO_TEST_CASE(raccoong_shake_kat)         { RUN_RACCOONG_KAT(raccoong_shake); }
BOOST_AUTO_TEST_CASE(raccoong_xof_sample_q_kat)  { RUN_RACCOONG_KAT(raccoong_xof_sample_q); }
BOOST_AUTO_TEST_CASE(raccoong_gaussian_kat)      { RUN_RACCOONG_KAT(raccoong_gaussian); }
BOOST_AUTO_TEST_CASE(raccoong_matvec_kat)        { RUN_RACCOONG_KAT(raccoong_matvec); }
BOOST_AUTO_TEST_CASE(raccoong_keygen_t_kat)      { RUN_RACCOONG_KAT(raccoong_keygen_t); }
BOOST_AUTO_TEST_CASE(raccoong_keypair_kat)       { RUN_RACCOONG_KAT(raccoong_keypair); }
BOOST_AUTO_TEST_CASE(raccoong_hd_derive_kat)     { RUN_RACCOONG_KAT(raccoong_hd_derive); }
BOOST_AUTO_TEST_CASE(raccoong_signature_serialize_kat)
                                                  { RUN_RACCOONG_KAT(raccoong_signature_serialize); }
BOOST_AUTO_TEST_CASE(raccoong_hash_vec_kat)      { RUN_RACCOONG_KAT(raccoong_hash_vec); }
BOOST_AUTO_TEST_CASE(raccoong_chal_poly_kat)     { RUN_RACCOONG_KAT(raccoong_chal_poly); }
BOOST_AUTO_TEST_CASE(raccoong_buff_mu_kat)       { RUN_RACCOONG_KAT(raccoong_buff_mu); }
BOOST_AUTO_TEST_CASE(raccoong_sign_kat)          { RUN_RACCOONG_KAT(raccoong_sign); }

BOOST_AUTO_TEST_SUITE_END()
