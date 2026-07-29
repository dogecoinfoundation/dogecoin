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
 * Negacyclic NTT for Z_q[X]/(X^n+1) at the Raccoon-G-44 parameters
 * (n=256, q=562949953438721). Ported 1:1 from upstream
 * src/raccoon/thrc-py/polyr.py at commit
 * 461a5ed9b6d57e3bf8c381be3bb79325ab21d906.
 *
 * Twiddle table: bit-reversed precomputed RACC_W from upstream. Its SHA-256
 * over the LE-u64 encoding is recorded in src/raccoon_g/README.md and gated
 * by test/raccoong_ntt_tests.c (test_raccoong_ntt) against
 * test/data/raccoong_ntt_vectors.h (which is regenerated from upstream).
 */

#include "ntt.h"

#include <stddef.h>

/* Pre-computed negacyclic NTT twiddle factors for n=256 over q=562949953438721.
 * In-tree symbol is `RACCOONG_W`; in upstream Python it is `RACC_W`. The
 * values are byte-for-byte identical, verified by RACCOONG_NTT_W_SHA256_HEX
 * = 007cf593d0147d705768503556f096e25ac65b9837cf99d2bd7a43b251f0df36. */
static const uint64_t RACCOONG_W[RACCOONG_N] = {
    1ULL, 296906434238998ULL, 181781957684384ULL, 191406895362494ULL, 96916284855744ULL, 527770056491899ULL, 390596018438458ULL, 144417730180852ULL,
    343797132273457ULL, 536922258790245ULL, 433569942776299ULL, 72305240403475ULL, 441345718559494ULL, 468611498753924ULL, 558875681544363ULL, 482537422310465ULL,
    215497411143094ULL, 467415149987830ULL, 219454469693684ULL, 97777236770764ULL, 478012315927396ULL, 425728544469615ULL, 172120307892393ULL, 72251592568563ULL,
    437547177204445ULL, 340362439625502ULL, 496623572145823ULL, 176373822073846ULL, 30602652245083ULL, 73332893405541ULL, 237772615036862ULL, 428072708517192ULL,
    135948448084008ULL, 401282176971642ULL, 514741044692888ULL, 249537811936473ULL, 470331420435140ULL, 434078931748102ULL, 352404743643638ULL, 195737947455592ULL,
    434379608476017ULL, 507187753812509ULL, 263346828390015ULL, 374671504552198ULL, 44719881044138ULL, 184849065156583ULL, 209754917943589ULL, 188761456810925ULL,
    279596747062554ULL, 456084299944347ULL, 230333756607878ULL, 293918424792913ULL, 523070715809650ULL, 388512944219688ULL, 386258909038340ULL, 438502123127754ULL,
    136375741794045ULL, 555857235431026ULL, 13508910611294ULL, 483335714399441ULL, 377798815075217ULL, 501131695473255ULL, 39076332254779ULL, 427136680714875ULL,
    245762989047718ULL, 433450943117213ULL, 455704413783881ULL, 506148755142929ULL, 130957910506195ULL, 443377888433476ULL, 221545866880358ULL, 427229297404741ULL,
    550855861998066ULL, 540971223035962ULL, 137617862180852ULL, 175372814902870ULL, 13975467385753ULL, 24965657230597ULL, 522436305816199ULL, 374327376745901ULL,
    544920610901674ULL, 326268776923754ULL, 276693455910792ULL, 142619409869871ULL, 313644087070365ULL, 274900382211365ULL, 280350971755833ULL, 519243703332558ULL,
    129232637389137ULL, 246030940334002ULL, 46545494674471ULL, 57043433830445ULL, 184925167707926ULL, 469155884095523ULL, 503182856499133ULL, 23814644835421ULL,
    475559647097777ULL, 34073549943749ULL, 316691401824261ULL, 399215566287434ULL, 539897402266692ULL, 315255324521502ULL, 173125366109746ULL, 124538868681078ULL,
    71461040333485ULL, 73937466223620ULL, 54380101038198ULL, 398747125630441ULL, 448462236563893ULL, 140761532104851ULL, 178622113504236ULL, 497493031236821ULL,
    419081134729643ULL, 60377106249605ULL, 251359295165389ULL, 347898082741553ULL, 384688472728281ULL, 297054159475731ULL, 93380565089038ULL, 500675344171667ULL,
    284070877540961ULL, 358996607064300ULL, 525976674073262ULL, 260032344045148ULL, 17068528300956ULL, 269585966230833ULL, 298565133282905ULL, 416568378662712ULL,
    171069777926290ULL, 349324998749994ULL, 259049291682050ULL, 184600346861179ULL, 432246427366052ULL, 288989901132148ULL, 355883147610296ULL, 256312858090165ULL,
    542194995533580ULL, 408452938138445ULL, 373445388319357ULL, 274193355487517ULL, 79550316493975ULL, 233882663516073ULL, 181989055589022ULL, 121703131609392ULL,
    107234486079216ULL, 550464159571222ULL, 458592507839679ULL, 352024591642451ULL, 266690484267974ULL, 496941637675982ULL, 438380120748369ULL, 397572140302510ULL,
    58181436514136ULL, 486719248706067ULL, 206536278983011ULL, 180604527078985ULL, 478670103441868ULL, 26251809161300ULL, 150600676894001ULL, 276367279114637ULL,
    56399468039126ULL, 436508531710035ULL, 249137198966024ULL, 34372922093606ULL, 427906659988979ULL, 4592833677263ULL, 433888507899784ULL, 134098906412161ULL,
    369334384396631ULL, 298728342283482ULL, 424473914662438ULL, 527464202413984ULL, 341271781778061ULL, 81081214712098ULL, 369307190539312ULL, 526658785439601ULL,
    324042382005955ULL, 291578765791809ULL, 319083982706637ULL, 278133882827943ULL, 218112738633496ULL, 261726605062989ULL, 420615368297607ULL, 184166878949130ULL,
    323810824421245ULL, 192283000615540ULL, 172362130304804ULL, 139132034756151ULL, 138328555557310ULL, 87355951296240ULL, 425050139960683ULL, 202539666888605ULL,
    529612860528803ULL, 3972258931452ULL, 95747869031130ULL, 134884673824368ULL, 461229474958967ULL, 372614880404995ULL, 75112314349665ULL, 175651329769148ULL,
    531273365329484ULL, 187005993903311ULL, 495191416407645ULL, 283402266119023ULL, 269581130095040ULL, 410686341484674ULL, 93344412371069ULL, 534690300822244ULL,
    268118300630235ULL, 256200697475194ULL, 87921460884356ULL, 292205602599711ULL, 141523556695052ULL, 333262844005394ULL, 417784557684255ULL, 130861630039851ULL,
    440797410820196ULL, 155010276897247ULL, 236872209573035ULL, 311715275406078ULL, 340915559899885ULL, 405291498688271ULL, 404035139068240ULL, 141329712471110ULL,
    354314985867238ULL, 449882612326041ULL, 334944106229028ULL, 193118827534695ULL, 534175344893290ULL, 454473183423671ULL, 142830197859598ULL, 262685363539882ULL,
    27346571217940ULL, 241681832106042ULL, 42867263645174ULL, 183486179335091ULL, 447396338088031ULL, 7318421462452ULL, 192260433830520ULL, 331813242208782ULL,
    498783959776516ULL, 177666180607119ULL, 386442316586840ULL, 9819396035471ULL, 48683959880399ULL, 93224787374408ULL, 461567322571994ULL, 327753888849199ULL,
    419642897253790ULL, 307218422705703ULL, 534306751173139ULL, 30412449240137ULL, 392781217659613ULL, 15316548626552ULL, 21923346096342ULL, 320756038422460ULL,
};

/**
 * @brief Stateless init stub.
 *
 * Stateless. ntt_init/ntt_shutdown are kept to honor the public stub API but
 * are no-ops because the twiddle table is a static const at link time.
 *
 * @return Always returns true.
 */
dogecoin_bool ntt_init(void)    { return true; }

/**
 * @brief Stateless shutdown stub.
 */
void          ntt_shutdown(void) {}

/* Modular helpers: a, b in [0, q); a*b uses 128-bit accumulator. */
static inline uint64_t mul_mod_q(uint64_t a, uint64_t b)
{
    __uint128_t prod = (__uint128_t)a * (__uint128_t)b;
    return (uint64_t)(prod % RACCOONG_Q);
}

static inline uint64_t add_mod_q(uint64_t a, uint64_t b)
{
    uint64_t s = a + b; // a + b < 2q < 2^51, no overflow
    return s >= RACCOONG_Q ? s - RACCOONG_Q : s;
}

static inline uint64_t sub_mod_q(uint64_t a, uint64_t b)
{
    // a + q - b < 2q < 2^51
    uint64_t s = a + RACCOONG_Q - b;
    return s >= RACCOONG_Q ? s - RACCOONG_Q : s;
}

/**
 * @brief Forward NTT transform on a polynomial.
 *
 * Mirrors upstream:
 *   l = n//2; wi = 0
 *   while l > 0:
 *       for i in range(0, n, 2*l):
 *           wi += 1; z = w[wi]
 *           for j in range(i, i + l):
 *               x = f[j]; y = (f[j + l] * z) % q
 *               f[j]     = (x + y) % q
 *               f[j + l] = (x - y) % q
 *       l >>= 1
 *
 * @param[in,out] r Polynomial to transform in-place.
 *
 * @return True on success, false if r is NULL.
 */
dogecoin_bool ntt_forward(polyr* r)
{
    if (!r) {
        return false;
    }
    uint64_t* f = r->coeffs;
    size_t l = RACCOONG_N / 2;
    size_t wi = 0;
    while (l > 0) {
        for (size_t i = 0; i < RACCOONG_N; i += 2 * l) {
            wi++;
            const uint64_t z = RACCOONG_W[wi];
            for (size_t j = i; j < i + l; ++j) {
                const uint64_t x = f[j];
                const uint64_t y = mul_mod_q(f[j + l], z);
                f[j]     = add_mod_q(x, y);
                f[j + l] = sub_mod_q(x, y);
            }
        }
        l >>= 1;
    }
    return true;
}

/**
 * @brief Inverse NTT transform on a polynomial.
 *
 * Mirrors upstream:
 *   l = 1; wi = n
 *   while l < n:
 *       for i in range(0, n, 2*l):
 *           wi -= 1; z = w[wi]
 *           for j in range(i, i + l):
 *               x = f[j]; y = f[j + l]
 *               f[j]     = (x + y) % q
 *               f[j + l] = (z * (y - x)) % q
 *       l <<= 1
 *   for i in range(n): f[i] = (ni * f[i]) % q
 *
 * @param[in,out] r Polynomial to transform in-place.
 *
 * @return True on success, false if r is NULL.
 */
dogecoin_bool ntt_inverse(polyr* r)
{
    if (!r) {
        return false;
    }
    uint64_t* f = r->coeffs;
    size_t l = 1;
    size_t wi = RACCOONG_N;
    while (l < RACCOONG_N) {
        for (size_t i = 0; i < RACCOONG_N; i += 2 * l) {
            wi--;
            const uint64_t z = RACCOONG_W[wi];
            for (size_t j = i; j < i + l; ++j) {
                const uint64_t x = f[j];
                const uint64_t y = f[j + l];
                f[j]     = add_mod_q(x, y);
                f[j + l] = mul_mod_q(z, sub_mod_q(y, x));
            }
        }
        l <<= 1;
    }
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        f[i] = mul_mod_q(RACCOONG_NI, f[i]);
    }
    return true;
}

/**
 * @brief Pointwise multiplication of two polynomials in NTT domain.
 *
 * Identical to polyr_mul_pointwise: kept as part of the NTT API for
 * call-site readability (callers that already work in NTT domain).
 *
 * @param[out] r Result polynomial.
 * @param[in]  a First operand.
 * @param[in]  b Second operand.
 *
 * @return True on success, false if any argument is NULL.
 */
dogecoin_bool ntt_pointwise(polyr* r, const polyr* a, const polyr* b)
{
    if (!r || !a || !b) {
        return false;
    }
    for (size_t i = 0; i < RACCOONG_N; ++i) {
        r->coeffs[i] = mul_mod_q(a->coeffs[i], b->coeffs[i]);
    }
    return true;
}
