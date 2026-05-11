/* sha2.h compat shim — exposes the C-shaped sha256_raw / hmac_sha256 /
 * hmac_sha512 API the libdogecoin Raccoon-G port expects, implemented in
 * raccoon_g/dogecoin_compat.cpp on top of dogecoin-core's CSHA256 /
 * CHMAC_SHA256 / CHMAC_SHA512 classes.
 */
#ifndef DOGECOIN_RACCOON_G_COMPAT_SHA2_H
#define DOGECOIN_RACCOON_G_COMPAT_SHA2_H

#include <stddef.h>
#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

#ifndef SHA256_DIGEST_LENGTH
#  define SHA256_DIGEST_LENGTH 32
#endif
#ifndef SHA512_DIGEST_LENGTH
#  define SHA512_DIGEST_LENGTH 64
#endif

void sha256_raw(const uint8_t* msg, size_t msglen, uint8_t out[SHA256_DIGEST_LENGTH]);

/* HMAC-SHA256 ----------------------------------------------------------
 *
 * The `impl` member below is an aligned opaque byte buffer sized to hold a
 * CHMAC_SHA256 instance (constructed in-place by hmac_sha256_init via
 * placement-new in raccoon_g/dogecoin_compat.cpp). Using inline storage
 * instead of a heap `new` keeps the lifetime symmetric with the C struct
 * itself, removes a heap allocation per HMAC, avoids the UB of letting
 * std::bad_alloc escape across an `extern "C"` boundary, and avoids the
 * leak that would otherwise occur on any code path that calls
 * hmac_sha256_init without a matching hmac_sha256_finalize.
 *
 * The buffer size is verified at compile time in dogecoin_compat.cpp via
 * static_assert against sizeof(CHMAC_SHA256). If a future libdogecoin
 * change grows CHMAC_SHA256 beyond these bounds the build will fail
 * loudly. The `_align` member ensures suitable alignment for the C++
 * object on all targeted platforms.
 */
#define DOGECOIN_RACCOON_G_COMPAT_HMAC_SHA256_STORAGE 256u
typedef struct hmac_sha256_context {
    unsigned char impl[DOGECOIN_RACCOON_G_COMPAT_HMAC_SHA256_STORAGE];
    /* Force at least uintmax_t / pointer alignment for the placement-new'd
       CHMAC_SHA256 object stored in `impl`. */
    union { void* _p; unsigned long long _u; } _align;
} hmac_sha256_context;

void hmac_sha256_init(hmac_sha256_context* hctx, const uint8_t* key, uint32_t keylen);
void hmac_sha256_write(hmac_sha256_context* hctx, const uint8_t* msg, uint32_t msglen);
void hmac_sha256_finalize(hmac_sha256_context* hctx, uint8_t* hmac);
void hmac_sha256(const uint8_t* key, size_t keylen,
                 const uint8_t* msg, size_t msglen,
                 uint8_t* hmac);

/* HMAC-SHA512 ----------------------------------------------------------
 * See the rationale on hmac_sha256_context above; the SHA-512 hasher is
 * larger so the inline storage budget is correspondingly larger. */
#define DOGECOIN_RACCOON_G_COMPAT_HMAC_SHA512_STORAGE 448u
typedef struct hmac_sha512_context {
    unsigned char impl[DOGECOIN_RACCOON_G_COMPAT_HMAC_SHA512_STORAGE];
    union { void* _p; unsigned long long _u; } _align;
} hmac_sha512_context;

void hmac_sha512_init(hmac_sha512_context* hctx, const uint8_t* key, uint32_t keylen);
void hmac_sha512_write(hmac_sha512_context* hctx, const uint8_t* msg, uint32_t msglen);
void hmac_sha512_finalize(hmac_sha512_context* hctx, uint8_t* hmac);
void hmac_sha512(const uint8_t* key, size_t keylen,
                 const uint8_t* msg, size_t msglen,
                 uint8_t* hmac);

LIBDOGECOIN_END_DECL

#endif /* DOGECOIN_RACCOON_G_COMPAT_SHA2_H */
