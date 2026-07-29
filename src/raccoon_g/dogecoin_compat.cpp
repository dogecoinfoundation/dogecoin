// Compatibility implementation for the libdogecoin Raccoon-G port.
//
// Implements the C-shaped sha256_raw / hmac_sha256 / hmac_sha512 API and the
// dogecoin_random_bytes thunk that the upstream port (kept verbatim under
// src/raccoon_g/) expects, on top of this tree's existing C++ crypto.
//
// The HMAC entry points use placement-new into inline aligned storage
// embedded in the C `hmac_sha*_context` structs declared in
// raccoon_g/dogecoin/sha2.h. This avoids two earlier hazards:
//   - heap `new` from inside `extern "C"` could throw std::bad_alloc, which
//     is UB to propagate across the C/C++ FFI boundary; and
//   - any code path that called `_init` without a matching `_finalize`
//     would leak the heap-allocated hasher.

#include "raccoon_g/dogecoin/sha2.h"
#include "raccoon_g/dogecoin/random.h"

#include "crypto/sha256.h"
#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "random.h"
#include "support/cleanse.h"

#include <climits>
#include <cstddef>
#include <new>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Compile-time guarantees that the inline `impl` storage in the C contexts
// is large enough and properly aligned to placement-construct the C++
// hasher objects. If a future libdogecoin change grows these classes past
// the budget defined in sha2.h, the build will fail loudly here.
static_assert(sizeof(CHMAC_SHA256) <= sizeof(((hmac_sha256_context*)0)->impl),
              "hmac_sha256_context.impl too small for CHMAC_SHA256");
static_assert(alignof(CHMAC_SHA256) <= alignof(hmac_sha256_context),
              "hmac_sha256_context alignment insufficient for CHMAC_SHA256");
static_assert(sizeof(CHMAC_SHA512) <= sizeof(((hmac_sha512_context*)0)->impl),
              "hmac_sha512_context.impl too small for CHMAC_SHA512");
static_assert(alignof(CHMAC_SHA512) <= alignof(hmac_sha512_context),
              "hmac_sha512_context alignment insufficient for CHMAC_SHA512");

// ---- SHA-256 raw --------------------------------------------------------
extern "C" void sha256_raw(const uint8_t* msg, size_t msglen, uint8_t out[SHA256_DIGEST_LENGTH])
{
    CSHA256 h;
    h.Write(msg, msglen);
    h.Finalize(out);
}

// ---- HMAC-SHA-256 -------------------------------------------------------
extern "C" void hmac_sha256_init(hmac_sha256_context* hctx, const uint8_t* key, uint32_t keylen)
{
    // Placement-new into the caller-provided inline storage. Cannot throw
    // bad_alloc (no heap allocation) so it is safe to be called across the
    // extern "C" boundary.
    new (static_cast<void*>(hctx->impl)) CHMAC_SHA256(key, keylen);
}

extern "C" void hmac_sha256_write(hmac_sha256_context* hctx, const uint8_t* msg, uint32_t msglen)
{
    reinterpret_cast<CHMAC_SHA256*>(hctx->impl)->Write(msg, msglen);
}

extern "C" void hmac_sha256_finalize(hmac_sha256_context* hctx, uint8_t* hmac)
{
    CHMAC_SHA256* h = reinterpret_cast<CHMAC_SHA256*>(hctx->impl);
    h->Finalize(hmac);
    h->~CHMAC_SHA256();
    // Wipe the inline scratch so any residual key/state material does not
    // outlive the caller-owned context.
    memory_cleanse(hctx->impl, sizeof(hctx->impl));
}

extern "C" void hmac_sha256(const uint8_t* key, size_t keylen,
                            const uint8_t* msg, size_t msglen,
                            uint8_t* hmac)
{
    CHMAC_SHA256 h(key, keylen);
    h.Write(msg, msglen);
    h.Finalize(hmac);
}

// ---- HMAC-SHA-512 -------------------------------------------------------
extern "C" void hmac_sha512_init(hmac_sha512_context* hctx, const uint8_t* key, uint32_t keylen)
{
    new (static_cast<void*>(hctx->impl)) CHMAC_SHA512(key, keylen);
}

extern "C" void hmac_sha512_write(hmac_sha512_context* hctx, const uint8_t* msg, uint32_t msglen)
{
    reinterpret_cast<CHMAC_SHA512*>(hctx->impl)->Write(msg, msglen);
}

extern "C" void hmac_sha512_finalize(hmac_sha512_context* hctx, uint8_t* hmac)
{
    CHMAC_SHA512* h = reinterpret_cast<CHMAC_SHA512*>(hctx->impl);
    h->Finalize(hmac);
    h->~CHMAC_SHA512();
    memory_cleanse(hctx->impl, sizeof(hctx->impl));
}

extern "C" void hmac_sha512(const uint8_t* key, size_t keylen,
                            const uint8_t* msg, size_t msglen,
                            uint8_t* hmac)
{
    CHMAC_SHA512 h(key, keylen);
    h.Write(msg, msglen);
    h.Finalize(hmac);
}

// ---- random -------------------------------------------------------------
extern "C" dogecoin_bool dogecoin_random_bytes(uint8_t* buf, uint32_t len, uint8_t /*update_seed*/)
{
    if (buf == nullptr) return 0;
    // GetStrongRandBytes takes a signed int length; defensively reject any
    // request that would not fit so the cast below cannot wrap to a
    // negative value. The Raccoon-G port only ever asks for small fixed
    // buffers (32-byte seeds, etc.) so this is purely a safety net.
    if (len > static_cast<uint32_t>(INT_MAX)) return 0;
    GetStrongRandBytes(buf, static_cast<int>(len));
    return 1;
}
