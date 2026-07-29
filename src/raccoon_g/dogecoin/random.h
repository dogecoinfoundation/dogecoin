/* random.h compat shim — backed by GetStrongRandBytes() from dogecoin-core. */
#ifndef DOGECOIN_RACCOON_G_COMPAT_RANDOM_H
#define DOGECOIN_RACCOON_G_COMPAT_RANDOM_H

#include <stdint.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

/* Mirrors the libdogecoin signature so the upstream Raccoon-G sources compile
 * verbatim. update_seed is accepted for ABI compatibility and ignored — the
 * underlying GetStrongRandBytes() in random.cpp is already auto-reseeding. */
dogecoin_bool dogecoin_random_bytes(uint8_t* buf, uint32_t len, uint8_t update_seed);

LIBDOGECOIN_END_DECL

#endif /* DOGECOIN_RACCOON_G_COMPAT_RANDOM_H */
