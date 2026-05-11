/* Compatibility shim for the libdogecoin in-tree Raccoon-G-44 port.
 *
 * The Raccoon-G-44 C sources under src/raccoon_g/ were ported verbatim from
 * edtubbs/libdogecoin@0.1.5-dev-pqc-carrier. To keep the upstream sources
 * unmodified (so they remain trivially diffable against libdogecoin and the
 * upstream Python reference), this directory provides stub headers that map
 * the `<dogecoin/...>` includes onto the dogecoin-core (this tree's) crypto
 * and memory primitives.
 */
#ifndef DOGECOIN_RACCOON_G_COMPAT_DOGECOIN_H
#define DOGECOIN_RACCOON_G_COMPAT_DOGECOIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#  define LIBDOGECOIN_BEGIN_DECL extern "C" {
#  define LIBDOGECOIN_END_DECL }
#else
#  define LIBDOGECOIN_BEGIN_DECL /* empty */
#  define LIBDOGECOIN_END_DECL   /* empty */
#endif

#ifndef LIBDOGECOIN_API
#  define LIBDOGECOIN_API
#endif

typedef uint8_t dogecoin_bool;

#endif /* DOGECOIN_RACCOON_G_COMPAT_DOGECOIN_H */
