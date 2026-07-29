/* mem.h compat shim — see dogecoin.h in this directory. */
#ifndef DOGECOIN_RACCOON_G_COMPAT_MEM_H
#define DOGECOIN_RACCOON_G_COMPAT_MEM_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <dogecoin/dogecoin.h>

LIBDOGECOIN_BEGIN_DECL

static inline void* dogecoin_malloc(size_t size) { return malloc(size); }
static inline void* dogecoin_calloc(size_t count, size_t size) { return calloc(count, size); }
static inline void* dogecoin_realloc(void* ptr, size_t size) { return realloc(ptr, size); }
static inline void  dogecoin_free(void* ptr) { free(ptr); }

/* Best-effort memory wipe. The volatile pointer prevents the compiler from
 * eliding the store; this is the same shape as upstream libdogecoin's
 * memset_safe / dogecoin_mem_zero. */
static inline volatile void* dogecoin_mem_zero(volatile void* dst, size_t len)
{
    volatile unsigned char* p = (volatile unsigned char*)dst;
    while (len--) *p++ = 0;
    return dst;
}

LIBDOGECOIN_END_DECL

#endif /* DOGECOIN_RACCOON_G_COMPAT_MEM_H */
