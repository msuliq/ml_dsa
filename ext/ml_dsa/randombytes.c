/*
 * randombytes.c — OS-backed CSPRNG.
 *
 * Replaces PQClean's common/randombytes.c.  All randomness for keygen
 * and signing is generated before the GVL drop and passed explicitly
 * to the PQClean functions (seed_in for keygen, rnd_in for signing).
 * This file is only used for OS CSPRNG calls made while holding the GVL.
 */

#include "randombytes.h"

#if defined(_WIN32)
# include <windows.h>
# include <bcrypt.h>
# pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
# include <stdlib.h>   /* arc4random_buf */
#else
# include <errno.h>
# include <sys/random.h>  /* getrandom(2), Linux >= 3.17 */
#endif

void randombytes(uint8_t *x, size_t xlen)
{
#if defined(_WIN32)
    /* BCryptGenRandom takes ULONG; guard against truncation on 64-bit. */
    if (xlen > (size_t)ULONG_MAX) abort();
    NTSTATUS status = BCryptGenRandom(NULL, x, (ULONG)xlen,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) abort();

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(x, xlen);

#else
    /* Linux: loop on EINTR; getrandom never returns partial reads for <= 256 bytes */
    while (xlen > 0) {
        ssize_t ret = getrandom(x, xlen, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            /* getrandom failure is fatal — caller cannot continue safely */
            __builtin_trap();
        }
        x    += (size_t)ret;
        xlen -= (size_t)ret;
    }
#endif
}
