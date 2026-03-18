#ifndef ML_DSA_RANDOMBYTES_H
#define ML_DSA_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

/*
 * Generate xlen random bytes into x using the OS CSPRNG:
 *   - Linux:        getrandom(2)
 *   - macOS/BSD:    arc4random_buf(3)
 *   - Windows:      BCryptGenRandom
 */
void randombytes(uint8_t *x, size_t xlen);

#endif /* ML_DSA_RANDOMBYTES_H */
