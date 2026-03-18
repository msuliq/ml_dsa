/*
 * ml_dsa_impl_template.h — Parametric amalgamation template.
 *
 * Single source of truth for which PQClean .c files are included per
 * parameter set.  Each ml_dsa_NN_impl.c defines ML_DSA_PS to its
 * parameter set code (44, 65, or 87) and includes this template.
 *
 * Including .c files causes GCC/Clang to resolve their quoted includes
 * (e.g. #include "params.h") relative to the directory of the included
 * file, so each variant picks up its own params.h automatically.
 * fips202.h and randombytes.h are resolved via -I$(srcdir) (ext/ml_dsa/).
 *
 * To add a new PQClean source file, add it ONCE here — all three
 * parameter sets pick it up automatically.
 */

#ifndef ML_DSA_PS
#  error "ML_DSA_PS must be defined before including ml_dsa_impl_template.h"
#endif

/* Token-paste helpers to build paths like ml-dsa-44/clean/ntt.c */
#define ML_DSA_PASTE2(a, b) a ## b
#define ML_DSA_PASTE(a, b) ML_DSA_PASTE2(a, b)
#define ML_DSA_PATH(file) ML_DSA_STRINGIFY(ml-dsa-ML_DSA_PS/clean/file)
#define ML_DSA_STRINGIFY(x) ML_DSA_STRINGIFY2(x)
#define ML_DSA_STRINGIFY2(x) #x

#include ML_DSA_PATH(ntt.c)
#include ML_DSA_PATH(packing.c)
#include ML_DSA_PATH(poly.c)
#include ML_DSA_PATH(polyvec.c)
#include ML_DSA_PATH(reduce.c)
#include ML_DSA_PATH(rounding.c)
#include ML_DSA_PATH(symmetric-shake.c)
#include ML_DSA_PATH(sign.c)
