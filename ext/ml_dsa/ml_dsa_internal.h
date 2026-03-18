/*
 * ml_dsa_internal.h — Shared declarations for the ML-DSA C extension.
 *
 * This header provides the minimal interface consumed by ml_dsa_ext.c
 * and the parametric impl template files (ml_dsa_NN_impl.c).  It contains:
 *   - Standard and Ruby includes
 *   - C11 atomics compatibility macros
 *   - PQClean api.h includes (ifdef-guarded by parameter set)
 *   - Constants and named boundary-array positions
 *   - Dispatch table typedef
 *   - TypedData struct definitions for PublicKey and SecretKey
 *
 * Design decisions:
 *
 *   Why no Signer/Verifier streaming classes?
 *     True incremental ML-DSA signing would require splitting PQClean's
 *     sign/verify at the SHAKE-256 mu-computation boundary — a fragile
 *     change that breaks on every PQClean update.  The former Ruby
 *     Signer/Verifier classes buffered the full message anyway, providing
 *     an illusion of streaming without actual streaming.  Removed in
 *     favor of direct sk.sign / pk.verify calls.
 *
 *   Why batch-only C layer (no single-op sign/verify in C)?
 *     The batch sign/verify C paths already handle single items.  Having
 *     separate single-op C functions duplicated ~190 lines of nogvl
 *     structs, callbacks, body/ensure pairs.  Now sk.sign and pk.verify
 *     are Ruby methods that call sign_many/verify_many with a single-
 *     element array.  The overhead (one Ruby Array + one SignRequest/
 *     VerifyRequest) is negligible vs. the ~50us crypto operation.
 *
 *   Why ParameterSet in Ruby, not C?
 *     ParameterSet is a value object with Comparable, inspect, to_s —
 *     features that are trivial in Ruby but would require 100+ lines of
 *     boilerplate in C.  The C layer passes integer codes (44/65/87)
 *     through the boundary.  The build_param_data array-of-arrays bridges
 *     C constants into Ruby with no per-call overhead (runs once at
 *     require time).
 *
 *   Why no code generator for the dispatch table?
 *     ML-DSA has exactly 3 parameter sets (44, 65, 87), standardized by
 *     NIST FIPS 204.  This set will not change.  A code generator would
 *     add build complexity for a table that has 3 entries.
 *
 *   Why context is a plain string (not a Context class)?
 *     FIPS 204 defines context as 0..255 bytes — that's a string with a
 *     length check.  A wrapper class adds API surface without adding
 *     invariants beyond what the primitive can express.
 *
 *   rb_ensure pattern:
 *     Every GVL-released crypto operation follows this structure:
 *       1. Allocate buffers in body (covered by ensure on OOM)
 *       2. Pin Ruby strings with rb_str_new_frozen before GVL drop
 *       3. Call rb_thread_call_without_gvl
 *       4. Build result objects
 *       5. Place RB_GC_GUARD at END of body (not in ensure!)
 *       6. Ensure function: secure_zero + free all allocations
 *     CRITICAL: RB_GC_GUARD must live on the body's stack frame, not
 *     in ensure, because ensure may execute after body's locals are gone.
 */

#ifndef ML_DSA_INTERNAL_H
#define ML_DSA_INTERNAL_H

/* Must precede <string.h> so memset_s is declared when available. */
#define __STDC_WANT_LIB_EXT1__ 1

#include <ruby.h>
#include <ruby/thread.h>
#include <ruby/st.h>
#include <ruby/encoding.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* C11 atomics for thread-safe wipe flag.  MSVC < 2022 lacks stdatomic.h,
 * so we fall back to volatile int + compiler barriers on that platform. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#  include <stdatomic.h>
#  define ML_DSA_ATOMIC _Atomic
#  define ML_DSA_ATOMIC_LOAD(p) atomic_load_explicit((p), memory_order_acquire)
#  define ML_DSA_ATOMIC_STORE(p, v) atomic_store_explicit((p), (v), memory_order_release)
#else
#  define ML_DSA_ATOMIC volatile
#  define ML_DSA_ATOMIC_LOAD(p) (*(p))
#  define ML_DSA_ATOMIC_STORE(p, v) (*(p) = (v))
#endif

#ifdef ML_DSA_ENABLE_44
#  include "ml-dsa-44/clean/api.h"
#endif
#ifdef ML_DSA_ENABLE_65
#  include "ml-dsa-65/clean/api.h"
#endif
#ifdef ML_DSA_ENABLE_87
#  include "ml-dsa-87/clean/api.h"
#endif

#include "randombytes.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define ML_DSA_RNDBYTES   32
#define ML_DSA_SEED_BYTES 32

/* Named positions for the flat Ruby->C boundary arrays.
 * sign_many: [sk, message, ctx_or_nil, deterministic_or_nil, rnd_or_nil]
 * verify_many: [pk, message, signature, ctx_or_nil] */
#define SIGN_OP_SK   0
#define SIGN_OP_MSG  1
#define SIGN_OP_CTX  2
#define SIGN_OP_DET  3
#define SIGN_OP_RND  4   /* optional pre-generated rnd bytes from pluggable RNG */

#define VERIFY_OP_PK   0
#define VERIFY_OP_MSG  1
#define VERIFY_OP_SIG  2
#define VERIFY_OP_CTX  3

#ifdef ML_DSA_ENABLE_87
#  define ML_DSA_MAX_PK_BYTES  PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES
#  define ML_DSA_MAX_SK_BYTES  PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES
#  define ML_DSA_MAX_SIG_BYTES PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES
#elif defined(ML_DSA_ENABLE_65)
#  define ML_DSA_MAX_PK_BYTES  PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#  define ML_DSA_MAX_SK_BYTES  PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
#  define ML_DSA_MAX_SIG_BYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES
#else
#  define ML_DSA_MAX_PK_BYTES  PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
#  define ML_DSA_MAX_SK_BYTES  PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES
#  define ML_DSA_MAX_SIG_BYTES PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES
#endif

/* Convenience macro — wraps rb_ensure with the cast boilerplate. */
#define ML_DSA_ENSURE(body, ensure, state) \
    rb_ensure((body), (VALUE)(state), (ensure), (VALUE)(state))

/* ------------------------------------------------------------------ */
/* Dispatch table                                                      */
/* ------------------------------------------------------------------ */

typedef int (*keygen_fn_t)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*sign_fn_t)(uint8_t *, size_t *,
                         const uint8_t *, size_t,
                         const uint8_t *, size_t,
                         const uint8_t *,
                         const uint8_t *);   /* rnd_in */
typedef int (*verify_fn_t)(const uint8_t *, size_t,
                           const uint8_t *, size_t,
                           const uint8_t *, size_t,
                           const uint8_t *);

typedef struct {
    int              ps;
    int              security_level;
    keygen_fn_t      keygen_fn;
    sign_fn_t        sign_fn;
    verify_fn_t      verify_fn;
    size_t           pk_len;
    size_t           sk_len;
    size_t           sig_len;
} ml_dsa_impl_t;

extern const ml_dsa_impl_t ML_DSA_IMPLS[];
extern const size_t ML_DSA_IMPL_COUNT;

/* ------------------------------------------------------------------ */
/* TypedData structures                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    size_t   len;
    int      ps_code;
    VALUE    fingerprint;  /* cached SHA-256 hex prefix, Qnil until computed */
    uint8_t  bytes[];   /* flexible array member — allocated inline */
} ml_dsa_pk_t;

typedef struct {
    size_t          len;
    int             ps_code;
    ML_DSA_ATOMIC int wiped;  /* non-zero after wipe! — atomic for thread safety */
    int             has_seed; /* non-zero if seed[] contains the keygen seed */
    uint8_t         seed[ML_DSA_SEED_BYTES]; /* keygen seed (zeroed if !has_seed) */
    uint8_t         bytes[];  /* flexible array member — allocated inline */
} ml_dsa_sk_t;

#endif /* ML_DSA_INTERNAL_H */
