/*
 * ml_dsa_ext.c — ML-DSA Ruby C extension (single translation unit).
 *
 * Contains:
 *   - Global VALUE/ID definitions
 *   - Platform helpers (secure zeroing, mlock, constant-time compare, hex)
 *   - Structured error helpers
 *   - Dispatch table for ML-DSA parameter sets
 *   - TypedData definitions for PublicKey and SecretKey
 *   - All key instance methods
 *   - Key generation (random + seeded) with GVL release
 *   - Batch sign/verify with GVL release
 *   - Init_ml_dsa_ext entry point
 *
 * Single-op sign/verify are NOT here — they are thin Ruby wrappers in
 * lib/ml_dsa.rb that call sign_many/verify_many with a single-element
 * array.  See ml_dsa_internal.h for design rationale.
 *
 * DER/PEM serialization is implemented in Ruby (lib/ml_dsa.rb) using
 * the pqc_asn1 gem, which provides algorithm-agnostic SPKI/PKCS#8
 * DER/PEM encoding with SecureBuffer for secret key intermediates.
 */

#include "ml_dsa_internal.h"
#include <limits.h>  /* LONG_MAX */
#include <stdio.h>   /* snprintf */

/* ------------------------------------------------------------------ */
/* Global VALUE/ID definitions                                         */
/* ------------------------------------------------------------------ */

static VALUE rb_mMlDsa;
static VALUE rb_eMlDsaError;
static VALUE rb_eKeyGenError;
static VALUE rb_eSigningError;
static VALUE rb_eDeserializationError;
static VALUE rb_cPublicKey;
static VALUE rb_cSecretKey;

static VALUE ml_dsa_param_data_cache = Qundef;

static ID id_name;
static ID id_at_format;
static ID id_at_position;
static ID id_at_reason;
static ID id_public_key;

/* ------------------------------------------------------------------ */
/* Platform-appropriate secure memory zeroing                          */
/*                                                                     */
/* The compiler may elide a plain memset() on a buffer that is freed   */
/* immediately after (dead-store elimination).  Each platform provides  */
/* a zeroing primitive the compiler is contractually forbidden to       */
/* optimise away.  The volatile fallback adds a compiler fence to      */
/* prevent reordering.                                                 */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
#  include <windows.h>
static void secure_zero(void *p, size_t n)
{
    SecureZeroMemory(p, n);
}
#elif defined(HAVE_EXPLICIT_BZERO)
/* Forward-declare to avoid -std=c11 suppressing BSD/POSIX extensions */
extern void explicit_bzero(void *, size_t);
static void secure_zero(void *p, size_t n)
{
    explicit_bzero(p, n);
}
#elif defined(HAVE_MEMSET_S) || defined(__STDC_LIB_EXT1__)
static void secure_zero(void *p, size_t n)
{
    memset_s(p, n, 0, n);
}
#else
/* Fallback: volatile write + compiler fence to suppress dead-store elim. */
static void secure_zero(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++) vp[i] = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("" : : "r"(vp) : "memory");
#endif
}
#endif

/* ------------------------------------------------------------------ */
/* mlock/munlock — prevent secret key pages from being swapped         */
/* ------------------------------------------------------------------ */

#if defined(_WIN32)
static void sk_mlock(void *ptr, size_t len) { VirtualLock(ptr, len); }
static void sk_munlock(void *ptr, size_t len) { VirtualUnlock(ptr, len); }
#elif defined(HAVE_MLOCK)
#include <sys/mman.h>
static void sk_mlock(void *ptr, size_t len) { mlock(ptr, len); }
static void sk_munlock(void *ptr, size_t len) { munlock(ptr, len); }
#else
static void sk_mlock(void *ptr, size_t len) { (void)ptr; (void)len; }
static void sk_munlock(void *ptr, size_t len) { (void)ptr; (void)len; }
#endif

/* ------------------------------------------------------------------ */
/* Constant-time byte comparison with compiler fence                   */
/*                                                                     */
/* Used for secret key equality — timing must not reveal which bytes   */
/* differ.  Public keys use plain memcmp (they are not secret).        */
/* ------------------------------------------------------------------ */

static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    volatile uint8_t diff = 0;
    size_t i;
    for (i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("" : "+r"(diff) : : "memory");
#endif
    return diff == 0;
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

static VALUE bytes_to_hex_value(const uint8_t *bytes, size_t len)
{
    static const char hc[] = "0123456789abcdef";
    if (len > LONG_MAX / 2)
        rb_raise(rb_eArgError, "key too large to hex-encode");
    VALUE hex = rb_str_new(NULL, (long)(len * 2));
    char *p   = RSTRING_PTR(hex);
    size_t i;
    for (i = 0; i < len; i++) {
        *p++ = hc[(bytes[i] >> 4) & 0xf];
        *p++ = hc[bytes[i]        & 0xf];
    }
    OBJ_FREEZE(hex);
    return hex;
}

static VALUE hash_key_bytes(int ps_code, const uint8_t *bytes, size_t len)
{
    st_index_t h = rb_hash_start((st_index_t)ps_code);
    h = rb_hash_uint(h, rb_memhash(bytes, (long)len));
    h = rb_hash_end(h);
    return LONG2NUM((long)h);
}

/*
 * Encode a context string to ASCII-8BIT if not already.
 * Context is a plain string (0..255 bytes) per FIPS 204 — no wrapper
 * class needed.  Length validation is at the C boundary in batch ops.
 */
static VALUE encode_context_binary(VALUE rb_ctx)
{
    if (rb_enc_get_index(rb_ctx) == rb_ascii8bit_encindex())
        return rb_ctx;
    return rb_str_encode(rb_ctx,
                         rb_enc_from_encoding(rb_ascii8bit_encoding()),
                         0, Qnil);
}

/* ------------------------------------------------------------------ */
/* Structured error helpers                                            */
/*                                                                     */
/* All MlDsa::Error subclasses carry a machine-readable @reason symbol */
/* so callers can programmatically distinguish failure types without   */
/* parsing human-readable messages.                                    */
/* ------------------------------------------------------------------ */

static VALUE error_format(VALUE self) { return rb_ivar_get(self, id_at_format); }
static VALUE error_position(VALUE self) { return rb_ivar_get(self, id_at_position); }
static VALUE error_reason(VALUE self) { return rb_ivar_get(self, id_at_reason); }

/*
 * Raise an MlDsa::Error subclass with a @reason symbol.
 * Used by keygen, sign, and wipe error paths.
 */
NORETURN(static void raise_with_reason(VALUE klass, const char *reason,
                                        const char *fmt, ...));
/* Definition repeats NORETURN via compiler attribute so both declaration
 * and definition carry the noreturn contract. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#elif defined(_MSC_VER)
__declspec(noreturn)
#endif
static void raise_with_reason(VALUE klass, const char *reason,
                               const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    VALUE msg = rb_vsprintf(fmt, ap);
    va_end(ap);

    VALUE exc = rb_exc_new_str(klass, msg);
    rb_ivar_set(exc, id_at_reason, ID2SYM(rb_intern(reason)));
    rb_exc_raise(exc);
}

/* Convenience macro — raises MlDsa::Error if key has been wiped.
 * Uses atomic load so a concurrent wipe! on another thread is visible. */
#define SK_CHECK_WIPED(d) \
    do { if (ML_DSA_ATOMIC_LOAD(&(d)->wiped)) raise_with_reason(rb_eMlDsaError, "key_wiped", \
                                           "SecretKey has been wiped"); } while (0)

/* ------------------------------------------------------------------ */
/* Dispatch table                                                      */
/*                                                                     */
/* Single source of truth for all parameter-set-specific data.         */
/* build_param_data derives Ruby ParameterSet constants from this.     */
/*                                                                     */
/* ML-DSA has exactly 3 parameter sets (44, 65, 87) standardized by   */
/* NIST FIPS 204.  This set is fixed — a code generator would add     */
/* build complexity for a 3-entry table.  The #ifdef guards are        */
/* mechanical but stable.                                              */
/* ------------------------------------------------------------------ */

const ml_dsa_impl_t ML_DSA_IMPLS[] = {
#ifdef ML_DSA_ENABLE_44
    { 44, 2,
      PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
      PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx,
      PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx,
      PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES },
#endif
#ifdef ML_DSA_ENABLE_65
    { 65, 3,
      PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
      PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
      PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
      PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES },
#endif
#ifdef ML_DSA_ENABLE_87
    { 87, 5,
      PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
      PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx,
      PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx,
      PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES },
#endif
};

const size_t ML_DSA_IMPL_COUNT = sizeof(ML_DSA_IMPLS) / sizeof(ML_DSA_IMPLS[0]);

static const ml_dsa_impl_t *find_impl(int ps)
{
    size_t i;
    for (i = 0; i < ML_DSA_IMPL_COUNT; i++)
        if (ML_DSA_IMPLS[i].ps == ps) return &ML_DSA_IMPLS[i];
    rb_raise(rb_eArgError, "invalid or disabled parameter set code: %d", ps);
    UNREACHABLE_RETURN(NULL);
}

/* ------------------------------------------------------------------ */
/* param_set lookup — derives Ruby ParameterSet from int ps_code       */
/* ------------------------------------------------------------------ */

static VALUE lookup_param_set(int ps_code)
{
    char name[16];
    snprintf(name, sizeof(name), "ML_DSA_%d", ps_code);
    return rb_const_get(rb_mMlDsa, rb_intern(name));
}

/* ================================================================== */
/* PublicKey TypedData                                                  */
/* ================================================================== */

static void pk_free(void *ptr)
{
    ruby_xfree(ptr);
}

static void pk_mark(void *ptr)
{
    ml_dsa_pk_t *d = (ml_dsa_pk_t *)ptr;
    rb_gc_mark_movable(d->fingerprint);
}

static void pk_compact(void *ptr)
{
    ml_dsa_pk_t *d = (ml_dsa_pk_t *)ptr;
    d->fingerprint = rb_gc_location(d->fingerprint);
}

static size_t pk_memsize(const void *ptr)
{
    const ml_dsa_pk_t *d = (const ml_dsa_pk_t *)ptr;
    return sizeof(ml_dsa_pk_t) + d->len;
}

static const rb_data_type_t ml_dsa_pk_type = {
    "MlDsa::PublicKey",
    { pk_mark, pk_free, pk_memsize, pk_compact, {0} },
    0, 0,
    RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED
};

static VALUE pk_alloc(VALUE klass)
{
    ml_dsa_pk_t *d = (ml_dsa_pk_t *)ruby_xmalloc(sizeof(ml_dsa_pk_t));
    d->len         = 0;
    d->ps_code     = 0;
    d->fingerprint = Qnil;
    return TypedData_Wrap_Struct(klass, &ml_dsa_pk_type, d);
}

static VALUE pk_new_from_buf(VALUE klass, const uint8_t *raw_buf, size_t raw_len,
                             int ps_code)
{
    ml_dsa_pk_t *d = (ml_dsa_pk_t *)ruby_xmalloc(sizeof(ml_dsa_pk_t) + raw_len);
    d->len         = raw_len;
    d->ps_code     = ps_code;
    d->fingerprint = Qnil;
    memcpy(d->bytes, raw_buf, raw_len);
    return TypedData_Wrap_Struct(klass, &ml_dsa_pk_type, d);
}

/* ================================================================== */
/* SecretKey TypedData                                                  */
/* ================================================================== */

static void sk_free(void *ptr)
{
    ml_dsa_sk_t *d = (ml_dsa_sk_t *)ptr;
    if (!ML_DSA_ATOMIC_LOAD(&d->wiped) && d->len > 0) {
        secure_zero(d->bytes, d->len);
        sk_munlock(d->bytes, d->len);
    }
    if (d->has_seed)
        secure_zero(d->seed, ML_DSA_SEED_BYTES);
    ruby_xfree(d);
}

static size_t sk_memsize(const void *ptr)
{
    const ml_dsa_sk_t *d = (const ml_dsa_sk_t *)ptr;
    return sizeof(ml_dsa_sk_t) + d->len;
}

static const rb_data_type_t ml_dsa_sk_type = {
    "MlDsa::SecretKey",
    { NULL, sk_free, sk_memsize, NULL, {0} },
    0, 0,
    RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE sk_alloc(VALUE klass)
{
    ml_dsa_sk_t *d = (ml_dsa_sk_t *)ruby_xmalloc(sizeof(ml_dsa_sk_t));
    d->len        = 0;
    d->ps_code    = 0;
    d->wiped      = 0;
    d->has_seed   = 0;
    memset(d->seed, 0, ML_DSA_SEED_BYTES);
    return TypedData_Wrap_Struct(klass, &ml_dsa_sk_type, d);
}

static VALUE sk_new_from_buf(VALUE klass, const uint8_t *raw_buf, size_t raw_len,
                             int ps_code)
{
    ml_dsa_sk_t *d = (ml_dsa_sk_t *)ruby_xmalloc(sizeof(ml_dsa_sk_t) + raw_len);
    d->len        = raw_len;
    d->ps_code    = ps_code;
    d->wiped      = 0;
    d->has_seed   = 0;
    memset(d->seed, 0, ML_DSA_SEED_BYTES);
    sk_mlock(d->bytes, raw_len);
    memcpy(d->bytes, raw_buf, raw_len);
    return TypedData_Wrap_Struct(klass, &ml_dsa_sk_type, d);
}

/* ================================================================== */
/* PublicKey instance methods                                           */
/* ================================================================== */

static VALUE pk_param_set(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    return lookup_param_set(d->ps_code);
}

static VALUE pk_bytesize(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    return SIZET2NUM(d->len);
}

static VALUE pk_to_bytes(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    VALUE s = rb_str_new((const char *)d->bytes, (long)d->len);
    rb_enc_associate(s, rb_ascii8bit_encoding());
    OBJ_FREEZE(s);
    return s;
}

static VALUE pk_to_hex(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    return bytes_to_hex_value(d->bytes, d->len);
}

/* Lazy-computed fingerprint: first 16 bytes (32 hex chars) of SHA-256
 * of the raw public key bytes.  Cached in the C struct. */
static VALUE pk_fingerprint(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    if (!NIL_P(d->fingerprint)) return d->fingerprint;

    /* rb_require is idempotent; calling it every time is safe but we
     * only get here once per PK object. */
    rb_require("digest/sha2");
    VALUE rb_digest = rb_path2class("Digest::SHA256");
    VALUE raw = rb_str_new((const char *)d->bytes, (long)d->len);
    VALUE hex = rb_funcall(rb_digest, rb_intern("hexdigest"), 1, raw);
    VALUE prefix = rb_str_substr(hex, 0, 32);
    OBJ_FREEZE(prefix);
    RB_OBJ_WRITE(self, &d->fingerprint, prefix);
    return d->fingerprint;
}

static VALUE pk_inspect(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    if (d->len == 0)
        return rb_str_new_cstr("#<MlDsa::PublicKey [uninitialized]>");
    size_t show = d->len < 8 ? d->len : 8;
    VALUE prefix_hex = bytes_to_hex_value(d->bytes, show);
    VALUE ps = lookup_param_set(d->ps_code);
    VALUE ps_name = rb_funcall(ps, id_name, 0);
    VALUE result = rb_sprintf("#<MlDsa::PublicKey %"PRIsVALUE" %"PRIsVALUE"\xe2\x80\xa6>",
                              ps_name, prefix_hex);
    RB_GC_GUARD(prefix_hex);
    return result;
}

static VALUE pk_to_s(VALUE self)
{
    return pk_inspect(self);
}

static VALUE pk_equal(VALUE self, VALUE other)
{
    if (!rb_obj_is_kind_of(other, rb_cPublicKey)) return Qfalse;
    ml_dsa_pk_t *d1, *d2;
    TypedData_Get_Struct(self,  ml_dsa_pk_t, &ml_dsa_pk_type, d1);
    TypedData_Get_Struct(other, ml_dsa_pk_t, &ml_dsa_pk_type, d2);
    if (d1->len != d2->len || d1->ps_code != d2->ps_code) return Qfalse;
    return (memcmp(d1->bytes, d2->bytes, d1->len) == 0) ? Qtrue : Qfalse;
}

static VALUE pk_eql(VALUE self, VALUE other)
{
    return pk_equal(self, other);
}

static VALUE pk_hash(VALUE self)
{
    ml_dsa_pk_t *d;
    TypedData_Get_Struct(self, ml_dsa_pk_t, &ml_dsa_pk_type, d);
    return hash_key_bytes(d->ps_code, d->bytes, d->len);
}

static VALUE pk_from_bytes_raw(VALUE klass, VALUE rb_raw, VALUE rb_ps_code)
{
    Check_Type(rb_raw, T_STRING);
    int ps_code = NUM2INT(rb_ps_code);
    const ml_dsa_impl_t *impl = find_impl(ps_code);

    if ((size_t)RSTRING_LEN(rb_raw) != impl->pk_len)
        rb_raise(rb_eArgError,
                 "expected %lu bytes for ML-DSA-%d, got %ld",
                 (unsigned long)impl->pk_len, ps_code, RSTRING_LEN(rb_raw));

    return pk_new_from_buf(klass,
                           (const uint8_t *)RSTRING_PTR(rb_raw),
                           (size_t)RSTRING_LEN(rb_raw),
                           ps_code);
}

/* dup/clone prevention — alloc creates NULL-bytes objects which silently break */
static VALUE pk_initialize_copy(VALUE self, VALUE orig)
{
    (void)self; (void)orig;
    rb_raise(rb_eTypeError,
             "MlDsa::PublicKey cannot be duplicated; "
             "use from_bytes or from_der to create a copy");
    return Qnil;
}

/* Marshal prevention — TypedData has no default marshal support */
static VALUE pk_dump_data(VALUE self)
{
    (void)self;
    rb_raise(rb_eTypeError,
             "MlDsa::PublicKey cannot be marshalled; "
             "use to_der/from_der or to_bytes/from_bytes for serialization");
    return Qnil;
}

/* ================================================================== */
/* SecretKey instance methods                                          */
/* ================================================================== */

static VALUE sk_param_set(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    return lookup_param_set(d->ps_code);
}

/* Returns the associated PublicKey, or nil if the key was deserialized
 * without one (e.g. from_bytes, from_der). */
static VALUE sk_public_key(VALUE self)
{
    return rb_ivar_get(self, id_public_key);
}

/* Internal: set the associated public key after keygen.
 * Called from keygen_body below. */
static void sk_set_public_key(VALUE sk_obj, VALUE pk_obj)
{
    rb_ivar_set(sk_obj, id_public_key, pk_obj);
}

/* Internal: store the keygen seed in the SK struct for later retrieval. */
static void sk_set_seed(VALUE sk_obj, const uint8_t *seed, size_t seed_len)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(sk_obj, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    if (seed && seed_len == ML_DSA_SEED_BYTES) {
        memcpy(d->seed, seed, ML_DSA_SEED_BYTES);
        d->has_seed = 1;
    }
}

/* Returns the 32-byte keygen seed as a frozen binary String, or nil
 * if the key was not created from a seed (random keygen, from_bytes, etc.). */
static VALUE sk_seed(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    SK_CHECK_WIPED(d);
    if (!d->has_seed) return Qnil;
    VALUE s = rb_str_new((const char *)d->seed, ML_DSA_SEED_BYTES);
    rb_enc_associate(s, rb_ascii8bit_encoding());
    OBJ_FREEZE(s);
    return s;
}

static VALUE sk_bytesize(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    SK_CHECK_WIPED(d);
    return SIZET2NUM(d->len);
}

/*
 * with_bytes { |binary_string| ... } -> block_return_value
 *
 * Yields a temporary binary String.  The buffer is secure_zero'd before
 * with_bytes returns — guaranteed by rb_ensure even if the block raises.
 */
static VALUE sk_with_bytes_yield(VALUE buf)
{
    return rb_yield(buf);
}

static VALUE sk_with_bytes_ensure(VALUE buf)
{
    /* rb_str_modify ensures exclusive ownership of the byte buffer.
     * Without this, if the block called dup (which uses copy-on-write),
     * secure_zero would write through the shared CoW buffer and corrupt
     * the user's copy.  After rb_str_modify, we zero only our private
     * copy; the user's dup retains the original key bytes. */
    rb_str_modify(buf);
    char *ptr = RSTRING_PTR(buf);
    long  len = RSTRING_LEN(buf);
    if (ptr && len > 0) secure_zero(ptr, (size_t)len);
    rb_str_resize(buf, 0);
    /* Freeze the emptied buffer so any stored reference fails loudly
     * on mutation attempts rather than silently operating on empty data. */
    OBJ_FREEZE(buf);
    return Qnil;
}

static VALUE sk_with_bytes(VALUE self)
{
    if (!rb_block_given_p())
        rb_raise(rb_eArgError, "with_bytes requires a block");
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    SK_CHECK_WIPED(d);
    VALUE buf = rb_str_new((const char *)d->bytes, (long)d->len);
    return ML_DSA_ENSURE(sk_with_bytes_yield, sk_with_bytes_ensure, buf);
}

/*
 * wipe! -> nil
 *
 * Explicitly zeroes and frees the key bytes.  Callable even on a frozen
 * object because the bytes live in C-managed memory, not Ruby ivars.
 * After wipe! the key cannot be used for signing; inspect and param_set
 * still work and show [wiped] status.
 *
 * Thread safety: the wiped flag is atomic, so a concurrent wipe! from
 * another thread is visible to SK_CHECK_WIPED immediately.  However,
 * if one thread calls wipe! while another is between SK_CHECK_WIPED
 * and the GVL drop in sign, the signing thread has already copied the
 * sk_bytes pointer — secure_zero will zero the bytes under it.  This
 * is safe (PQClean reads from the buffer, which is now zeros, and will
 * produce a garbage signature) but callers should still ensure wipe!
 * is called only after all signing threads have finished.
 */
static VALUE sk_wipe(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    if (!ML_DSA_ATOMIC_LOAD(&d->wiped) && d->len > 0) {
        secure_zero(d->bytes, d->len);
        sk_munlock(d->bytes, d->len);
        if (d->has_seed) {
            secure_zero(d->seed, ML_DSA_SEED_BYTES);
            d->has_seed = 0;
        }
        ML_DSA_ATOMIC_STORE(&d->wiped, 1);
    }
    return Qnil;
}

static VALUE sk_inspect(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    VALUE ps = lookup_param_set(d->ps_code);
    VALUE ps_name = rb_funcall(ps, id_name, 0);
    if (ML_DSA_ATOMIC_LOAD(&d->wiped))
        return rb_sprintf("#<MlDsa::SecretKey %"PRIsVALUE" [wiped]>", ps_name);
    return rb_sprintf("#<MlDsa::SecretKey %"PRIsVALUE">", ps_name);
}

static VALUE sk_to_s(VALUE self)
{
    return sk_inspect(self);
}

/* == uses ct_memeq — secret key material must not leak timing */
static VALUE sk_equal(VALUE self, VALUE other)
{
    if (!rb_obj_is_kind_of(other, rb_cSecretKey)) return Qfalse;
    ml_dsa_sk_t *d1, *d2;
    TypedData_Get_Struct(self,  ml_dsa_sk_t, &ml_dsa_sk_type, d1);
    TypedData_Get_Struct(other, ml_dsa_sk_t, &ml_dsa_sk_type, d2);
    SK_CHECK_WIPED(d1);
    SK_CHECK_WIPED(d2);
    if (d1->len != d2->len || d1->ps_code != d2->ps_code) return Qfalse;
    return ct_memeq(d1->bytes, d2->bytes, d1->len) ? Qtrue : Qfalse;
}

static VALUE sk_eql(VALUE self, VALUE other)
{
    return sk_equal(self, other);
}

static VALUE sk_hash(VALUE self)
{
    ml_dsa_sk_t *d;
    TypedData_Get_Struct(self, ml_dsa_sk_t, &ml_dsa_sk_type, d);
    SK_CHECK_WIPED(d);
    return hash_key_bytes(d->ps_code, d->bytes, d->len);
}

static VALUE sk_from_bytes_raw(VALUE klass, VALUE rb_raw, VALUE rb_ps_code)
{
    Check_Type(rb_raw, T_STRING);
    int ps_code = NUM2INT(rb_ps_code);
    const ml_dsa_impl_t *impl = find_impl(ps_code);

    if ((size_t)RSTRING_LEN(rb_raw) != impl->sk_len)
        rb_raise(rb_eArgError,
                 "expected %lu bytes for ML-DSA-%d, got %ld",
                 (unsigned long)impl->sk_len, ps_code, RSTRING_LEN(rb_raw));

    return sk_new_from_buf(klass,
                           (const uint8_t *)RSTRING_PTR(rb_raw),
                           (size_t)RSTRING_LEN(rb_raw),
                           ps_code);
}

/* dup/clone prevention — would create a NULL-bytes object */
static VALUE sk_initialize_copy(VALUE self, VALUE orig)
{
    (void)self; (void)orig;
    rb_raise(rb_eTypeError,
             "MlDsa::SecretKey cannot be duplicated; "
             "use from_bytes or from_der to create a copy");
    return Qnil;
}

/* Marshal prevention — key material must not be silently serialised */
static VALUE sk_dump_data(VALUE self)
{
    (void)self;
    rb_raise(rb_eTypeError,
             "MlDsa::SecretKey cannot be marshalled; "
             "use to_der/from_der or with_bytes for serialization");
    return Qnil;
}

/* ================================================================== */
/* Key generation                                                      */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/* keygen — nogvl callback                                             */
/*                                                                     */
/* Unified path: seed is always passed explicitly to PQClean keygen.   */
/* The caller (Ruby side or C body) generates the seed from OS CSPRNG, */
/* pluggable RNG, or user-provided bytes before calling this.          */
/* ------------------------------------------------------------------ */

struct keygen_nogvl_args {
    keygen_fn_t      keygen_fn;
    uint8_t         *pk;
    uint8_t         *sk;
    const uint8_t   *seed;
    int              result;
};

static void *ml_dsa_keygen_nogvl(void *ptr)
{
    struct keygen_nogvl_args *a = (struct keygen_nogvl_args *)ptr;
    a->result = a->keygen_fn(a->pk, a->sk, a->seed);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* keygen with heap buffers + rb_ensure                                */
/*                                                                     */
/* Unified keygen: seed is always passed explicitly.  For random       */
/* keygen, the seed is generated from OS CSPRNG before the GVL drop.  */
/* For deterministic keygen, the caller provides it.                   */
/*                                                                     */
/* Both allocations happen INSIDE keygen_body so keygen_ensure covers  */
/* both — no partial-free leak if the second ruby_xmalloc raises OOM.  */
/* ------------------------------------------------------------------ */

struct keygen_state {
    const ml_dsa_impl_t *impl;
    int                  ps;
    int                  has_seed;    /* caller provided seed -> store in SK */
    uint8_t              seed[ML_DSA_SEED_BYTES]; /* always filled before nogvl */
    uint8_t             *pk_buf;   /* NULL until allocated in keygen_body */
    uint8_t             *sk_buf;   /* NULL until allocated in keygen_body */
};

static VALUE keygen_body(VALUE arg)
{
    struct keygen_state *s = (struct keygen_state *)arg;

    /* Allocate inside body so ensure always runs on OOM from either malloc */
    s->pk_buf = (uint8_t *)ruby_xmalloc(s->impl->pk_len);
    s->sk_buf = (uint8_t *)ruby_xmalloc(s->impl->sk_len);

    struct keygen_nogvl_args nargs;
    nargs.keygen_fn = s->impl->keygen_fn;
    nargs.pk        = s->pk_buf;
    nargs.sk        = s->sk_buf;
    nargs.seed      = s->seed;
    nargs.result    = 0;

    rb_thread_call_without_gvl(ml_dsa_keygen_nogvl, &nargs, RUBY_UBF_IO, NULL);

    if (nargs.result != 0)
        raise_with_reason(rb_eKeyGenError, "internal_failure",
                          "ML-DSA key generation failed");

    VALUE pk_obj = pk_new_from_buf(rb_cPublicKey, s->pk_buf, s->impl->pk_len,
                                   s->ps);
    VALUE sk_obj = sk_new_from_buf(rb_cSecretKey, s->sk_buf, s->impl->sk_len,
                                   s->ps);
    sk_set_public_key(sk_obj, pk_obj);
    if (s->has_seed)
        sk_set_seed(sk_obj, s->seed, ML_DSA_SEED_BYTES);
    VALUE pair = rb_ary_new2(2);
    rb_ary_push(pair, pk_obj);
    rb_ary_push(pair, sk_obj);
    OBJ_FREEZE(pair);
    return pair;
}

static VALUE keygen_ensure(VALUE arg)
{
    struct keygen_state *s = (struct keygen_state *)arg;
    secure_zero(s->seed, ML_DSA_SEED_BYTES);
    if (s->sk_buf) {
        secure_zero(s->sk_buf, s->impl->sk_len);
        ruby_xfree(s->sk_buf);
        s->sk_buf = NULL;
    }
    if (s->pk_buf) {
        ruby_xfree(s->pk_buf);   /* public key — no secure zeroing needed */
        s->pk_buf = NULL;
    }
    return Qnil;
}

static VALUE rb_ml_dsa_keygen(VALUE self, VALUE rb_ps)
{
    (void)self;
    int ps = NUM2INT(rb_ps);
    const ml_dsa_impl_t *impl = find_impl(ps);

    struct keygen_state s;
    s.impl         = impl;
    s.ps           = ps;
    s.has_seed     = 0;
    s.pk_buf       = NULL;
    s.sk_buf       = NULL;

    /* Generate seed from OS CSPRNG before GVL drop */
    randombytes(s.seed, ML_DSA_SEED_BYTES);

    return ML_DSA_ENSURE(keygen_body, keygen_ensure, &s);
}

/* ------------------------------------------------------------------ */
/* keygen_from_seed — deterministic keygen with caller-provided seed   */
/* ------------------------------------------------------------------ */

static VALUE rb_ml_dsa_keygen_seed(VALUE self, VALUE rb_ps, VALUE rb_seed)
{
    (void)self;
    Check_Type(rb_seed, T_STRING);
    if (RSTRING_LEN(rb_seed) != ML_DSA_SEED_BYTES)
        rb_raise(rb_eArgError, "seed must be exactly %d bytes, got %ld",
                 ML_DSA_SEED_BYTES, RSTRING_LEN(rb_seed));

    int ps = NUM2INT(rb_ps);
    const ml_dsa_impl_t *impl = find_impl(ps);

    struct keygen_state s;
    s.impl         = impl;
    s.ps           = ps;
    s.has_seed     = 1;
    s.pk_buf       = NULL;
    s.sk_buf       = NULL;
    memcpy(s.seed, RSTRING_PTR(rb_seed), ML_DSA_SEED_BYTES);

    return ML_DSA_ENSURE(keygen_body, keygen_ensure, &s);
}

/* ================================================================== */
/* Batch signing                                                       */
/*                                                                     */
/* MlDsa._sign_many(array) -> Array of frozen binary Strings          */
/*                                                                     */
/* Each element of `array` is a flat 5-element Array:                 */
/*   [sk, message, ctx_or_nil, deterministic_or_nil, rnd_or_nil]      */
/*                                                                     */
/* This is the ONLY C codepath for signing.  Single-op sk.sign is a   */
/* Ruby wrapper that calls sign_many with a 1-element array.           */
/* ================================================================== */

struct sign_batch_item {
    sign_fn_t      sign_fn;
    const uint8_t *sk_bytes;
    const uint8_t *m;
    size_t         mlen;
    const uint8_t *ctx;
    size_t         ctxlen;
    VALUE          msg_pinned;
    VALUE          ctx_pinned;
    uint8_t        rnd[ML_DSA_RNDBYTES];
    uint8_t       *sig_buf;
    size_t         sig_max;
    size_t         siglen;
    int            result;
};

struct sign_batch_state {
    VALUE                   rb_ops;
    struct sign_batch_item *items;
    size_t                  count;
    size_t                  items_initialized;  /* items with rnd set */
};

struct sign_batch_nogvl_args {
    struct sign_batch_item *items;
    size_t                  count;
};

static void *ml_dsa_sign_batch_nogvl(void *ptr)
{
    struct sign_batch_nogvl_args *a = (struct sign_batch_nogvl_args *)ptr;
    size_t i;
    for (i = 0; i < a->count; i++) {
        struct sign_batch_item *it = &a->items[i];
        it->result = it->sign_fn(it->sig_buf, &it->siglen,
                                 it->m, it->mlen,
                                 it->ctx, it->ctxlen,
                                 it->sk_bytes, it->rnd);
    }
    return NULL;
}

static VALUE sign_many_body(VALUE arg)
{
    struct sign_batch_state *s = (struct sign_batch_state *)arg;
    size_t i;

    s->items    = (struct sign_batch_item *)ruby_xcalloc(
                      s->count, sizeof(struct sign_batch_item));

    for (i = 0; i < s->count; i++) {
        /* Each op is a flat array: [sk, message, ctx, det, rnd_or_nil] */
        VALUE op = RARRAY_AREF(s->rb_ops, (long)i);
        Check_Type(op, T_ARRAY);

        VALUE rb_sk      = RARRAY_AREF(op, SIGN_OP_SK);
        VALUE rb_msg     = RARRAY_AREF(op, SIGN_OP_MSG);
        VALUE rb_ctx_raw = RARRAY_AREF(op, SIGN_OP_CTX);   /* may be nil */
        VALUE rb_det     = RARRAY_AREF(op, SIGN_OP_DET);   /* may be nil */
        /* Optional pre-generated rnd bytes (from pluggable RNG) */
        VALUE rb_rnd     = (RARRAY_LEN(op) > SIGN_OP_RND)
                             ? RARRAY_AREF(op, SIGN_OP_RND) : Qnil;

        if (!rb_obj_is_kind_of(rb_sk, rb_cSecretKey))
            rb_raise(rb_eTypeError,
                     "_sign_many: item %lu sk must be a MlDsa::SecretKey", (unsigned long)i);
        ml_dsa_sk_t *sk_d;
        TypedData_Get_Struct(rb_sk, ml_dsa_sk_t, &ml_dsa_sk_type, sk_d);
        SK_CHECK_WIPED(sk_d);

        Check_Type(rb_msg, T_STRING);

        VALUE rb_ctx = NIL_P(rb_ctx_raw) ? rb_str_new("", 0) : rb_ctx_raw;
        Check_Type(rb_ctx, T_STRING);
        if (RSTRING_LEN(rb_ctx) > 255)
            rb_raise(rb_eArgError,
                     "_sign_many: item %lu context must not exceed 255 bytes", (unsigned long)i);

        const ml_dsa_impl_t *impl = find_impl(sk_d->ps_code);
        VALUE ctx_b = encode_context_binary(rb_ctx);

        struct sign_batch_item *it = &s->items[i];
        it->sign_fn    = impl->sign_fn;
        it->sk_bytes   = sk_d->bytes;
        it->msg_pinned = rb_str_new_frozen(rb_msg);
        it->ctx_pinned = rb_str_new_frozen(ctx_b);
        it->m          = (const uint8_t *)RSTRING_PTR(it->msg_pinned);
        it->mlen       = (size_t)RSTRING_LEN(it->msg_pinned);
        it->ctx        = (const uint8_t *)RSTRING_PTR(it->ctx_pinned);
        it->ctxlen     = (size_t)RSTRING_LEN(it->ctx_pinned);
        it->sig_buf    = (uint8_t *)ruby_xmalloc(impl->sig_len);
        it->sig_max    = impl->sig_len;
        it->siglen     = impl->sig_len;

        if (RTEST(rb_det)) {
            memset(it->rnd, 0, ML_DSA_RNDBYTES);
        } else if (!NIL_P(rb_rnd) && RB_TYPE_P(rb_rnd, T_STRING)
                   && RSTRING_LEN(rb_rnd) == ML_DSA_RNDBYTES) {
            /* Use pre-generated rnd bytes from the pluggable RNG */
            memcpy(it->rnd, RSTRING_PTR(rb_rnd), ML_DSA_RNDBYTES);
        } else {
            randombytes(it->rnd, ML_DSA_RNDBYTES);
        }

        s->items_initialized = i + 1;  /* rnd is now set for item i */
    }

    struct sign_batch_nogvl_args nargs;
    nargs.items = s->items;
    nargs.count = s->count;
    rb_thread_call_without_gvl(ml_dsa_sign_batch_nogvl, &nargs,
                                RUBY_UBF_IO, NULL);

    VALUE out = rb_ary_new2((long)s->count);
    for (i = 0; i < s->count; i++) {
        struct sign_batch_item *it = &s->items[i];
        if (it->result != 0)
            raise_with_reason(rb_eSigningError, "internal_failure",
                              "ML-DSA signing failed for batch item %lu",
                              (unsigned long)i);
        VALUE sig = rb_str_new((const char *)it->sig_buf, (long)it->siglen);
        rb_enc_associate(sig, rb_ascii8bit_encoding());
        OBJ_FREEZE(sig);
        rb_ary_push(out, sig);
    }
    OBJ_FREEZE(out);

    /* GC guards on the body's stack frame — where the pinned VALUEs are live */
    for (i = 0; i < s->count; i++) {
        RB_GC_GUARD(s->items[i].msg_pinned);
        RB_GC_GUARD(s->items[i].ctx_pinned);
    }
    return out;
}

static VALUE sign_many_ensure(VALUE arg)
{
    struct sign_batch_state *s = (struct sign_batch_state *)arg;
    size_t i;
    /* Only wipe rnd and free sig_buf for items that were actually initialized */
    for (i = 0; i < s->items_initialized; i++) {
        secure_zero(s->items[i].rnd, ML_DSA_RNDBYTES);
        if (s->items[i].sig_buf) {
            secure_zero(s->items[i].sig_buf, s->items[i].sig_max);
            ruby_xfree(s->items[i].sig_buf);
            s->items[i].sig_buf = NULL;
        }
    }
    if (s->items) {
        ruby_xfree(s->items);
        s->items = NULL;
    }
    return Qnil;
}

static VALUE rb_ml_dsa_sign_many(VALUE self, VALUE rb_ops)
{
    (void)self;
    Check_Type(rb_ops, T_ARRAY);
    long count = RARRAY_LEN(rb_ops);
    if (count == 0) {
        VALUE empty = rb_ary_new();
        OBJ_FREEZE(empty);
        return empty;
    }

    struct sign_batch_state s;
    s.rb_ops            = rb_ops;
    s.count             = (size_t)count;
    s.items_initialized = 0;
    s.items             = NULL;

    return ML_DSA_ENSURE(sign_many_body, sign_many_ensure, &s);
}

/* ================================================================== */
/* Batch verification                                                  */
/*                                                                     */
/* MlDsa._verify_many(array) -> Array of true|false                   */
/*                                                                     */
/* Each element is a flat 4-element Array:                             */
/*   [pk, message, signature, ctx_or_nil]                              */
/*                                                                     */
/* This is the ONLY C codepath for verification.  Single-op pk.verify  */
/* is a Ruby wrapper that calls verify_many with a 1-element array.    */
/* ================================================================== */

struct verify_batch_item {
    verify_fn_t    verify_fn;
    const uint8_t *pk_bytes;
    const uint8_t *sig;
    size_t         siglen;
    const uint8_t *m;
    size_t         mlen;
    const uint8_t *ctx;
    size_t         ctxlen;
    VALUE          msg_pinned;
    VALUE          sig_pinned;
    VALUE          ctx_pinned;
    int            result;
    int            size_ok;   /* 0 = bad size, skip nogvl */
};

struct verify_batch_state {
    VALUE                    rb_ops;
    struct verify_batch_item *items;
    size_t                   count;
    size_t                   items_initialized;
};

struct verify_batch_nogvl_args {
    struct verify_batch_item *items;
    size_t                    count;
};

static void *ml_dsa_verify_batch_nogvl(void *ptr)
{
    struct verify_batch_nogvl_args *a = (struct verify_batch_nogvl_args *)ptr;
    size_t i;
    for (i = 0; i < a->count; i++) {
        struct verify_batch_item *it = &a->items[i];
        if (!it->size_ok) {
            it->result = -1;  /* will map to false */
            continue;
        }
        it->result = it->verify_fn(it->sig, it->siglen,
                                   it->m, it->mlen,
                                   it->ctx, it->ctxlen,
                                   it->pk_bytes);
    }
    return NULL;
}

static VALUE verify_many_body(VALUE arg)
{
    struct verify_batch_state *s = (struct verify_batch_state *)arg;
    size_t i;

    s->items = (struct verify_batch_item *)ruby_xcalloc(
                   s->count, sizeof(struct verify_batch_item));

    for (i = 0; i < s->count; i++) {
        /* Each op is a flat 4-element array: [pk, message, signature, ctx] */
        VALUE op = RARRAY_AREF(s->rb_ops, (long)i);
        Check_Type(op, T_ARRAY);

        VALUE rb_pk      = RARRAY_AREF(op, VERIFY_OP_PK);
        VALUE rb_msg     = RARRAY_AREF(op, VERIFY_OP_MSG);
        VALUE rb_sig     = RARRAY_AREF(op, VERIFY_OP_SIG);
        VALUE rb_ctx_raw = RARRAY_AREF(op, VERIFY_OP_CTX);   /* may be nil */

        if (!rb_obj_is_kind_of(rb_pk, rb_cPublicKey))
            rb_raise(rb_eTypeError,
                     "_verify_many: item %lu pk must be a MlDsa::PublicKey", (unsigned long)i);
        ml_dsa_pk_t *pk_d;
        TypedData_Get_Struct(rb_pk, ml_dsa_pk_t, &ml_dsa_pk_type, pk_d);

        if (!RB_TYPE_P(rb_msg, T_STRING))
            rb_raise(rb_eTypeError,
                     "_verify_many: item %lu message must be a String", (unsigned long)i);
        if (!RB_TYPE_P(rb_sig, T_STRING))
            rb_raise(rb_eTypeError,
                     "_verify_many: item %lu signature must be a String", (unsigned long)i);

        VALUE rb_ctx = NIL_P(rb_ctx_raw) ? rb_str_new("", 0) : rb_ctx_raw;
        if (!RB_TYPE_P(rb_ctx, T_STRING) || RSTRING_LEN(rb_ctx) > 255)
            rb_raise(rb_eArgError,
                     "_verify_many: item %lu context must be a String <= 255 bytes", (unsigned long)i);

        const ml_dsa_impl_t *impl = find_impl(pk_d->ps_code);
        VALUE ctx_b = encode_context_binary(rb_ctx);

        struct verify_batch_item *it = &s->items[i];
        it->verify_fn  = impl->verify_fn;
        it->pk_bytes   = pk_d->bytes;
        it->msg_pinned = rb_str_new_frozen(rb_msg);
        it->sig_pinned = rb_str_new_frozen(rb_sig);
        it->ctx_pinned = rb_str_new_frozen(ctx_b);
        it->m          = (const uint8_t *)RSTRING_PTR(it->msg_pinned);
        it->mlen       = (size_t)RSTRING_LEN(it->msg_pinned);
        it->sig        = (const uint8_t *)RSTRING_PTR(it->sig_pinned);
        it->siglen     = (size_t)RSTRING_LEN(it->sig_pinned);
        it->ctx        = (const uint8_t *)RSTRING_PTR(it->ctx_pinned);
        it->ctxlen     = (size_t)RSTRING_LEN(it->ctx_pinned);
        /* Early-reject wrong-size signatures before GVL drop */
        it->size_ok    = (it->siglen == impl->sig_len) ? 1 : 0;
        if (!it->size_ok) it->result = -1;  /* explicit reject before nogvl */

        s->items_initialized = i + 1;
    }

    struct verify_batch_nogvl_args nargs;
    nargs.items = s->items;
    nargs.count = s->count;
    rb_thread_call_without_gvl(ml_dsa_verify_batch_nogvl, &nargs,
                                RUBY_UBF_IO, NULL);

    VALUE out = rb_ary_new2((long)s->count);
    for (i = 0; i < s->count; i++) {
        rb_ary_push(out, s->items[i].result == 0 ? Qtrue : Qfalse);
    }
    OBJ_FREEZE(out);

    /* GC guards on the body's stack frame */
    for (i = 0; i < s->count; i++) {
        RB_GC_GUARD(s->items[i].msg_pinned);
        RB_GC_GUARD(s->items[i].sig_pinned);
        RB_GC_GUARD(s->items[i].ctx_pinned);
    }
    return out;
}

static VALUE verify_many_ensure(VALUE arg)
{
    struct verify_batch_state *s = (struct verify_batch_state *)arg;
    if (s->items) {
        ruby_xfree(s->items);
        s->items = NULL;
    }
    return Qnil;
}

static VALUE rb_ml_dsa_verify_many(VALUE self, VALUE rb_ops)
{
    (void)self;
    Check_Type(rb_ops, T_ARRAY);
    long count = RARRAY_LEN(rb_ops);
    if (count == 0) {
        VALUE empty = rb_ary_new();
        OBJ_FREEZE(empty);
        return empty;
    }

    struct verify_batch_state s;
    s.rb_ops            = rb_ops;
    s.count             = (size_t)count;
    s.items_initialized = 0;
    s.items             = NULL;

    return ML_DSA_ENSURE(verify_many_body, verify_many_ensure, &s);
}

/* ------------------------------------------------------------------ */
/* _param_data — derived from ML_DSA_IMPLS                            */
/* ------------------------------------------------------------------ */

static VALUE rb_ml_dsa_param_data(VALUE self)
{
    (void)self;
    return ml_dsa_param_data_cache;
}

/* Build param data as array-of-arrays from ML_DSA_IMPLS — single source
 * of truth.  Each inner array is [code, security_level, pk_len, sk_len,
 * sig_len] — positional access avoids per-item Hash/Symbol allocation.  */
static VALUE build_param_data(void)
{
    VALUE arr = rb_ary_new_capa(ML_DSA_IMPL_COUNT);
    size_t i;
    for (i = 0; i < ML_DSA_IMPL_COUNT; i++) {
        const ml_dsa_impl_t *m = &ML_DSA_IMPLS[i];
        VALUE row = rb_ary_new_capa(5);
        rb_ary_push(row, INT2FIX(m->ps));
        rb_ary_push(row, INT2FIX(m->security_level));
        rb_ary_push(row, SIZET2NUM(m->pk_len));
        rb_ary_push(row, SIZET2NUM(m->sk_len));
        rb_ary_push(row, SIZET2NUM(m->sig_len));
        OBJ_FREEZE(row);
        rb_ary_push(arr, row);
    }
    OBJ_FREEZE(arr);
    return arr;
}

/* ------------------------------------------------------------------ */
/* Init_ml_dsa_ext                                                     */
/* ------------------------------------------------------------------ */

RUBY_FUNC_EXPORTED void Init_ml_dsa_ext(void)
{
    /* Cache all IDs once at load time */
    id_name              = rb_intern("name");
    id_at_format         = rb_intern("@format");
    id_at_position       = rb_intern("@position");
    id_at_reason         = rb_intern("@reason");
    id_public_key        = rb_intern("@public_key");

    rb_mMlDsa      = rb_define_module("MlDsa");
    rb_eMlDsaError = rb_define_class_under(rb_mMlDsa, "Error", rb_eStandardError);

    /* Error subclasses nested under MlDsa::Error */
    rb_eKeyGenError          = rb_define_class_under(rb_eMlDsaError, "KeyGeneration",
                                                     rb_eMlDsaError);
    rb_eSigningError         = rb_define_class_under(rb_eMlDsaError, "Signing",
                                                     rb_eMlDsaError);
    rb_eDeserializationError = rb_define_class_under(rb_eMlDsaError, "Deserialization",
                                                     rb_eMlDsaError);
    /* reason accessor on base Error — all subclasses inherit it */
    rb_define_method(rb_eMlDsaError, "reason", error_reason, 0);
    /* Structured error metadata accessors on DeserializationError */
    rb_define_method(rb_eDeserializationError, "format", error_format, 0);
    rb_define_method(rb_eDeserializationError, "position", error_position, 0);

    ml_dsa_param_data_cache = build_param_data();
    rb_gc_register_mark_object(ml_dsa_param_data_cache);

    /* Define the key classes */
    rb_cPublicKey = rb_define_class_under(rb_mMlDsa, "PublicKey", rb_cObject);
    rb_cSecretKey = rb_define_class_under(rb_mMlDsa, "SecretKey", rb_cObject);

    /* ---- PublicKey: TypedData, WB-protected ---- */
    rb_define_alloc_func(rb_cPublicKey, pk_alloc);
    rb_undef_method(CLASS_OF(rb_cPublicKey), "new");

    rb_define_method(rb_cPublicKey, "param_set",   pk_param_set,   0);
    rb_define_method(rb_cPublicKey, "bytesize",    pk_bytesize,    0);
    rb_define_method(rb_cPublicKey, "to_bytes",    pk_to_bytes,    0);
    rb_define_method(rb_cPublicKey, "to_hex",      pk_to_hex,      0);
    rb_define_method(rb_cPublicKey, "fingerprint", pk_fingerprint, 0);
    rb_define_method(rb_cPublicKey, "to_s",        pk_to_s,        0);
    rb_define_method(rb_cPublicKey, "inspect",     pk_inspect,     0);
    rb_define_method(rb_cPublicKey, "==",          pk_equal,       1);
    rb_define_method(rb_cPublicKey, "eql?",        pk_eql,         1);
    rb_define_method(rb_cPublicKey, "hash",        pk_hash,        0);
    rb_define_method(rb_cPublicKey, "initialize_copy", pk_initialize_copy, 1);
    rb_define_method(rb_cPublicKey, "_dump_data",      pk_dump_data,       0);

    rb_define_singleton_method(rb_cPublicKey, "_from_bytes_raw",
                               pk_from_bytes_raw, 2);
    rb_funcall(rb_cPublicKey, rb_intern("private_class_method"), 1,
               ID2SYM(rb_intern("_from_bytes_raw")));

    /* ---- SecretKey: TypedData, secure_zero on GC ---- */
    rb_define_alloc_func(rb_cSecretKey, sk_alloc);
    rb_undef_method(CLASS_OF(rb_cSecretKey), "new");

    rb_define_method(rb_cSecretKey, "param_set",   sk_param_set,   0);
    rb_define_method(rb_cSecretKey, "public_key",  sk_public_key,  0);
    rb_define_method(rb_cSecretKey, "seed",        sk_seed,        0);
    rb_define_method(rb_cSecretKey, "bytesize",    sk_bytesize,    0);
    rb_define_method(rb_cSecretKey, "with_bytes",  sk_with_bytes,  0);
    rb_define_method(rb_cSecretKey, "wipe!",       sk_wipe,        0);
    rb_define_method(rb_cSecretKey, "inspect",     sk_inspect,     0);
    rb_define_method(rb_cSecretKey, "to_s",        sk_to_s,        0);
    rb_define_method(rb_cSecretKey, "==",          sk_equal,       1);
    rb_define_method(rb_cSecretKey, "eql?",        sk_eql,         1);
    rb_define_method(rb_cSecretKey, "hash",        sk_hash,        0);
    rb_define_method(rb_cSecretKey, "initialize_copy", sk_initialize_copy, 1);
    rb_define_method(rb_cSecretKey, "_dump_data",      sk_dump_data,       0);

    rb_define_singleton_method(rb_cSecretKey, "_from_bytes_raw",
                               sk_from_bytes_raw, 2);
    rb_funcall(rb_cSecretKey, rb_intern("private_class_method"), 1,
               ID2SYM(rb_intern("_from_bytes_raw")));

    /* ---- Keygen + batch ops — module singleton methods ---- */
    rb_define_singleton_method(rb_mMlDsa, "_keygen",      rb_ml_dsa_keygen,      1);
    rb_define_singleton_method(rb_mMlDsa, "_keygen_seed", rb_ml_dsa_keygen_seed, 2);
    rb_define_singleton_method(rb_mMlDsa, "_sign_many",   rb_ml_dsa_sign_many,   1);
    rb_define_singleton_method(rb_mMlDsa, "_verify_many", rb_ml_dsa_verify_many, 1);
    rb_define_singleton_method(rb_mMlDsa, "_param_data",  rb_ml_dsa_param_data,  0);

    /* Make all underscore-prefixed module methods private */
    {
        const char *private_methods[] = {
            "_keygen", "_keygen_seed", "_sign_many", "_verify_many", "_param_data"
        };
        size_t i;
        ID pcm = rb_intern("private_class_method");
        for (i = 0; i < sizeof(private_methods) / sizeof(private_methods[0]); i++)
            rb_funcall(rb_mMlDsa, pcm, 1, ID2SYM(rb_intern(private_methods[i])));
    }

    /* Declare Ractor safety — no mutable global state beyond
     * ml_dsa_param_data_cache which is deeply frozen. */
#ifdef HAVE_RB_EXT_RACTOR_SAFE
    rb_ext_ractor_safe(true);
#endif
}
