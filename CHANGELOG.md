# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-18

Initial release implementing NIST FIPS 204 ML-DSA (Module-Lattice-Based
Digital Signature Algorithm) as a Ruby C extension.

### Features

#### Core cryptography
- Three parameter sets: ML-DSA-44 (NIST Level 2), ML-DSA-65 (Level 3),
  ML-DSA-87 (Level 5), backed by vendored PQClean clean C implementation.
- `MlDsa.keygen(param_set)` — key pair generation with optional `seed:`
  for deterministic keygen from a 32-byte seed.
- `SecretKey#sign(message, deterministic:, context:)` — hedged (randomized,
  default) and deterministic signing with optional FIPS 204 context strings.
- `PublicKey#verify(message, signature, context:)` — signature verification.
- Batch operations: `MlDsa.sign_many` / `MlDsa.verify_many` execute
  multiple operations in a single GVL release for thread concurrency.
- `MlDsa.batch { |b| ... }` — block-based batch builder that collects
  sign or verify operations and executes them together.
- `verify_many` returns `Array[Result]` with per-item `.ok?` and `.reason`
  (distinguishes `wrong_signature_size` from `verification_failed`).
- Build-time parameter set selection: `--with-ml-dsa-params=44,65` to
  compile only a subset (reduces binary size).

#### Key management
- `SecretKey#public_key` — returns the associated `PublicKey` from keygen
  (nil for deserialized keys).
- `SecretKey.from_seed(seed, param_set)` — reconstruct from a 32-byte seed
  with `public_key` attached automatically.
- `SecretKey#seed` — access the keygen seed for compact storage (nil if not
  created from a seed). Securely zeroed on `wipe!` and GC.
- `PublicKey#fingerprint` — SHA-256 prefix (32 hex chars) for identification
  in logs and UIs.
- `PublicKey#created_at` / `SecretKey#created_at` — timestamp set at
  construction for audit trails and key rotation policies.
- `PublicKey#key_usage=` / `SecretKey#key_usage=` — optional `Symbol`
  metadata for application-defined usage labels.

#### Serialization
- Raw bytes: `to_bytes` / `from_bytes` with auto-detection of parameter set
  from byte length.
- Hex: `to_hex` / `from_hex` with auto-detection.
- DER: `to_der` / `from_der` — SubjectPublicKeyInfo for public keys,
  PKCS#8 / OneAsymmetricKey for secret keys (OIDs per FIPS 204).
- PEM: `to_pem` / `from_pem` — PEM-armored DER.
- DER/PEM handled by the [`pqc_asn1`](https://github.com/msuliq/pqc_asn1)
  gem with no OpenSSL dependency. Secret key DER intermediates are held in
  `PqcAsn1::SecureBuffer` (mmap-protected, securely zeroed).

#### Secret key hygiene
- Key bytes live in C-managed memory, securely zeroed on GC.
- `SecretKey#with_bytes { |buf| ... }` — controlled access with automatic
  wipe on block exit (even on exception).
- `SecretKey#wipe!` — explicit zeroing; subsequent operations raise
  `MlDsa::Error`.
- Memory locking: `mlock` prevents secret key pages from swapping to disk.
- No `SecretKey#to_bytes` or `#to_hex` — prevents accidental key leakage
  into logs, exception messages, or long-lived Ruby Strings.
- `dup` / `clone` and `Marshal.dump` raise `TypeError` on both key classes.

#### Configuration and instrumentation
- `MlDsa::Config` — encapsulates mutable state (subscribers, RNG). All
  operations accept optional `config:` for per-Ractor or per-test contexts.
- `MlDsa.subscribe { |event| ... }` — audit logging hooks with
  `:operation`, `:param_set`, `:count`, `:duration_ns`. No key material
  exposed.
- `MlDsa.random_source=` — pluggable RNG for testing or HSM integration.
  Keygen uses it to generate a seed; signing uses it for the rnd nonce.
- `yield_every:` keyword on batch operations for cooperative fiber
  scheduling in async servers.

#### Concurrency
- GVL release: all crypto operations run without the Global VM Lock.
- `PublicKey` is Ractor-shareable (`RUBY_TYPED_FROZEN_SHAREABLE`, Ruby 3.0+).
- Thread-safe wipe detection via C11 `_Atomic` with acquire/release semantics.
- Ractor-compatible instrumentation (silently no-op in non-main Ractors).

#### PQC namespace
- `PQC::MlDsa` alias with `PQC.register` / `PQC.algorithms` /
  `PQC.algorithm(:name)` registry for future multi-algorithm discovery.

#### Error handling
- `MlDsa::Error` base class with subclasses `Error::KeyGeneration`,
  `Error::Signing`, `Error::Deserialization`.
- Deserialization errors include `format`, `position`, and `reason` metadata.
- `ParameterSet` includes `Comparable` for sorting and comparison.

### Security
- Secure zeroing: `SecureZeroMemory` (Windows), `explicit_bzero`
  (Linux/BSD/macOS), `memset_s` (C11), or volatile fallback with compiler
  fence.
- Constant-time secret key comparison via XOR-accumulate with compiler fence.
- Platform-appropriate CSPRNG: `getrandom(2)` (Linux), `arc4random_buf`
  (macOS/BSD), `BCryptGenRandom` (Windows).
- `-fvisibility=hidden` prevents PQClean symbols from clashing with other gems.
- Process-salted hashing for `#hash` method.
- Heap buffers freed via `rb_ensure` — no leak on exceptions.
