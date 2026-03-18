# ml_dsa

Ruby C extension for **ML-DSA** (NIST FIPS 204), the post-quantum digital
signature algorithm formerly known as CRYSTALS-Dilithium.

Bundles the [PQClean](https://github.com/PQClean/PQClean) clean C
implementation for all three standardized parameter sets:

| Parameter Set | NIST Security Level | Public Key | Secret Key | Signature |
|---------------|---------------------|------------|------------|-----------|
| ML-DSA-44     | 2                   | 1,312 B    | 2,560 B    | 2,420 B   |
| ML-DSA-65     | 3                   | 1,952 B    | 4,032 B    | 3,309 B   |
| ML-DSA-87     | 5                   | 2,592 B    | 4,896 B    | 4,627 B   |

## Installation

```ruby
gem "ml_dsa"
```

```sh
gem install ml_dsa
```

Compile only a subset of parameter sets to reduce binary size:

```sh
gem install ml_dsa -- --with-ml-dsa-params=44,65
bundle config build.ml_dsa --with-ml-dsa-params=65
```

### Requirements

- Ruby >= 2.7.2
- C11-compatible compiler (GCC, Clang, MSVC)
- Linux, macOS (Intel + ARM), or Windows
- No OpenSSL dependency

## Usage

### Key generation

```ruby
require "ml_dsa"

pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65)
```

Deterministic keygen from a 32-byte seed:

```ruby
seed = SecureRandom.random_bytes(32)
pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65, seed: seed)
```

### Signing and verification

```ruby
message = "Hello, post-quantum world!"

signature = sk.sign(message)                          # hedged (randomized)
signature = sk.sign(message, deterministic: true)     # deterministic
signature = sk.sign(message, context: "app-v1")       # with FIPS 204 context

pk.verify(message, signature)                         # => true
pk.verify(message, signature, context: "app-v1")      # => true
```

### Batch operations

Sign or verify multiple messages in a single GVL release:

```ruby
signatures = MlDsa.sign_many([
  MlDsa::SignRequest.new(sk: sk, message: "msg1"),
  MlDsa::SignRequest.new(sk: sk, message: "msg2"),
])

results = MlDsa.verify_many([
  MlDsa::VerifyRequest.new(pk: pk, message: "msg1", signature: signatures[0]),
  MlDsa::VerifyRequest.new(pk: pk, message: "msg2", signature: signatures[1]),
])

results.each do |r|
  puts r.ok? ? "valid" : "failed: #{r.reason}"
end
```

Block-based batch builder:

```ruby
sigs = MlDsa.batch { |b|
  b.sign(sk: sk, message: "msg1")
  b.sign(sk: sk, message: "msg2")
}
```

### Serialization

```ruby
# Raw bytes — param_set auto-detected from byte size
pk2 = MlDsa::PublicKey.from_bytes(pk.to_bytes)

# Hex — param_set auto-detected from byte size
pk3 = MlDsa::PublicKey.from_hex(pk.to_hex)

# DER (SubjectPublicKeyInfo / PKCS#8) — param_set auto-detected from OID
pk4 = MlDsa::PublicKey.from_der(pk.to_der)
sk2 = MlDsa::SecretKey.from_der(sk.to_der)

# PEM
pk5 = MlDsa::PublicKey.from_pem(pk.to_pem)
sk3 = MlDsa::SecretKey.from_pem(sk.to_pem)

# Seed-only compact storage (32 bytes instead of full key)
sk4 = MlDsa::SecretKey.from_seed(seed, MlDsa::ML_DSA_65)
```

### Key management

```ruby
# Secret keys from keygen/from_seed carry the associated public key
sk.public_key == pk  # => true
sk.seed              # => 32-byte seed (nil if not created from seed)

# Keys deserialized from bytes/DER/PEM have no associated public key
MlDsa::SecretKey.from_der(sk.to_der).public_key  # => nil

# Fingerprint for logs and UIs (SHA-256 prefix, 32 hex chars)
pk.fingerprint  # => "a3b1c9f0e2d4..."

# Timestamps and metadata
pk.created_at           # => Time
sk.key_usage = :signing # application-defined label
```

### Secret key hygiene

Secret keys live in C-managed memory with `mlock` (prevents swap) and
`secure_zero` on GC. There is no `to_bytes` or `to_hex` on secret keys.

```ruby
# Controlled access — buffer is wiped on block exit, even on exception
sk.with_bytes do |buf|
  # buf is a temporary binary String
end

# Explicit wipe — subsequent operations raise MlDsa::Error
sk.wipe!
```

### Pluggable RNG

```ruby
MlDsa.random_source = proc { |n| "\x42" * n }  # for testing / HSM
MlDsa.random_source = nil                       # restore OS CSPRNG
```

### Instrumentation

```ruby
subscriber = MlDsa.subscribe do |event|
  logger.info "#{event[:operation]} #{event[:param_set].name} " \
              "count=#{event[:count]} duration=#{event[:duration_ns]}ns"
end

MlDsa.unsubscribe(subscriber)
```

Isolated configuration for per-Ractor or per-test contexts:

```ruby
cfg = MlDsa::Config.new
cfg.random_source = proc { |n| SecureRandom.random_bytes(n) }
pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65, config: cfg)
```

### PQC namespace

```ruby
PQC::MlDsa == MlDsa       # => true
PQC.algorithms             # => { ml_dsa: MlDsa }
PQC.algorithm(:ml_dsa)     # => MlDsa
```

## Error handling

```ruby
begin
  MlDsa::PublicKey.from_der(bad_data)
rescue MlDsa::Error::Deserialization => e
  e.message   # => "invalid DER: ..."
  e.format    # => "DER"
  e.position  # => 12
  e.reason    # => :unknown_oid
end
```

- `MlDsa::Error` — base class
  - `MlDsa::Error::KeyGeneration`
  - `MlDsa::Error::Signing`
  - `MlDsa::Error::Deserialization` — includes `format`, `position`, `reason`

## Security

| Property | Implementation |
|----------|---------------|
| Secure zeroing | `SecureZeroMemory` / `explicit_bzero` / `memset_s` / volatile fallback |
| Constant-time comparison | XOR-accumulate with compiler fence for secret key equality |
| Memory locking | `mlock` prevents secret key pages from swapping to disk |
| Thread-safe wipe | C11 `_Atomic` with acquire/release semantics |
| GVL release | All crypto runs without the Global VM Lock |
| Ractor safety | `PublicKey` is Ractor-shareable (`RUBY_TYPED_FROZEN_SHAREABLE`) |
| Symbol isolation | `-fvisibility=hidden` prevents PQClean symbol clashes |
| No OpenSSL | DER/PEM via [`pqc_asn1`](https://github.com/msuliq/pqc_asn1) gem |

## Development

```sh
bundle install
bundle exec rake compile
bundle exec rake test
bundle exec rake bench            # benchmarks (requires benchmark-ips)
bundle exec rake yard             # API docs
bundle exec standardrb            # Ruby lint
bundle exec rake lint:c           # C static analysis (requires cppcheck)
bundle exec rake pqclean:verify   # verify vendored PQClean patches
bundle exec rake generate:impl    # regenerate amalgamation files
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
