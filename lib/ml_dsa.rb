# frozen_string_literal: true

require_relative "ml_dsa/version"
require "ml_dsa/ml_dsa_ext"
require "pqc_asn1"

require_relative "ml_dsa/config"
require_relative "ml_dsa/parameter_set"
require_relative "ml_dsa/internal"
require_relative "ml_dsa/requests"
require_relative "ml_dsa/key_pair"
require_relative "ml_dsa/public_key"
require_relative "ml_dsa/secret_key"
require_relative "ml_dsa/batch_builder"

module MlDsa
  # Seed size (bytes) for deterministic key generation.
  SEED_BYTES = 32

  # The default global Config instance.
  # @return [Config]
  def self.config
    @config
  end

  @config = Config.new

  # -----------------------------------------------------------------------
  # Convenience delegators — keep the existing top-level API working
  # -----------------------------------------------------------------------

  # Subscribe to instrumentation events on the default config.
  # @see Config#subscribe
  def self.subscribe(&block)
    @config.subscribe(&block)
  end

  # Remove a subscriber from the default config.
  # @see Config#unsubscribe
  def self.unsubscribe(subscriber)
    @config.unsubscribe(subscriber)
  end

  # @return [Proc, nil] the current random source on the default config
  def self.random_source
    @config.random_source
  end

  # Set the random source on the default config.
  # @param source [Proc, nil]
  def self.random_source=(source)
    @config.random_source = source
  end

  # -----------------------------------------------------------------------
  # Module-level API
  # -----------------------------------------------------------------------

  class << self
    # Generate a key pair for the given parameter set.
    #
    # @param param_set [ParameterSet] ML_DSA_44, ML_DSA_65, or ML_DSA_87
    # @param seed [String, nil] optional 32-byte seed for deterministic keygen
    # @param config [Config] configuration (default: MlDsa.config)
    # @return [KeyPair] frozen key pair (supports destructuring: +pk, sk = keygen(...)+)
    # @raise [TypeError] if param_set is not a ParameterSet
    # @raise [ArgumentError] if seed is not exactly 32 bytes
    def keygen(param_set, seed: nil, config: nil)
      cfg = config || @config
      ps = Internal.resolve_ps(param_set)
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      if seed
        raise TypeError, "seed must be a String" unless seed.is_a?(String)
        seed_bin = seed.b
        raise ArgumentError, "seed must be exactly 32 bytes, got #{seed_bin.bytesize}" unless seed_bin.bytesize == 32
        pk, sk = _keygen_seed(ps.code, seed_bin)
      elsif cfg.random_source
        # Pluggable RNG: generate a seed and use deterministic keygen
        rng_seed = cfg.random_source.call(SEED_BYTES)
        unless rng_seed.is_a?(String) && rng_seed.bytesize == SEED_BYTES
          raise ArgumentError,
            "random_source must return #{SEED_BYTES} bytes, " \
            "got #{rng_seed.is_a?(String) ? rng_seed.bytesize : rng_seed.class}"
        end
        pk, sk = _keygen_seed(ps.code, rng_seed.b)
      else
        pk, sk = _keygen(ps.code)
      end
      now = Time.now.freeze
      pk.instance_variable_set(:@created_at, now)
      sk.instance_variable_set(:@created_at, now)
      duration = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - t0
      cfg.notify(:keygen, ps, 1, duration)
      KeyPair.new(pk, sk)
    end

    # Sign multiple messages in a single GVL drop.
    #
    # @param operations [Array<SignRequest>]
    # @param config [Config] configuration (default: MlDsa.config)
    # @param yield_every [Integer] yield to the fiber scheduler every N items
    #   during the normalization loop (0 = never, default)
    # @return [Array<String>] frozen array of frozen binary signature strings
    def sign_many(operations, config: nil, yield_every: Internal::DEFAULT_YIELD_EVERY)
      cfg = config || @config
      unless operations.is_a?(Array)
        raise TypeError, "operations must be an Array, got #{operations.class}"
      end
      return [].freeze if operations.empty?
      ops = operations.each_with_index.map do |op, i|
        Internal.maybe_yield(i, yield_every)
        normalize_sign_op(op, i, cfg)
      end
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      result = _sign_many(ops)
      duration = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - t0
      ps = operations.first&.sk&.param_set
      cfg.notify(:sign, ps, operations.size, duration)
      result
    end

    # Verify multiple signatures in a single GVL drop.
    #
    # Returns {Result} objects with per-item details: +.ok?+ indicates
    # success, +.reason+ distinguishes wrong-size signatures from
    # cryptographic verification failures.
    #
    # @param operations [Array<VerifyRequest>]
    # @param config [Config] configuration (default: MlDsa.config)
    # @param yield_every [Integer] yield to the fiber scheduler every N items
    #   during the normalization loop (0 = never, default)
    # @return [Array<Result>] frozen array of Result objects
    def verify_many(operations, config: nil, yield_every: Internal::DEFAULT_YIELD_EVERY)
      cfg = config || @config
      unless operations.is_a?(Array)
        raise TypeError, "operations must be an Array, got #{operations.class}"
      end
      return [].freeze if operations.empty?
      # Pre-check signature sizes to distinguish size errors from crypto failures
      size_ok = operations.map do |op|
        Internal.resolve_ps(op.pk.param_set)
        op.signature.bytesize == op.pk.param_set.signature_bytes
      end
      ops = operations.each_with_index.map do |op, i|
        Internal.maybe_yield(i, yield_every)
        normalize_verify_op(op, i)
      end
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      bools = _verify_many(ops)
      duration = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - t0
      ps = operations.first&.pk&.param_set
      cfg.notify(:verify, ps, operations.size, duration)
      results = operations.each_with_index.map do |op, i|
        if bools[i]
          Result.new(value: true, ok: true, reason: nil)
        elsif !size_ok[i]
          expected = op.pk.param_set.signature_bytes
          Result.new(value: false, ok: false,
            reason: "wrong_signature_size: expected #{expected}, got #{op.signature.bytesize}")
        else
          Result.new(value: false, ok: false, reason: "verification_failed")
        end
      end
      results.freeze
    end

    # Unified batch builder — collects sign/verify ops and executes them
    # in a single GVL drop.
    #
    # @example Batch signing
    #   sigs = MlDsa.batch { |b| b.sign(sk: sk, message: msg) }
    #
    # @example Batch verification
    #   results = MlDsa.batch { |b| b.verify(pk: pk, message: msg, signature: sig) }
    #
    # @yield [BatchBuilder]
    # @return [Array<String>] for sign batches, [Array<Result>] for verify batches
    # @raise [ArgumentError] if the batch mixes sign and verify operations
    def batch(config: nil, yield_every: Internal::DEFAULT_YIELD_EVERY)
      cfg = config || @config
      builder = BatchBuilder.new
      yield builder
      builder.execute(config: cfg, yield_every: yield_every)
    end

    private

    # Returns a flat 5-element array [sk, message, ctx, det, rnd_or_nil].
    # Flat arrays avoid per-item Hash allocation in the Ruby→C boundary.
    # Position constants are in Internal::SIGN_OP_*.
    def normalize_sign_op(op, idx, cfg)
      unless op.is_a?(SignRequest)
        raise TypeError,
          "sign_many: item #{idx} must be a SignRequest, got #{op.class}"
      end
      op.validate!
      rnd = nil
      rng = cfg.random_source
      if !op.deterministic && rng
        rnd = rng.call(Internal::RND_BYTES)
        unless rnd.is_a?(String) && rnd.bytesize == Internal::RND_BYTES
          raise ArgumentError,
            "random_source must return #{Internal::RND_BYTES} bytes, " \
            "got #{rnd.is_a?(String) ? rnd.bytesize : rnd.class}"
        end
      end
      [op.sk, op.message, op.context, op.deterministic, rnd]
    end

    # Returns a flat 4-element array [pk, message, signature, ctx_or_nil].
    # Position constants are in Internal::VERIFY_OP_*.
    def normalize_verify_op(op, idx)
      unless op.is_a?(VerifyRequest)
        raise TypeError,
          "verify_many: item #{idx} must be a VerifyRequest, got #{op.class}"
      end
      op.validate!
      [op.pk, op.message, op.signature, op.context]
    end

    # Look up the ParameterSet whose signature size matches +n+ bytes.
    # @param n [Integer] signature byte count
    # @return [ParameterSet]
    # @raise [ArgumentError] if no parameter set matches
    def param_set_for_signature_size(n)
      ps = PARAM_SET_BY_SIG_SIZE[n]
      return ps if ps
      raise ArgumentError, "no ML-DSA parameter set has #{n}-byte signatures"
    end

    # Look up the ParameterSet whose public key size matches +n+ bytes.
    # @param n [Integer] public key byte count
    # @return [ParameterSet]
    # @raise [ArgumentError] if no parameter set matches
    def param_set_for_pk_size(n)
      ps = PARAM_SET_BY_PK_SIZE[n]
      return ps if ps
      raise ArgumentError, "no ML-DSA parameter set has #{n}-byte public keys"
    end
  end
end

# PQC umbrella namespace for post-quantum cryptographic algorithms.
#
# Currently only ML-DSA is implemented; future algorithms (ML-KEM,
# SLH-DSA, etc.) can register here for unified discovery.
#
# @example
#   PQC.algorithms              # => { ml_dsa: MlDsa }
#   PQC.algorithm(:ml_dsa)      # => MlDsa
#   PQC::MlDsa == ::MlDsa       # => true
module PQC
  @registry = {}

  # Register a PQC algorithm module under a symbolic name.
  # @param name [Symbol]
  # @param mod [Module]
  def self.register(name, mod)
    @registry[name.to_sym] = mod
  end

  # List all registered PQC algorithms.
  # @return [Hash{Symbol => Module}]
  def self.algorithms
    @registry.dup
  end

  # Look up a registered algorithm by name.
  # @param name [Symbol]
  # @return [Module, nil]
  def self.algorithm(name)
    @registry[name.to_sym]
  end

  MlDsa = ::MlDsa
  register(:ml_dsa, ::MlDsa)
end
