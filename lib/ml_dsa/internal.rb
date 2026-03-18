# frozen_string_literal: true

module MlDsa
  # Nested module with private_constant so that MlDsa::Internal is
  # accessible inside this gem but invisible to external callers.
  module Internal
    # Named positions for the flat Ruby→C boundary arrays.
    # Must match SIGN_OP_* / VERIFY_OP_* macros in ml_dsa_internal.h.
    SIGN_OP_SK = 0
    SIGN_OP_MSG = 1
    SIGN_OP_CTX = 2
    SIGN_OP_DET = 3
    SIGN_OP_RND = 4   # optional pre-generated rnd bytes (pluggable RNG)

    VERIFY_OP_PK = 0
    VERIFY_OP_MSG = 1
    VERIFY_OP_SIG = 2
    VERIFY_OP_CTX = 3

    RND_BYTES = 32

    # Default number of items between cooperative yields to the fiber
    # scheduler during batch normalization loops.  Zero means no yielding.
    DEFAULT_YIELD_EVERY = 0

    # Yield to the fiber scheduler if one is active and yield_every > 0.
    # Called inside normalization loops to allow other fibers to run
    # during large batch preparations.
    def self.maybe_yield(i, yield_every)
      return unless yield_every > 0 && ((i + 1) % yield_every).zero?
      scheduler = Fiber.scheduler
      return unless scheduler
      scheduler.yield
    rescue NoMethodError
      # Fiber.scheduler or scheduler.yield not available (Ruby < 3.1)
      nil
    end

    # Raise MlDsa::Error::Deserialization with structured metadata.
    def self.raise_deser(format_str, position, reason, message)
      err = MlDsa::Error::Deserialization.new(message)
      err.instance_variable_set(:@format, format_str)
      err.instance_variable_set(:@position, position)
      err.instance_variable_set(:@reason, reason.to_sym)
      raise err
    end

    # Look up the ParameterSet for a given code (44, 65, or 87).
    def self.param_set_for_code(code)
      MlDsa.const_get("ML_DSA_#{code}")
    end

    # Validate and return a ParameterSet.
    def self.resolve_ps(ps)
      case ps
      when ParameterSet then ps
      else
        raise TypeError,
          "param_set must be a MlDsa::ParameterSet " \
          "(ML_DSA_44, ML_DSA_65, or ML_DSA_87), got #{ps.class}"
      end
    end

    # Validate a hex string and decode to binary bytes.
    def self.decode_hex(hex)
      raise TypeError, "hex must be a String, got #{hex.class}" unless hex.is_a?(String)
      raise ArgumentError, "hex string must not be empty" if hex.empty?
      unless hex.match?(/\A[0-9a-fA-F]+\z/) && hex.length.even?
        raise ArgumentError,
          "hex must contain only hexadecimal characters and have even length"
      end
      [hex].pack("H*")
    end
  end
  private_constant :Internal
end
