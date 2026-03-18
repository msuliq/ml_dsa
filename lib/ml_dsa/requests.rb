# frozen_string_literal: true

module MlDsa
  # Describes a single sign operation for {MlDsa.sign_many}.
  #
  # @!attribute [rw] sk
  #   @return [SecretKey] the signing key
  # @!attribute [rw] message
  #   @return [String] the message to sign
  # @!attribute [rw] context
  #   @return [String, nil] optional FIPS 204 context (0..255 bytes)
  # @!attribute [rw] deterministic
  #   @return [Boolean, nil] use deterministic signing (zero rnd)
  SignRequest = Struct.new(:sk, :message, :context, :deterministic,
    keyword_init: true) do
    # Validates field types before entering C.
    # @return [self]
    # @raise [ArgumentError] if any field has an invalid type
    def validate!
      unless sk.is_a?(MlDsa::SecretKey)
        raise ArgumentError,
          "SignRequest :sk must be a MlDsa::SecretKey, got #{sk.class}"
      end
      unless message.is_a?(String)
        raise ArgumentError,
          "SignRequest :message must be a String, got #{message.class}"
      end
      if !context.nil? && !context.is_a?(String)
        raise ArgumentError,
          "SignRequest :context must be a String or nil, got #{context.class}"
      end
      self
    end
  end

  # Describes a single verify operation for {MlDsa.verify_many}.
  #
  # @!attribute [rw] pk
  #   @return [PublicKey] the verification key
  # @!attribute [rw] message
  #   @return [String] the message that was signed
  # @!attribute [rw] signature
  #   @return [String] the signature to verify
  # @!attribute [rw] context
  #   @return [String, nil] optional FIPS 204 context (0..255 bytes)
  VerifyRequest = Struct.new(:pk, :message, :signature, :context,
    keyword_init: true) do
    # Validates field types before entering C.
    # @return [self]
    # @raise [ArgumentError] if any field has an invalid type
    def validate!
      unless pk.is_a?(MlDsa::PublicKey)
        raise ArgumentError,
          "VerifyRequest :pk must be a MlDsa::PublicKey, got #{pk.class}"
      end
      unless message.is_a?(String)
        raise ArgumentError,
          "VerifyRequest :message must be a String, got #{message.class}"
      end
      unless signature.is_a?(String)
        raise ArgumentError,
          "VerifyRequest :signature must be a String, got #{signature.class}"
      end
      if !context.nil? && !context.is_a?(String)
        raise ArgumentError,
          "VerifyRequest :context must be a String or nil, got #{context.class}"
      end
      self
    end
  end

  # Result wrapper for batch operations that need per-item error details.
  #
  # @example
  #   results = MlDsa.verify_many(operations)
  #   results.each do |r|
  #     if r.ok?
  #       puts "valid"
  #     else
  #       puts "failed: #{r.reason}"
  #     end
  #   end
  Result = Struct.new(:value, :ok, :reason, keyword_init: true) do
    # @return [Boolean] true if the operation succeeded
    def ok?
      ok
    end

    # @return [String]
    def inspect
      ok? ? "#<MlDsa::Result ok>" : "#<MlDsa::Result error=#{reason}>"
    end

    alias_method :to_s, :inspect
  end
end
