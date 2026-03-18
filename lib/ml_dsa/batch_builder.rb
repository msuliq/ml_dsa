# frozen_string_literal: true

module MlDsa
  # Collects sign or verify operations for batch execution.
  # Obtained via {MlDsa.batch}. Do not mix sign and verify in one batch.
  class BatchBuilder
    def initialize
      @ops = []
      @mode = nil
    end

    # Add a sign operation to the batch.
    # @param sk [SecretKey]
    # @param message [String]
    # @param context [String, nil] FIPS 204 context (0..255 bytes)
    # @param deterministic [Boolean] use deterministic signing
    # @return [self] for chaining
    def sign(sk:, message:, context: nil, deterministic: false)
      check_mode!(:sign)
      @ops << SignRequest.new(sk: sk, message: message,
        context: context, deterministic: deterministic)
      self
    end

    # Add a verify operation to the batch.
    # @param pk [PublicKey]
    # @param message [String]
    # @param signature [String]
    # @param context [String, nil] FIPS 204 context (0..255 bytes)
    # @return [self] for chaining
    def verify(pk:, message:, signature:, context: nil)
      check_mode!(:verify)
      @ops << VerifyRequest.new(pk: pk, message: message,
        signature: signature, context: context)
      self
    end

    # @api private
    def execute(config: MlDsa.config, yield_every: Internal::DEFAULT_YIELD_EVERY)
      return [] if @ops.empty?
      if @mode == :sign
        MlDsa.sign_many(@ops, config: config, yield_every: yield_every)
      else
        MlDsa.verify_many(@ops, config: config, yield_every: yield_every)
      end
    end

    private

    def check_mode!(mode)
      if @mode && @mode != mode
        raise ArgumentError, "cannot mix sign and verify in the same batch"
      end
      @mode = mode
    end
  end
end
