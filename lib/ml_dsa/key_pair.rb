# frozen_string_literal: true

module MlDsa
  # Holds a matched public/secret key pair returned by {MlDsa.keygen}.
  # Supports destructuring: +pk, sk = MlDsa.keygen(...)+.
  class KeyPair
    # @return [PublicKey]
    attr_reader :public_key
    # @return [SecretKey]
    attr_reader :secret_key

    def initialize(public_key, secret_key)
      @public_key = public_key
      @secret_key = secret_key
      freeze
    end

    # Support destructuring: +pk, sk = keygen(...)+.
    # @return [Array(PublicKey, SecretKey)]
    def to_ary
      [public_key, secret_key]
    end

    alias_method :to_a, :to_ary
    alias_method :deconstruct, :to_ary

    # @return [ParameterSet]
    def param_set
      public_key.param_set
    end

    # @return [String]
    def inspect
      "#<MlDsa::KeyPair #{param_set.name}>"
    end

    alias_method :to_s, :inspect
  end
end
