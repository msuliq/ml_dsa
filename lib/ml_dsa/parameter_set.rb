# frozen_string_literal: true

module MlDsa
  # Encapsulates a concrete ML-DSA parameter set (44, 65, or 87).
  #
  # Obtain instances via the +ML_DSA_44+, +ML_DSA_65+, +ML_DSA_87+ constants;
  # do not call +new+ directly.  Supports +Comparable+ ordering by security
  # level: +ML_DSA_44 < ML_DSA_65 < ML_DSA_87+.
  class ParameterSet
    include Comparable

    # @return [String] human-readable name, e.g. +"ML-DSA-44"+
    attr_reader :name
    # @return [Integer] numeric code (44, 65, or 87)
    attr_reader :code
    # @return [Integer] NIST security level (2, 3, or 5)
    attr_reader :security_level
    # @return [Integer] public key size in bytes
    attr_reader :public_key_bytes
    # @return [Integer] secret key size in bytes
    attr_reader :secret_key_bytes
    # @return [Integer] signature size in bytes
    attr_reader :signature_bytes

    def initialize(name, code, security_level, pk, sk, sig)
      @name = name.freeze
      @code = code
      @security_level = security_level
      @public_key_bytes = pk
      @secret_key_bytes = sk
      @signature_bytes = sig
      freeze
    end

    def <=>(other)
      return nil unless other.is_a?(ParameterSet)
      @security_level <=> other.security_level
    end

    def to_s
      @name
    end

    def inspect
      "#<MlDsa::ParameterSet #{@name}>"
    end

    private_class_method :new
  end

  # Build ParameterSet constants from C extension data — no raw integer
  # constants are exposed in the public API.
  # Each row is [code, security_level, pk_bytes, sk_bytes, sig_bytes].
  _param_data.each do |code, security_level, pk_bytes, sk_bytes, sig_bytes|
    name = "ML-DSA-#{code}"
    const_name = "ML_DSA_#{code}"
    ps = ParameterSet.send(:new,
      name, code, security_level, pk_bytes, sk_bytes, sig_bytes)
    const_set(const_name, ps)
  end

  # OIDs assigned by NIST for ML-DSA parameter sets (FIPS 204).
  ML_DSA_OIDS = {
    44 => "2.16.840.1.101.3.4.3.17",
    65 => "2.16.840.1.101.3.4.3.18",
    87 => "2.16.840.1.101.3.4.3.19"
  }.freeze

  ML_DSA_OID_TO_CODE = ML_DSA_OIDS.invert.freeze

  # O(1) lookup tables for param_set_for_signature_size / param_set_for_pk_size
  PARAM_SET_BY_SIG_SIZE = constants.filter_map { |c|
    ps = const_get(c)
    [ps.signature_bytes, ps] if ps.is_a?(ParameterSet)
  }.to_h.freeze
  private_constant :PARAM_SET_BY_SIG_SIZE

  PARAM_SET_BY_PK_SIZE = constants.filter_map { |c|
    ps = const_get(c)
    [ps.public_key_bytes, ps] if ps.is_a?(ParameterSet)
  }.to_h.freeze
  private_constant :PARAM_SET_BY_PK_SIZE

  PARAM_SET_BY_SK_SIZE = constants.filter_map { |c|
    ps = const_get(c)
    [ps.secret_key_bytes, ps] if ps.is_a?(ParameterSet)
  }.to_h.freeze
  private_constant :PARAM_SET_BY_SK_SIZE
end
