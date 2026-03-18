# frozen_string_literal: true

module MlDsa
  # SecretKey — reopen the C TypedData class to add Ruby-level methods.
  #
  # C methods: param_set, public_key, seed, bytesize, with_bytes, wipe!,
  # inspect, to_s, ==, eql?, hash, initialize_copy, _dump_data.
  #
  # sign is defined HERE in Ruby — it delegates to sign_many (batch
  # C API) with a single-element array.  This eliminates a separate
  # single-op sign C codepath that duplicated the batch logic.
  #
  # DER/PEM serialization is defined HERE in Ruby via the pqc_asn1 gem.
  # SecureBuffer from pqc_asn1 handles secure zeroing of DER intermediates.
  #
  # Key lives in C-managed memory that is secure_zero'd on GC.
  # SecretKey is intentionally NOT frozen so wipe! is semantically
  # consistent with Ruby's mutability contract.
  # dup/clone raise TypeError (C: initialize_copy).
  # Marshal.dump raises TypeError (C: _dump_data).

  class SecretKey
    # Sign a message.
    #
    # Delegates to the batch C API (sign_many) with a single element.
    # This avoids maintaining a separate single-op C sign path.
    #
    # @param message       [String]
    # @param deterministic [Boolean] use zero rnd (reproducible signatures)
    # @param context       [String]  FIPS 204 context string (0..255 bytes)
    # @return [String] frozen binary signature
    def sign(message, deterministic: false, context: "")
      raise TypeError, "message must be a String, got #{message.class}" unless message.is_a?(String)
      unless context.is_a?(String)
        raise TypeError, "context must be a String, got #{context.class}"
      end
      if context.bytesize > 255
        raise ArgumentError, "context must not exceed 255 bytes"
      end
      req = SignRequest.new(sk: self, message: message,
        context: context, deterministic: deterministic)
      MlDsa.sign_many([req]).first
    end

    # Build PKCS#8 / OneAsymmetricKey DER using the pqc_asn1 gem.
    # The raw key bytes are accessed via with_bytes and the intermediate
    # DER is held in a pqc_asn1 SecureBuffer (mmap-protected, securely zeroed).
    # @return [String] frozen binary DER (ASCII-8BIT)
    def to_der
      oid = PqcAsn1::OID[ML_DSA_OIDS[param_set.code]]
      with_bytes do |raw|
        secure_buf = PqcAsn1::DER.build_pkcs8(oid, raw, validate: false)
        # Force a real memory copy (not CoW) since SecureBuffer will
        # re-lock the mmap'd page after the use block returns.
        result = secure_buf.use { |der_bytes| "".b << der_bytes }
        secure_buf.wipe!
        result.freeze
      end
    end

    # Build PEM-encoded PKCS#8 / OneAsymmetricKey using the pqc_asn1 gem.
    # @return [String] frozen PEM string
    def to_pem
      oid = PqcAsn1::OID[ML_DSA_OIDS[param_set.code]]
      with_bytes do |raw|
        secure_buf = PqcAsn1::DER.build_pkcs8(oid, raw, validate: false)
        result = PqcAsn1::PEM.encode(secure_buf, "PRIVATE KEY")
        secure_buf.wipe!
        result
      end
    end

    # Deserialize a secret key from raw binary bytes.
    #
    # When param_set is omitted, the parameter set is auto-detected from
    # the byte length (each ML-DSA parameter set has a unique SK size).
    #
    # The bytes are copied into C-managed memory; the caller's String is
    # independent.  The returned SecretKey will zero its copy on GC.
    # Prefer with_bytes { |b| ... } for automatic wipe-on-exit.
    #
    # @param bytes     [String]
    # @param param_set [ParameterSet, nil] auto-detected from size if omitted
    # @return [SecretKey]
    def self.from_bytes(bytes, param_set = nil)
      raise TypeError, "bytes must be a String" unless bytes.is_a?(String)
      if param_set
        ps = Internal.resolve_ps(param_set)
        unless bytes.bytesize == ps.secret_key_bytes
          raise ArgumentError,
            "expected #{ps.secret_key_bytes} bytes for #{ps.name}, " \
            "got #{bytes.bytesize}"
        end
      else
        ps = PARAM_SET_BY_SK_SIZE[bytes.bytesize]
        unless ps
          raise ArgumentError,
            "cannot auto-detect parameter set from #{bytes.bytesize}-byte secret key " \
            "(expected #{PARAM_SET_BY_SK_SIZE.keys.sort.join(", ")})"
        end
      end
      sk = _from_bytes_raw(bytes.b, ps.code)
      sk.instance_variable_set(:@created_at, Time.now.freeze)
      sk
    end

    # Deserialize a secret key from a lowercase or uppercase hex string.
    #
    # @param hex       [String]
    # @param param_set [ParameterSet, nil] auto-detected from size if omitted
    # @return [SecretKey]
    def self.from_hex(hex, param_set = nil)
      from_bytes(Internal.decode_hex(hex), param_set)
    end

    # Deserialize a secret key from PKCS#8 / OneAsymmetricKey DER.
    # Uses pqc_asn1 gem for parsing; secret key bytes are held in a
    # SecureBuffer and only temporarily unlocked to create the key.
    # @param der [String] DER-encoded PKCS#8
    # @return [SecretKey]
    # @raise [MlDsa::Error::Deserialization] on malformed or unrecognized input
    def self.from_der(der)
      raise TypeError, "der must be a String, got #{der.class}" unless der.is_a?(String)
      begin
        info = PqcAsn1::DER.parse_pkcs8(der)
      rescue PqcAsn1::ParseError, PqcAsn1::Error => e
        Internal.raise_deser("DER", e.respond_to?(:offset) ? e.offset : nil,
          e.respond_to?(:code) ? e.code.to_s : "parse_error", e.message)
      end
      oid_code = ML_DSA_OID_TO_CODE[info.oid.dotted]
      unless oid_code
        Internal.raise_deser("DER", nil, "unknown_oid",
          "unknown ML-DSA OID: #{info.oid.dotted}")
      end
      ps = Internal.param_set_for_code(oid_code)
      # info.key is a PqcAsn1::SecureBuffer — unlock temporarily
      sk = info.key.use do |raw_bytes|
        unless raw_bytes.bytesize == ps.secret_key_bytes
          Internal.raise_deser("DER", nil, "wrong_key_size",
            "invalid DER: secret key is #{raw_bytes.bytesize} bytes, " \
            "expected #{ps.secret_key_bytes} for #{ps.name}")
        end
        _from_bytes_raw(raw_bytes.b, ps.code)
      end
      info.key.wipe!
      sk.instance_variable_set(:@created_at, Time.now.freeze)
      sk
    end

    # Deserialize a secret key from PEM-encoded PKCS#8.
    # @param pem [String] PEM-encoded private key
    # @return [SecretKey]
    # @raise [MlDsa::Error::Deserialization] on malformed or unrecognized input
    def self.from_pem(pem)
      raise TypeError, "pem must be a String, got #{pem.class}" unless pem.is_a?(String)
      begin
        result = PqcAsn1::PEM.decode_auto(pem)
      rescue PqcAsn1::ParseError, PqcAsn1::Error => e
        Internal.raise_deser("PEM", nil, "missing_armor", e.message)
      end
      unless result.label == "PRIVATE KEY"
        Internal.raise_deser("PEM", nil, "wrong_label",
          "invalid PEM: expected PRIVATE KEY, found #{result.label}")
      end
      begin
        info = PqcAsn1::DER.parse_pkcs8(result.data)
      rescue PqcAsn1::ParseError, PqcAsn1::Error => e
        Internal.raise_deser("PEM", e.respond_to?(:offset) ? e.offset : nil,
          e.respond_to?(:code) ? e.code.to_s : "parse_error", e.message)
      end
      oid_code = ML_DSA_OID_TO_CODE[info.oid.dotted]
      unless oid_code
        Internal.raise_deser("PEM", nil, "unknown_oid",
          "unknown ML-DSA OID: #{info.oid.dotted}")
      end
      ps = Internal.param_set_for_code(oid_code)
      sk = info.key.use do |raw_bytes|
        unless raw_bytes.bytesize == ps.secret_key_bytes
          Internal.raise_deser("PEM", nil, "wrong_key_size",
            "invalid PEM: secret key is #{raw_bytes.bytesize} bytes, " \
            "expected #{ps.secret_key_bytes} for #{ps.name}")
        end
        _from_bytes_raw(raw_bytes.b, ps.code)
      end
      info.key.wipe!
      sk.instance_variable_set(:@created_at, Time.now.freeze)
      sk
    end

    # @return [Time] when this key was created (set by keygen/from_bytes/from_der/from_pem)
    attr_reader :created_at

    # @return [Symbol, nil] application-defined usage label
    attr_reader :key_usage

    # Set an application-defined usage label.
    # @param value [Symbol, nil]
    def key_usage=(value)
      unless value.nil? || value.is_a?(Symbol)
        raise TypeError, "key_usage must be a Symbol or nil, got #{value.class}"
      end
      @key_usage = value
    end

    # Reconstruct a secret key deterministically from a 32-byte seed.
    #
    # This is the compact "seed-only" approach: store just 32 bytes and
    # expand to the full secret key (+ public key) on demand.  The
    # returned SecretKey has +public_key+ set automatically.
    #
    # @param seed      [String] exactly 32 bytes
    # @param param_set [ParameterSet] ML_DSA_44, ML_DSA_65, or ML_DSA_87
    # @return [SecretKey] with +public_key+ attached
    # @raise [TypeError] if seed is not a String or param_set is invalid
    # @raise [ArgumentError] if seed is not exactly 32 bytes
    def self.from_seed(seed, param_set)
      pair = MlDsa.keygen(param_set, seed: seed)
      pair.secret_key
    end
  end
end
