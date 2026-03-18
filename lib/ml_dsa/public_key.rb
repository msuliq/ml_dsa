# frozen_string_literal: true

module MlDsa
  # PublicKey — reopen the C TypedData class to add Ruby-level methods.
  #
  # C methods: param_set, bytesize, to_bytes, to_hex, fingerprint,
  # to_s, inspect, ==, eql?, hash, initialize_copy, _dump_data.
  #
  # verify is defined HERE in Ruby — it delegates to verify_many (batch
  # C API) with a single-element array.  This eliminates a separate
  # single-op verify C codepath that duplicated the batch logic.
  #
  # Bytes live in C-managed memory with a stable pointer.
  # dup/clone raise TypeError (C: initialize_copy).
  # Marshal.dump raises TypeError (C: _dump_data).

  class PublicKey
    # Verify a signature.
    #
    # Delegates to the batch C API (verify_many) with a single element.
    # This avoids maintaining a separate single-op C verify path.
    #
    # Returns false (not raises) for: wrong-size signature, context >255 bytes,
    # or cryptographic verification failure.
    # Raises TypeError for non-String message/signature/context.
    #
    # @param message   [String]
    # @param signature [String]
    # @param context   [String] FIPS 204 context string (0..255 bytes)
    # @return [Boolean]
    def verify(message, signature, context: "")
      raise TypeError, "message must be a String, got #{message.class}" unless message.is_a?(String)
      raise TypeError, "signature must be a String, got #{signature.class}" unless signature.is_a?(String)
      raise TypeError, "context must be a String, got #{context.class}" unless context.is_a?(String)
      # Context >255 bytes can never verify per FIPS 204 — return false
      # rather than raising, since verify is a predicate.
      return false unless context.bytesize <= 255
      # Early-reject wrong-size signatures without entering C
      return false unless signature.bytesize == param_set.signature_bytes
      req = VerifyRequest.new(pk: self, message: message,
        signature: signature, context: context)
      MlDsa.verify_many([req]).first.ok?
    end

    # Build SubjectPublicKeyInfo DER using the pqc_asn1 gem.
    # @return [String] frozen binary DER (ASCII-8BIT)
    def to_der
      oid = PqcAsn1::OID[ML_DSA_OIDS[param_set.code]]
      PqcAsn1::DER.build_spki(oid, to_bytes, validate: false)
    end

    # Build PEM-encoded SubjectPublicKeyInfo using the pqc_asn1 gem.
    # @return [String] frozen PEM string
    def to_pem
      PqcAsn1::PEM.encode(to_der, "PUBLIC KEY")
    end

    # fingerprint is now a C method (lazy-computed, cached in struct).
    # See pk_fingerprint in ml_dsa_ext.c.

    # Deserialize a public key from raw binary bytes.
    #
    # When param_set is omitted, the parameter set is auto-detected from
    # the byte length (each ML-DSA parameter set has a unique PK size).
    #
    # @param bytes     [String]
    # @param param_set [ParameterSet, nil] auto-detected from size if omitted
    # @return [PublicKey]
    def self.from_bytes(bytes, param_set = nil)
      raise TypeError, "bytes must be a String, got #{bytes.class}" unless bytes.is_a?(String)
      if param_set
        ps = Internal.resolve_ps(param_set)
        unless bytes.bytesize == ps.public_key_bytes
          raise ArgumentError,
            "expected #{ps.public_key_bytes} bytes for #{ps.name}, " \
            "got #{bytes.bytesize}"
        end
      else
        ps = PARAM_SET_BY_PK_SIZE[bytes.bytesize]
        unless ps
          raise ArgumentError,
            "cannot auto-detect parameter set from #{bytes.bytesize}-byte public key " \
            "(expected #{PARAM_SET_BY_PK_SIZE.keys.sort.join(", ")})"
        end
      end
      pk = _from_bytes_raw(bytes.b, ps.code)
      pk.instance_variable_set(:@created_at, Time.now.freeze)
      pk
    end

    # Deserialize a public key from a lowercase or uppercase hex string.
    #
    # @param hex       [String]
    # @param param_set [ParameterSet, nil] auto-detected from size if omitted
    # @return [PublicKey]
    def self.from_hex(hex, param_set = nil)
      from_bytes(Internal.decode_hex(hex), param_set)
    end

    # Deserialize a public key from SubjectPublicKeyInfo DER.
    # @param der [String] DER-encoded SPKI
    # @return [PublicKey]
    # @raise [MlDsa::Error::Deserialization] on malformed or unrecognized input
    def self.from_der(der)
      raise TypeError, "der must be a String, got #{der.class}" unless der.is_a?(String)
      begin
        info = PqcAsn1::DER.parse_spki(der)
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
      unless info.key.bytesize == ps.public_key_bytes
        Internal.raise_deser("DER", nil, "wrong_key_size",
          "invalid DER: public key is #{info.key.bytesize} bytes, " \
          "expected #{ps.public_key_bytes} for #{ps.name}")
      end
      pk = from_bytes(info.key, ps)
      pk.instance_variable_set(:@created_at, Time.now.freeze)
      pk
    end

    # Deserialize a public key from PEM-encoded SubjectPublicKeyInfo.
    # @param pem [String] PEM-encoded public key
    # @return [PublicKey]
    # @raise [MlDsa::Error::Deserialization] on malformed or unrecognized input
    def self.from_pem(pem)
      raise TypeError, "pem must be a String, got #{pem.class}" unless pem.is_a?(String)
      begin
        result = PqcAsn1::PEM.decode_auto(pem)
      rescue PqcAsn1::ParseError, PqcAsn1::Error => e
        Internal.raise_deser("PEM", nil, "missing_armor", e.message)
      end
      unless result.label == "PUBLIC KEY"
        Internal.raise_deser("PEM", nil, "wrong_label",
          "invalid PEM: expected PUBLIC KEY, found #{result.label}")
      end
      begin
        info = PqcAsn1::DER.parse_spki(result.data)
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
      unless info.key.bytesize == ps.public_key_bytes
        Internal.raise_deser("PEM", nil, "wrong_key_size",
          "invalid PEM: public key is #{info.key.bytesize} bytes, " \
          "expected #{ps.public_key_bytes} for #{ps.name}")
      end
      pk = from_bytes(info.key, ps)
      pk.instance_variable_set(:@created_at, Time.now.freeze)
      pk
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
  end
end
