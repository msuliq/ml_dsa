# frozen_string_literal: true

require "test_helper"

class MlDsaErrorClassesTest < Minitest::Test
  def test_error_hierarchy
    assert MlDsa::Error < StandardError
    assert MlDsa::Error::KeyGeneration < MlDsa::Error
    assert MlDsa::Error::Signing < MlDsa::Error
    assert MlDsa::Error::Deserialization < MlDsa::Error
  end

  def test_error_subclasses_are_distinct
    refute_equal MlDsa::Error::KeyGeneration, MlDsa::Error::Signing
    refute_equal MlDsa::Error::KeyGeneration, MlDsa::Error::Deserialization
    refute_equal MlDsa::Error::Signing, MlDsa::Error::Deserialization
  end

  def test_rescue_base_error_catches_subclasses
    rescued = false
    begin
      raise MlDsa::Error::Signing, "test"
    rescue MlDsa::Error
      rescued = true
    end
    assert rescued
  end

  def test_rescue_specific_subclass
    assert_raises(MlDsa::Error::Signing) { raise MlDsa::Error::Signing, "sign failed" }
    assert_raises(MlDsa::Error::KeyGeneration) { raise MlDsa::Error::KeyGeneration, "keygen failed" }
    assert_raises(MlDsa::Error::Deserialization) { raise MlDsa::Error::Deserialization, "deser" }
  end

  def test_signing_error_not_rescued_by_keygen_handler
    raise MlDsa::Error::Signing, "test"
  rescue MlDsa::Error::KeyGeneration
    flunk "Signing should not be rescued by KeyGeneration handler"
  rescue MlDsa::Error::Signing
    # expected
  end

  # --- Structured error metadata ---

  def test_deserialization_error_has_metadata_accessors
    exc = MlDsa::Error::Deserialization.new("test")
    assert_respond_to exc, :format
    assert_respond_to exc, :position
    assert_respond_to exc, :reason
  end

  def test_sk_from_der_invalid_tag_metadata
    garbage = "\x00\x01\x02".b
    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_der(garbage)
    end
    assert_equal "DER", exc.format
    assert_equal :outer_sequence, exc.reason
    assert_match(/SEQUENCE/, exc.message)
  end

  def test_sk_from_pem_wrong_label_metadata
    pem = "-----BEGIN PUBLIC KEY-----\nYQ==\n-----END PUBLIC KEY-----\n"
    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_pem(pem)
    end
    assert_equal "PEM", exc.format
    assert_nil exc.position
    assert_equal :wrong_label, exc.reason
    assert_match(/expected PRIVATE KEY/, exc.message)
  end

  def test_sk_from_pem_missing_armor_metadata
    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_pem("not pem at all")
    end
    assert_equal "PEM", exc.format
    assert_equal :missing_armor, exc.reason
  end

  def test_pk_from_der_unknown_oid_metadata
    # Build a minimal DER SEQUENCE with a bogus OID
    oid = "\x06\x03\x55\x04\x03".b  # commonName OID, not ML-DSA
    alg_id = "\x30".b + [oid.bytesize].pack("C") + oid
    bit_string = "\x03\x02\x00\x01".b
    seq_content = alg_id + bit_string
    der = "\x30".b + [seq_content.bytesize].pack("C") + seq_content

    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_der(der)
    end
    assert_equal "DER", exc.format
    assert_equal :unknown_oid, exc.reason
  end

  def test_pk_from_pem_wrong_label_metadata
    pem = "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----\n"
    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_pem(pem)
    end
    assert_equal "PEM", exc.format
    assert_nil exc.position
    assert_equal :wrong_label, exc.reason
    assert_match(/expected PUBLIC KEY.*found PRIVATE KEY/, exc.message)
  end

  def test_pk_from_pem_missing_armor_metadata
    exc = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_pem("garbage")
    end
    assert_equal "PEM", exc.format
    assert_equal :missing_armor, exc.reason
  end
end
