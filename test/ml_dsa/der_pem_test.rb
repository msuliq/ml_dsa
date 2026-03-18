# frozen_string_literal: true

require "test_helper"

class MlDsaDerPemTest < Minitest::Test
  def setup
    @pk44, @sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk65, @sk65 = MlDsa.keygen(MlDsa::ML_DSA_65)
    @pk87, @sk87 = MlDsa.keygen(MlDsa::ML_DSA_87)
  end

  # -----------------------------------------------------------------------
  # OID constants
  # -----------------------------------------------------------------------

  def test_ml_dsa_oids_defined
    assert_equal "2.16.840.1.101.3.4.3.17", MlDsa::ML_DSA_OIDS[44]
    assert_equal "2.16.840.1.101.3.4.3.18", MlDsa::ML_DSA_OIDS[65]
    assert_equal "2.16.840.1.101.3.4.3.19", MlDsa::ML_DSA_OIDS[87]
  end

  def test_oid_to_code_is_inverse_of_oids
    assert_equal 44, MlDsa::ML_DSA_OID_TO_CODE["2.16.840.1.101.3.4.3.17"]
    assert_equal 65, MlDsa::ML_DSA_OID_TO_CODE["2.16.840.1.101.3.4.3.18"]
    assert_equal 87, MlDsa::ML_DSA_OID_TO_CODE["2.16.840.1.101.3.4.3.19"]
  end

  # -----------------------------------------------------------------------
  # PublicKey DER roundtrip
  # -----------------------------------------------------------------------

  def test_public_key_der_returns_frozen_binary_string
    der = @pk44.to_der
    assert_instance_of String, der
    assert_equal Encoding::ASCII_8BIT, der.encoding
    assert der.frozen?, "to_der must return a frozen String"
  end

  def test_public_key_der_roundtrip_44
    pk2 = MlDsa::PublicKey.from_der(@pk44.to_der)
    assert_equal @pk44, pk2
    assert_equal MlDsa::ML_DSA_44, pk2.param_set
  end

  def test_public_key_der_roundtrip_65
    pk2 = MlDsa::PublicKey.from_der(@pk65.to_der)
    assert_equal @pk65, pk2
    assert_equal MlDsa::ML_DSA_65, pk2.param_set
  end

  def test_public_key_der_roundtrip_87
    pk2 = MlDsa::PublicKey.from_der(@pk87.to_der)
    assert_equal @pk87, pk2
    assert_equal MlDsa::ML_DSA_87, pk2.param_set
  end

  def test_public_key_der_matches_openssl_encoding
    require "openssl"
    [[@pk44, 44], [@pk65, 65], [@pk87, 87]].each do |pk, code|
      oid = OpenSSL::ASN1::ObjectId.new(MlDsa::ML_DSA_OIDS[code])
      alg_id = OpenSSL::ASN1::Sequence.new([oid])
      bit_str = OpenSSL::ASN1::BitString.new(pk.to_bytes)
      expected = OpenSSL::ASN1::Sequence.new([alg_id, bit_str]).to_der
      assert_equal expected, pk.to_der,
        "C pk_to_der should match OpenSSL encoding for ML-DSA-#{code}"
    end
  end

  def test_public_key_from_der_unknown_oid_raises
    require "openssl"
    oid = OpenSSL::ASN1::ObjectId.new("1.2.840.10045.2.1")  # EC
    alg_id = OpenSSL::ASN1::Sequence.new([oid])
    bit_str = OpenSSL::ASN1::BitString.new("\x00" * 10)
    bad_der = OpenSSL::ASN1::Sequence.new([alg_id, bit_str]).to_der
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_der(bad_der)
    end
  end

  def test_public_key_from_der_garbage_raises
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_der("not der at all")
    end
  end

  # -----------------------------------------------------------------------
  # PublicKey PEM roundtrip
  # -----------------------------------------------------------------------

  def test_public_key_pem_has_correct_header_footer
    pem = @pk44.to_pem
    assert_match(/-----BEGIN PUBLIC KEY-----/, pem)
    assert_match(/-----END PUBLIC KEY-----/, pem)
  end

  def test_public_key_pem_is_frozen
    assert @pk44.to_pem.frozen?, "to_pem must return a frozen String"
  end

  def test_public_key_pem_line_width_is_64
    pem = @pk44.to_pem
    body_lines = pem.lines.reject { |l| l.start_with?("-----") }.map(&:chomp)
    body_lines[0..-2].each do |line|
      assert_equal 64, line.length, "PEM body lines should be 64 characters"
    end
  end

  def test_public_key_pem_roundtrip_44
    pk2 = MlDsa::PublicKey.from_pem(@pk44.to_pem)
    assert_equal @pk44, pk2
  end

  def test_public_key_pem_roundtrip_65
    pk2 = MlDsa::PublicKey.from_pem(@pk65.to_pem)
    assert_equal @pk65, pk2
  end

  def test_public_key_pem_roundtrip_87
    pk2 = MlDsa::PublicKey.from_pem(@pk87.to_pem)
    assert_equal @pk87, pk2
  end

  def test_public_key_from_pem_no_armor_raises
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_pem("no pem armor here")
    end
  end

  def test_public_key_from_pem_wrong_label_raises
    # PRIVATE KEY label should be rejected by PublicKey.from_pem
    pem = @sk44.to_pem
    err = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::PublicKey.from_pem(pem)
    end
    assert_match(/expected PUBLIC KEY, found PRIVATE KEY/, err.message)
  end

  # -----------------------------------------------------------------------
  # SecretKey DER roundtrip
  # -----------------------------------------------------------------------

  def test_secret_key_der_returns_frozen_binary_string
    der = @sk44.to_der
    assert_instance_of String, der
    assert_equal Encoding::ASCII_8BIT, der.encoding
    assert der.frozen?, "to_der must return a frozen String"
  end

  def test_secret_key_der_roundtrip_44
    sig1 = @sk44.sign("test", deterministic: true)
    sk2 = MlDsa::SecretKey.from_der(@sk44.to_der)
    sig2 = sk2.sign("test", deterministic: true)
    assert_equal sig1, sig2
    assert_equal MlDsa::ML_DSA_44, sk2.param_set
  end

  def test_secret_key_der_roundtrip_65
    sk2 = MlDsa::SecretKey.from_der(@sk65.to_der)
    assert_equal MlDsa::ML_DSA_65, sk2.param_set
    assert @pk65.verify("msg", sk2.sign("msg", deterministic: true))
  end

  def test_secret_key_der_roundtrip_87
    sk2 = MlDsa::SecretKey.from_der(@sk87.to_der)
    assert_equal MlDsa::ML_DSA_87, sk2.param_set
    assert @pk87.verify("msg", sk2.sign("msg", deterministic: true))
  end

  def test_secret_key_der_matches_openssl_encoding
    require "openssl"
    [[@sk44, 44], [@sk65, 65], [@sk87, 87]].each do |sk, code|
      sk.with_bytes do |key_bytes|
        ver = OpenSSL::ASN1::Integer.new(0)
        oid = OpenSSL::ASN1::ObjectId.new(MlDsa::ML_DSA_OIDS[code])
        alg_id = OpenSSL::ASN1::Sequence.new([oid])
        key_oct = OpenSSL::ASN1::OctetString.new(key_bytes)
        expected = OpenSSL::ASN1::Sequence.new([ver, alg_id, key_oct]).to_der
        assert_equal expected, sk.to_der,
          "C sk_to_der should match OpenSSL encoding for ML-DSA-#{code}"
      end
    end
  end

  def test_secret_key_from_der_unknown_oid_raises
    require "openssl"
    # Build a valid PKCS#8 structure but with an EC OID instead of ML-DSA
    ver = OpenSSL::ASN1::Integer.new(0)
    oid = OpenSSL::ASN1::ObjectId.new("1.2.840.10045.2.1")  # EC
    alg_id = OpenSSL::ASN1::Sequence.new([oid])
    key_oct = OpenSSL::ASN1::OctetString.new("\x00" * 10)
    bad_der = OpenSSL::ASN1::Sequence.new([ver, alg_id, key_oct]).to_der
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_der(bad_der)
    end
  end

  def test_secret_key_from_der_garbage_raises
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_der("garbage")
    end
  end

  # -----------------------------------------------------------------------
  # SecretKey PEM roundtrip
  # -----------------------------------------------------------------------

  def test_secret_key_pem_has_correct_header_footer
    pem = @sk44.to_pem
    assert_match(/-----BEGIN PRIVATE KEY-----/, pem)
    assert_match(/-----END PRIVATE KEY-----/, pem)
  end

  def test_secret_key_pem_is_frozen
    assert @sk44.to_pem.frozen?, "to_pem must return a frozen String"
  end

  def test_secret_key_pem_roundtrip_44
    sk2 = MlDsa::SecretKey.from_pem(@sk44.to_pem)
    sig1 = @sk44.sign("msg", deterministic: true)
    sig2 = sk2.sign("msg", deterministic: true)
    assert_equal sig1, sig2
  end

  def test_secret_key_pem_roundtrip_65
    sk2 = MlDsa::SecretKey.from_pem(@sk65.to_pem)
    assert @pk65.verify("msg", sk2.sign("msg", deterministic: true))
  end

  def test_secret_key_pem_roundtrip_87
    sk2 = MlDsa::SecretKey.from_pem(@sk87.to_pem)
    assert @pk87.verify("msg", sk2.sign("msg", deterministic: true))
  end

  def test_secret_key_from_pem_no_armor_raises
    assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_pem("no pem armor here")
    end
  end

  def test_secret_key_from_pem_wrong_label_raises
    # PUBLIC KEY label should be rejected by SecretKey.from_pem
    pem = @pk44.to_pem
    err = assert_raises(MlDsa::Error::Deserialization) do
      MlDsa::SecretKey.from_pem(pem)
    end
    assert_match(/expected PRIVATE KEY, found PUBLIC KEY/, err.message)
  end

  # -----------------------------------------------------------------------
  # DER-based signature roundtrip
  # -----------------------------------------------------------------------

  def test_der_pk_can_verify_signature_from_der_sk
    msg = "interop test"
    sig = MlDsa::SecretKey.from_der(@sk44.to_der).sign(msg, deterministic: true)
    pk2 = MlDsa::PublicKey.from_der(@pk44.to_der)
    assert pk2.verify(msg, sig)
  end
end
