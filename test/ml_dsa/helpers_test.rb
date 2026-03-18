# frozen_string_literal: true

require "test_helper"

class MlDsaHelpersTest < Minitest::Test
  # -----------------------------------------------------------------------
  # param_set_for_signature_size
  # -----------------------------------------------------------------------

  def test_param_set_for_signature_size_44
    ps = MlDsa.send(:param_set_for_signature_size, MlDsa::ML_DSA_44.signature_bytes)
    assert_equal MlDsa::ML_DSA_44, ps
  end

  def test_param_set_for_signature_size_65
    ps = MlDsa.send(:param_set_for_signature_size, MlDsa::ML_DSA_65.signature_bytes)
    assert_equal MlDsa::ML_DSA_65, ps
  end

  def test_param_set_for_signature_size_87
    ps = MlDsa.send(:param_set_for_signature_size, MlDsa::ML_DSA_87.signature_bytes)
    assert_equal MlDsa::ML_DSA_87, ps
  end

  def test_param_set_for_signature_size_unknown_raises
    assert_raises(ArgumentError) { MlDsa.send(:param_set_for_signature_size, 999) }
  end

  # -----------------------------------------------------------------------
  # param_set_for_pk_size
  # -----------------------------------------------------------------------

  def test_param_set_for_pk_size_44
    ps = MlDsa.send(:param_set_for_pk_size, MlDsa::ML_DSA_44.public_key_bytes)
    assert_equal MlDsa::ML_DSA_44, ps
  end

  def test_param_set_for_pk_size_65
    ps = MlDsa.send(:param_set_for_pk_size, MlDsa::ML_DSA_65.public_key_bytes)
    assert_equal MlDsa::ML_DSA_65, ps
  end

  def test_param_set_for_pk_size_87
    ps = MlDsa.send(:param_set_for_pk_size, MlDsa::ML_DSA_87.public_key_bytes)
    assert_equal MlDsa::ML_DSA_87, ps
  end

  def test_param_set_for_pk_size_unknown_raises
    assert_raises(ArgumentError) { MlDsa.send(:param_set_for_pk_size, 999) }
  end

  # -----------------------------------------------------------------------
  # with_bytes buffer frozen after block
  # -----------------------------------------------------------------------

  def test_with_bytes_buffer_frozen_after_block
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    leaked_buf = nil
    sk.with_bytes { |b| leaked_buf = b }
    assert leaked_buf.frozen?, "buffer should be frozen after with_bytes block exits"
    assert_equal 0, leaked_buf.bytesize, "buffer should be emptied after with_bytes"
  end

  # -----------------------------------------------------------------------
  # from_hex single-pass (pack-based)
  # -----------------------------------------------------------------------

  def test_from_hex_odd_length_raises
    pk, = MlDsa.keygen(MlDsa::ML_DSA_44)
    hex = pk.to_hex + "a"  # make it odd length
    assert_raises(ArgumentError) do
      MlDsa::PublicKey.from_hex(hex, MlDsa::ML_DSA_44)
    end
  end

  def test_from_hex_invalid_chars_raises
    pk, = MlDsa.keygen(MlDsa::ML_DSA_44)
    hex = "zz" + pk.to_hex[2..]
    assert_raises(ArgumentError) do
      MlDsa::PublicKey.from_hex(hex, MlDsa::ML_DSA_44)
    end
  end

  def test_from_hex_empty_raises
    assert_raises(ArgumentError) do
      MlDsa::PublicKey.from_hex("", MlDsa::ML_DSA_44)
    end
  end

  # -----------------------------------------------------------------------
  # Binary encoding on return values (item 4)
  # -----------------------------------------------------------------------

  def test_pk_to_bytes_encoding_is_binary
    pk, = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal Encoding::ASCII_8BIT, pk.to_bytes.encoding
  end

  def test_sk_with_bytes_encoding_is_binary
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.with_bytes do |buf|
      assert_equal Encoding::ASCII_8BIT, buf.encoding
    end
  end

  def test_sign_returns_binary_encoding
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sig = sk.sign("test", deterministic: true)
    assert_equal Encoding::ASCII_8BIT, sig.encoding
  end

  def test_sign_many_returns_binary_encoding
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sigs = MlDsa.sign_many([MlDsa::SignRequest.new(sk: sk, message: "test")])
    assert_equal Encoding::ASCII_8BIT, sigs[0].encoding
  end

  def test_sk_to_der_encoding_is_binary
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal Encoding::ASCII_8BIT, sk.to_der.encoding
  end

  # -----------------------------------------------------------------------
  # Empty batch arrays are frozen (item 5)
  # -----------------------------------------------------------------------

  def test_sign_many_empty_returns_frozen_array
    result = MlDsa.sign_many([])
    assert result.frozen?, "sign_many([]) should return frozen array"
  end

  def test_verify_many_empty_returns_frozen_array
    result = MlDsa.verify_many([])
    assert result.frozen?, "verify_many([]) should return frozen array"
  end

  # -----------------------------------------------------------------------
  # SK to_der produces valid PKCS#8 (item 1)
  # -----------------------------------------------------------------------

  def test_sk_to_der_c_roundtrips_with_from_der
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    der = sk.to_der
    sk2 = MlDsa::SecretKey.from_der(der)
    sig1 = sk.sign("roundtrip", deterministic: true)
    sig2 = sk2.sign("roundtrip", deterministic: true)
    assert_equal sig1, sig2
  end

  def test_sk_to_der_is_frozen
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert sk.to_der.frozen?
  end

  def test_sk_to_der_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.to_der }
  end

  # -----------------------------------------------------------------------
  # PQC namespace alias
  # -----------------------------------------------------------------------

  def test_pqc_namespace_resolves_to_ml_dsa
    assert_equal MlDsa, PQC::MlDsa
  end

  def test_pqc_namespace_constants_accessible
    assert_equal MlDsa::ML_DSA_44, PQC::MlDsa::ML_DSA_44
    assert_equal MlDsa::ML_DSA_65, PQC::MlDsa::ML_DSA_65
    assert_equal MlDsa::ML_DSA_87, PQC::MlDsa::ML_DSA_87
  end

  def test_pqc_namespace_keygen_works
    pk, sk = PQC::MlDsa.keygen(PQC::MlDsa::ML_DSA_44)
    assert_instance_of MlDsa::PublicKey, pk
    assert_instance_of MlDsa::SecretKey, sk
  end
end
