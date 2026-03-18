# frozen_string_literal: true

require "test_helper"

class MlDsaKeygenTest < Minitest::Test
  def test_keygen_returns_key_objects
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65)
    assert_instance_of MlDsa::PublicKey, pk
    assert_instance_of MlDsa::SecretKey, sk
  end

  def test_keygen_returns_mutable_public_key
    pk, = MlDsa.keygen(MlDsa::ML_DSA_65)
    refute pk.frozen?, "PublicKey should not be frozen (key_usage= needs mutability)"
  end

  def test_keygen_secret_key_is_not_frozen
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_65)
    refute sk.frozen?, "SecretKey should not be frozen (wipe! needs mutability)"
  end

  def test_keygen_returns_frozen_array
    pair = MlDsa.keygen(MlDsa::ML_DSA_65)
    assert pair.frozen?
  end

  def test_keygen_requires_param_set
    assert_raises(ArgumentError) { MlDsa.keygen }
  end

  def test_keygen_44_sizes
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal MlDsa::ML_DSA_44.public_key_bytes, pk.bytesize
    assert_equal MlDsa::ML_DSA_44.secret_key_bytes, sk.bytesize
  end

  def test_keygen_65_sizes
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65)
    assert_equal MlDsa::ML_DSA_65.public_key_bytes, pk.bytesize
    assert_equal MlDsa::ML_DSA_65.secret_key_bytes, sk.bytesize
  end

  def test_keygen_87_sizes
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_87)
    assert_equal MlDsa::ML_DSA_87.public_key_bytes, pk.bytesize
    assert_equal MlDsa::ML_DSA_87.secret_key_bytes, sk.bytesize
  end

  def test_keygen_produces_different_keys
    pk1, = MlDsa.keygen(MlDsa::ML_DSA_44)
    pk2, = MlDsa.keygen(MlDsa::ML_DSA_44)
    refute_equal pk1.to_bytes, pk2.to_bytes
  end

  def test_keygen_binary_encoding
    pk, = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal Encoding::ASCII_8BIT, pk.to_bytes.encoding
  end

  def test_keygen_invalid_param_set_raises
    assert_raises(TypeError) { MlDsa.keygen(:ml_dsa_44) }
    assert_raises(TypeError) { MlDsa.keygen(44) }
    assert_raises(TypeError) { MlDsa.keygen("ML-DSA-65") }
  end

  def test_keygen_carries_param_set
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal MlDsa::ML_DSA_44, pk.param_set
    assert_equal MlDsa::ML_DSA_44, sk.param_set
  end
end
