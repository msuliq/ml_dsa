# frozen_string_literal: true

require "test_helper"

class MlDsaKeyPairTest < Minitest::Test
  def setup
    @pair = MlDsa.keygen(MlDsa::ML_DSA_44)
  end

  def test_keygen_returns_key_pair
    assert_instance_of MlDsa::KeyPair, @pair
  end

  def test_key_pair_is_frozen
    assert @pair.frozen?
  end

  def test_public_key_accessor
    assert_instance_of MlDsa::PublicKey, @pair.public_key
  end

  def test_secret_key_accessor
    assert_instance_of MlDsa::SecretKey, @pair.secret_key
  end

  def test_param_set_delegates_to_public_key
    assert_equal MlDsa::ML_DSA_44, @pair.param_set
  end

  def test_destructuring_assignment
    pk, sk = @pair
    assert_instance_of MlDsa::PublicKey, pk
    assert_instance_of MlDsa::SecretKey, sk
    assert_same @pair.public_key, pk
    assert_same @pair.secret_key, sk
  end

  def test_to_a
    arr = @pair.to_a
    assert_instance_of Array, arr
    assert_equal 2, arr.length
    assert_same @pair.public_key, arr[0]
    assert_same @pair.secret_key, arr[1]
  end

  def test_to_ary_enables_implicit_conversion
    arr = [] + @pair
    assert_equal 2, arr.length
  end

  def test_inspect
    assert_match(/KeyPair.*ML-DSA-44/, @pair.inspect)
  end

  def test_sign_and_verify_with_key_pair
    msg = "hello"
    sig = @pair.secret_key.sign(msg)
    assert @pair.public_key.verify(msg, sig)
  end

  def test_all_parameter_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      pair = MlDsa.keygen(ps)
      assert_instance_of MlDsa::KeyPair, pair
      assert_equal ps, pair.param_set
    end
  end

  # --- Seed-based deterministic keygen ---

  def test_seed_keygen_returns_key_pair
    seed = "\x01" * 32
    pair = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    assert_instance_of MlDsa::KeyPair, pair
    assert_equal MlDsa::ML_DSA_44, pair.param_set
  end

  def test_seed_keygen_is_deterministic
    seed = "\xAB" * 32
    pair1 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    pair2 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    assert_equal pair1.public_key.to_bytes, pair2.public_key.to_bytes
  end

  def test_seed_keygen_different_seeds_produce_different_keys
    seed1 = "\x01" * 32
    seed2 = "\x02" * 32
    pair1 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed1)
    pair2 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed2)
    refute_equal pair1.public_key.to_bytes, pair2.public_key.to_bytes
  end

  def test_seed_keygen_sign_and_verify
    seed = Random.urandom(32)
    pair = MlDsa.keygen(MlDsa::ML_DSA_65, seed: seed)
    msg = "deterministic keygen test"
    sig = pair.secret_key.sign(msg)
    assert pair.public_key.verify(msg, sig)
  end

  def test_seed_keygen_wrong_size_raises
    assert_raises(ArgumentError) { MlDsa.keygen(MlDsa::ML_DSA_44, seed: "\x00" * 16) }
    assert_raises(ArgumentError) { MlDsa.keygen(MlDsa::ML_DSA_44, seed: "\x00" * 64) }
    assert_raises(ArgumentError) { MlDsa.keygen(MlDsa::ML_DSA_44, seed: "") }
  end

  def test_seed_keygen_non_string_raises
    assert_raises(TypeError) { MlDsa.keygen(MlDsa::ML_DSA_44, seed: 42) }
  end

  def test_seed_keygen_all_parameter_sets
    seed = "\xCC" * 32
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      pair = MlDsa.keygen(ps, seed: seed)
      assert_instance_of MlDsa::KeyPair, pair
      assert_equal ps, pair.param_set
    end
  end

  def test_seed_bytes_constant
    assert_equal 32, MlDsa::SEED_BYTES
  end
end
