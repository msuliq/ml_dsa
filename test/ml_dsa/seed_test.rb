# frozen_string_literal: true

require "test_helper"
require "securerandom"

class MlDsaSeedTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
  end

  def test_seed_returns_nil_for_random_keygen
    assert_nil @sk.seed
  end

  def test_seed_returns_seed_for_seeded_keygen
    seed = SecureRandom.random_bytes(32)
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    assert_equal seed, sk.seed
  end

  def test_seed_is_frozen_binary
    seed = SecureRandom.random_bytes(32)
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    result = sk.seed
    assert result.frozen?
    assert_equal Encoding::ASCII_8BIT, result.encoding
    assert_equal 32, result.bytesize
  end

  def test_seed_returns_nil_for_from_bytes
    raw = nil
    @sk.with_bytes { |b| raw = b.dup }
    sk2 = MlDsa::SecretKey.from_bytes(raw)
    assert_nil sk2.seed
  end

  def test_seed_returns_nil_for_from_seed_after_wipe
    seed = SecureRandom.random_bytes(32)
    sk = MlDsa::SecretKey.from_seed(seed, MlDsa::ML_DSA_44)
    assert_equal seed, sk.seed
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.seed }
  end

  def test_seed_zeroed_after_wipe
    seed = SecureRandom.random_bytes(32)
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
    assert_equal seed, sk.seed
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.seed }
  end

  def test_seed_all_param_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      seed = SecureRandom.random_bytes(32)
      _, sk = MlDsa.keygen(ps, seed: seed)
      assert_equal seed, sk.seed, "seed mismatch for #{ps.name}"
    end
  end

  def test_from_seed_has_seed_accessor
    seed = SecureRandom.random_bytes(32)
    sk = MlDsa::SecretKey.from_seed(seed, MlDsa::ML_DSA_44)
    assert_equal seed, sk.seed
  end
end
