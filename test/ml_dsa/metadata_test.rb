# frozen_string_literal: true

require "test_helper"

class MlDsaMetadataTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
  end

  def test_pk_created_at_is_time
    assert_kind_of Time, @pk.created_at
  end

  def test_pk_created_at_is_frozen
    assert @pk.created_at.frozen?
  end

  def test_pk_created_at_is_recent
    assert_in_delta Time.now.to_f, @pk.created_at.to_f, 5.0
  end

  def test_sk_created_at_is_time
    assert_kind_of Time, @sk.created_at
  end

  def test_sk_created_at_is_frozen
    assert @sk.created_at.frozen?
  end

  def test_pk_key_usage_default_nil
    assert_nil @pk.key_usage
  end

  def test_sk_key_usage_default_nil
    assert_nil @sk.key_usage
  end

  def test_pk_key_usage_setter
    @pk.key_usage = :verify_only
    assert_equal :verify_only, @pk.key_usage
  end

  def test_sk_key_usage_setter
    @sk.key_usage = :sign_only
    assert_equal :sign_only, @sk.key_usage
  end

  def test_pk_key_usage_can_be_cleared
    @pk.key_usage = :test
    @pk.key_usage = nil
    assert_nil @pk.key_usage
  end

  def test_key_usage_rejects_non_symbol
    assert_raises(TypeError) { @pk.key_usage = "not a symbol" }
    assert_raises(TypeError) { @sk.key_usage = 42 }
  end

  def test_created_at_all_param_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      pk, sk = MlDsa.keygen(ps)
      assert_kind_of Time, pk.created_at, "PK created_at for #{ps.name}"
      assert_kind_of Time, sk.created_at, "SK created_at for #{ps.name}"
    end
  end

  def test_created_at_from_bytes_roundtrip
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes)
    # Deserialized key gets a new created_at
    assert_kind_of Time, pk2.created_at
  end
end
