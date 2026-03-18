# frozen_string_literal: true

require "test_helper"

class MlDsaParameterSetsTest < Minitest::Test
  PARAM_SETS = [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].freeze

  def test_parameter_set_constants_are_frozen
    PARAM_SETS.each { |ps| assert ps.frozen?, "#{ps.name} should be frozen" }
  end

  def test_parameter_set_names
    assert_equal "ML-DSA-44", MlDsa::ML_DSA_44.name
    assert_equal "ML-DSA-65", MlDsa::ML_DSA_65.name
    assert_equal "ML-DSA-87", MlDsa::ML_DSA_87.name
  end

  def test_parameter_set_codes
    assert_equal 44, MlDsa::ML_DSA_44.code
    assert_equal 65, MlDsa::ML_DSA_65.code
    assert_equal 87, MlDsa::ML_DSA_87.code
  end

  def test_parameter_set_security_levels
    assert_equal 2, MlDsa::ML_DSA_44.security_level
    assert_equal 3, MlDsa::ML_DSA_65.security_level
    assert_equal 5, MlDsa::ML_DSA_87.security_level
  end

  def test_size_constants_ml_dsa_44
    assert_equal 1312, MlDsa::ML_DSA_44.public_key_bytes
    assert_equal 2560, MlDsa::ML_DSA_44.secret_key_bytes
    assert_equal 2420, MlDsa::ML_DSA_44.signature_bytes
  end

  def test_size_constants_ml_dsa_65
    assert_equal 1952, MlDsa::ML_DSA_65.public_key_bytes
    assert_equal 4032, MlDsa::ML_DSA_65.secret_key_bytes
    assert_equal 3309, MlDsa::ML_DSA_65.signature_bytes
  end

  def test_size_constants_ml_dsa_87
    assert_equal 2592, MlDsa::ML_DSA_87.public_key_bytes
    assert_equal 4896, MlDsa::ML_DSA_87.secret_key_bytes
    assert_equal 4627, MlDsa::ML_DSA_87.signature_bytes
  end

  def test_security_level_ordering
    assert MlDsa::ML_DSA_65.security_level > MlDsa::ML_DSA_44.security_level
    assert MlDsa::ML_DSA_87.security_level > MlDsa::ML_DSA_65.security_level
  end

  # -----------------------------------------------------------------------
  # Comparable ordering
  # -----------------------------------------------------------------------

  def test_comparable_ordering
    assert MlDsa::ML_DSA_44 < MlDsa::ML_DSA_65
    assert MlDsa::ML_DSA_65 < MlDsa::ML_DSA_87
    assert MlDsa::ML_DSA_44 < MlDsa::ML_DSA_87
    refute MlDsa::ML_DSA_87 < MlDsa::ML_DSA_65
  end

  def test_min_max_on_array
    sets = [MlDsa::ML_DSA_87, MlDsa::ML_DSA_44, MlDsa::ML_DSA_65]
    assert_equal MlDsa::ML_DSA_44, sets.min
    assert_equal MlDsa::ML_DSA_87, sets.max
  end

  def test_sorted_order
    sets = [MlDsa::ML_DSA_87, MlDsa::ML_DSA_44, MlDsa::ML_DSA_65]
    assert_equal [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87], sets.sort
  end

  def test_spaceship_with_non_parameter_set_returns_nil
    assert_nil(MlDsa::ML_DSA_44 <=> "not a param set")
    assert_nil(MlDsa::ML_DSA_44 <=> 44)
  end

  def test_no_raw_integer_size_constants
    # The flat ML_DSA_44_PUBLIC_KEY_BYTES etc. should NOT be in the public API
    refute defined?(MlDsa::ML_DSA_44_PUBLIC_KEY_BYTES),
      "raw integer constants should not be part of the public API"
  end

  def test_invalid_param_set_type_raises
    assert_raises(TypeError) { MlDsa.keygen(:ml_dsa_65) }
    assert_raises(TypeError) { MlDsa.keygen("ML-DSA-65") }
    assert_raises(TypeError) { MlDsa.keygen(65) }
  end

  PARAM_SETS.each do |ps|
    define_method("test_roundtrip_#{ps.name.downcase.tr("-", "_")}") do
      pk, sk = MlDsa.keygen(ps)
      msg = "roundtrip test for #{ps.name}"
      sig = sk.sign(msg, deterministic: true)
      assert pk.verify(msg, sig), "verify failed for #{ps.name}"
    end
  end
end
