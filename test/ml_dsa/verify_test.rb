# frozen_string_literal: true

require "test_helper"

class MlDsaVerifyTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "verify me"
    @sig = @sk.sign(@msg, deterministic: true)
  end

  def test_verify_valid_signature
    assert @pk.verify(@msg, @sig)
  end

  def test_verify_wrong_message
    refute @pk.verify("wrong message", @sig)
  end

  def test_verify_tampered_signature
    tampered = @sig.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)
    refute @pk.verify(@msg, tampered)
  end

  def test_verify_wrong_public_key
    pk2, = MlDsa.keygen(MlDsa::ML_DSA_44)
    refute pk2.verify(@msg, @sig)
  end

  def test_verify_empty_signature
    refute @pk.verify(@msg, "")
  end

  def test_verify_truncated_signature
    refute @pk.verify(@msg, @sig[0, 100])
  end

  def test_verify_nil_message_raises_type_error
    assert_raises(TypeError) { @pk.verify(nil, @sig) }
  end

  def test_verify_nil_signature_raises_type_error
    assert_raises(TypeError) { @pk.verify(@msg, nil) }
  end

  def test_verify_non_string_message_raises_type_error
    err = assert_raises(TypeError) { @pk.verify(123, @sig) }
    assert_match(/message must be a String/, err.message)
  end

  def test_verify_non_string_signature_raises_type_error
    err = assert_raises(TypeError) { @pk.verify(@msg, 456) }
    assert_match(/signature must be a String/, err.message)
  end

  def test_verify_with_context
    sig_ctx = @sk.sign(@msg, deterministic: true, context: "myapp")
    assert @pk.verify(@msg, sig_ctx, context: "myapp")
    refute @pk.verify(@msg, sig_ctx, context: "wrong")
    refute @pk.verify(@msg, sig_ctx)
  end

  def test_verify_context_too_long_returns_false
    refute @pk.verify(@msg, @sig, context: "x" * 256)
  end

  def test_verify_raises_type_error_for_non_string_context
    assert_raises(TypeError) { @pk.verify(@msg, @sig, context: 123) }
    assert_raises(TypeError) { @pk.verify(@msg, @sig, context: nil) }
    assert_raises(TypeError) { @pk.verify(@msg, @sig, context: :sym) }
  end

  def test_verify_returns_boolean
    assert_equal true, @pk.verify(@msg, @sig)
    assert_equal false, @pk.verify("bad", @sig)
  end

  def test_cross_parameter_set_rejection
    _pk44, sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    pk65, = MlDsa.keygen(MlDsa::ML_DSA_65)
    sig44 = sk44.sign("cross param test", deterministic: true)
    refute pk65.verify("cross param test", sig44)
  end
end

# Ensure verify works correctly across all three parameter sets.
class MlDsaVerifyAllParamSetsTest < Minitest::Test
  [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
    define_method(:"test_sign_verify_roundtrip_#{ps.name}") do
      pk, sk = MlDsa.keygen(ps)
      sig = sk.sign("roundtrip", deterministic: true)
      assert pk.verify("roundtrip", sig)
    end

    define_method(:"test_wrong_message_#{ps.name}") do
      pk, sk = MlDsa.keygen(ps)
      sig = sk.sign("correct", deterministic: true)
      refute pk.verify("wrong", sig)
    end

    define_method(:"test_tampered_signature_#{ps.name}") do
      pk, sk = MlDsa.keygen(ps)
      sig = sk.sign("tamper test", deterministic: true)
      tampered = sig.dup
      tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)
      refute pk.verify("tamper test", tampered)
    end

    define_method(:"test_context_roundtrip_#{ps.name}") do
      pk, sk = MlDsa.keygen(ps)
      sig = sk.sign("ctx test", deterministic: true, context: "app")
      assert pk.verify("ctx test", sig, context: "app")
      refute pk.verify("ctx test", sig, context: "other")
    end
  end
end
