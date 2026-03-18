# frozen_string_literal: true

require "test_helper"

class MlDsaSignHedgedTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "hello, ml-dsa"
  end

  def test_sign_returns_frozen_binary_string
    sig = @sk.sign(@msg)
    assert_instance_of String, sig
    assert sig.frozen?
    assert_equal Encoding::ASCII_8BIT, sig.encoding
  end

  def test_sign_correct_size
    sig = @sk.sign(@msg)
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_hedged_produces_different_sigs
    sig1 = @sk.sign(@msg)
    sig2 = @sk.sign(@msg)
    refute_equal sig1, sig2
  end

  def test_sign_empty_message
    sig = @sk.sign("")
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_sign_binary_message_with_null_bytes
    sig = @sk.sign("hello\x00world")
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_sign_long_message
    sig = @sk.sign("a" * 100_000)
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_sign_with_context
    sig = @sk.sign(@msg, context: "myapp")
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
    assert @pk.verify(@msg, sig, context: "myapp")
  end

  def test_sign_type_guard_message
    assert_raises(TypeError) { @sk.sign(nil) }
    assert_raises(TypeError) { @sk.sign(123) }
  end

  def test_sign_context_too_long
    assert_raises(ArgumentError) { @sk.sign(@msg, context: "x" * 256) }
  end
end

class MlDsaSignDeterministicTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "deterministic test"
  end

  def test_deterministic_is_reproducible
    sig1 = @sk.sign(@msg, deterministic: true)
    sig2 = @sk.sign(@msg, deterministic: true)
    assert_equal sig1, sig2
  end

  def test_deterministic_different_messages_differ
    sig1 = @sk.sign("message_a", deterministic: true)
    sig2 = @sk.sign("message_b", deterministic: true)
    refute_equal sig1, sig2
  end

  def test_deterministic_different_keys_differ
    _pk2, sk2 = MlDsa.keygen(MlDsa::ML_DSA_44)
    sig1 = @sk.sign(@msg, deterministic: true)
    sig2 = sk2.sign(@msg, deterministic: true)
    refute_equal sig1, sig2
  end

  def test_deterministic_differs_from_hedged
    det = @sk.sign(@msg, deterministic: true)
    hed = @sk.sign(@msg, deterministic: false)
    refute_equal det, hed
  end

  def test_deterministic_correct_size
    sig = @sk.sign(@msg, deterministic: true)
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_deterministic_with_context_reproducible
    sig1 = @sk.sign(@msg, deterministic: true, context: "ctx")
    sig2 = @sk.sign(@msg, deterministic: true, context: "ctx")
    assert_equal sig1, sig2
  end

  def test_deterministic_different_contexts_differ
    sig1 = @sk.sign(@msg, deterministic: true, context: "ctx_a")
    sig2 = @sk.sign(@msg, deterministic: true, context: "ctx_b")
    refute_equal sig1, sig2
  end
end

# Ensure sign works correctly across all three parameter sets.
class MlDsaSignAllParamSetsTest < Minitest::Test
  [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
    define_method(:"test_sign_correct_size_#{ps.name}") do
      _pk, sk = MlDsa.keygen(ps)
      sig = sk.sign("test", deterministic: true)
      assert_equal ps.signature_bytes, sig.bytesize
    end

    define_method(:"test_deterministic_reproducible_#{ps.name}") do
      _pk, sk = MlDsa.keygen(ps)
      sig1 = sk.sign("msg", deterministic: true)
      sig2 = sk.sign("msg", deterministic: true)
      assert_equal sig1, sig2
    end

    define_method(:"test_hedged_differs_#{ps.name}") do
      _pk, sk = MlDsa.keygen(ps)
      sig1 = sk.sign("msg")
      sig2 = sk.sign("msg")
      refute_equal sig1, sig2
    end
  end
end
