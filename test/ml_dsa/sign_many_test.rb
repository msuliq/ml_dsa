# frozen_string_literal: true

require "test_helper"

class MlDsaSignManyTest < Minitest::Test
  def setup
    @pk44, @sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk65, @sk65 = MlDsa.keygen(MlDsa::ML_DSA_65)
  end

  # -----------------------------------------------------------------------
  # Basic correctness
  # -----------------------------------------------------------------------

  def test_sign_many_returns_array_of_frozen_binary_strings
    sigs = MlDsa.sign_many([
      MlDsa::SignRequest.new(sk: @sk44, message: "hello"),
      MlDsa::SignRequest.new(sk: @sk44, message: "world")
    ])
    assert_instance_of Array, sigs
    assert_equal 2, sigs.size
    sigs.each do |sig|
      assert_instance_of String, sig
      assert sig.frozen?
      assert_equal Encoding::ASCII_8BIT, sig.encoding
    end
  end

  def test_sign_many_produces_verifiable_signatures
    ops = [
      MlDsa::SignRequest.new(sk: @sk44, message: "msg1", deterministic: true),
      MlDsa::SignRequest.new(sk: @sk44, message: "msg2", deterministic: true),
      MlDsa::SignRequest.new(sk: @sk65, message: "msg3", deterministic: true)
    ]
    sigs = MlDsa.sign_many(ops)

    assert @pk44.verify("msg1", sigs[0])
    assert @pk44.verify("msg2", sigs[1])
    assert @pk65.verify("msg3", sigs[2])
  end

  def test_sign_many_with_context
    ops = [
      MlDsa::SignRequest.new(sk: @sk44, message: "msg", context: "ctx", deterministic: true)
    ]
    sigs = MlDsa.sign_many(ops)
    assert @pk44.verify("msg", sigs[0], context: "ctx")
    refute @pk44.verify("msg", sigs[0])
  end

  def test_sign_many_deterministic_matches_single_sign
    msg = "deterministic batch"
    sig_batch = MlDsa.sign_many([
      MlDsa::SignRequest.new(sk: @sk44, message: msg, deterministic: true)
    ]).first
    sig_single = @sk44.sign(msg, deterministic: true)
    assert_equal sig_single, sig_batch
  end

  def test_sign_many_correct_signature_sizes
    sigs = MlDsa.sign_many([
      MlDsa::SignRequest.new(sk: @sk44, message: "a"),
      MlDsa::SignRequest.new(sk: @sk65, message: "b")
    ])
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sigs[0].bytesize
    assert_equal MlDsa::ML_DSA_65.signature_bytes, sigs[1].bytesize
  end

  def test_sign_many_empty_array_returns_empty_array
    assert_equal [], MlDsa.sign_many([])
  end

  def test_sign_many_empty_does_not_notify_subscribers
    cfg = MlDsa::Config.new
    notified = false
    cfg.subscribe { |_| notified = true }
    MlDsa.sign_many([], config: cfg)
    refute notified, "sign_many([]) should not notify subscribers"
  end

  def test_sign_many_hedged_produces_different_sigs
    sigs1 = MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk44, message: "x")])
    sigs2 = MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk44, message: "x")])
    refute_equal sigs1[0], sigs2[0]
  end

  def test_sign_many_result_is_frozen
    result = MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk44, message: "m")])
    assert result.frozen?
  end

  # -----------------------------------------------------------------------
  # Error handling
  # -----------------------------------------------------------------------

  def test_sign_many_raises_on_non_array
    assert_raises(TypeError) { MlDsa.sign_many("not an array") }
  end

  def test_sign_many_raises_on_non_sign_request_item
    assert_raises(TypeError) { MlDsa.sign_many(["not a SignRequest"]) }
  end

  def test_sign_many_raises_on_wrong_sk_type
    assert_raises(ArgumentError) do
      MlDsa.sign_many([MlDsa::SignRequest.new(sk: "not a key", message: "m")])
    end
  end

  def test_sign_many_raises_on_missing_message_type
    assert_raises(ArgumentError) do
      MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk44, message: 123)])
    end
  end

  def test_sign_many_raises_on_context_too_long
    assert_raises(ArgumentError) do
      MlDsa.sign_many([
        MlDsa::SignRequest.new(sk: @sk44, message: "m", context: "x" * 256)
      ])
    end
  end

  # -----------------------------------------------------------------------
  # SignRequest struct
  # -----------------------------------------------------------------------

  def test_sign_many_accepts_sign_request_struct
    req = MlDsa::SignRequest.new(sk: @sk44, message: "hello", deterministic: true)
    sigs = MlDsa.sign_many([req])
    assert_equal 1, sigs.size
    assert @pk44.verify("hello", sigs[0])
  end

  def test_sign_many_sign_request_with_context
    req = MlDsa::SignRequest.new(sk: @sk44, message: "msg", context: "ctx",
      deterministic: true)
    sigs = MlDsa.sign_many([req])
    assert @pk44.verify("msg", sigs[0], context: "ctx")
    refute @pk44.verify("msg", sigs[0])
  end
end
