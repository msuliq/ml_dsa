# frozen_string_literal: true

require "test_helper"

class MlDsaBatchBuilderTest < Minitest::Test
  def setup
    @pair = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk = @pair.public_key
    @sk = @pair.secret_key
    @msg = "batch builder test"
  end

  def test_batch_sign_single
    sigs = MlDsa.batch { |b| b.sign(sk: @sk, message: @msg, deterministic: true) }
    assert_instance_of Array, sigs
    assert_equal 1, sigs.size
    assert @pk.verify(@msg, sigs.first)
  end

  def test_batch_sign_multiple
    msgs = ["msg1", "msg2", "msg3"]
    sigs = MlDsa.batch do |b|
      msgs.each { |m| b.sign(sk: @sk, message: m, deterministic: true) }
    end
    assert_equal 3, sigs.size
    msgs.zip(sigs).each do |m, sig|
      assert @pk.verify(m, sig)
    end
  end

  def test_batch_verify_single
    sig = @sk.sign(@msg)
    results = MlDsa.batch { |b| b.verify(pk: @pk, message: @msg, signature: sig) }
    assert results.first.ok?
  end

  def test_batch_verify_multiple
    msgs = ["msg1", "msg2"]
    sigs = msgs.map { |m| @sk.sign(m, deterministic: true) }
    results = MlDsa.batch do |b|
      msgs.zip(sigs).each { |m, sig| b.verify(pk: @pk, message: m, signature: sig) }
    end
    assert results[0].ok?
    assert results[1].ok?
  end

  def test_batch_verify_wrong_message
    sig = @sk.sign("correct", deterministic: true)
    results = MlDsa.batch { |b| b.verify(pk: @pk, message: "wrong", signature: sig) }
    refute results.first.ok?
  end

  def test_batch_mixing_raises
    assert_raises(ArgumentError) do
      MlDsa.batch do |b|
        b.sign(sk: @sk, message: "msg")
        b.verify(pk: @pk, message: "msg", signature: "x" * MlDsa::ML_DSA_44.signature_bytes)
      end
    end
  end

  def test_batch_empty
    result = MlDsa.batch { |_b| }
    assert_equal [], result
  end

  def test_batch_sign_with_context
    ctx = "test-ctx"
    sigs = MlDsa.batch { |b| b.sign(sk: @sk, message: @msg, context: ctx, deterministic: true) }
    assert @pk.verify(@msg, sigs.first, context: ctx)
    refute @pk.verify(@msg, sigs.first)
  end

  def test_batch_sign_chaining
    sigs = MlDsa.batch do |b|
      b.sign(sk: @sk, message: "a", deterministic: true)
        .sign(sk: @sk, message: "b", deterministic: true)
    end
    assert_equal 2, sigs.size
  end
end
