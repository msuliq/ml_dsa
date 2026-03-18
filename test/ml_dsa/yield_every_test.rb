# frozen_string_literal: true

require "test_helper"

class MlDsaYieldEveryTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "yield every test"
  end

  def test_sign_many_accepts_yield_every
    req = MlDsa::SignRequest.new(sk: @sk, message: @msg)
    sigs = MlDsa.sign_many([req], yield_every: 1)
    assert_equal 1, sigs.size
    assert @pk.verify(@msg, sigs.first)
  end

  def test_verify_many_accepts_yield_every
    sig = @sk.sign(@msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: sig)
    results = MlDsa.verify_many([req], yield_every: 1)
    assert results.first.ok?
  end

  def test_batch_accepts_yield_every
    sigs = MlDsa.batch(yield_every: 1) do |b|
      b.sign(sk: @sk, message: @msg)
    end
    assert_equal 1, sigs.size
  end

  def test_verify_many_accepts_yield_every_returns_results
    sig = @sk.sign(@msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: sig)
    results = MlDsa.verify_many([req], yield_every: 1)
    assert_instance_of MlDsa::Result, results.first
    assert results.first.ok?
  end
end
