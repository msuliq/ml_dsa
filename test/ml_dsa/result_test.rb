# frozen_string_literal: true

require "test_helper"

class MlDsaResultTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "result test"
  end

  def test_verify_many_results_all_valid
    sig = @sk.sign(@msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: sig)
    results = MlDsa.verify_many([req])
    assert_equal 1, results.size
    assert results.first.ok?
    assert_equal true, results.first.value
    assert_nil results.first.reason
  end

  def test_verify_many_results_wrong_signature_size
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: "short")
    results = MlDsa.verify_many([req])
    assert_equal 1, results.size
    refute results.first.ok?
    assert_match(/wrong_signature_size/, results.first.reason)
  end

  def test_verify_many_results_verification_failed
    sig = @sk.sign(@msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk, message: "wrong message", signature: sig)
    results = MlDsa.verify_many([req])
    assert_equal 1, results.size
    refute results.first.ok?
    assert_equal "verification_failed", results.first.reason
  end

  def test_verify_many_results_mixed
    sig = @sk.sign(@msg, deterministic: true)
    good = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: sig)
    bad_size = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: "x")
    bad_crypto = MlDsa::VerifyRequest.new(pk: @pk, message: "wrong", signature: sig)
    results = MlDsa.verify_many([good, bad_size, bad_crypto])
    assert results[0].ok?
    refute results[1].ok?
    assert_match(/wrong_signature_size/, results[1].reason)
    refute results[2].ok?
    assert_equal "verification_failed", results[2].reason
  end

  def test_result_inspect
    ok = MlDsa::Result.new(value: true, ok: true, reason: nil)
    err = MlDsa::Result.new(value: false, ok: false, reason: "test_error")
    assert_match(/ok/, ok.inspect)
    assert_match(/test_error/, err.inspect)
  end
end
