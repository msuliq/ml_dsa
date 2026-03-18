# frozen_string_literal: true

require "test_helper"

class MlDsaVerifyManyTest < Minitest::Test
  def setup
    @pk44, @sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk65, @sk65 = MlDsa.keygen(MlDsa::ML_DSA_65)
  end

  # -----------------------------------------------------------------------
  # Basic correctness
  # -----------------------------------------------------------------------

  def test_verify_many_returns_frozen_array_of_results
    sig = @sk44.sign("hello", deterministic: true)
    results = MlDsa.verify_many([
      MlDsa::VerifyRequest.new(pk: @pk44, message: "hello", signature: sig)
    ])
    assert_instance_of Array, results
    assert results.frozen?
    assert_instance_of MlDsa::Result, results.first
    assert results.first.ok?
  end

  def test_verify_many_valid_and_invalid_in_batch
    msg = "batch verify test"
    sig = @sk44.sign(msg, deterministic: true)
    results = MlDsa.verify_many([
      MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig),
      MlDsa::VerifyRequest.new(pk: @pk44, message: "wrong", signature: sig)
    ])
    assert results[0].ok?
    refute results[1].ok?
  end

  def test_verify_many_multiple_param_sets
    msg44 = "msg for 44"
    msg65 = "msg for 65"
    sig44 = @sk44.sign(msg44, deterministic: true)
    sig65 = @sk65.sign(msg65, deterministic: true)
    results = MlDsa.verify_many([
      MlDsa::VerifyRequest.new(pk: @pk44, message: msg44, signature: sig44),
      MlDsa::VerifyRequest.new(pk: @pk65, message: msg65, signature: sig65)
    ])
    assert results[0].ok?
    assert results[1].ok?
  end

  def test_verify_many_with_context
    msg = "ctx verify"
    sig = @sk44.sign(msg, context: "myctx", deterministic: true)
    results = MlDsa.verify_many([
      MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig, context: "myctx"),
      MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig)
    ])
    assert results[0].ok?
    refute results[1].ok?
  end

  def test_verify_many_empty_array_returns_empty_array
    assert_equal [], MlDsa.verify_many([])
  end

  def test_verify_many_result_matches_single_verify
    msg = "single vs batch"
    sig = @sk44.sign(msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig)
    batch_result = MlDsa.verify_many([req]).first
    single_result = @pk44.verify(msg, sig)
    assert_equal single_result, batch_result.ok?
  end

  # -----------------------------------------------------------------------
  # VerifyRequest struct
  # -----------------------------------------------------------------------

  def test_verify_many_accepts_verify_request_struct
    msg = "struct verify"
    sig = @sk44.sign(msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig)
    results = MlDsa.verify_many([req])
    assert results.first.ok?
  end

  def test_verify_many_verify_request_with_context
    msg = "struct ctx"
    sig = @sk44.sign(msg, context: "ctx", deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk44, message: msg, signature: sig,
      context: "ctx")
    results = MlDsa.verify_many([req])
    assert results.first.ok?
  end

  # -----------------------------------------------------------------------
  # Error handling
  # -----------------------------------------------------------------------

  def test_verify_many_raises_on_non_array
    assert_raises(TypeError) { MlDsa.verify_many("not an array") }
  end

  def test_verify_many_raises_on_non_verify_request_item
    assert_raises(NoMethodError, TypeError) { MlDsa.verify_many(["not a VerifyRequest"]) }
  end

  def test_verify_many_raises_on_wrong_pk_type
    sig = @sk44.sign("m", deterministic: true)
    assert_raises(NoMethodError, ArgumentError) do
      MlDsa.verify_many([
        MlDsa::VerifyRequest.new(pk: "not a key", message: "m", signature: sig)
      ])
    end
  end

  def test_verify_many_raises_on_non_string_message
    sig = @sk44.sign("m", deterministic: true)
    assert_raises(NoMethodError, ArgumentError) do
      MlDsa.verify_many([
        MlDsa::VerifyRequest.new(pk: @pk44, message: 123, signature: sig)
      ])
    end
  end

  def test_verify_many_raises_on_non_string_signature
    assert_raises(NoMethodError, ArgumentError) do
      MlDsa.verify_many([
        MlDsa::VerifyRequest.new(pk: @pk44, message: "m", signature: 123)
      ])
    end
  end

  def test_verify_many_raises_on_context_too_long
    sig = @sk44.sign("m", deterministic: true)
    assert_raises(ArgumentError) do
      MlDsa.verify_many([
        MlDsa::VerifyRequest.new(pk: @pk44, message: "m", signature: sig,
          context: "x" * 256)
      ])
    end
  end
end
