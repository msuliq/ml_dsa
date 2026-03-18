# frozen_string_literal: true

require "test_helper"

class MlDsaThreadSafetyTest < Minitest::Test
  THREAD_COUNT = 50

  def test_concurrent_keygen_and_sign_verify
    results = THREAD_COUNT.times.map do |i|
      Thread.new do
        pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
        msg = "thread_#{i}_message"
        sig = sk.sign(msg)
        assert pk.verify(msg, sig)
        refute pk.verify("wrong", sig)
        pk.to_bytes
      end
    end
    raw_keys = results.map(&:value)
    assert_equal THREAD_COUNT, raw_keys.uniq.size
  end

  def test_concurrent_hedged_and_deterministic
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    msg = "concurrent mode test"

    threads = THREAD_COUNT.times.map do |i|
      Thread.new do
        sig = sk.sign(msg, deterministic: i.odd?)
        assert pk.verify(msg, sig)
        sig
      end
    end

    sigs = threads.map(&:value)
    # All deterministic signatures (odd indices) must be equal
    det_sigs = sigs.each_with_index.select { |_, i| i.odd? }.map(&:first)
    assert det_sigs.uniq.size == 1,
      "all deterministic signatures must match"
  end

  def test_concurrent_key_object_operations
    threads = THREAD_COUNT.times.map do |i|
      Thread.new do
        pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65)
        msg = "key_obj_thread_#{i}"
        sig = sk.sign(msg, deterministic: true)
        assert pk.verify(msg, sig)
        pk.to_hex
      end
    end
    hexes = threads.map(&:value)
    assert_equal THREAD_COUNT, hexes.uniq.size
  end

  def test_concurrent_with_bytes
    pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    msg = "with_bytes_thread_test"

    threads = THREAD_COUNT.times.map do
      Thread.new do
        sk.with_bytes do |buf|
          sk2 = MlDsa::SecretKey.from_bytes(buf, MlDsa::ML_DSA_44)
          sig = sk2.sign(msg, deterministic: true)
          pk.verify(msg, sig)
        end
      end
    end

    results = threads.map(&:value)
    assert results.all?, "all with_bytes threads should verify successfully"
  end

  def test_concurrent_sign_many
    pk44, sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    shared_msg = "sign_many_shared_deterministic"

    threads = THREAD_COUNT.times.map do |i|
      Thread.new do
        per_thread_msg = "sign_many_per_thread_#{i}"
        ops = [
          MlDsa::SignRequest.new(sk: sk44, message: shared_msg, deterministic: true),
          MlDsa::SignRequest.new(sk: sk44, message: per_thread_msg, deterministic: false)
        ]
        sigs = MlDsa.sign_many(ops)
        assert_equal 2, sigs.size
        assert pk44.verify(shared_msg, sigs[0])
        assert pk44.verify(per_thread_msg, sigs[1])
        sigs[0]  # deterministic sig for the shared message
      end
    end

    det_sigs = threads.map(&:value)
    # All threads signed the same message deterministically — must all match
    assert_equal 1, det_sigs.uniq.size,
      "concurrent deterministic batch sigs for same message must match"
  end

  def test_concurrent_verify_many
    pk44, sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    msg = "verify_many_concurrent"
    sig = sk44.sign(msg, deterministic: true)

    threads = THREAD_COUNT.times.map do
      Thread.new do
        results = MlDsa.verify_many([
          MlDsa::VerifyRequest.new(pk: pk44, message: msg, signature: sig),
          MlDsa::VerifyRequest.new(pk: pk44, message: "wrong", signature: sig)
        ])
        results
      end
    end

    all_results = threads.map(&:value)
    all_results.each do |res|
      assert res[0].ok?, "valid signature must verify"
      refute res[1].ok?, "wrong message must not verify"
    end
  end
end
