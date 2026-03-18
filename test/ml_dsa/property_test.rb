# frozen_string_literal: true

require "test_helper"

# Property-based / fuzz-style tests for ML-DSA.
#
# Each test runs ITERATIONS iterations with randomised inputs (message and
# context lengths, binary content) to exercise edge cases that fixed-value
# unit tests miss.  Not a substitute for a proper fuzzer but catches
# off-by-one errors, encoding edge cases, and context boundary issues.
#
# Reproducibility: set ML_DSA_TEST_SEED to an integer to lock the PRNG.
# When a CI run fails, the seed is printed in the test name so you can
# reproduce locally:
#
#   ML_DSA_TEST_SEED=12345 bundle exec rake test
class MlDsaPropertyTest < Minitest::Test
  ITERATIONS = 100

  SEED = (ENV["ML_DSA_TEST_SEED"] || Random.new_seed).to_i

  def setup
    @rng = Random.new(SEED)
    @pk44, @sk44 = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk65, @sk65 = MlDsa.keygen(MlDsa::ML_DSA_65)
    @pk87, @sk87 = MlDsa.keygen(MlDsa::ML_DSA_87)
  end

  # Sign + verify roundtrip for random binary messages of varying length.
  def test_sign_verify_random_messages
    ITERATIONS.times do
      msg_len = @rng.rand(0..4096)
      msg = @rng.bytes(msg_len)
      sig = @sk44.sign(msg, deterministic: true)
      assert @pk44.verify(msg, sig),
        "failed to verify for msg_len=#{msg_len} (seed=#{SEED})"
    end
  end

  # Sign + verify with random context strings.
  # ctx_len starts at 1: empty context is indistinguishable from no context,
  # so the separation refute only makes sense for non-empty contexts.
  def test_sign_verify_random_contexts
    ITERATIONS.times do
      ctx_len = @rng.rand(1..255)
      ctx = @rng.bytes(ctx_len)
      msg = @rng.bytes(@rng.rand(1..256))
      sig = @sk44.sign(msg, context: ctx, deterministic: true)
      assert @pk44.verify(msg, sig, context: ctx),
        "failed to verify for ctx_len=#{ctx_len} (seed=#{SEED})"
      refute @pk44.verify(msg, sig),
        "should not verify without context for ctx_len=#{ctx_len} (seed=#{SEED})"
    end
  end

  # Flipping any bit in the signature must cause verification to fail.
  def test_bit_flip_in_signature_fails_verification
    ITERATIONS.times do
      msg = @rng.bytes(@rng.rand(1..128))
      sig = @sk44.sign(msg, deterministic: true)
      corrupted = sig.b
      byte_idx = @rng.rand(0...corrupted.bytesize)
      corrupted.setbyte(byte_idx, corrupted.getbyte(byte_idx) ^ 0xff)
      refute @pk44.verify(msg, corrupted),
        "corrupted signature should not verify (seed=#{SEED})"
    end
  end

  # Changing any byte of the message must cause verification to fail.
  def test_message_corruption_fails_verification
    ITERATIONS.times do
      msg = @rng.bytes(@rng.rand(1..256))
      sig = @sk44.sign(msg, deterministic: true)
      corrupted_msg = msg.b
      byte_idx = @rng.rand(0...corrupted_msg.bytesize)
      corrupted_msg.setbyte(byte_idx, (corrupted_msg.getbyte(byte_idx) + 1) % 256)
      refute @pk44.verify(corrupted_msg, sig),
        "signature should not verify for mutated message (seed=#{SEED})"
    end
  end

  # Hedged signing with the same message always produces different signatures
  # (with overwhelming probability).
  def test_hedged_uniqueness
    msg = @rng.bytes(64)
    sigs = ITERATIONS.times.map { @sk44.sign(msg) }
    assert_equal ITERATIONS, sigs.uniq.size,
      "hedged signatures should all differ (collision extremely unlikely)"
  end

  # sign_many and single sign produce consistent results for deterministic mode.
  def test_sign_many_matches_single_sign
    ITERATIONS.times do
      msg = @rng.bytes(@rng.rand(1..128))
      single = @sk44.sign(msg, deterministic: true)
      batch = MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk44, message: msg, deterministic: true)]).first
      assert_equal single, batch,
        "sign_many deterministic must match sk.sign deterministic (seed=#{SEED})"
    end
  end

  # verify_many results match single verify for each param set.
  def test_verify_many_matches_single_verify_all_param_sets
    [[MlDsa::ML_DSA_44, @pk44, @sk44],
      [MlDsa::ML_DSA_65, @pk65, @sk65],
      [MlDsa::ML_DSA_87, @pk87, @sk87]].each do |_ps, pk, sk|
      ITERATIONS.times do
        msg = @rng.bytes(@rng.rand(0..128))
        sig = sk.sign(msg, deterministic: true)
        batch_ok = MlDsa.verify_many([MlDsa::VerifyRequest.new(pk: pk, message: msg, signature: sig)]).first.ok?
        single_ok = pk.verify(msg, sig)
        assert_equal single_ok, batch_ok
      end
    end
  end

  # Seed-based keygen is deterministic: same seed always yields same key pair.
  def test_seed_keygen_determinism
    ITERATIONS.times do
      seed = @rng.bytes(32)
      pair1 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
      pair2 = MlDsa.keygen(MlDsa::ML_DSA_44, seed: seed)
      assert_equal pair1.public_key.to_bytes, pair2.public_key.to_bytes
      msg = @rng.bytes(64)
      sig = pair1.secret_key.sign(msg)
      assert pair2.public_key.verify(msg, sig)
    end
  end

  # DER roundtrip preserves key identity for all param sets.
  def test_pk_der_roundtrip
    [[MlDsa::ML_DSA_44, @pk44],
      [MlDsa::ML_DSA_65, @pk65],
      [MlDsa::ML_DSA_87, @pk87]].each do |ps, pk|
      der = pk.to_der
      restored = MlDsa::PublicKey.from_der(der)
      assert_equal pk.to_bytes, restored.to_bytes,
        "DER roundtrip failed for #{ps.name}"
      assert_equal pk.param_set, restored.param_set
    end
  end

  # Context binding: signing with context A must not verify with context B.
  def test_context_binding
    ITERATIONS.times do
      ctx_a = @rng.bytes(@rng.rand(1..255))
      ctx_b = @rng.bytes(@rng.rand(1..255))
      next if ctx_a == ctx_b
      msg = @rng.bytes(@rng.rand(1..128))
      sig = @sk44.sign(msg, context: ctx_a, deterministic: true)
      assert @pk44.verify(msg, sig, context: ctx_a)
      refute @pk44.verify(msg, sig, context: ctx_b),
        "signature should not verify with different context (seed=#{SEED})"
    end
  end

  # Cross-key: a signature from key A must not verify under key B.
  def test_cross_key_rejection
    pair_a = MlDsa.keygen(MlDsa::ML_DSA_44)
    pair_b = MlDsa.keygen(MlDsa::ML_DSA_44)
    ITERATIONS.times do
      msg = @rng.bytes(@rng.rand(0..256))
      sig = pair_a.secret_key.sign(msg, deterministic: true)
      refute pair_b.public_key.verify(msg, sig),
        "signature should not verify under a different key (seed=#{SEED})"
    end
  end

  # Cross-parameter-set: sign+verify roundtrip for all three param sets.
  def test_sign_verify_all_param_sets
    pairs = {
      44 => [@pk44, @sk44],
      65 => [@pk65, @sk65],
      87 => [@pk87, @sk87]
    }
    ITERATIONS.times do
      pairs.each do |code, (pk, sk)|
        msg = @rng.bytes(@rng.rand(0..512))
        sig = sk.sign(msg, deterministic: true)
        assert pk.verify(msg, sig),
          "roundtrip failed for ML-DSA-#{code} (seed=#{SEED})"
      end
    end
  end

  # SecretKey#public_key matches the PK from keygen for all param sets.
  def test_sk_public_key_matches_keygen_pk
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      ITERATIONS.times do
        pair = MlDsa.keygen(ps)
        assert_equal pair.public_key, pair.secret_key.public_key,
          "sk.public_key should match keygen pk for #{ps.name} (seed=#{SEED})"
        # Verify signature using the sk-derived public key
        msg = @rng.bytes(@rng.rand(1..128))
        sig = pair.secret_key.sign(msg, deterministic: true)
        assert pair.secret_key.public_key.verify(msg, sig),
          "verify via sk.public_key failed for #{ps.name} (seed=#{SEED})"
      end
    end
  end

  # SecretKey.from_seed is deterministic and produces working keys.
  def test_from_seed_all_param_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      ITERATIONS.times do
        seed = @rng.bytes(32)
        sk1 = MlDsa::SecretKey.from_seed(seed, ps)
        sk2 = MlDsa::SecretKey.from_seed(seed, ps)
        assert_equal sk1, sk2,
          "from_seed should be deterministic for #{ps.name} (seed=#{SEED})"
        assert_equal sk1.public_key, sk2.public_key
        msg = @rng.bytes(@rng.rand(1..64))
        sig = sk1.sign(msg, deterministic: true)
        assert sk2.public_key.verify(msg, sig)
      end
    end
  end

  # Instrumentation events fire for every operation.
  def test_instrumentation_fires_events
    events = []
    sub = MlDsa.subscribe { |e| events << e }
    begin
      pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      sig = sk.sign("instrumentation test", deterministic: true)
      pk.verify("instrumentation test", sig)
      assert_equal 3, events.size
      assert_equal :keygen, events[0][:operation]
      assert_equal :sign, events[1][:operation]
      assert_equal :verify, events[2][:operation]
      events.each do |e|
        assert_kind_of Integer, e[:duration_ns]
        assert e[:duration_ns] >= 0
        assert_equal 1, e[:count]
      end
    ensure
      MlDsa.unsubscribe(sub)
    end
  end
end
