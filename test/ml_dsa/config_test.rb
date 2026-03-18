# frozen_string_literal: true

require "test_helper"

class MlDsaConfigTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "config test"
  end

  def teardown
    MlDsa.random_source = nil
  end

  # -----------------------------------------------------------------------
  # Pluggable RNG
  # -----------------------------------------------------------------------

  def test_random_source_default_is_nil
    assert_nil MlDsa.random_source
  end

  def test_random_source_can_be_set_and_cleared
    rng = proc { |n| "\x42" * n }
    MlDsa.random_source = rng
    assert_equal rng, MlDsa.random_source
    MlDsa.random_source = nil
    assert_nil MlDsa.random_source
  end

  def test_random_source_rejects_non_callable
    assert_raises(TypeError) { MlDsa.random_source = "not a proc" }
  end

  def test_random_source_keygen_is_deterministic
    calls = []
    fixed_seed = "\x01" * 32
    MlDsa.random_source = proc { |n|
      calls << n
      fixed_seed[0, n]
    }
    pk1, _sk1 = MlDsa.keygen(MlDsa::ML_DSA_44)
    pk2, _sk2 = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_equal pk1.to_bytes, pk2.to_bytes,
      "custom RNG keygen should be deterministic with same source"
    assert calls.include?(32), "should have requested 32 bytes for seed"
  end

  def test_random_source_sign_uses_custom_rnd
    calls = []
    fixed_rnd = "\xAB" * 32
    MlDsa.random_source = proc { |n|
      calls << n
      fixed_rnd[0, n]
    }
    # Use a pre-generated key (not from custom RNG)
    MlDsa.random_source = nil
    _pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)

    MlDsa.random_source = proc { |n|
      calls << n
      fixed_rnd[0, n]
    }
    sig1 = sk.sign(@msg)
    sig2 = sk.sign(@msg)
    # Same RNG output -> same signatures (since rnd is the same)
    assert_equal sig1, sig2,
      "same custom RNG output should produce identical hedged signatures"
  end

  def test_random_source_not_used_for_deterministic_sign
    called = false
    MlDsa.random_source = proc { |n|
      called = true
      "\x00" * n
    }
    # Deterministic signing should not call the RNG
    MlDsa.random_source = nil
    _pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    MlDsa.random_source = proc { |n|
      called = true
      "\x00" * n
    }
    sk.sign(@msg, deterministic: true)
    refute called, "deterministic signing should not call random_source"
  end

  def test_random_source_wrong_size_raises
    MlDsa.random_source = proc { |_n| "\x00" * 16 }  # wrong size
    assert_raises(ArgumentError) { MlDsa.keygen(MlDsa::ML_DSA_44) }
  end

  # -----------------------------------------------------------------------
  # Instrumentation
  # -----------------------------------------------------------------------

  def test_instrumentation_still_works
    events = []
    sub = MlDsa.subscribe { |e| events << e }
    begin
      pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      sig = sk.sign("test", deterministic: true)
      pk.verify("test", sig)
      assert_equal 3, events.size
      assert_equal :keygen, events[0][:operation]
      assert_equal :sign, events[1][:operation]
      assert_equal :verify, events[2][:operation]
    ensure
      MlDsa.unsubscribe(sub)
    end
  end

  def test_unsubscribe_removes_listener
    events = []
    sub = MlDsa.subscribe { |e| events << e }
    MlDsa.unsubscribe(sub)
    MlDsa.keygen(MlDsa::ML_DSA_44)
    assert_empty events
  end

  def test_subscribe_requires_block
    assert_raises(ArgumentError) { MlDsa.subscribe }
  end

  # -----------------------------------------------------------------------
  # Config object
  # -----------------------------------------------------------------------

  def test_config_returns_config_instance
    assert_kind_of MlDsa::Config, MlDsa.config
  end

  def test_config_custom_instance
    cfg = MlDsa::Config.new
    assert_nil cfg.random_source
  end

  def test_config_custom_rng_for_keygen
    fixed_seed = "\x01" * 32
    cfg = MlDsa::Config.new
    cfg.random_source = proc { |n| fixed_seed[0, n] }
    pk1, _ = MlDsa.keygen(MlDsa::ML_DSA_44, config: cfg)
    pk2, _ = MlDsa.keygen(MlDsa::ML_DSA_44, config: cfg)
    assert_equal pk1.to_bytes, pk2.to_bytes
  end

  def test_config_custom_instance_for_sign_many
    cfg = MlDsa::Config.new
    events = []
    cfg.subscribe { |e| events << e }
    req = MlDsa::SignRequest.new(sk: @sk, message: @msg)
    MlDsa.sign_many([req], config: cfg)
    assert_equal 1, events.size
    assert_equal :sign, events.first[:operation]
  end

  def test_config_custom_instance_for_verify_many
    cfg = MlDsa::Config.new
    events = []
    cfg.subscribe { |e| events << e }
    sig = @sk.sign(@msg, deterministic: true)
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: sig)
    MlDsa.verify_many([req], config: cfg)
    assert_equal 1, events.size
    assert_equal :verify, events.first[:operation]
  end

  def test_config_notify_skipped_in_non_main_ractor
    # Just ensure the method doesn't raise
    cfg = MlDsa::Config.new
    cfg.notify(:test, MlDsa::ML_DSA_44, 1, 0)
  end
end
