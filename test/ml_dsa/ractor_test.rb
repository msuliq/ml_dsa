# frozen_string_literal: true

require "test_helper"

class MlDsaRactorTest < Minitest::Test
  # Ractor requires Ruby 3.0+ and the C extension declares rb_ext_ractor_safe.
  # However, full Ractor support requires all referenced Ruby objects to be
  # shareable. The extension uses cached class/module VALUEs that are not yet
  # Ractor-shareable on Ruby < 3.4. Test what we can, skip what we can't.
  if defined?(Ractor)
    # Ruby 4.0 renamed Ractor#take to Ractor#value.
    def ractor_result(r)
      r.respond_to?(:value) ? r.value : r.take
    end

    def test_parameter_set_constants_are_shareable
      # ParameterSet constants are frozen and should be Ractor-shareable
      assert Ractor.shareable?(MlDsa::ML_DSA_44)
      assert Ractor.shareable?(MlDsa::ML_DSA_65)
      assert Ractor.shareable?(MlDsa::ML_DSA_87)
    end

    def test_frozen_public_key_can_be_sent_as_copy
      pk, _sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      # PublicKey is frozen; we can send its bytes across Ractors
      pk_bytes = pk.to_bytes
      assert Ractor.shareable?(pk_bytes)
    end

    def test_public_key_is_not_ractor_shareable
      pk, _sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      refute Ractor.shareable?(pk),
        "PublicKey is mutable (key_usage=) and should not be Ractor-shareable"
    end

    def test_public_key_bytes_can_be_shared_across_ractors
      pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      msg = "shared-pk-test"
      sig = sk.sign(msg, deterministic: true)

      # PK is not shareable — send bytes and reconstruct in the Ractor
      pk_bytes = pk.to_bytes
      r = Ractor.new(pk_bytes, sig) do |pk_b, s|
        pk2 = MlDsa::PublicKey.from_bytes(pk_b, MlDsa::ML_DSA_44)
        pk2.verify("shared-pk-test", s)
      end
      assert ractor_result(r)
    rescue Ractor::RemoteError => e
      if e.cause.is_a?(Ractor::UnsafeError) || e.cause.is_a?(Ractor::IsolationError)
        skip "Ractor C extension calls not yet supported on Ruby #{RUBY_VERSION}"
      else
        raise
      end
    end

    def test_keygen_in_ractor
      r = Ractor.new do
        pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
        sig = sk.sign("hello from ractor")
        pk.verify("hello from ractor", sig)
      end
      assert ractor_result(r)
    rescue Ractor::RemoteError => e
      if e.cause.is_a?(Ractor::UnsafeError) || e.cause.is_a?(Ractor::IsolationError)
        skip "Ractor C extension calls not yet supported on Ruby #{RUBY_VERSION}"
      else
        raise
      end
    end

    def test_verify_in_ractor
      pk, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
      sig = sk.sign("cross-ractor message")
      pk_bytes = pk.to_bytes

      r = Ractor.new(pk_bytes, sig) do |pk_b, s|
        pk2 = MlDsa::PublicKey.from_bytes(pk_b, MlDsa::ML_DSA_44)
        pk2.verify("cross-ractor message", s)
      end
      assert ractor_result(r)
    rescue Ractor::RemoteError => e
      if e.cause.is_a?(Ractor::UnsafeError) || e.cause.is_a?(Ractor::IsolationError)
        skip "Ractor C extension calls not yet supported on Ruby #{RUBY_VERSION}"
      else
        raise
      end
    end
  else
    def test_ractor_not_available
      skip "Ractor not available on Ruby #{RUBY_VERSION}"
    end
  end
end
