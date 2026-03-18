# frozen_string_literal: true

require "test_helper"
require "yaml"

# Known-Answer Tests (KAT) for ML-DSA.
#
# Two layers of validation:
#
# 1. Regression vectors — fixtures generated from the compiled implementation
#    and committed to the repo.  These catch any future change to the C
#    implementation that silently alters signing output.  The fixture file is
#    at test/fixtures/kat_vectors.yaml; regenerate it with:
#
#      bundle exec ruby test/fixtures/generate_kat_vectors.rb
#
# 2. Self-consistency — verifies that deterministic signing is stable within
#    the current process (independent of the fixture file).
#
class MlDsaKnownAnswerTest < Minitest::Test
  FIXTURE_PATH = File.expand_path("../fixtures/kat_vectors.yaml", __dir__)

  # -----------------------------------------------------------------------
  # Regression vector tests (require the fixture file)
  # -----------------------------------------------------------------------

  def test_fixture_file_exists
    assert File.exist?(FIXTURE_PATH),
      "KAT fixture file missing: #{FIXTURE_PATH}\n" \
      "Run: bundle exec ruby test/fixtures/generate_kat_vectors.rb"
  end

  [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
    define_method("test_regression_vector_#{ps.name.downcase.tr("-", "_")}") do
      skip "fixture file missing" unless File.exist?(FIXTURE_PATH)

      vectors = YAML.safe_load(File.read(FIXTURE_PATH))
      v = vectors[ps.name]
      refute_nil v, "no vector for #{ps.name} in fixture"

      # Deserialize keys from stored hex
      pk = MlDsa::PublicKey.from_hex(v["pk_hex"], ps)
      sk = MlDsa::SecretKey.from_hex(v["sk_hex"], ps)

      # Reproduced signature must exactly match the stored vector
      sig = sk.sign(v["msg"], deterministic: true)
      assert_equal v["sig_hex"], sig.unpack1("H*"),
        "#{ps.name} deterministic signature differs from stored vector — " \
        "C implementation may have changed"

      # The stored signature must verify against the stored public key
      stored_sig = [v["sig_hex"]].pack("H*")
      assert pk.verify(v["msg"], stored_sig),
        "#{ps.name} stored signature does not verify against stored public key"
    end
  end

  # -----------------------------------------------------------------------
  # Self-consistency tests (no fixture file required)
  # -----------------------------------------------------------------------

  [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
    define_method("test_deterministic_stability_#{ps.name.downcase.tr("-", "_")}") do
      pk, sk = MlDsa.keygen(ps)
      msg = "kat message for #{ps.name}"
      ctx = "kat-context"

      sig_a = sk.sign(msg, deterministic: true, context: ctx)
      sig_b = sk.sign(msg, deterministic: true, context: ctx)

      assert_equal sig_a, sig_b,
        "#{ps.name} deterministic sign must be stable across calls"
      assert pk.verify(msg, sig_a, context: ctx),
        "#{ps.name} deterministic signature must verify"
    end
  end

  # -----------------------------------------------------------------------
  # Key size assertions against fixture
  # -----------------------------------------------------------------------

  def test_fixture_key_sizes_match_constants
    skip "fixture file missing" unless File.exist?(FIXTURE_PATH)

    vectors = YAML.safe_load(File.read(FIXTURE_PATH))
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      v = vectors[ps.name]
      next unless v

      pk_bytes = v["pk_hex"].length / 2
      sk_bytes = v["sk_hex"].length / 2
      sig_bytes = v["sig_hex"].length / 2

      assert_equal ps.public_key_bytes, pk_bytes, "#{ps.name} pk size mismatch"
      assert_equal ps.secret_key_bytes, sk_bytes, "#{ps.name} sk size mismatch"
      assert_equal ps.signature_bytes, sig_bytes, "#{ps.name} sig size mismatch"
    end
  end
end
