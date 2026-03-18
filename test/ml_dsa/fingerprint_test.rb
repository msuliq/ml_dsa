# frozen_string_literal: true

require "test_helper"
require "digest"

class MlDsaFingerprintTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
  end

  def test_fingerprint_returns_32_hex_chars
    fp = @pk.fingerprint
    assert_equal 32, fp.length
    assert_match(/\A[0-9a-f]{32}\z/, fp)
  end

  def test_fingerprint_is_frozen
    assert @pk.fingerprint.frozen?
  end

  def test_fingerprint_is_deterministic
    assert_equal @pk.fingerprint, @pk.fingerprint
  end

  def test_fingerprint_matches_sha256_of_raw_bytes
    expected = Digest::SHA256.hexdigest(@pk.to_bytes)[0, 32]
    assert_equal expected, @pk.fingerprint
  end

  def test_fingerprint_differs_across_keys
    pk2, _ = MlDsa.keygen(MlDsa::ML_DSA_44)
    refute_equal @pk.fingerprint, pk2.fingerprint
  end

  def test_fingerprint_matches_after_roundtrip
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes)
    assert_equal @pk.fingerprint, pk2.fingerprint
  end

  def test_fingerprint_all_param_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      pk, _ = MlDsa.keygen(ps)
      fp = pk.fingerprint
      assert_equal 32, fp.length, "fingerprint length for #{ps.name}"
      assert_match(/\A[0-9a-f]{32}\z/, fp, "fingerprint format for #{ps.name}")
    end
  end
end
