# frozen_string_literal: true

require "test_helper"

class MlDsaWipeTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "wipe test message"
  end

  def test_wipe_returns_nil
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    result = sk.wipe!
    assert_nil result
  end

  def test_wipe_is_idempotent
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    sk.wipe!  # second call must not raise
  end

  def test_inspect_shows_wiped_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_match(/\[wiped\]/, sk.inspect)
  end

  def test_to_s_shows_wiped_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_match(/\[wiped\]/, sk.to_s)
  end

  def test_param_set_still_works_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_equal MlDsa::ML_DSA_44, sk.param_set
  end

  def test_sign_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.sign(@msg) }
  end

  def test_with_bytes_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.with_bytes { |_b| } }
  end

  def test_bytesize_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.bytesize }
  end

  def test_hash_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.hash }
  end

  def test_equality_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    _, sk2 = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk == sk2 }
  end

  def test_to_der_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.to_der }
  end

  def test_to_pem_raises_after_wipe
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk.wipe!
    assert_raises(MlDsa::Error) { sk.to_pem }
  end

  def test_normal_key_unaffected_by_other_key_wipe
    _, sk1 = MlDsa.keygen(MlDsa::ML_DSA_44)
    _, sk2 = MlDsa.keygen(MlDsa::ML_DSA_44)
    sk1.wipe!
    sig = sk2.sign(@msg)  # must not raise
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end
end
