# frozen_string_literal: true

require "test_helper"

class MlDsaSafetyTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "safety test"
    @sig = @sk.sign(@msg, deterministic: true)
  end

  # -----------------------------------------------------------------------
  # dup/clone prevention
  # -----------------------------------------------------------------------

  def test_public_key_dup_raises_type_error
    err = assert_raises(TypeError) { @pk.dup }
    assert_match(/cannot be duplicated/, err.message)
  end

  def test_public_key_clone_raises_type_error
    err = assert_raises(TypeError) { @pk.clone }
    assert_match(/cannot be duplicated/, err.message)
  end

  def test_secret_key_dup_raises_type_error
    err = assert_raises(TypeError) { @sk.dup }
    assert_match(/cannot be duplicated/, err.message)
  end

  def test_secret_key_clone_raises_type_error
    err = assert_raises(TypeError) { @sk.clone }
    assert_match(/cannot be duplicated/, err.message)
  end

  # -----------------------------------------------------------------------
  # Marshal.dump prevention
  # -----------------------------------------------------------------------

  def test_public_key_marshal_dump_raises
    err = assert_raises(TypeError) { Marshal.dump(@pk) }
    assert_match(/cannot be marshalled|to_der/, err.message)
  end

  def test_secret_key_marshal_dump_raises
    err = assert_raises(TypeError) { Marshal.dump(@sk) }
    assert_match(/cannot be marshalled|to_der/, err.message)
  end

  # -----------------------------------------------------------------------
  # C-created strings are frozen
  # -----------------------------------------------------------------------

  def test_pk_to_bytes_is_frozen
    assert @pk.to_bytes.frozen?
  end

  def test_pk_to_hex_is_frozen
    assert @pk.to_hex.frozen?
  end

  def test_sign_returns_frozen_string
    assert @sig.frozen?
  end

  def test_keygen_returns_frozen_array
    pair = MlDsa.keygen(MlDsa::ML_DSA_44)
    assert pair.frozen?
  end

  def test_sign_many_returns_frozen_array_of_frozen_strings
    sigs = MlDsa.sign_many([MlDsa::SignRequest.new(sk: @sk, message: @msg)])
    assert sigs.frozen?
    sigs.each { |s| assert s.frozen? }
  end

  def test_verify_many_returns_frozen_array
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: @sig)
    result = MlDsa.verify_many([req])
    assert result.frozen?
  end

  def test_pk_to_der_is_frozen
    assert @pk.to_der.frozen?
  end

  def test_pk_to_pem_is_frozen
    assert @pk.to_pem.frozen?
  end

  def test_sk_to_der_is_frozen
    assert @sk.to_der.frozen?
  end

  def test_sk_to_pem_is_frozen
    assert @sk.to_pem.frozen?
  end

  # -----------------------------------------------------------------------
  # verify_many with wrong-size signature returns false
  # -----------------------------------------------------------------------

  def test_verify_many_returns_false_for_wrong_size_sig
    bad_sig = "x" * 10  # wrong size
    req = MlDsa::VerifyRequest.new(pk: @pk, message: @msg, signature: bad_sig)
    result = MlDsa.verify_many([req])
    refute result.first.ok?
    assert_match(/wrong_signature_size/, result.first.reason)
  end
end
