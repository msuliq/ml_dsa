# frozen_string_literal: true

require "test_helper"

class MlDsaKeyObjectsTest < Minitest::Test
  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @msg = "key object test"
  end

  # -----------------------------------------------------------------------
  # SecretKey signing
  # -----------------------------------------------------------------------

  def test_secret_key_sign_returns_frozen_binary_string
    sig = @sk.sign(@msg)
    assert_instance_of String, sig
    assert sig.frozen?
    assert_equal MlDsa::ML_DSA_44.signature_bytes, sig.bytesize
  end

  def test_public_key_verify_convenience
    sig = @sk.sign(@msg, deterministic: true)
    assert @pk.verify(@msg, sig)
    refute @pk.verify("wrong", sig)
  end

  def test_sign_with_context
    sig = @sk.sign(@msg, context: "myapp", deterministic: true)
    assert @pk.verify(@msg, sig, context: "myapp")
    refute @pk.verify(@msg, sig, context: "wrong")
  end

  # -----------------------------------------------------------------------
  # PublicKey serialization
  # -----------------------------------------------------------------------

  def test_public_key_to_bytes_returns_binary_string
    raw = @pk.to_bytes
    assert_equal Encoding::ASCII_8BIT, raw.encoding
    assert_equal @pk.bytesize, raw.bytesize
  end

  def test_public_key_to_hex
    assert_match(/\A[0-9a-f]+\z/, @pk.to_hex)
    assert_equal @pk.bytesize * 2, @pk.to_hex.length
  end

  def test_public_key_to_s_returns_inspect_not_bytes
    # to_s must NOT expose raw key bytes — it returns inspect output
    assert_match(/MlDsa::PublicKey/, @pk.to_s)
    refute_equal @pk.to_bytes, @pk.to_s
  end

  # -----------------------------------------------------------------------
  # SecretKey serialization
  # -----------------------------------------------------------------------

  def test_secret_key_with_bytes_yields_binary_string
    @sk.with_bytes do |buf|
      assert_instance_of String, buf
      assert_equal @sk.bytesize, buf.bytesize
      assert_equal Encoding::ASCII_8BIT, buf.encoding
    end
  end

  def test_secret_key_with_bytes_wipes_buffer_after_block
    leaked = nil
    @sk.with_bytes { |buf| leaked = buf }
    # The buffer is zeroed and resized to zero after the block
    assert_equal 0, leaked.bytesize
  end

  def test_secret_key_with_bytes_wipes_even_on_exception
    leaked = nil
    assert_raises(RuntimeError) do
      @sk.with_bytes do |buf|
        leaked = buf
        raise "oops"
      end
    end
    assert_equal 0, leaked.bytesize
  end

  def test_secret_key_with_bytes_requires_block
    assert_raises(ArgumentError) { @sk.with_bytes }
  end

  def test_secret_key_with_bytes_returns_block_value
    result = @sk.with_bytes { |buf| buf.bytesize }
    assert_equal @sk.bytesize, result
  end

  # -----------------------------------------------------------------------
  # Equality and hashing
  # -----------------------------------------------------------------------

  def test_public_key_equality_with_self
    assert_equal @pk, @pk
  end

  def test_public_key_equality_from_bytes_roundtrip
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes, MlDsa::ML_DSA_44)
    assert_equal @pk, pk2
  end

  def test_public_key_inequality_with_raw_string
    # to_bytes no longer makes pk == raw_string
    refute_equal @pk, @pk.to_bytes
  end

  def test_public_key_eql_consistent_with_equality
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes, MlDsa::ML_DSA_44)
    assert @pk.eql?(pk2)
    refute @pk.eql?("not a key")
  end

  def test_public_key_hash_consistent_with_eql
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes, MlDsa::ML_DSA_44)
    assert_equal @pk.hash, pk2.hash
  end

  def test_public_key_usable_as_hash_key
    h = {@pk => "value"}
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes, MlDsa::ML_DSA_44)
    assert_equal "value", h[pk2]
  end

  def test_secret_key_equality
    _pk2, sk2 = MlDsa.keygen(MlDsa::ML_DSA_44)
    refute_equal @sk, sk2
    assert_equal @sk, @sk
  end

  def test_secret_key_eql_consistent_with_equality
    sk2 = @sk.with_bytes { |b| MlDsa::SecretKey.from_bytes(b, MlDsa::ML_DSA_44) }
    assert @sk.eql?(sk2)
    refute @sk.eql?("not a key")
  end

  def test_secret_key_hash_consistent_with_eql
    sk2 = @sk.with_bytes { |b| MlDsa::SecretKey.from_bytes(b, MlDsa::ML_DSA_44) }
    assert_equal @sk.hash, sk2.hash
  end

  def test_secret_key_usable_as_hash_key
    h = {@sk => "value"}
    sk2 = @sk.with_bytes { |b| MlDsa::SecretKey.from_bytes(b, MlDsa::ML_DSA_44) }
    assert_equal "value", h[sk2]
  end

  # -----------------------------------------------------------------------
  # Deserialization roundtrips
  # -----------------------------------------------------------------------

  def test_public_key_from_bytes_roundtrip
    pk2 = MlDsa::PublicKey.from_bytes(@pk.to_bytes, MlDsa::ML_DSA_44)
    assert_equal @pk, pk2
    assert_equal MlDsa::ML_DSA_44, pk2.param_set
  end

  def test_public_key_from_hex_roundtrip
    pk2 = MlDsa::PublicKey.from_hex(@pk.to_hex, MlDsa::ML_DSA_44)
    assert_equal @pk, pk2
  end

  def test_secret_key_from_bytes_roundtrip
    sk2 = @sk.with_bytes { |b| MlDsa::SecretKey.from_bytes(b, MlDsa::ML_DSA_44) }
    sig1 = @sk.sign(@msg, deterministic: true)
    sig2 = sk2.sign(@msg, deterministic: true)
    assert_equal sig1, sig2
  end

  def test_secret_key_from_hex_roundtrip
    hex = @sk.with_bytes { |b| b.unpack1("H*") }
    sk2 = MlDsa::SecretKey.from_hex(hex, MlDsa::ML_DSA_44)
    assert @pk.verify(@msg, sk2.sign(@msg, deterministic: true))
  end

  def test_from_bytes_wrong_size_raises
    assert_raises(ArgumentError) do
      MlDsa::PublicKey.from_bytes("tooshort", MlDsa::ML_DSA_44)
    end
  end

  def test_from_bytes_wrong_param_set_type_raises
    assert_raises(TypeError) do
      MlDsa::PublicKey.from_bytes(@pk.to_bytes, :ml_dsa_44)
    end
  end

  # -----------------------------------------------------------------------
  # Inspect
  # -----------------------------------------------------------------------

  def test_public_key_inspect
    assert_match(/MlDsa::PublicKey/, @pk.inspect)
    assert_match(/ML-DSA-44/, @pk.inspect)
  end

  def test_secret_key_inspect
    assert_match(/MlDsa::SecretKey/, @sk.inspect)
    assert_match(/ML-DSA-44/, @sk.inspect)
  end

  # -----------------------------------------------------------------------
  # Private factory is truly private
  # -----------------------------------------------------------------------

  def test_sk_from_bytes_raw_is_private
    assert_raises(NoMethodError) do
      MlDsa::SecretKey._from_bytes_raw("x", 44, MlDsa::ML_DSA_44)
    end
  end

  def test_pk_from_bytes_raw_is_private
    assert_raises(NoMethodError) do
      MlDsa::PublicKey._from_bytes_raw("x", 44, MlDsa::ML_DSA_44)
    end
  end

  # -----------------------------------------------------------------------
  # from_hex input validation
  # -----------------------------------------------------------------------

  def test_public_key_from_hex_rejects_odd_length
    odd_hex = @pk.to_hex[0..-2]  # drop last char → odd length
    assert_raises(ArgumentError) { MlDsa::PublicKey.from_hex(odd_hex, MlDsa::ML_DSA_44) }
  end

  def test_public_key_from_hex_rejects_non_hex_chars
    bad_hex = "zz" * @pk.bytesize
    assert_raises(ArgumentError) { MlDsa::PublicKey.from_hex(bad_hex, MlDsa::ML_DSA_44) }
  end

  def test_public_key_from_hex_rejects_non_string
    assert_raises(TypeError) { MlDsa::PublicKey.from_hex(123, MlDsa::ML_DSA_44) }
  end

  def test_secret_key_from_hex_rejects_odd_length
    odd_hex = @sk.with_bytes { |b| b.unpack1("H*") }[0..-2]
    assert_raises(ArgumentError) { MlDsa::SecretKey.from_hex(odd_hex, MlDsa::ML_DSA_44) }
  end

  def test_secret_key_from_hex_rejects_non_hex_chars
    bad_hex = "xx" * @sk.bytesize
    assert_raises(ArgumentError) { MlDsa::SecretKey.from_hex(bad_hex, MlDsa::ML_DSA_44) }
  end

  def test_secret_key_from_hex_rejects_non_string
    assert_raises(TypeError) { MlDsa::SecretKey.from_hex(nil, MlDsa::ML_DSA_44) }
  end

  # -----------------------------------------------------------------------
  # .new is blocked  (#4)
  # -----------------------------------------------------------------------

  def test_public_key_new_is_blocked
    assert_raises(NoMethodError) { MlDsa::PublicKey.new }
  end

  def test_secret_key_new_is_blocked
    assert_raises(NoMethodError) { MlDsa::SecretKey.new }
  end

  # -----------------------------------------------------------------------
  # from_bytes auto-detection by size
  # -----------------------------------------------------------------------

  def test_pk_from_bytes_auto_detects_param_set
    raw = @pk.to_bytes
    pk2 = MlDsa::PublicKey.from_bytes(raw)
    assert_equal @pk.param_set, pk2.param_set
    assert_equal @pk, pk2
  end

  def test_sk_from_bytes_auto_detects_param_set
    _, sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    raw = nil
    sk.with_bytes { |b| raw = b.dup }
    sk2 = MlDsa::SecretKey.from_bytes(raw)
    assert_equal sk.param_set, sk2.param_set
    assert_equal sk, sk2
  end

  def test_pk_from_bytes_auto_detect_all_param_sets
    [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
      pk, _ = MlDsa.keygen(ps)
      pk2 = MlDsa::PublicKey.from_bytes(pk.to_bytes)
      assert_equal ps, pk2.param_set
    end
  end

  def test_pk_from_bytes_auto_detect_bad_size_raises
    err = assert_raises(ArgumentError) do
      MlDsa::PublicKey.from_bytes("x" * 999)
    end
    assert_match(/cannot auto-detect/, err.message)
  end

  def test_sk_from_bytes_auto_detect_bad_size_raises
    err = assert_raises(ArgumentError) do
      MlDsa::SecretKey.from_bytes("x" * 999)
    end
    assert_match(/cannot auto-detect/, err.message)
  end

  def test_pk_from_hex_auto_detects_param_set
    hex = @pk.to_hex
    pk2 = MlDsa::PublicKey.from_hex(hex)
    assert_equal @pk, pk2
  end

  def test_sk_from_hex_auto_detects_param_set
    hex = nil
    @sk.with_bytes { |b| hex = b.unpack1("H*") }
    sk2 = MlDsa::SecretKey.from_hex(hex)
    assert_equal @sk, sk2
  end
end
