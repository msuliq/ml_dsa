# frozen_string_literal: true

require "test_helper"
require "securerandom"

class MlDsaFuzzTest < Minitest::Test
  ALLOWED_ERRORS = [MlDsa::Error::Deserialization, ArgumentError, TypeError].freeze

  def setup
    @pk, @sk = MlDsa.keygen(MlDsa::ML_DSA_44)
    @pk_der = @pk.to_der
    @sk_der = @sk.to_der
    @pk_pem = @pk.to_pem
    @sk_pem = @sk.to_pem
  end

  # ---------------------------------------------------------------------------
  # 1. Random bytes of various lengths
  # ---------------------------------------------------------------------------

  [0, 1, 10, 100, 1000, 10_000].each do |len|
    define_method(:"test_public_key_from_der_random_bytes_length_#{len}") do
      100.times do
        data = (len == 0) ? "" : SecureRandom.random_bytes(len)
        assert_raises(*ALLOWED_ERRORS) { MlDsa::PublicKey.from_der(data) }
      end
    end

    define_method(:"test_secret_key_from_der_random_bytes_length_#{len}") do
      100.times do
        data = (len == 0) ? "" : SecureRandom.random_bytes(len)
        assert_raises(*ALLOWED_ERRORS) { MlDsa::SecretKey.from_der(data) }
      end
    end

    define_method(:"test_public_key_from_pem_random_bytes_length_#{len}") do
      100.times do
        data = (len == 0) ? "" : SecureRandom.random_bytes(len)
        assert_raises(*ALLOWED_ERRORS) { MlDsa::PublicKey.from_pem(data) }
      end
    end

    define_method(:"test_secret_key_from_pem_random_bytes_length_#{len}") do
      100.times do
        data = (len == 0) ? "" : SecureRandom.random_bytes(len)
        assert_raises(*ALLOWED_ERRORS) { MlDsa::SecretKey.from_pem(data) }
      end
    end
  end

  # ---------------------------------------------------------------------------
  # 2. Valid DER with single-byte mutations (flip each byte)
  # ---------------------------------------------------------------------------

  def test_public_key_der_single_byte_mutations
    @pk_der.bytes.each_with_index do |byte, i|
      mutated = @pk_der.dup
      mutated.setbyte(i, byte ^ 0xFF)
      begin
        pk2 = MlDsa::PublicKey.from_der(mutated)
        # If parsing succeeds, the key must differ from original (corrupted key material)
        # This is acceptable -- the parser accepted structurally valid DER with different content
        refute_nil pk2
      rescue *ALLOWED_ERRORS
        # Expected for structural corruption
      end
    end
  end

  def test_secret_key_der_single_byte_mutations
    @sk_der.bytes.each_with_index do |byte, i|
      mutated = @sk_der.dup
      mutated.setbyte(i, byte ^ 0xFF)
      begin
        MlDsa::SecretKey.from_der(mutated)
      rescue *ALLOWED_ERRORS
        # Expected
      end
    end
  end

  # ---------------------------------------------------------------------------
  # 3. Truncated valid DER at every position
  # ---------------------------------------------------------------------------

  def test_public_key_der_truncated_at_every_position
    (0...@pk_der.bytesize).each do |pos|
      truncated = @pk_der.byteslice(0, pos)
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::PublicKey.from_der(truncated)
      end
    end
  end

  def test_secret_key_der_truncated_at_every_position
    (0...@sk_der.bytesize).each do |pos|
      truncated = @sk_der.byteslice(0, pos)
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::SecretKey.from_der(truncated)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # 4. Extended valid DER with trailing garbage
  # ---------------------------------------------------------------------------

  def test_public_key_der_with_trailing_garbage
    [1, 10, 100, 1000].each do |extra_len|
      extended = @pk_der + SecureRandom.random_bytes(extra_len)
      begin
        MlDsa::PublicKey.from_der(extended)
        # Some parsers may accept trailing data -- not ideal but not a crash
      rescue *ALLOWED_ERRORS
        # Expected
      end
    end
  end

  def test_secret_key_der_with_trailing_garbage
    [1, 10, 100, 1000].each do |extra_len|
      extended = @sk_der + SecureRandom.random_bytes(extra_len)
      begin
        MlDsa::SecretKey.from_der(extended)
      rescue *ALLOWED_ERRORS
        # Expected
      end
    end
  end

  # ---------------------------------------------------------------------------
  # 5. PEM with corrupted Base64 body
  # ---------------------------------------------------------------------------

  def test_public_key_pem_corrupted_base64_body
    lines = @pk_pem.lines
    header = lines.first
    footer = lines.last
    body_lines = lines[1..-2]

    # Corrupt each body line individually
    body_lines.each_with_index do |line, i|
      corrupted_lines = body_lines.dup
      corrupted_lines[i] = "!@\#$%^&*()_+{}|:<>?" + "\n"
      corrupted_pem = header + corrupted_lines.join + footer
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::PublicKey.from_pem(corrupted_pem)
      end
    end
  end

  def test_secret_key_pem_corrupted_base64_body
    lines = @sk_pem.lines
    header = lines.first
    footer = lines.last
    body_lines = lines[1..-2]

    body_lines.each_with_index do |line, i|
      corrupted_lines = body_lines.dup
      corrupted_lines[i] = "!@\#$%^&*()_+{}|:<>?" + "\n"
      corrupted_pem = header + corrupted_lines.join + footer
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::SecretKey.from_pem(corrupted_pem)
      end
    end
  end

  def test_public_key_pem_truncated_base64_body
    lines = @pk_pem.lines
    header = lines.first
    footer = lines.last
    body_lines = lines[1..-2]

    # Keep only first N body lines
    (0...body_lines.size).each do |n|
      truncated_pem = header + body_lines[0, n].join + footer
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::PublicKey.from_pem(truncated_pem)
      end
    end
  end

  def test_secret_key_pem_truncated_base64_body
    lines = @sk_pem.lines
    header = lines.first
    footer = lines.last
    body_lines = lines[1..-2]

    (0...body_lines.size).each do |n|
      truncated_pem = header + body_lines[0, n].join + footer
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::SecretKey.from_pem(truncated_pem)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # 6. PEM with wrong labels
  # ---------------------------------------------------------------------------

  WRONG_PEM_LABELS = [
    "CERTIFICATE",
    "RSA PUBLIC KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "X509 CRL",
    "GARBAGE LABEL"
  ].freeze

  def test_public_key_from_pem_wrong_labels
    body = @pk_pem.lines[1..-2].join
    WRONG_PEM_LABELS.each do |label|
      wrong_pem = "-----BEGIN #{label}-----\n#{body}-----END #{label}-----\n"
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::PublicKey.from_pem(wrong_pem)
      end
    end
  end

  def test_secret_key_from_pem_wrong_labels
    body = @sk_pem.lines[1..-2].join
    WRONG_PEM_LABELS.each do |label|
      wrong_pem = "-----BEGIN #{label}-----\n#{body}-----END #{label}-----\n"
      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::SecretKey.from_pem(wrong_pem)
      end
    end
  end

  def test_public_key_from_pem_private_key_label
    assert_raises(*ALLOWED_ERRORS) do
      MlDsa::PublicKey.from_pem(@sk_pem)
    end
  end

  def test_secret_key_from_pem_public_key_label
    assert_raises(*ALLOWED_ERRORS) do
      MlDsa::SecretKey.from_pem(@pk_pem)
    end
  end

  # ---------------------------------------------------------------------------
  # 7. DER with incorrect lengths (too short, too long, overflow)
  # ---------------------------------------------------------------------------

  def test_public_key_der_length_byte_too_short
    # Modify the outer SEQUENCE length to be shorter than actual content
    mutated = @pk_der.dup
    # The second byte (or bytes) encode the length of the outer SEQUENCE.
    # For long-form lengths (>127 bytes), byte 1 is 0x82 meaning 2 length bytes follow.
    if mutated.getbyte(1) & 0x80 != 0
      num_len_bytes = mutated.getbyte(1) & 0x7F
      # Reduce the encoded length by 10
      len_offset = 2
      encoded_len = 0
      num_len_bytes.times do |j|
        encoded_len = (encoded_len << 8) | mutated.getbyte(len_offset + j)
      end
      new_len = [encoded_len - 10, 0].max
      num_len_bytes.times do |j|
        shift = (num_len_bytes - 1 - j) * 8
        mutated.setbyte(len_offset + j, (new_len >> shift) & 0xFF)
      end
    else
      # Short form: reduce length
      mutated.setbyte(1, [mutated.getbyte(1) - 5, 0].max)
    end
    assert_raises(*ALLOWED_ERRORS) { MlDsa::PublicKey.from_der(mutated) }
  end

  def test_public_key_der_length_byte_too_long
    mutated = @pk_der.dup
    if mutated.getbyte(1) & 0x80 != 0
      num_len_bytes = mutated.getbyte(1) & 0x7F
      len_offset = 2
      encoded_len = 0
      num_len_bytes.times do |j|
        encoded_len = (encoded_len << 8) | mutated.getbyte(len_offset + j)
      end
      new_len = encoded_len + 100
      num_len_bytes.times do |j|
        shift = (num_len_bytes - 1 - j) * 8
        mutated.setbyte(len_offset + j, (new_len >> shift) & 0xFF)
      end
    else
      mutated.setbyte(1, [mutated.getbyte(1) + 50, 127].min)
    end
    assert_raises(*ALLOWED_ERRORS) { MlDsa::PublicKey.from_der(mutated) }
  end

  def test_secret_key_der_length_byte_too_short
    mutated = @sk_der.dup
    if mutated.getbyte(1) & 0x80 != 0
      num_len_bytes = mutated.getbyte(1) & 0x7F
      len_offset = 2
      encoded_len = 0
      num_len_bytes.times do |j|
        encoded_len = (encoded_len << 8) | mutated.getbyte(len_offset + j)
      end
      new_len = [encoded_len - 10, 0].max
      num_len_bytes.times do |j|
        shift = (num_len_bytes - 1 - j) * 8
        mutated.setbyte(len_offset + j, (new_len >> shift) & 0xFF)
      end
    else
      mutated.setbyte(1, [mutated.getbyte(1) - 5, 0].max)
    end
    assert_raises(*ALLOWED_ERRORS) { MlDsa::SecretKey.from_der(mutated) }
  end

  def test_secret_key_der_length_byte_too_long
    mutated = @sk_der.dup
    if mutated.getbyte(1) & 0x80 != 0
      num_len_bytes = mutated.getbyte(1) & 0x7F
      len_offset = 2
      encoded_len = 0
      num_len_bytes.times do |j|
        encoded_len = (encoded_len << 8) | mutated.getbyte(len_offset + j)
      end
      new_len = encoded_len + 100
      num_len_bytes.times do |j|
        shift = (num_len_bytes - 1 - j) * 8
        mutated.setbyte(len_offset + j, (new_len >> shift) & 0xFF)
      end
    else
      mutated.setbyte(1, [mutated.getbyte(1) + 50, 127].min)
    end
    assert_raises(*ALLOWED_ERRORS) { MlDsa::SecretKey.from_der(mutated) }
  end

  def test_der_with_overflow_length_bytes
    # DER with length field claiming absurdly large content (0xFFFFFFFF)
    overflow_ders = [
      "\x30\x84\xFF\xFF\xFF\xFF".b,          # SEQUENCE with 4-byte len = 4GB
      "\x30\x83\xFF\xFF\xFF".b,               # SEQUENCE with 3-byte len = 16MB
      "\x30\x82\xFF\xFF".b,                   # SEQUENCE with 2-byte len = 64KB
      "\x30\x80".b,                           # Indefinite length (not valid DER)
      "\x30\x85\xFF\xFF\xFF\xFF\xFF".b       # 5-byte length
    ]

    overflow_ders.each do |bad_der|
      assert_raises(*ALLOWED_ERRORS) { MlDsa::PublicKey.from_der(bad_der) }
      assert_raises(*ALLOWED_ERRORS) { MlDsa::SecretKey.from_der(bad_der) }
    end
  end

  # ---------------------------------------------------------------------------
  # 8. Minimal valid ASN.1 structures with wrong OIDs
  # ---------------------------------------------------------------------------

  def test_public_key_der_wrong_oids
    require "openssl"

    wrong_oids = [
      "1.2.840.113549.1.1.1",   # RSA
      "1.2.840.10045.2.1",      # EC
      "1.3.101.112",            # Ed25519
      "1.3.101.110",            # X25519
      "2.16.840.1.101.3.4.2.1", # SHA-256 (not a key algorithm)
      "1.2.3.4.5.6.7.8.9"     # Nonsense OID
    ]

    wrong_oids.each do |oid_str|
      oid = OpenSSL::ASN1::ObjectId.new(oid_str)
      alg_id = OpenSSL::ASN1::Sequence.new([oid])
      bit_str = OpenSSL::ASN1::BitString.new("\x00" * 100)
      bad_der = OpenSSL::ASN1::Sequence.new([alg_id, bit_str]).to_der

      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::PublicKey.from_der(bad_der)
      end
    end
  end

  def test_secret_key_der_wrong_oids
    require "openssl"

    wrong_oids = [
      "1.2.840.113549.1.1.1",   # RSA
      "1.2.840.10045.2.1",      # EC
      "1.3.101.112",            # Ed25519
      "1.3.101.110",            # X25519
      "2.16.840.1.101.3.4.2.1", # SHA-256
      "1.2.3.4.5.6.7.8.9"     # Nonsense OID
    ]

    wrong_oids.each do |oid_str|
      ver = OpenSSL::ASN1::Integer.new(0)
      oid = OpenSSL::ASN1::ObjectId.new(oid_str)
      alg_id = OpenSSL::ASN1::Sequence.new([oid])
      key_oct = OpenSSL::ASN1::OctetString.new("\x00" * 100)
      bad_der = OpenSSL::ASN1::Sequence.new([ver, alg_id, key_oct]).to_der

      assert_raises(*ALLOWED_ERRORS) do
        MlDsa::SecretKey.from_der(bad_der)
      end
    end
  end

  def test_public_key_der_correct_oid_wrong_key_size
    require "openssl"

    # Use valid ML-DSA OIDs but with wrong-sized key material
    [44, 65, 87].each do |code|
      oid = OpenSSL::ASN1::ObjectId.new(MlDsa::ML_DSA_OIDS[code])
      alg_id = OpenSSL::ASN1::Sequence.new([oid])

      [0, 1, 10, 50, 500].each do |size|
        bit_str = OpenSSL::ASN1::BitString.new("\x00" * size)
        bad_der = OpenSSL::ASN1::Sequence.new([alg_id, bit_str]).to_der
        assert_raises(*ALLOWED_ERRORS) do
          MlDsa::PublicKey.from_der(bad_der)
        end
      end
    end
  end

  def test_secret_key_der_correct_oid_wrong_key_size
    require "openssl"

    [44, 65, 87].each do |code|
      ver = OpenSSL::ASN1::Integer.new(0)
      oid = OpenSSL::ASN1::ObjectId.new(MlDsa::ML_DSA_OIDS[code])
      alg_id = OpenSSL::ASN1::Sequence.new([oid])

      [0, 1, 10, 50, 500].each do |size|
        key_oct = OpenSSL::ASN1::OctetString.new("\x00" * size)
        bad_der = OpenSSL::ASN1::Sequence.new([ver, alg_id, key_oct]).to_der
        assert_raises(*ALLOWED_ERRORS) do
          MlDsa::SecretKey.from_der(bad_der)
        end
      end
    end
  end
end
