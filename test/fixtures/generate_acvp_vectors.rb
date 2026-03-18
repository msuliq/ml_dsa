#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates test/fixtures/acvp_vectors.yaml from the compiled ML-DSA extension.
#
# This produces BOOTSTRAP vectors derived from the gem's own implementation,
# useful for regression testing but NOT a substitute for official NIST vectors.
#
# Run once after building the extension:
#   bundle exec ruby test/fixtures/generate_acvp_vectors.rb
#
# ============================================================================
# HOW TO OBTAIN OFFICIAL NIST ACVP VECTORS
# ============================================================================
#
# Official NIST ACVP test vectors for ML-DSA (FIPS 204) are published at:
#
#   https://github.com/usnistgov/ACVP-Server
#
# Look under:
#   gen-val/json-files/ML-DSA-keyGen-FIPS204/
#   gen-val/json-files/ML-DSA-sigGen-FIPS204/
#   gen-val/json-files/ML-DSA-sigVer-FIPS204/
#
# Each directory contains:
#   - prompt.json      (inputs: seeds, messages, keys)
#   - expectedResults.json  (expected outputs)
#   - internalProjection.json (internal state, optional)
#
# To convert NIST JSON vectors to the YAML format expected by acvp_test.rb:
#
#   1. Download the prompt.json and expectedResults.json for each operation
#      (keyGen, sigGen, sigVer) and each parameter set (ML-DSA-44, -65, -87).
#
#   2. The JSON structure follows the ACVP spec:
#      - keyGen prompt has testGroups[].tests[] with fields like {seed}
#        and expectedResults has {pk, sk}
#      - sigGen prompt has testGroups[].tests[] with {sk (or seed), message}
#        and expectedResults has {signature}
#      - sigVer prompt has testGroups[].tests[] with {pk, message, signature}
#        and expectedResults has {testPassed: true/false}
#
#   3. Map to the YAML structure:
#      - parameter_set: 44 | 65 | 87
#        type: keyGen | sigGen | sigVer
#        tests:
#          - sk_hex: "..."      (keyGen / sigGen)
#            pk_hex: "..."      (keyGen / sigVer)
#            msg_hex: "..."     (sigGen / sigVer)
#            sig_hex: "..."     (sigGen / sigVer)
#            expected: true     (sigVer only)
#
# Once you have the official vectors in acvp_vectors.yaml, the tests in
# acvp_test.rb will activate automatically. Until then, this script generates
# bootstrap vectors for regression testing.
# ============================================================================

require "yaml"
require "securerandom"

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
require "ml_dsa"

output_path = File.expand_path("acvp_vectors.yaml", __dir__)

vectors = []

[
  [MlDsa::ML_DSA_44, 44],
  [MlDsa::ML_DSA_65, 65],
  [MlDsa::ML_DSA_87, 87]
].each do |ps, code|
  # ---------------------------------------------------------------------------
  # keyGen vectors
  # ---------------------------------------------------------------------------
  keygen_tests = []
  3.times do
    pk, sk = MlDsa.keygen(ps)
    sk_hex = sk.with_bytes { |b| b.unpack1("H*") }
    keygen_tests << {
      "pk_hex" => pk.to_hex,
      "sk_hex" => sk_hex
    }
  end
  vectors << {
    "parameter_set" => code,
    "type" => "keyGen",
    "tests" => keygen_tests
  }

  # ---------------------------------------------------------------------------
  # sigGen vectors (deterministic signing for reproducibility)
  # ---------------------------------------------------------------------------
  siggen_tests = []
  messages = [
    "",                                          # empty message
    "ACVP-bootstrap-#{ps.name}",                 # ASCII message
    SecureRandom.random_bytes(128).unpack1("H*")  # random hex as msg content
  ]

  pk, sk = MlDsa.keygen(ps)
  sk_hex = sk.with_bytes { |b| b.unpack1("H*") }

  messages.each do |msg_str|
    msg_bytes = msg_str.b
    sig = sk.sign(msg_bytes, deterministic: true)
    siggen_tests << {
      "sk_hex" => sk_hex,
      "msg_hex" => msg_bytes.unpack1("H*"),
      "sig_hex" => sig.unpack1("H*")
    }
  end
  vectors << {
    "parameter_set" => code,
    "type" => "sigGen",
    "tests" => siggen_tests
  }

  # ---------------------------------------------------------------------------
  # sigVer vectors (mix of valid and invalid signatures)
  # ---------------------------------------------------------------------------
  sigver_tests = []

  # Valid signature
  msg = "ACVP-sigVer-valid-#{ps.name}".b
  sig = sk.sign(msg, deterministic: true)
  sigver_tests << {
    "pk_hex" => pk.to_hex,
    "msg_hex" => msg.unpack1("H*"),
    "sig_hex" => sig.unpack1("H*"),
    "expected" => true
  }

  # Invalid: corrupted signature (flip first byte)
  bad_sig = sig.dup
  bad_sig.setbyte(0, bad_sig.getbyte(0) ^ 0xFF)
  sigver_tests << {
    "pk_hex" => pk.to_hex,
    "msg_hex" => msg.unpack1("H*"),
    "sig_hex" => bad_sig.unpack1("H*"),
    "expected" => false
  }

  # Invalid: wrong message
  wrong_msg = "ACVP-sigVer-wrong-#{ps.name}".b
  sigver_tests << {
    "pk_hex" => pk.to_hex,
    "msg_hex" => wrong_msg.unpack1("H*"),
    "sig_hex" => sig.unpack1("H*"),
    "expected" => false
  }

  # Invalid: wrong key
  pk2, _sk2 = MlDsa.keygen(ps)
  sigver_tests << {
    "pk_hex" => pk2.to_hex,
    "msg_hex" => msg.unpack1("H*"),
    "sig_hex" => sig.unpack1("H*"),
    "expected" => false
  }

  vectors << {
    "parameter_set" => code,
    "type" => "sigVer",
    "tests" => sigver_tests
  }

  puts "Generated bootstrap vectors for #{ps.name}"
end

File.write(output_path, YAML.dump(vectors))
puts "Written to #{output_path}"
puts ""
puts "NOTE: These are bootstrap vectors generated by the gem itself."
puts "      Replace with official NIST ACVP vectors when available."
puts "      See comments at the top of this script for instructions."
