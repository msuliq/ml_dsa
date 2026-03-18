# frozen_string_literal: true

require "test_helper"

# ACVP (Automated Cryptographic Validation Protocol) test vectors.
#
# These tests are skipped unless NIST FIPS 204 ACVP vectors are placed at:
#   test/fixtures/acvp_vectors.yaml
#
# The vectors should contain sigGen / sigVer / keyGen test groups conforming
# to the ACVP ML-DSA specification.
#
# ============================================================================
# HOW TO OBTAIN OFFICIAL NIST ACVP VECTORS
# ============================================================================
#
# Official NIST ACVP test vectors for ML-DSA (FIPS 204) are available at:
#
#   https://github.com/usnistgov/ACVP-Server
#
# Look under gen-val/json-files/ for these directories:
#   - ML-DSA-keyGen-FIPS204/
#   - ML-DSA-sigGen-FIPS204/
#   - ML-DSA-sigVer-FIPS204/
#
# Each contains prompt.json (inputs) and expectedResults.json (outputs).
# Convert to the YAML format below and save as test/fixtures/acvp_vectors.yaml.
#
# BOOTSTRAP VECTORS (for regression testing until NIST vectors are available):
#   bundle exec ruby test/fixtures/generate_acvp_vectors.rb
#
# This generates vectors from the gem itself -- useful for regression but
# NOT a substitute for official NIST conformance testing.
# ============================================================================
#
# Expected YAML structure:
#   - parameter_set: 44 | 65 | 87
#     type: keyGen | sigGen | sigVer
#     tests:
#       - sk_hex: "..."      (keyGen / sigGen)
#         pk_hex: "..."      (all)
#         msg_hex: "..."     (sigGen / sigVer)
#         sig_hex: "..."     (sigGen / sigVer)
#         expected: true     (sigVer only)

ACVP_FIXTURE = File.join(__dir__, "..", "fixtures", "acvp_vectors.yaml")

class MlDsaAcvpTest < Minitest::Test
  def self.load_vectors
    return [] unless File.exist?(ACVP_FIXTURE)
    require "yaml"
    YAML.safe_load_file(ACVP_FIXTURE, permitted_classes: [Symbol])
  rescue => e
    warn "ACVP fixture load failed: #{e.message}"
    []
  end

  VECTORS = load_vectors

  if VECTORS.empty?
    define_method(:test_acvp_vectors_not_present) do
      skip "ACVP vectors not found at #{ACVP_FIXTURE}; " \
           "place NIST FIPS 204 ACVP vectors there to enable conformance tests"
    end
  else
    VECTORS.each_with_index do |group, gi|
      ps_code = group["parameter_set"]
      type = group["type"]

      group["tests"].each_with_index do |tc, ti|
        define_method("test_acvp_#{type}_ps#{ps_code}_g#{gi}_t#{ti}") do
          ps = MlDsa.const_get("ML_DSA_#{ps_code}")

          case type
          when "keyGen"
            pk = MlDsa::PublicKey.from_hex(tc["pk_hex"], ps)
            sk = MlDsa::SecretKey.from_hex(tc["sk_hex"], ps)
            assert_equal tc["pk_hex"], pk.to_hex
            sk.with_bytes { |b| assert_equal tc["sk_hex"], b.unpack1("H*") }
          when "sigGen"
            sk = MlDsa::SecretKey.from_hex(tc["sk_hex"], ps)
            msg = [tc["msg_hex"]].pack("H*")
            sig = sk.sign(msg, deterministic: true)
            assert_equal tc["sig_hex"], sig.unpack1("H*")
          when "sigVer"
            pk = MlDsa::PublicKey.from_hex(tc["pk_hex"], ps)
            msg = [tc["msg_hex"]].pack("H*")
            sig = [tc["sig_hex"]].pack("H*")
            assert_equal tc["expected"], pk.verify(msg, sig)
          else
            flunk "Unknown ACVP test type: #{type}"
          end
        end
      end
    end
  end
end
