#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates test/fixtures/kat_vectors.yaml from the compiled ML-DSA extension.
#
# Run once after building the extension:
#   bundle exec ruby test/fixtures/generate_kat_vectors.rb
#
# Commit the resulting kat_vectors.yaml.  Regenerate if the C implementation
# or PQClean sources are intentionally updated.

require "yaml"
$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)
require "ml_dsa"

output_path = File.expand_path("kat_vectors.yaml", __dir__)

fixtures = {}
[MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].each do |ps|
  pk, sk = MlDsa.keygen(ps)
  msg = "NIST-KAT-#{ps.name}"
  sig = sk.sign(msg, deterministic: true)

  sk_hex = sk.with_bytes { |b| b.unpack1("H*") }
  fixtures[ps.name] = {
    "msg" => msg,
    "pk_hex" => pk.to_hex,
    "sk_hex" => sk_hex,
    "sig_hex" => sig.unpack1("H*")
  }
  puts "Generated vector for #{ps.name}"
end

File.write(output_path, YAML.dump(fixtures))
puts "Written to #{output_path}"
