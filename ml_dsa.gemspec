# frozen_string_literal: true

require_relative "lib/ml_dsa/version"

Gem::Specification.new do |s|
  s.name = "ml_dsa"
  s.version = MlDsa::VERSION
  s.authors = ["Suleyman Musayev"]
  s.email = ["slmusayev@gmail.com"]

  s.summary = "ML-DSA (FIPS 204): post-quantum digital signature algorithm."
  s.description = "Ruby C extension wrapping the ML-DSA post-quantum digital signature " \
    "algorithm (NIST FIPS 204, formerly CRYSTALS-Dilithium). Bundles the " \
    "PQClean clean C implementation for all three parameter sets: " \
    "ML-DSA-44 (NIST Level 2), ML-DSA-65 (Level 3), and ML-DSA-87 (Level 5). " \
    "Supports both hedged (randomized) and deterministic signing modes."
  s.homepage = "https://github.com/msuliq/ml_dsa"
  s.licenses = ["MIT", "Apache-2.0"]
  s.metadata = {
    "rubygems_mfa_required" => "true",
    "homepage_uri" => s.homepage,
    "source_code_uri" => s.homepage,
    "changelog_uri" => "#{s.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{s.homepage}/issues"
  }

  s.required_ruby_version = ">= 2.7.2"

  s.files = Dir[
    "lib/**/*.rb",
    "ext/**/*.{c,h,rb}",
    "sig/**/*.rbs",
    "patches/**/*",
    "test/fixtures/kat_vectors.yaml",
    "CHANGELOG.md",
    "LICENSE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "README.md"
  ]
  s.require_paths = ["lib"]
  s.extensions = ["ext/ml_dsa/extconf.rb"]

  s.add_dependency "pqc_asn1"

  s.add_development_dependency "minitest", "~> 5.0"
  s.add_development_dependency "rake", "~> 13.0"
  s.add_development_dependency "rake-compiler", "~> 1.0"
end
