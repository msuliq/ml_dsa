# frozen_string_literal: true

# Usage: ruby benchmark/bench.rb
#
# Measures keygen, sign, and verify throughput for each ML-DSA parameter set.
# Requires the benchmark-ips gem: gem install benchmark-ips

require "bundler/setup"
require "ml_dsa"
require "benchmark/ips"

PARAM_SETS = [MlDsa::ML_DSA_44, MlDsa::ML_DSA_65, MlDsa::ML_DSA_87].freeze
MESSAGE = "The quick brown fox jumps over the lazy dog" * 10

# Pre-generate keys and signatures for each parameter set
keys = {}
signatures = {}
PARAM_SETS.each do |ps|
  pk, sk = MlDsa.keygen(ps)
  keys[ps.code] = [pk, sk]
  signatures[ps.code] = sk.sign(MESSAGE)
end

puts "ML-DSA Benchmark (message: #{MESSAGE.bytesize} bytes)"
puts "=" * 60

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  PARAM_SETS.each do |ps|
    x.report("keygen  #{ps.name}") { MlDsa.keygen(ps) }
  end

  PARAM_SETS.each do |ps|
    _, sk = keys[ps.code]
    x.report("sign    #{ps.name}") { sk.sign(MESSAGE) }
  end

  PARAM_SETS.each do |ps|
    pk, _ = keys[ps.code]
    sig = signatures[ps.code]
    x.report("verify  #{ps.name}") { pk.verify(MESSAGE, sig) }
  end

  x.compare!
end

# Batch benchmark — measure GVL-drop amortization
puts "\n"
puts "Batch Sign/Verify (10 operations per call)"
puts "=" * 60

Benchmark.ips do |x|
  x.config(warmup: 1, time: 3)

  PARAM_SETS.each do |ps|
    pk, sk = keys[ps.code]
    sig = signatures[ps.code]

    sign_ops = 10.times.map do
      MlDsa::SignRequest.new(sk: sk, message: MESSAGE, deterministic: false)
    end

    verify_ops = 10.times.map do
      MlDsa::VerifyRequest.new(pk: pk, message: MESSAGE, signature: sig)
    end

    x.report("sign_many(10)   #{ps.name}") { MlDsa.sign_many(sign_ops) }
    x.report("verify_many(10) #{ps.name}") { MlDsa.verify_many(verify_ops) }
  end

  x.compare!
end
