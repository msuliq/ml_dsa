# frozen_string_literal: true

require "mkmf"

# Allow selecting which parameter sets to compile at build time.
# Defaults to all three. To compile only a subset:
#   gem install ml_dsa -- --with-ml-dsa-params=65
#   bundle config build.ml_dsa --with-ml-dsa-params=44,65
params_config = with_config("ml-dsa-params", "44,65,87").to_s
enabled = params_config
  .split(",")
  .filter_map { |s| Integer(s.strip) rescue nil } # standard:disable Style/RescueModifier
  .select { |n| [44, 65, 87].include?(n) }
  .uniq

if enabled.empty?
  abort "No valid ML-DSA parameter sets. " \
        "Use --with-ml-dsa-params=44,65,87 (any non-empty subset)."
end

# Pass compile-time flags for each enabled parameter set
enabled.each { |ps| $CFLAGS << " -DML_DSA_ENABLE_#{ps}" }

# Compile only the impl files for enabled parameter sets;
# fips202.c and randombytes.c are always needed.
$srcs = %w[ml_dsa_ext.c fips202.c randombytes.c]
enabled.each { |ps| $srcs << "ml_dsa_#{ps}_impl.c" }

# -std=c11 for C11 features; -I$(srcdir) is added automatically by mkmf,
# making fips202.h and randombytes.h visible to amalgamation impl files.
# -fvisibility=hidden prevents PQClean helper symbols (shake256, poly_ntt,
# etc.) from leaking into the process symbol table and conflicting with
# other gems that bundle different versions of the same libraries.
$CFLAGS << " -O2 -Wall -Wextra -Wshadow -std=c11"
$CFLAGS << " -fvisibility=hidden" if try_cflags("-fvisibility=hidden")

# Probe for platform-appropriate secure zeroing
have_func("explicit_bzero", ["string.h"])
have_func("memset_s", ["string.h"])

# Probe for mlock (prevent secret key pages from being swapped to disk)
have_func("mlock", ["sys/mman.h"])

# Probe for Ractor safety API (Ruby 3.0+)
have_func("rb_ext_ractor_safe", ["ruby.h"])

create_makefile("ml_dsa/ml_dsa_ext")
