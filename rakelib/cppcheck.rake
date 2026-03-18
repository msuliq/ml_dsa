# frozen_string_literal: true

# Project-owned C source and header files.
# Excludes vendored PQClean sources (ml-dsa-NN/), auto-generated
# impl amalgamation files (ml_dsa_NN_impl.c), and vendored fips202
# (upstream Keccak code with intentional variable scoping style).
CPPCHECK_SOURCES = FileList[
  "ext/ml_dsa/ml_dsa_ext.c",
  "ext/ml_dsa/ml_dsa_internal.h",
  "ext/ml_dsa/randombytes.c",
  "ext/ml_dsa/randombytes.h"
]

namespace :lint do
  desc "Run cppcheck on project-owned C extension files"
  task :c do
    exe = ENV.fetch("CPPCHECK", "cppcheck")

    unless system(exe, "--version", out: File::NULL, err: File::NULL)
      abort "cppcheck not found. Install it (brew install cppcheck / apt install cppcheck) or set CPPCHECK env var."
    end

    args = [
      exe,
      "--enable=warning,style,performance,portability",
      "--error-exitcode=1",
      "--suppress=missingIncludeSystem",
      "--suppress=unusedFunction",
      "--inline-suppr",
      "--quiet",
      "--std=c11",
      "-I", "ext/ml_dsa",
      *CPPCHECK_SOURCES
    ]

    puts "Running: #{args.join(" ")}"
    system(*args) || abort("cppcheck reported findings — see above.")
    puts "cppcheck: clean"
  end
end
