# frozen_string_literal: true

require "test_helper"

class MlDsaPqcNamespaceTest < Minitest::Test
  def test_pqc_mldsa_alias
    assert_same ::MlDsa, PQC::MlDsa
  end

  def test_pqc_algorithms_registry
    algos = PQC.algorithms
    assert_kind_of Hash, algos
    assert_same ::MlDsa, algos[:ml_dsa]
  end

  def test_pqc_algorithm_lookup
    assert_same ::MlDsa, PQC.algorithm(:ml_dsa)
    assert_nil PQC.algorithm(:unknown)
  end

  def test_pqc_register_new_algorithm
    mod = Module.new
    PQC.register(:test_algo, mod)
    assert_same mod, PQC.algorithm(:test_algo)
  end

  def test_pqc_keygen_through_namespace
    pk, sk = PQC::MlDsa.keygen(PQC::MlDsa::ML_DSA_44)
    sig = sk.sign("pqc namespace test")
    assert pk.verify("pqc namespace test", sig)
  end
end
