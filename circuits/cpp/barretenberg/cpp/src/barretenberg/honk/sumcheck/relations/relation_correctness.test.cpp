#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <unordered_set>

#include "barretenberg/common/thread.hpp"
#include "barretenberg/honk/composer/standard_composer.hpp"
#include "barretenberg/honk/composer/ultra_composer.hpp"
#include "barretenberg/honk/flavor/goblin_translator.hpp"
#include "barretenberg/honk/proof_system/grand_product_library.hpp"
#include "barretenberg/honk/proof_system/prover_library.hpp"
#include "barretenberg/honk/sumcheck/relations/arithmetic_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/auxiliary_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/ecc_op_queue_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/elliptic_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/gen_perm_sort_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/goblin_translator_extra_relations.hpp"
#include "barretenberg/honk/sumcheck/relations/goblin_translator_gen_perm_sort_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/goblin_translator_main_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/lookup_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/permutation_relation.hpp"
#include "barretenberg/honk/sumcheck/relations/relation_parameters.hpp"
#include "barretenberg/honk/sumcheck/relations/ultra_arithmetic_relation.hpp"
#include "barretenberg/numeric/random/engine.hpp"
#include "barretenberg/numeric/uint128/uint128.hpp"
#include "barretenberg/numeric/uint256/uint256.hpp"
#include "barretenberg/plonk/proof_system/types/polynomial_manifest.hpp"
#include "barretenberg/polynomials/polynomial.hpp"
#include "barretenberg/proof_system/circuit_builder/goblin_translator_circuit_builder.hpp"
#include "barretenberg/proof_system/composer/permutation_lib.hpp"
#include "barretenberg/proof_system/op_queue/ecc_op_queue.hpp"

using namespace proof_system::honk;

namespace test_honk_relations {

void ensure_non_zero(auto& polynomial)
{
    bool has_non_zero_coefficient = false;
    for (auto& coeff : polynomial) {
        has_non_zero_coefficient |= !coeff.is_zero();
    }
    ASSERT_TRUE(has_non_zero_coefficient);
}

/**
 * @brief Check that a given relation is satified for a set of polynomials
 *
 * @tparam relation_idx Index into a tuple of provided relations
 * @tparam Flavor
 */
template <typename Flavor> void check_relation(auto relation, auto circuit_size, auto polynomials, auto params)
{
    using ClaimedEvaluations = typename Flavor::ClaimedEvaluations;
    for (size_t i = 0; i < circuit_size; i++) {
        // Extract an array containing all the polynomial evaluations at a given row i
        ClaimedEvaluations evaluations_at_index_i;
        size_t poly_idx = 0;
        for (auto& poly : polynomials) {
            evaluations_at_index_i[poly_idx] = poly[i];
            ++poly_idx;
        }

        // Define the appropriate RelationValues type for this relation and initialize to zero
        using RelationValues = typename decltype(relation)::RelationValues;
        RelationValues result;
        for (auto& element : result) {
            element = 0;
        }
        // Evaluate each constraint in the relation and check that each is satisfied
        relation.add_full_relation_value_contribution(result, evaluations_at_index_i, params);
        for (auto& element : result) {
            ASSERT_EQ(element, 0);
        }
    }
}

template <typename Flavor> void create_some_add_gates(auto& circuit_builder)
{
    fr a = fr::random_element();

    // Add some basic add gates; incorporate a public input for non-trivial PI-delta
    uint32_t a_idx = circuit_builder.add_public_variable(a);
    fr b = fr::random_element();
    fr c = a + b;
    fr d = a + c;
    uint32_t b_idx = circuit_builder.add_variable(b);
    uint32_t c_idx = circuit_builder.add_variable(c);
    uint32_t d_idx = circuit_builder.add_variable(d);
    for (size_t i = 0; i < 16; i++) {
        circuit_builder.create_add_gate({ a_idx, b_idx, c_idx, 1, 1, -1, 0 });
        circuit_builder.create_add_gate({ d_idx, c_idx, a_idx, 1, -1, -1, 0 });
    }

    // If Ultra arithmetization, add a big add gate with use of next row to test q_arith = 2
    if constexpr (IsUltraFlavor<Flavor>) {
        fr e = a + b + c + d;
        uint32_t e_idx = circuit_builder.add_variable(e);

        uint32_t zero_idx = circuit_builder.zero_idx;
        circuit_builder.create_big_add_gate({ a_idx, b_idx, c_idx, d_idx, -1, -1, -1, -1, 0 }, true); // use next row
        circuit_builder.create_big_add_gate({ zero_idx, zero_idx, zero_idx, e_idx, 0, 0, 0, 0, 0 }, false);
    }
}

template <typename Flavor> void create_some_lookup_gates(auto& circuit_builder)
{
    // Add some lookup gates (related to pedersen hashing)
    barretenberg::fr pedersen_input_value = fr::random_element();
    const fr input_hi = uint256_t(pedersen_input_value).slice(126, 256);
    const fr input_lo = uint256_t(pedersen_input_value).slice(0, 126);
    const auto input_hi_index = circuit_builder.add_variable(input_hi);
    const auto input_lo_index = circuit_builder.add_variable(input_lo);

    const auto sequence_data_hi = plookup::get_lookup_accumulators(plookup::MultiTableId::PEDERSEN_LEFT_HI, input_hi);
    const auto sequence_data_lo = plookup::get_lookup_accumulators(plookup::MultiTableId::PEDERSEN_LEFT_LO, input_lo);

    circuit_builder.create_gates_from_plookup_accumulators(
        plookup::MultiTableId::PEDERSEN_LEFT_HI, sequence_data_hi, input_hi_index);
    circuit_builder.create_gates_from_plookup_accumulators(
        plookup::MultiTableId::PEDERSEN_LEFT_LO, sequence_data_lo, input_lo_index);
}

template <typename Flavor> void create_some_genperm_sort_gates(auto& circuit_builder)
{
    // Add a sort gate (simply checks that consecutive inputs have a difference of < 4)
    using FF = typename Flavor::FF;
    auto a_idx = circuit_builder.add_variable(FF(0));
    auto b_idx = circuit_builder.add_variable(FF(1));
    auto c_idx = circuit_builder.add_variable(FF(2));
    auto d_idx = circuit_builder.add_variable(FF(3));
    circuit_builder.create_sort_constraint({ a_idx, b_idx, c_idx, d_idx });
}

template <typename Flavor> void create_some_RAM_gates(auto& circuit_builder)
{
    // Add some RAM gates
    uint32_t ram_values[8]{
        circuit_builder.add_variable(fr::random_element()), circuit_builder.add_variable(fr::random_element()),
        circuit_builder.add_variable(fr::random_element()), circuit_builder.add_variable(fr::random_element()),
        circuit_builder.add_variable(fr::random_element()), circuit_builder.add_variable(fr::random_element()),
        circuit_builder.add_variable(fr::random_element()), circuit_builder.add_variable(fr::random_element()),
    };

    size_t ram_id = circuit_builder.create_RAM_array(8);

    for (size_t i = 0; i < 8; ++i) {
        circuit_builder.init_RAM_element(ram_id, i, ram_values[i]);
    }

    auto a_idx = circuit_builder.read_RAM_array(ram_id, circuit_builder.add_variable(5));
    EXPECT_EQ(a_idx != ram_values[5], true);

    auto b_idx = circuit_builder.read_RAM_array(ram_id, circuit_builder.add_variable(4));
    auto c_idx = circuit_builder.read_RAM_array(ram_id, circuit_builder.add_variable(1));

    circuit_builder.write_RAM_array(ram_id, circuit_builder.add_variable(4), circuit_builder.add_variable(500));
    auto d_idx = circuit_builder.read_RAM_array(ram_id, circuit_builder.add_variable(4));

    EXPECT_EQ(circuit_builder.get_variable(d_idx), 500);

    // ensure these vars get used in another arithmetic gate
    const auto e_value = circuit_builder.get_variable(a_idx) + circuit_builder.get_variable(b_idx) +
                         circuit_builder.get_variable(c_idx) + circuit_builder.get_variable(d_idx);
    auto e_idx = circuit_builder.add_variable(e_value);

    circuit_builder.create_big_add_gate({ a_idx, b_idx, c_idx, d_idx, -1, -1, -1, -1, 0 }, true);
    circuit_builder.create_big_add_gate(
        {
            circuit_builder.zero_idx,
            circuit_builder.zero_idx,
            circuit_builder.zero_idx,
            e_idx,
            0,
            0,
            0,
            0,
            0,
        },
        false);
}

template <typename Flavor> void create_some_elliptic_curve_addition_gates(auto& circuit_builder)
{
    // Add an elliptic curve addition gate
    grumpkin::g1::affine_element p1 = crypto::generators::get_generator_data({ 0, 0 }).generator;
    grumpkin::g1::affine_element p2 = crypto::generators::get_generator_data({ 0, 1 }).generator;

    grumpkin::fq beta_scalar = grumpkin::fq::cube_root_of_unity();
    grumpkin::g1::affine_element p2_endo = p2;
    p2_endo.x *= beta_scalar;

    grumpkin::g1::affine_element p3(grumpkin::g1::element(p1) - grumpkin::g1::element(p2_endo));

    uint32_t x1 = circuit_builder.add_variable(p1.x);
    uint32_t y1 = circuit_builder.add_variable(p1.y);
    uint32_t x2 = circuit_builder.add_variable(p2.x);
    uint32_t y2 = circuit_builder.add_variable(p2.y);
    uint32_t x3 = circuit_builder.add_variable(p3.x);
    uint32_t y3 = circuit_builder.add_variable(p3.y);

    circuit_builder.create_ecc_add_gate({ x1, y1, x2, y2, x3, y3, beta_scalar, -1 });
}

template <typename Flavor> void create_some_ecc_op_queue_gates(auto& circuit_builder)
{
    static_assert(IsGoblinFlavor<Flavor>);
    const size_t num_ecc_operations = 10; // arbitrary
    for (size_t i = 0; i < num_ecc_operations; ++i) {
        auto point = g1::affine_one * fr::random_element();
        auto scalar = fr::random_element();
        circuit_builder.queue_ecc_mul_accum(point, scalar);
    }
}

class RelationCorrectnessTests : public ::testing::Test {
  protected:
    static void SetUpTestSuite() { barretenberg::srs::init_crs_factory("../srs_db/ignition"); }
};

/**
 * @brief Test the correctness of the Standard Honk relations
 *
 * @details Check that the constraints encoded by the relations are satisfied by the polynomials produced by the
 * Standard Honk Composer for a real circuit.
 *
 * TODO(Kesha): We'll have to update this function once we add zk, since the relation will be incorrect for he first few
 * indices
 *
 */
TEST_F(RelationCorrectnessTests, StandardRelationCorrectness)
{
    using Flavor = honk::flavor::Standard;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;

    // Create a composer and a dummy circuit with a few gates
    auto circuit_constructor = StandardCircuitBuilder();

    create_some_add_gates<Flavor>(circuit_constructor);

    // Create a prover (it will compute proving key and witness)
    auto composer = StandardComposer();
    auto prover = composer.create_prover(circuit_constructor);
    auto circuit_size = prover.key->circuit_size;

    // Generate beta and gamma
    fr beta = fr::random_element();
    fr gamma = fr::random_element();

    // Compute public input delta
    const auto public_inputs = circuit_constructor.get_public_inputs();
    auto public_input_delta =
        honk::compute_public_input_delta<Flavor>(public_inputs, beta, gamma, prover.key->circuit_size);

    sumcheck::RelationParameters<FF> params{
        .beta = beta,
        .gamma = gamma,
        .public_input_delta = public_input_delta,
    };

    // Create an array of spans to the underlying polynomials to more easily
    // get the transposition.
    // Ex: polynomial_spans[3][i] returns the i-th coefficient of the third polynomial
    // in the list below
    ProverPolynomials prover_polynomials;

    prover_polynomials.w_l = prover.key->w_l;
    prover_polynomials.w_r = prover.key->w_r;
    prover_polynomials.w_o = prover.key->w_o;
    prover_polynomials.q_m = prover.key->q_m;
    prover_polynomials.q_l = prover.key->q_l;
    prover_polynomials.q_r = prover.key->q_r;
    prover_polynomials.q_o = prover.key->q_o;
    prover_polynomials.q_c = prover.key->q_c;
    prover_polynomials.sigma_1 = prover.key->sigma_1;
    prover_polynomials.sigma_2 = prover.key->sigma_2;
    prover_polynomials.sigma_3 = prover.key->sigma_3;
    prover_polynomials.id_1 = prover.key->id_1;
    prover_polynomials.id_2 = prover.key->id_2;
    prover_polynomials.id_3 = prover.key->id_3;
    prover_polynomials.lagrange_first = prover.key->lagrange_first;
    prover_polynomials.lagrange_last = prover.key->lagrange_last;

    // Compute grand product polynomial
    grand_product_library::compute_grand_products<honk::flavor::Standard>(prover.key, prover_polynomials, params);

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::ArithmeticRelation<FF>(), honk::sumcheck::PermutationRelation<FF>());

    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<1>(relations), circuit_size, prover_polynomials, params);
}

/**
 * @brief Test the correctness of the Ultra Honk relations
 *
 * @details Check that the constraints encoded by the relations are satisfied by the polynomials produced by the
 * Ultra Honk Composer for a real circuit.
 *
 * TODO(Kesha): We'll have to update this function once we add zk, since the relation will be incorrect for he first few
 * indices
 *
 */
// TODO(luke): Add a gate that sets q_arith = 3 to check secondary arithmetic relation
TEST_F(RelationCorrectnessTests, UltraRelationCorrectness)
{
    using Flavor = honk::flavor::Ultra;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;

    // Create a composer and then add an assortment of gates designed to ensure that the constraint(s) represented
    // by each relation are non-trivially exercised.
    auto circuit_constructor = UltraCircuitBuilder();

    // Create an assortment of representative gates
    create_some_add_gates<Flavor>(circuit_constructor);
    create_some_lookup_gates<Flavor>(circuit_constructor);
    create_some_genperm_sort_gates<Flavor>(circuit_constructor);
    create_some_elliptic_curve_addition_gates<Flavor>(circuit_constructor);
    create_some_RAM_gates<Flavor>(circuit_constructor);

    // Create a prover (it will compute proving key and witness)
    auto composer = UltraComposer();
    auto prover = composer.create_prover(circuit_constructor);
    auto circuit_size = prover.key->circuit_size;

    // Generate eta, beta and gamma
    fr eta = fr::random_element();
    fr beta = fr::random_element();
    fr gamma = fr::random_element();

    // Compute public input delta
    const auto public_inputs = circuit_constructor.get_public_inputs();
    const size_t pub_inputs_offset = Flavor::has_zero_row ? 1 : 0;
    auto public_input_delta = honk::compute_public_input_delta<Flavor>(
        public_inputs, beta, gamma, prover.key->circuit_size, pub_inputs_offset);
    auto lookup_grand_product_delta =
        honk::compute_lookup_grand_product_delta<FF>(beta, gamma, prover.key->circuit_size);

    sumcheck::RelationParameters<FF> params{
        .eta = eta,
        .beta = beta,
        .gamma = gamma,
        .public_input_delta = public_input_delta,
        .lookup_grand_product_delta = lookup_grand_product_delta,
    };

    // Compute sorted witness-table accumulator
    prover.key->sorted_accum = prover_library::compute_sorted_list_accumulator<Flavor>(prover.key, eta);

    // Add RAM/ROM memory records to wire four
    prover_library::add_plookup_memory_records_to_wire_4<Flavor>(prover.key, eta);

    ProverPolynomials prover_polynomials;

    prover_polynomials.w_l = prover.key->w_l;
    prover_polynomials.w_r = prover.key->w_r;
    prover_polynomials.w_o = prover.key->w_o;
    prover_polynomials.w_4 = prover.key->w_4;
    prover_polynomials.w_l_shift = prover.key->w_l.shifted();
    prover_polynomials.w_r_shift = prover.key->w_r.shifted();
    prover_polynomials.w_o_shift = prover.key->w_o.shifted();
    prover_polynomials.w_4_shift = prover.key->w_4.shifted();
    prover_polynomials.sorted_accum = prover.key->sorted_accum;
    prover_polynomials.sorted_accum_shift = prover.key->sorted_accum.shifted();
    prover_polynomials.table_1 = prover.key->table_1;
    prover_polynomials.table_2 = prover.key->table_2;
    prover_polynomials.table_3 = prover.key->table_3;
    prover_polynomials.table_4 = prover.key->table_4;
    prover_polynomials.table_1_shift = prover.key->table_1.shifted();
    prover_polynomials.table_2_shift = prover.key->table_2.shifted();
    prover_polynomials.table_3_shift = prover.key->table_3.shifted();
    prover_polynomials.table_4_shift = prover.key->table_4.shifted();
    prover_polynomials.q_m = prover.key->q_m;
    prover_polynomials.q_l = prover.key->q_l;
    prover_polynomials.q_r = prover.key->q_r;
    prover_polynomials.q_o = prover.key->q_o;
    prover_polynomials.q_c = prover.key->q_c;
    prover_polynomials.q_4 = prover.key->q_4;
    prover_polynomials.q_arith = prover.key->q_arith;
    prover_polynomials.q_sort = prover.key->q_sort;
    prover_polynomials.q_elliptic = prover.key->q_elliptic;
    prover_polynomials.q_aux = prover.key->q_aux;
    prover_polynomials.q_lookup = prover.key->q_lookup;
    prover_polynomials.sigma_1 = prover.key->sigma_1;
    prover_polynomials.sigma_2 = prover.key->sigma_2;
    prover_polynomials.sigma_3 = prover.key->sigma_3;
    prover_polynomials.sigma_4 = prover.key->sigma_4;
    prover_polynomials.id_1 = prover.key->id_1;
    prover_polynomials.id_2 = prover.key->id_2;
    prover_polynomials.id_3 = prover.key->id_3;
    prover_polynomials.id_4 = prover.key->id_4;
    prover_polynomials.lagrange_first = prover.key->lagrange_first;
    prover_polynomials.lagrange_last = prover.key->lagrange_last;

    // Compute grand product polynomials for permutation + lookup
    grand_product_library::compute_grand_products<Flavor>(prover.key, prover_polynomials, params);

    // Check that selectors are nonzero to ensure corresponding relation has nontrivial contribution
    ensure_non_zero(prover.key->q_arith);
    ensure_non_zero(prover.key->q_sort);
    ensure_non_zero(prover.key->q_lookup);
    ensure_non_zero(prover.key->q_elliptic);
    ensure_non_zero(prover.key->q_aux);

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::UltraArithmeticRelation<FF>(),
                                honk::sumcheck::UltraPermutationRelation<FF>(),
                                honk::sumcheck::LookupRelation<FF>(),
                                honk::sumcheck::GenPermSortRelation<FF>(),
                                honk::sumcheck::EllipticRelation<FF>(),
                                honk::sumcheck::AuxiliaryRelation<FF>());

    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<1>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<2>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<3>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<4>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<5>(relations), circuit_size, prover_polynomials, params);
}

TEST_F(RelationCorrectnessTests, GoblinUltraRelationCorrectness)
{
    using Flavor = honk::flavor::GoblinUltra;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;

    // Create a composer and then add an assortment of gates designed to ensure that the constraint(s) represented
    // by each relation are non-trivially exercised.
    auto builder = UltraCircuitBuilder();

    // Create an assortment of representative gates
    create_some_add_gates<Flavor>(builder);
    create_some_lookup_gates<Flavor>(builder);
    create_some_genperm_sort_gates<Flavor>(builder);
    create_some_elliptic_curve_addition_gates<Flavor>(builder);
    create_some_RAM_gates<Flavor>(builder);
    create_some_ecc_op_queue_gates<Flavor>(builder); // Goblin!

    // Create a prover (it will compute proving key and witness)
    auto composer = GoblinUltraComposer();
    auto prover = composer.create_prover(builder);
    auto circuit_size = prover.key->circuit_size;

    // Generate eta, beta and gamma
    fr eta = fr::random_element();
    fr beta = fr::random_element();
    fr gamma = fr::random_element();

    // Compute public input delta
    const auto public_inputs = builder.get_public_inputs();

    // If Goblin, must account for the fact that PI are offset in the wire polynomials by the number of ecc op gates
    size_t pub_inputs_offset = Flavor::has_zero_row ? 1 : 0;
    if constexpr (IsGoblinFlavor<Flavor>) {
        pub_inputs_offset += builder.num_ecc_op_gates;
    }
    auto public_input_delta = honk::compute_public_input_delta<Flavor>(
        public_inputs, beta, gamma, prover.key->circuit_size, pub_inputs_offset);
    auto lookup_grand_product_delta =
        honk::compute_lookup_grand_product_delta<FF>(beta, gamma, prover.key->circuit_size);

    sumcheck::RelationParameters<FF> params{
        .eta = eta,
        .beta = beta,
        .gamma = gamma,
        .public_input_delta = public_input_delta,
        .lookup_grand_product_delta = lookup_grand_product_delta,
    };

    // Compute sorted witness-table accumulator
    prover.key->sorted_accum = prover_library::compute_sorted_list_accumulator<Flavor>(prover.key, eta);

    // Add RAM/ROM memory records to wire four
    prover_library::add_plookup_memory_records_to_wire_4<Flavor>(prover.key, eta);

    ProverPolynomials prover_polynomials;

    prover_polynomials.lagrange_ecc_op = prover.key->lagrange_ecc_op;
    prover_polynomials.ecc_op_wire_1 = prover.key->ecc_op_wire_1;
    prover_polynomials.ecc_op_wire_2 = prover.key->ecc_op_wire_2;
    prover_polynomials.ecc_op_wire_3 = prover.key->ecc_op_wire_3;
    prover_polynomials.ecc_op_wire_4 = prover.key->ecc_op_wire_4;

    prover_polynomials.w_l = prover.key->w_l;
    prover_polynomials.w_r = prover.key->w_r;
    prover_polynomials.w_o = prover.key->w_o;
    prover_polynomials.w_4 = prover.key->w_4;
    prover_polynomials.w_l_shift = prover.key->w_l.shifted();
    prover_polynomials.w_r_shift = prover.key->w_r.shifted();
    prover_polynomials.w_o_shift = prover.key->w_o.shifted();
    prover_polynomials.w_4_shift = prover.key->w_4.shifted();
    prover_polynomials.sorted_accum = prover.key->sorted_accum;
    prover_polynomials.sorted_accum_shift = prover.key->sorted_accum.shifted();
    prover_polynomials.table_1 = prover.key->table_1;
    prover_polynomials.table_2 = prover.key->table_2;
    prover_polynomials.table_3 = prover.key->table_3;
    prover_polynomials.table_4 = prover.key->table_4;
    prover_polynomials.table_1_shift = prover.key->table_1.shifted();
    prover_polynomials.table_2_shift = prover.key->table_2.shifted();
    prover_polynomials.table_3_shift = prover.key->table_3.shifted();
    prover_polynomials.table_4_shift = prover.key->table_4.shifted();
    prover_polynomials.q_m = prover.key->q_m;
    prover_polynomials.q_l = prover.key->q_l;
    prover_polynomials.q_r = prover.key->q_r;
    prover_polynomials.q_o = prover.key->q_o;
    prover_polynomials.q_c = prover.key->q_c;
    prover_polynomials.q_4 = prover.key->q_4;
    prover_polynomials.q_arith = prover.key->q_arith;
    prover_polynomials.q_sort = prover.key->q_sort;
    prover_polynomials.q_elliptic = prover.key->q_elliptic;
    prover_polynomials.q_aux = prover.key->q_aux;
    prover_polynomials.q_lookup = prover.key->q_lookup;
    prover_polynomials.sigma_1 = prover.key->sigma_1;
    prover_polynomials.sigma_2 = prover.key->sigma_2;
    prover_polynomials.sigma_3 = prover.key->sigma_3;
    prover_polynomials.sigma_4 = prover.key->sigma_4;
    prover_polynomials.id_1 = prover.key->id_1;
    prover_polynomials.id_2 = prover.key->id_2;
    prover_polynomials.id_3 = prover.key->id_3;
    prover_polynomials.id_4 = prover.key->id_4;
    prover_polynomials.lagrange_first = prover.key->lagrange_first;
    prover_polynomials.lagrange_last = prover.key->lagrange_last;

    // Compute grand product polynomials for permutation + lookup
    grand_product_library::compute_grand_products<Flavor>(prover.key, prover_polynomials, params);

    // Check that selectors are nonzero to ensure corresponding relation has nontrivial contribution
    ensure_non_zero(prover.key->q_arith);
    ensure_non_zero(prover.key->q_sort);
    ensure_non_zero(prover.key->q_lookup);
    ensure_non_zero(prover.key->q_elliptic);
    ensure_non_zero(prover.key->q_aux);

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::UltraArithmeticRelation<FF>(),
                                honk::sumcheck::UltraPermutationRelation<FF>(),
                                honk::sumcheck::LookupRelation<FF>(),
                                honk::sumcheck::GenPermSortRelation<FF>(),
                                honk::sumcheck::EllipticRelation<FF>(),
                                honk::sumcheck::AuxiliaryRelation<FF>(),
                                honk::sumcheck::EccOpQueueRelation<FF>());

    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<1>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<2>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<3>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<4>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<5>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<6>(relations), circuit_size, prover_polynomials, params);
}

/**
 * @brief Test the correctness of GolbinTranslator's Permutation Relation
 *
 */
TEST_F(RelationCorrectnessTests, GoblinTranslatorPermutationRelationCorrectness)
{
    using Flavor = honk::flavor::GoblinTranslatorBasic;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;
    auto& engine = numeric::random::get_debug_engine();
    // Create a prover (it will compute proving key and witness)
    auto circuit_size = Flavor::MINI_CIRCUIT_SIZE * Flavor::CONCATENATION_INDEX;

    // We only need gamma
    FF gamma = FF::random_element();

    // Compute public input delta
    sumcheck::RelationParameters<FF> params{
        .eta = 0,
        .beta = 0,
        .gamma = gamma,
        .public_input_delta = 0,
        .lookup_grand_product_delta = 0,
    };

    // Create storage for polynomials
    ProverPolynomials prover_polynomials;
    std::vector<Polynomial<FF>> polynomial_container;
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        Polynomial<FF> temporary_polynomial(circuit_size);
        polynomial_container.push_back(temporary_polynomial);
        prover_polynomials[i] = polynomial_container[i];
    }

    // Fill in lagrange polynomials
    prover_polynomials.lagrange_first[0] = 1;
    prover_polynomials.lagrange_last[circuit_size - 1] = 1;
    // Put random values in all the non-concatenated constraint polynomials used to range constrain the values
    auto fill_polynomial_with_random_14_bit_values = [&](auto& polynomial) {
        for (size_t i = 0; i < Flavor::MINI_CIRCUIT_SIZE; i++) {
            polynomial[i] = engine.get_random_uint16() & ((1 << Flavor::MICRO_LIMB_BITS) - 1);
        }
    };
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_low_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_x_high_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_low_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.p_y_high_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_lo_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.z_hi_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_lo_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.accumulator_hi_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_lo_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_3);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_4);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.quotient_hi_limbs_range_constraint_tail);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.relation_wide_limbs_range_constraint_0);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.relation_wide_limbs_range_constraint_1);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.relation_wide_limbs_range_constraint_2);
    fill_polynomial_with_random_14_bit_values(prover_polynomials.relation_wide_limbs_range_constraint_3);

    // Compute ordered range constraint polynomials that go in the denominator of the grand product polynomial
    compute_goblin_translator_range_constraint_ordered_polynomials<Flavor>(&prover_polynomials);
    // Compute the fixed numerator (part of verification key)

    compute_extra_range_constraint_numerator<Flavor>(&prover_polynomials);

    // Compute concatenated polynomials (4 polynomials produced from other constraint polynomials by concatenation)
    compute_concatenated_polynomials<Flavor>(&prover_polynomials);

    // Compute the grand product polynomial
    grand_product_library::compute_grand_product<Flavor, sumcheck::GoblinTranslatorPermutationRelation<FF>>(
        circuit_size, prover_polynomials, params);
    prover_polynomials.z_perm_shift = polynomial_container[Flavor::ALL_ENTITIES_IDS::Z_PERM].shifted();

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::GoblinTranslatorPermutationRelation<FF>());
    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
}
TEST_F(RelationCorrectnessTests, GoblinTranslatorGenPermSortRelationCorrectness)
{
    using Flavor = honk::flavor::GoblinTranslatorBasic;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;
    auto& engine = numeric::random::get_debug_engine();
    // Create a prover (it will compute proving key and witness)
    const auto circuit_size = Flavor::MINI_CIRCUIT_SIZE * Flavor::CONCATENATION_INDEX;
    const auto sort_step = Flavor::SORT_STEP;
    const auto max_value = (1 << Flavor::MICRO_LIMB_BITS) - 1;
    // Compute public input delta
    sumcheck::RelationParameters<FF> params{
        .eta = 0,
        .beta = 0,
        .gamma = 0,
        .public_input_delta = 0,
        .lookup_grand_product_delta = 0,
    };
    // Compute sorted witness-table accumulator
    ProverPolynomials prover_polynomials;
    std::vector<Polynomial<FF>> polynomial_container;
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        Polynomial<FF> temporary_polynomial(circuit_size);
        polynomial_container.push_back(temporary_polynomial);
        prover_polynomials[i] = polynomial_container[i];
    }
    prover_polynomials.lagrange_first[0] = 1;
    prover_polynomials.lagrange_last[circuit_size - 1] = 1;
    auto sorted_elements_count = (max_value / sort_step) + 1;
    std::vector<uint64_t> vector_for_sorting(circuit_size);
    for (size_t i = 0; i < sorted_elements_count - 1; i++) {
        vector_for_sorting[i] = i * sort_step;
    }
    vector_for_sorting[sorted_elements_count - 1] = max_value;
    for (size_t i = sorted_elements_count; i < circuit_size; i++) {
        vector_for_sorting[i] = engine.get_random_uint16() & ((1 << Flavor::MICRO_LIMB_BITS) - 1);
    }

    auto polynomial_pointers = std::vector{ &prover_polynomials.ordered_range_constraints_0,
                                            &prover_polynomials.ordered_range_constraints_1,
                                            &prover_polynomials.ordered_range_constraints_2,
                                            &prover_polynomials.ordered_range_constraints_3,
                                            &prover_polynomials.ordered_range_constraints_4 };
    std::sort(vector_for_sorting.begin(), vector_for_sorting.end());
    std::transform(vector_for_sorting.cbegin(),
                   vector_for_sorting.cend(),
                   prover_polynomials.ordered_range_constraints_0.begin(),
                   [](uint64_t in) { return FF(in); });
    parallel_for(4, [&](size_t i) {
        std::copy(prover_polynomials.ordered_range_constraints_0.begin(),
                  prover_polynomials.ordered_range_constraints_0.end(),
                  polynomial_pointers[i + 1]->begin());
    });
    prover_polynomials.ordered_range_constraints_0_shift =
        polynomial_container[Flavor::ORDERED_RANGE_CONSTRAINTS_0].shifted();
    prover_polynomials.ordered_range_constraints_1_shift =
        polynomial_container[Flavor::ORDERED_RANGE_CONSTRAINTS_1].shifted();
    prover_polynomials.ordered_range_constraints_2_shift =
        polynomial_container[Flavor::ORDERED_RANGE_CONSTRAINTS_2].shifted();
    prover_polynomials.ordered_range_constraints_3_shift =
        polynomial_container[Flavor::ORDERED_RANGE_CONSTRAINTS_3].shifted();
    prover_polynomials.ordered_range_constraints_4_shift =
        polynomial_container[Flavor::ORDERED_RANGE_CONSTRAINTS_4].shifted();
    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::GoblinTranslatorGenPermSortRelation<FF>());
    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
}

/**
 * @brief Test the correctness of GolbinTranslator's Decomposition Relation
 *
 */
TEST_F(RelationCorrectnessTests, GoblinTranslatorDecompositionRelationCorrectness)
{
    using Flavor = honk::flavor::GoblinTranslatorBasic;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;
    using ProverPolynomialIds = typename Flavor::ProverPolynomialIds;
    auto& engine = numeric::random::get_debug_engine();
    // Create a prover (it will compute proving key and witness)
    auto circuit_size = Flavor::FULL_CIRCUIT_SIZE;

    // Decomposition relation doesn'tu se any relation parameters
    // Compute public input delta
    sumcheck::RelationParameters<FF> params{
        .eta = 0,
        .beta = 0,
        .gamma = 0,
        .public_input_delta = 0,
        .lookup_grand_product_delta = 0,
    };

    // Create storage for polynomials
    ProverPolynomials prover_polynomials;
    ProverPolynomialIds prover_polynomial_ids;
    std::vector<Polynomial<FF>> polynomial_container;
    std::vector<size_t> polynomial_ids;
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        Polynomial<FF> temporary_polynomial(circuit_size);
        polynomial_container.push_back(temporary_polynomial);
        polynomial_ids.push_back(i);
        prover_polynomial_ids[i] = polynomial_ids[i];
    }
    auto shifted_ids = prover_polynomial_ids.get_shifted();
    std::unordered_set<size_t> shifted_id_set;
    for (auto& id : shifted_ids) {
        shifted_id_set.emplace(id);
    }
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        if (!shifted_id_set.contains(i)) {
            prover_polynomials[i] = polynomial_container[i];
        }
    }
    for (size_t i = 0; i < shifted_ids.size(); i++) {
        auto shifted_id = shifted_ids[i];
        auto to_be_shifted_id = prover_polynomial_ids.get_to_be_shifted()[i];
        prover_polynomials[shifted_id] = polynomial_container[to_be_shifted_id].shifted();
    }

    // Fill in lagrange odd polynomial (the only non-witness one we are using)
    for (size_t i = 1; i < Flavor::MINI_CIRCUIT_SIZE - 1; i += 2) {
        prover_polynomials.lagrange_odd[i] = 1;
    }
    const size_t HIGH_WIDE_LIMB_WIDTH = 68 + 50;
    const size_t LOW_WIDE_LIMB_WIDTH = 68 * 2;
    const size_t MICRO_LIMB_WIDTH = 14;
    const size_t SHIFT_12_TO_14 = 4;
    const size_t SHIFT_10_TO_14 = 16;
    const size_t SHIFT_8_TO_14 = 64;
    const size_t SHIFT_4_TO_14 = 1024;
    auto decompose_standard_limb =
        [](auto& input, auto& limb_0, auto& limb_1, auto& limb_2, auto& limb_3, auto& limb_4, auto& shifted_limb) {
            limb_0 = uint256_t(input).slice(0, MICRO_LIMB_WIDTH);
            limb_1 = uint256_t(input).slice(MICRO_LIMB_WIDTH, MICRO_LIMB_WIDTH * 2);
            limb_2 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 2, MICRO_LIMB_WIDTH * 3);
            limb_3 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 3, MICRO_LIMB_WIDTH * 4);
            limb_4 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 4, MICRO_LIMB_WIDTH * 5);
            shifted_limb = limb_4 * SHIFT_12_TO_14;
        };
    auto decompose_standard_top_limb =
        [](auto& input, auto& limb_0, auto& limb_1, auto& limb_2, auto& limb_3, auto& shifted_limb) {
            limb_0 = uint256_t(input).slice(0, MICRO_LIMB_WIDTH);
            limb_1 = uint256_t(input).slice(MICRO_LIMB_WIDTH, MICRO_LIMB_WIDTH * 2);
            limb_2 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 2, MICRO_LIMB_WIDTH * 3);
            limb_3 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 3, MICRO_LIMB_WIDTH * 4);
            shifted_limb = limb_3 * SHIFT_8_TO_14;
        };
    auto decompose_standard_top_z_limb =
        [](auto& input, auto& limb_0, auto& limb_1, auto& limb_2, auto& limb_3, auto& limb_4, auto& shifted_limb) {
            limb_0 = uint256_t(input).slice(0, MICRO_LIMB_WIDTH);
            limb_1 = uint256_t(input).slice(MICRO_LIMB_WIDTH, MICRO_LIMB_WIDTH * 2);
            limb_2 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 2, MICRO_LIMB_WIDTH * 3);
            limb_3 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 3, MICRO_LIMB_WIDTH * 4);
            limb_4 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 4, MICRO_LIMB_WIDTH * 5);
            shifted_limb = limb_4 * SHIFT_4_TO_14;
        };
    auto decompose_top_quotient_limb =
        [](auto& input, auto& limb_0, auto& limb_1, auto& limb_2, auto& limb_3, auto& shifted_limb) {
            limb_0 = uint256_t(input).slice(0, MICRO_LIMB_WIDTH);
            limb_1 = uint256_t(input).slice(MICRO_LIMB_WIDTH, MICRO_LIMB_WIDTH * 2);
            limb_2 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 2, MICRO_LIMB_WIDTH * 3);
            limb_3 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 3, MICRO_LIMB_WIDTH * 4);
            shifted_limb = limb_3 * SHIFT_10_TO_14;
        };
    auto decompose_relation_limb =
        [](auto& input, auto& limb_0, auto& limb_1, auto& limb_2, auto& limb_3, auto& limb_4, auto& limb_5) {
            limb_0 = uint256_t(input).slice(0, MICRO_LIMB_WIDTH);
            limb_1 = uint256_t(input).slice(MICRO_LIMB_WIDTH, MICRO_LIMB_WIDTH * 2);
            limb_2 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 2, MICRO_LIMB_WIDTH * 3);
            limb_3 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 3, MICRO_LIMB_WIDTH * 4);
            limb_4 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 4, MICRO_LIMB_WIDTH * 5);
            limb_5 = uint256_t(input).slice(MICRO_LIMB_WIDTH * 5, MICRO_LIMB_WIDTH * 6);
        };
    // Put random values in all the non-concatenated constraint polynomials used to range constrain the values
    for (size_t i = 1; i < Flavor::MINI_CIRCUIT_SIZE - 1; i += 2) {
        prover_polynomials.x_lo_y_hi[i] = FF(engine.get_random_uint256() & ((uint256_t(1) << LOW_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.x_hi_z_1[i] = FF(engine.get_random_uint256() & ((uint256_t(1) << HIGH_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.y_lo_z_2[i] = FF(engine.get_random_uint256() & ((uint256_t(1) << LOW_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.x_lo_y_hi[i + 1] =
            FF(engine.get_random_uint256() & ((uint256_t(1) << HIGH_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.x_hi_z_1[i + 1] =
            FF(engine.get_random_uint256() & ((uint256_t(1) << LOW_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.y_lo_z_2[i + 1] =
            FF(engine.get_random_uint256() & ((uint256_t(1) << LOW_WIDE_LIMB_WIDTH) - 1));
        prover_polynomials.p_x_low_limbs[i] = uint256_t(prover_polynomials.x_lo_y_hi[i]).slice(0, 68);
        prover_polynomials.p_x_low_limbs[i + 1] = uint256_t(prover_polynomials.x_lo_y_hi[i]).slice(68, 2 * 68);
        prover_polynomials.p_x_high_limbs[i] = uint256_t(prover_polynomials.x_hi_z_1[i]).slice(0, 68);
        prover_polynomials.p_x_high_limbs[i + 1] = uint256_t(prover_polynomials.x_hi_z_1[i]).slice(68, 2 * 68);
        prover_polynomials.p_y_low_limbs[i] = uint256_t(prover_polynomials.y_lo_z_2[i]).slice(0, 68);
        prover_polynomials.p_y_low_limbs[i + 1] = uint256_t(prover_polynomials.y_lo_z_2[i]).slice(68, 2 * 68);
        prover_polynomials.p_y_high_limbs[i] = uint256_t(prover_polynomials.x_lo_y_hi[i + 1]).slice(0, 68);
        prover_polynomials.p_y_high_limbs[i + 1] = uint256_t(prover_polynomials.x_lo_y_hi[i + 1]).slice(68, 2 * 68);
        prover_polynomials.z_lo_limbs[i] = uint256_t(prover_polynomials.x_hi_z_1[i + 1]).slice(0, 68);
        prover_polynomials.z_lo_limbs[i + 1] = uint256_t(prover_polynomials.y_lo_z_2[i + 1]).slice(0, 68);
        prover_polynomials.z_hi_limbs[i] = uint256_t(prover_polynomials.x_hi_z_1[i + 1]).slice(68, 2 * 68);
        prover_polynomials.z_hi_limbs[i + 1] = uint256_t(prover_polynomials.y_lo_z_2[i + 1]).slice(68, 2 * 68);
        auto tmp = engine.get_random_uint256() >> 2;
        prover_polynomials.accumulators_binary_limbs_0[i] = tmp.slice(0, 68);
        prover_polynomials.accumulators_binary_limbs_1[i] = tmp.slice(68, 68 * 2);
        prover_polynomials.accumulators_binary_limbs_2[i] = tmp.slice(68 * 2, 68 * 3);
        prover_polynomials.accumulators_binary_limbs_3[i] = tmp.slice(68 * 3, 68 * 4);
        decompose_standard_limb(prover_polynomials.p_x_low_limbs[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_0[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_1[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_2[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_3[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_4[i],
                                prover_polynomials.p_x_low_limbs_range_constraint_tail[i]);

        decompose_standard_limb(prover_polynomials.p_x_low_limbs[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_0[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_1[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_2[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_3[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_4[i + 1],
                                prover_polynomials.p_x_low_limbs_range_constraint_tail[i + 1]);

        decompose_standard_limb(prover_polynomials.p_x_high_limbs[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_0[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_1[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_2[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_3[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_4[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_tail[i]);

        decompose_standard_top_limb(prover_polynomials.p_x_high_limbs[i + 1],
                                    prover_polynomials.p_x_high_limbs_range_constraint_0[i + 1],
                                    prover_polynomials.p_x_high_limbs_range_constraint_1[i + 1],
                                    prover_polynomials.p_x_high_limbs_range_constraint_2[i + 1],
                                    prover_polynomials.p_x_high_limbs_range_constraint_3[i + 1],
                                    prover_polynomials.p_x_high_limbs_range_constraint_4[i + 1]);

        decompose_standard_limb(prover_polynomials.p_y_low_limbs[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_0[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_1[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_2[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_3[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_4[i],
                                prover_polynomials.p_y_low_limbs_range_constraint_tail[i]);

        decompose_standard_limb(prover_polynomials.p_y_low_limbs[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_0[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_1[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_2[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_3[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_4[i + 1],
                                prover_polynomials.p_y_low_limbs_range_constraint_tail[i + 1]);

        decompose_standard_limb(prover_polynomials.p_y_high_limbs[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_0[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_1[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_2[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_3[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_4[i],
                                prover_polynomials.p_y_high_limbs_range_constraint_tail[i]);

        decompose_standard_top_limb(prover_polynomials.p_y_high_limbs[i + 1],
                                    prover_polynomials.p_y_high_limbs_range_constraint_0[i + 1],
                                    prover_polynomials.p_y_high_limbs_range_constraint_1[i + 1],
                                    prover_polynomials.p_y_high_limbs_range_constraint_2[i + 1],
                                    prover_polynomials.p_y_high_limbs_range_constraint_3[i + 1],
                                    prover_polynomials.p_y_high_limbs_range_constraint_4[i + 1]);

        decompose_standard_limb(prover_polynomials.z_lo_limbs[i],
                                prover_polynomials.z_lo_limbs_range_constraint_0[i],
                                prover_polynomials.z_lo_limbs_range_constraint_1[i],
                                prover_polynomials.z_lo_limbs_range_constraint_2[i],
                                prover_polynomials.z_lo_limbs_range_constraint_3[i],
                                prover_polynomials.z_lo_limbs_range_constraint_4[i],
                                prover_polynomials.z_lo_limbs_range_constraint_tail[i]);

        decompose_standard_limb(prover_polynomials.z_lo_limbs[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_0[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_1[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_2[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_3[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_4[i + 1],
                                prover_polynomials.z_lo_limbs_range_constraint_tail[i + 1]);

        decompose_standard_top_z_limb(prover_polynomials.z_hi_limbs[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_0[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_1[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_2[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_3[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_4[i],
                                      prover_polynomials.z_hi_limbs_range_constraint_tail[i]);

        decompose_standard_top_z_limb(prover_polynomials.z_hi_limbs[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_0[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_1[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_2[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_3[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_4[i + 1],
                                      prover_polynomials.z_hi_limbs_range_constraint_tail[i + 1]);

        decompose_standard_limb(prover_polynomials.accumulators_binary_limbs_0[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_0[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_1[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_2[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_3[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_4[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_tail[i]);
        decompose_standard_limb(prover_polynomials.accumulators_binary_limbs_1[i],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_0[i + 1],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_1[i + 1],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_2[i + 1],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_3[i + 1],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_4[i + 1],
                                prover_polynomials.accumulator_lo_limbs_range_constraint_tail[i + 1]);

        decompose_standard_limb(prover_polynomials.accumulators_binary_limbs_2[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_0[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_1[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_2[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_3[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_4[i],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_tail[i]);
        decompose_standard_top_limb(prover_polynomials.accumulators_binary_limbs_3[i],
                                    prover_polynomials.accumulator_hi_limbs_range_constraint_0[i + 1],
                                    prover_polynomials.accumulator_hi_limbs_range_constraint_1[i + 1],
                                    prover_polynomials.accumulator_hi_limbs_range_constraint_2[i + 1],
                                    prover_polynomials.accumulator_hi_limbs_range_constraint_3[i + 1],
                                    prover_polynomials.accumulator_hi_limbs_range_constraint_4[i + 1]);

        decompose_standard_limb(prover_polynomials.quotient_lo_binary_limbs[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_0[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_1[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_2[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_3[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_4[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_tail[i]);
        decompose_standard_limb(prover_polynomials.quotient_lo_binary_limbs_shift[i],
                                prover_polynomials.quotient_lo_limbs_range_constraint_0[i + 1],
                                prover_polynomials.quotient_lo_limbs_range_constraint_1[i + 1],
                                prover_polynomials.quotient_lo_limbs_range_constraint_2[i + 1],
                                prover_polynomials.quotient_lo_limbs_range_constraint_3[i + 1],
                                prover_polynomials.quotient_lo_limbs_range_constraint_4[i + 1],
                                prover_polynomials.quotient_lo_limbs_range_constraint_tail[i + 1]);

        decompose_standard_limb(prover_polynomials.quotient_hi_binary_limbs[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_0[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_1[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_2[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_3[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_4[i],
                                prover_polynomials.quotient_hi_limbs_range_constraint_tail[i]);

        decompose_top_quotient_limb(prover_polynomials.quotient_hi_binary_limbs_shift[i],
                                    prover_polynomials.quotient_hi_limbs_range_constraint_0[i + 1],
                                    prover_polynomials.quotient_hi_limbs_range_constraint_1[i + 1],
                                    prover_polynomials.quotient_hi_limbs_range_constraint_2[i + 1],
                                    prover_polynomials.quotient_hi_limbs_range_constraint_3[i + 1],
                                    prover_polynomials.quotient_hi_limbs_range_constraint_4[i + 1]);

        decompose_relation_limb(prover_polynomials.relation_wide_limbs[i],
                                prover_polynomials.relation_wide_limbs_range_constraint_0[i],
                                prover_polynomials.relation_wide_limbs_range_constraint_1[i],
                                prover_polynomials.relation_wide_limbs_range_constraint_2[i],
                                prover_polynomials.relation_wide_limbs_range_constraint_3[i],
                                prover_polynomials.p_x_high_limbs_range_constraint_tail[i + 1],
                                prover_polynomials.accumulator_hi_limbs_range_constraint_tail[i + 1]);

        decompose_relation_limb(prover_polynomials.relation_wide_limbs[i + 1],
                                prover_polynomials.relation_wide_limbs_range_constraint_0[i + 1],
                                prover_polynomials.relation_wide_limbs_range_constraint_1[i + 1],
                                prover_polynomials.relation_wide_limbs_range_constraint_2[i + 1],
                                prover_polynomials.relation_wide_limbs_range_constraint_3[i + 1],
                                prover_polynomials.p_y_high_limbs_range_constraint_tail[i + 1],
                                prover_polynomials.quotient_hi_limbs_range_constraint_tail[i + 1]);
    }

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::GoblinTranslatorDecompositionRelation<FF>());
    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
}

/**
 * @brief Test the correctness of GolbinTranslator's  extra relations
 *
 */
TEST_F(RelationCorrectnessTests, GoblinTranslatorExtraRelationsCorrectness)
{
    using Flavor = honk::flavor::GoblinTranslatorBasic;
    using FF = typename Flavor::FF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;
    using ProverPolynomialIds = typename Flavor::ProverPolynomialIds;
    auto& engine = numeric::random::get_debug_engine();

    auto circuit_size = Flavor::FULL_CIRCUIT_SIZE;
    auto mini_circuit_size = Flavor::MINI_CIRCUIT_SIZE;

    // Decomposition relation doesn'tu se any relation parameters
    // Compute public input delta
    sumcheck::RelationParameters<FF> params{
        .eta = 0,
        .beta = 0,
        .gamma = 0,
        .public_input_delta = 0,
        .lookup_grand_product_delta = 0,
    };

    // Create storage for polynomials
    ProverPolynomials prover_polynomials;
    ProverPolynomialIds prover_polynomial_ids;
    std::vector<Polynomial<FF>> polynomial_container;
    std::vector<size_t> polynomial_ids;
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        Polynomial<FF> temporary_polynomial(circuit_size);
        polynomial_container.push_back(temporary_polynomial);
        polynomial_ids.push_back(i);
        prover_polynomial_ids[i] = polynomial_ids[i];
    }
    auto shifted_ids = prover_polynomial_ids.get_shifted();
    std::unordered_set<size_t> shifted_id_set;
    for (auto& id : shifted_ids) {
        shifted_id_set.emplace(id);
    }
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        if (!shifted_id_set.contains(i)) {
            prover_polynomials[i] = polynomial_container[i];
        }
    }
    for (size_t i = 0; i < shifted_ids.size(); i++) {
        auto shifted_id = shifted_ids[i];
        auto to_be_shifted_id = prover_polynomial_ids.get_to_be_shifted()[i];
        prover_polynomials[shifted_id] = polynomial_container[to_be_shifted_id].shifted();
    }

    // Fill in lagrange even polynomial
    for (size_t i = 2; i < mini_circuit_size; i += 2) {
        prover_polynomials.lagrange_even[i] = 1;
    }
    for (size_t i = 0; i < mini_circuit_size; i++) {
        prover_polynomials.op[i] = engine.get_random_uint8() & 3;
    }
    prover_polynomials.lagrange_second[1] = 1;
    prover_polynomials.lagrange_second_to_last_in_minicircuit[mini_circuit_size - 2] = 1;
    // Put random values in all the non-concatenated constraint polynomials used to range constrain the values
    for (size_t i = 2; i < mini_circuit_size - 2; i += 2) {
        prover_polynomials.accumulators_binary_limbs_0[i] = FF ::random_element();
        prover_polynomials.accumulators_binary_limbs_1[i] = FF ::random_element();
        prover_polynomials.accumulators_binary_limbs_2[i] = FF ::random_element();
        prover_polynomials.accumulators_binary_limbs_3[i] = FF ::random_element();
        prover_polynomials.accumulators_binary_limbs_0[i + 1] = prover_polynomials.accumulators_binary_limbs_0[i];
        prover_polynomials.accumulators_binary_limbs_1[i + 1] = prover_polynomials.accumulators_binary_limbs_1[i];
        prover_polynomials.accumulators_binary_limbs_2[i + 1] = prover_polynomials.accumulators_binary_limbs_2[i];
        prover_polynomials.accumulators_binary_limbs_3[i + 1] = prover_polynomials.accumulators_binary_limbs_3[i];
    }
    params.accumulated_result = {
        FF::random_element(), FF::random_element(), FF::random_element(), FF::random_element()
    };
    prover_polynomials.accumulators_binary_limbs_0[1] = params.accumulated_result[0];
    prover_polynomials.accumulators_binary_limbs_1[1] = params.accumulated_result[1];
    prover_polynomials.accumulators_binary_limbs_2[1] = params.accumulated_result[2];
    prover_polynomials.accumulators_binary_limbs_3[1] = params.accumulated_result[3];

    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::GoblinTranslatorOpRangeConstraintRelation<FF>(),
                                honk::sumcheck::GoblinTranslatorAccumulatorTransferRelation<FF>());

    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
    check_relation<Flavor>(std::get<1>(relations), circuit_size, prover_polynomials, params);
}

/**
 * @brief Test the correctness of GolbinTranslator's  main relation
 *
 */
TEST_F(RelationCorrectnessTests, GoblinTranslatorMainRelationCorrectness)
{
    using Flavor = honk::flavor::GoblinTranslatorBasic;
    using FF = typename Flavor::FF;
    using BF = typename Flavor::BF;
    using ProverPolynomials = typename Flavor::ProverPolynomials;
    using ProverPolynomialIds = typename Flavor::ProverPolynomialIds;
    using GroupElement = typename Flavor::GroupElement;
    auto& engine = numeric::random::get_debug_engine();
    ECCOpQueue op_queue;
    constexpr size_t NUM_LIMB_BITS = 68;

    for (size_t i = 0; i < ((Flavor::MINI_CIRCUIT_SIZE >> 1) - 1); i++) {
        switch (engine.get_random_uint8() & 3) {
        case 0:
            op_queue.empty_row();
            break;
        case 1:
            op_queue.eq();
            break;
        case 2:
            op_queue.add_accumulate(GroupElement::random_element(&engine));
            break;
        case 3:
            op_queue.mul_accumulate(GroupElement::random_element(), FF::random_element(&engine));
            break;
        }
    }
    auto batching_challenge_v = BF::random_element(&engine);
    auto evaluation_input_x = BF::random_element(&engine);
    auto circuit_builder = GoblinTranslatorCircuitBuilder(batching_challenge_v, evaluation_input_x, op_queue);
    auto circuit_size = Flavor::FULL_CIRCUIT_SIZE;
    auto mini_circuit_size = Flavor::MINI_CIRCUIT_SIZE;
    sumcheck::RelationParameters<FF> params{
        .eta = 0,
        .beta = 0,
        .gamma = 0,
        .public_input_delta = 0,
        .lookup_grand_product_delta = 0,
    };
    // Decomposition relation doesn'tu se any relation parameters
    // Compute public input delta
    auto v_power = BF::one();
    for (size_t i = 0; i < 4; i++) {
        v_power *= batching_challenge_v;
        auto uint_v_power = uint256_t(v_power);
        params.batching_challenge_v[i] = { uint_v_power.slice(0, NUM_LIMB_BITS),
                                           uint_v_power.slice(NUM_LIMB_BITS, NUM_LIMB_BITS * 2),
                                           uint_v_power.slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3),
                                           uint_v_power.slice(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4) };
    }
    auto uint_input_x = uint256_t(evaluation_input_x);
    params.evaluation_input_x = { uint_input_x.slice(0, NUM_LIMB_BITS),
                                  uint_input_x.slice(NUM_LIMB_BITS, NUM_LIMB_BITS * 2),
                                  uint_input_x.slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3),
                                  uint_input_x.slice(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4) };

    // Create storage for polynomials
    ProverPolynomials prover_polynomials;
    ProverPolynomialIds prover_polynomial_ids;
    std::vector<Polynomial<FF>> polynomial_container;
    std::vector<size_t> polynomial_ids;
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        Polynomial<FF> temporary_polynomial(circuit_size);
        polynomial_container.push_back(temporary_polynomial);
        polynomial_ids.push_back(i);
        prover_polynomial_ids[i] = polynomial_ids[i];
    }
    auto shifted_ids = prover_polynomial_ids.get_shifted();
    std::unordered_set<size_t> shifted_id_set;
    for (auto& id : shifted_ids) {
        shifted_id_set.emplace(id);
    }
    for (size_t i = 0; i < prover_polynomials.size(); i++) {
        if (!shifted_id_set.contains(i)) {
            prover_polynomials[i] = polynomial_container[i];
        }
    }
    for (size_t i = 0; i < shifted_ids.size(); i++) {
        auto shifted_id = shifted_ids[i];
        auto to_be_shifted_id = prover_polynomial_ids.get_to_be_shifted()[i];
        prover_polynomials[shifted_id] = polynomial_container[to_be_shifted_id].shifted();
    }
    for (size_t i = 1; i < circuit_builder.get_num_gates(); i++) {
        prover_polynomials.op[i] = circuit_builder.get_variable(circuit_builder.wires[circuit_builder.OP][i]);
        prover_polynomials.p_x_low_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.P_X_LOW_LIMBS][i]);
        prover_polynomials.p_x_high_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.P_X_HIGH_LIMBS][i]);
        prover_polynomials.p_y_low_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.P_Y_LOW_LIMBS][i]);
        prover_polynomials.p_y_high_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.P_Y_HIGH_LIMBS][i]);
        prover_polynomials.z_lo_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.Z_LO_LIMBS][i]);
        prover_polynomials.z_hi_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.Z_HI_LIMBS][i]);
        prover_polynomials.accumulators_binary_limbs_0[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.ACCUMULATORS_BINARY_LIMBS_0][i]);
        prover_polynomials.accumulators_binary_limbs_1[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.ACCUMULATORS_BINARY_LIMBS_1][i]);
        prover_polynomials.accumulators_binary_limbs_2[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.ACCUMULATORS_BINARY_LIMBS_2][i]);
        prover_polynomials.accumulators_binary_limbs_3[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.ACCUMULATORS_BINARY_LIMBS_3][i]);
        prover_polynomials.quotient_lo_binary_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.QUOTIENT_LO_BINARY_LIMBS][i]);
        prover_polynomials.quotient_hi_binary_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.QUOTIENT_HI_BINARY_LIMBS][i]);
        prover_polynomials.relation_wide_limbs[i] =
            circuit_builder.get_variable(circuit_builder.wires[circuit_builder.RELATION_WIDE_LIMBS][i]);
    }

    // Fill in lagrange odd polynomial
    for (size_t i = 1; i < mini_circuit_size - 1; i += 2) {
        prover_polynomials.lagrange_odd[i] = 1;
    }
    // Construct the round for applying sumcheck relations and results for storing computed results
    auto relations = std::tuple(honk::sumcheck::GoblinTranslatorMainRelation<FF>());

    // Check that each relation is satisfied across each row of the prover polynomials
    check_relation<Flavor>(std::get<0>(relations), circuit_size, prover_polynomials, params);
}

} // namespace test_honk_relations
