#include "./goblin_translator_verifier.hpp"
#include "barretenberg/honk/flavor/goblin_translator.hpp"
#include "barretenberg/honk/flavor/standard.hpp"
#include "barretenberg/honk/pcs/gemini/gemini.hpp"
#include "barretenberg/honk/transcript/transcript.hpp"
#include "barretenberg/honk/utils/power_polynomial.hpp"
#include "barretenberg/numeric/bitop/get_msb.hpp"
#include "barretenberg/numeric/uint256/uint256.hpp"
#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

using namespace barretenberg;
using namespace proof_system::honk::sumcheck;

namespace proof_system::honk {
template <typename Flavor>
GoblinTranslatorVerifier_<Flavor>::GoblinTranslatorVerifier_(
    std::shared_ptr<typename Flavor::VerificationKey> verifier_key)
    : key(verifier_key)
{}

template <typename Flavor>
GoblinTranslatorVerifier_<Flavor>::GoblinTranslatorVerifier_(GoblinTranslatorVerifier_&& other) noexcept
    : key(std::move(other.key))
    , pcs_verification_key(std::move(other.pcs_verification_key))
{}

template <typename Flavor>
GoblinTranslatorVerifier_<Flavor>& GoblinTranslatorVerifier_<Flavor>::operator=(
    GoblinTranslatorVerifier_&& other) noexcept
{
    key = other.key;
    pcs_verification_key = (std::move(other.pcs_verification_key));
    commitments.clear();
    pcs_fr_elements.clear();
    return *this;
}

/**
 * @brief This function verifies an GoblinTranslator Honk proof for given program settings.
 *
 */
template <typename Flavor> bool GoblinTranslatorVerifier_<Flavor>::verify_proof(const plonk::proof& proof)
{
    using FF = typename Flavor::FF;
    using BF = typename Flavor::BF;
    using GroupElement = typename Flavor::GroupElement;
    using Commitment = typename Flavor::Commitment;
    using PCSParams = typename Flavor::PCSParams;
    using PCS = typename Flavor::PCS;
    using Gemini = pcs::gemini::GeminiVerifier_<PCSParams>;
    using Shplonk = pcs::shplonk::ShplonkVerifier_<PCSParams>;
    using VerifierCommitments = typename Flavor::VerifierCommitments;
    using CommitmentLabels = typename Flavor::CommitmentLabels;

    const size_t NUM_LIMB_BITS = Flavor::NUM_LIMB_BITS;
    RelationParameters<FF> relation_parameters;

    transcript = VerifierTranscript<FF>{ proof.proof_data };

    auto commitments = VerifierCommitments(key, transcript);
    auto commitment_labels = CommitmentLabels();

    // TODO(Adrian): Change the initialization of the transcript to take the VK hash?
    const auto circuit_size = transcript.template receive_from_prover<uint32_t>("circuit_size");
    evaluation_input_x = transcript.template receive_from_prover<BF>("evaluation_input_x");
    batching_challenge_v = transcript.template receive_from_prover<BF>("batching_challenge_v");
    const auto uint_accumulated_result = uint256_t(transcript.template receive_from_prover<BF>("accumulated_result"));
    auto uint_evaluation_input = uint256_t(evaluation_input_x);
    relation_parameters.evaluation_input_x = { uint_evaluation_input.slice(0, NUM_LIMB_BITS),
                                               uint_evaluation_input.slice(NUM_LIMB_BITS, NUM_LIMB_BITS * 2),
                                               uint_evaluation_input.slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3),
                                               uint_evaluation_input.slice(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4) };
    relation_parameters.accumulated_result = { uint_accumulated_result.slice(0, NUM_LIMB_BITS),
                                               uint_accumulated_result.slice(NUM_LIMB_BITS, NUM_LIMB_BITS * 2),
                                               uint_accumulated_result.slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3),
                                               uint_accumulated_result.slice(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4) };
    std::vector<uint256_t> uint_batching_challenge_powers;
    uint_batching_challenge_powers.emplace_back(batching_challenge_v);
    auto running_power = batching_challenge_v * batching_challenge_v;
    uint_batching_challenge_powers.emplace_back(running_power);
    running_power *= batching_challenge_v;
    uint_batching_challenge_powers.emplace_back(running_power);
    running_power *= batching_challenge_v;
    uint_batching_challenge_powers.emplace_back(running_power);

    for (size_t i = 0; i < 4; i++) {
        relation_parameters.batching_challenge_v[i] = {
            uint_batching_challenge_powers[i].slice(0, NUM_LIMB_BITS),
            uint_batching_challenge_powers[i].slice(NUM_LIMB_BITS, NUM_LIMB_BITS * 2),
            uint_batching_challenge_powers[i].slice(NUM_LIMB_BITS * 2, NUM_LIMB_BITS * 3),
            uint_batching_challenge_powers[i].slice(NUM_LIMB_BITS * 3, NUM_LIMB_BITS * 4),
        };
    }
    if (circuit_size != key->circuit_size) {
        return false;
    }

    // Get commitments

    // Get all the values of wires
    commitments.op = transcript.template receive_from_prover<Commitment>(commitment_labels.op);
    commitments.x_lo_y_hi = transcript.template receive_from_prover<Commitment>(commitment_labels.x_lo_y_hi);
    commitments.x_hi_z_1 = transcript.template receive_from_prover<Commitment>(commitment_labels.x_hi_z_1);
    commitments.y_lo_z_2 = transcript.template receive_from_prover<Commitment>(commitment_labels.y_lo_z_2);
    commitments.p_x_low_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs);
    commitments.p_x_low_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_0);
    commitments.p_x_low_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_1);
    commitments.p_x_low_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_2);
    commitments.p_x_low_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_3);
    commitments.p_x_low_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_4);
    commitments.p_x_low_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_low_limbs_range_constraint_tail);
    commitments.p_x_high_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs);
    commitments.p_x_high_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_0);
    commitments.p_x_high_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_1);
    commitments.p_x_high_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_2);
    commitments.p_x_high_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_3);
    commitments.p_x_high_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_4);
    commitments.p_x_high_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_x_high_limbs_range_constraint_tail);
    commitments.p_y_low_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs);
    commitments.p_y_low_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_0);
    commitments.p_y_low_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_1);
    commitments.p_y_low_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_2);
    commitments.p_y_low_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_3);
    commitments.p_y_low_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_4);
    commitments.p_y_low_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_low_limbs_range_constraint_tail);
    commitments.p_y_high_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs);
    commitments.p_y_high_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_0);
    commitments.p_y_high_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_1);
    commitments.p_y_high_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_2);
    commitments.p_y_high_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_3);
    commitments.p_y_high_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_4);
    commitments.p_y_high_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.p_y_high_limbs_range_constraint_tail);
    commitments.z_lo_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs);
    commitments.z_lo_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_0);
    commitments.z_lo_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_1);
    commitments.z_lo_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_2);
    commitments.z_lo_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_3);
    commitments.z_lo_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_4);
    commitments.z_lo_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_lo_limbs_range_constraint_tail);
    commitments.z_hi_limbs = transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs);
    commitments.z_hi_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_0);
    commitments.z_hi_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_1);
    commitments.z_hi_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_2);
    commitments.z_hi_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_3);
    commitments.z_hi_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_4);
    commitments.z_hi_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.z_hi_limbs_range_constraint_tail);
    commitments.accumulators_binary_limbs_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulators_binary_limbs_0);
    commitments.accumulators_binary_limbs_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulators_binary_limbs_1);
    commitments.accumulators_binary_limbs_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulators_binary_limbs_2);
    commitments.accumulators_binary_limbs_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulators_binary_limbs_3);
    commitments.accumulator_lo_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_lo_limbs_range_constraint_0);
    commitments.accumulator_lo_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_lo_limbs_range_constraint_1);
    commitments.accumulator_lo_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_lo_limbs_range_constraint_2);
    commitments.accumulator_lo_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_lo_limbs_range_constraint_3);
    commitments.accumulator_lo_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_lo_limbs_range_constraint_4);
    commitments.accumulator_lo_limbs_range_constraint_tail = transcript.template receive_from_prover<Commitment>(
        commitment_labels.accumulator_lo_limbs_range_constraint_tail);
    commitments.accumulator_hi_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_hi_limbs_range_constraint_0);
    commitments.accumulator_hi_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_hi_limbs_range_constraint_1);
    commitments.accumulator_hi_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_hi_limbs_range_constraint_2);
    commitments.accumulator_hi_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_hi_limbs_range_constraint_3);
    commitments.accumulator_hi_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.accumulator_hi_limbs_range_constraint_4);
    commitments.accumulator_hi_limbs_range_constraint_tail = transcript.template receive_from_prover<Commitment>(
        commitment_labels.accumulator_hi_limbs_range_constraint_tail);
    commitments.quotient_lo_binary_limbs =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_binary_limbs);
    commitments.quotient_hi_binary_limbs =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_binary_limbs);
    commitments.quotient_lo_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_0);
    commitments.quotient_lo_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_1);
    commitments.quotient_lo_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_2);
    commitments.quotient_lo_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_3);
    commitments.quotient_lo_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_4);
    commitments.quotient_lo_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_lo_limbs_range_constraint_tail);
    commitments.quotient_hi_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_0);
    commitments.quotient_hi_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_1);
    commitments.quotient_hi_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_2);
    commitments.quotient_hi_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_3);
    commitments.quotient_hi_limbs_range_constraint_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_4);
    commitments.quotient_hi_limbs_range_constraint_tail =
        transcript.template receive_from_prover<Commitment>(commitment_labels.quotient_hi_limbs_range_constraint_tail);
    commitments.relation_wide_limbs =
        transcript.template receive_from_prover<Commitment>(commitment_labels.relation_wide_limbs);
    commitments.relation_wide_limbs_range_constraint_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.relation_wide_limbs_range_constraint_0);
    commitments.relation_wide_limbs_range_constraint_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.relation_wide_limbs_range_constraint_1);
    commitments.relation_wide_limbs_range_constraint_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.relation_wide_limbs_range_constraint_2);
    commitments.relation_wide_limbs_range_constraint_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.relation_wide_limbs_range_constraint_3);
    commitments.ordered_range_constraints_0 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.ordered_range_constraints_0);
    commitments.ordered_range_constraints_1 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.ordered_range_constraints_1);
    commitments.ordered_range_constraints_2 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.ordered_range_constraints_2);
    commitments.ordered_range_constraints_3 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.ordered_range_constraints_3);
    commitments.ordered_range_constraints_4 =
        transcript.template receive_from_prover<Commitment>(commitment_labels.ordered_range_constraints_4);

    // Get permutation challenges
    auto [gamma] = transcript.get_challenges("gamma");

    relation_parameters.beta = 0;
    relation_parameters.gamma = gamma;
    relation_parameters.public_input_delta = 0;
    relation_parameters.lookup_grand_product_delta = 0;

    // Get commitment to permutation and lookup grand products
    commitments.z_perm = transcript.template receive_from_prover<Commitment>(commitment_labels.z_perm);
    // Execute Sumcheck Verifier
    auto sumcheck = SumcheckVerifier<Flavor>(circuit_size, transcript);

    std::optional sumcheck_output = sumcheck.verify(relation_parameters);

    // If Sumcheck does not return an output, sumcheck verification has failed
    if (!sumcheck_output.has_value()) {
        return false;
    }
    // TODO:remove;
    // return true;

    auto [multivariate_challenge, purported_evaluations] = *sumcheck_output;

    // Execute Gemini/Shplonk verification:

    // Construct inputs for Gemini verifier:
    // - Multivariate opening point u = (u_0, ..., u_{d-1})
    // - batched unshifted and to-be-shifted polynomial commitments
    auto batched_commitment_unshifted = GroupElement::zero();
    auto batched_commitment_to_be_shifted = GroupElement::zero();

    // Compute powers of batching challenge rho
    FF rho = transcript.get_challenge("rho");
    std::vector<FF> rhos = pcs::gemini::powers_of_rho(rho, Flavor::NUM_ALL_ENTITIES);

    // Compute batched multivariate evaluation
    FF batched_evaluation = FF::zero();
    size_t evaluation_idx = 0;
    for (auto& value : purported_evaluations.get_unshifted_then_shifted_then_special()) {
        batched_evaluation += value * rhos[evaluation_idx];
        ++evaluation_idx;
    }

    // Construct batched commitment for NON-shifted polynomials
    size_t commitment_idx = 0;
    info("Breaking commitment: ",
         commitment_labels.concatenated_range_constraints_0,
         " = ",
         commitments.concatenated_range_constraints_0);
    for (auto& commitment : commitments.get_unshifted()) {
        batched_commitment_unshifted += commitment * rhos[commitment_idx];
        // info("Batch commitment_unshifted", commitment_idx, ": ", (batched_commitment_unshifted).normalize());
        ++commitment_idx;
    }

    // Construct batched commitment for to-be-shifted polynomials
    for (auto& commitment : commitments.get_to_be_shifted()) {
        batched_commitment_to_be_shifted += commitment * rhos[commitment_idx];
        ++commitment_idx;
    }
    // info("Challenge: ", multivariate_challenge);
    info("Batch commitment_shifted: ", batched_commitment_to_be_shifted);
    info("batcehed_evaluations", batched_evaluation);
    // Produce a Gemini claim consisting of:
    // - d+1 commitments [Fold_{r}^(0)], [Fold_{-r}^(0)], and [Fold^(l)], l = 1:d-1
    // - d+1 evaluations a_0_pos, and a_l, l = 0:d-1
    auto update_simulated_commitments = [&](FF r_challenge) {
        auto mini_circuit_size = Flavor::MINI_CIRCUIT_SIZE;
        auto r_to_the_mini_circuit_size = r_challenge.pow(mini_circuit_size);
        auto powers_of_r = pcs::gemini::powers_of_rho(r_to_the_mini_circuit_size, Flavor::CONCATENATION_INDEX);
        auto positive_accumulator = GroupElement::zero();
        auto concatenation_groups = commitments.get_concatenation_groups();
        for (size_t i = 0; i < commitments.get_special().size(); i++) {
            for (size_t j = 0; j < concatenation_groups[i].size(); j++) {
                positive_accumulator += concatenation_groups[i][j] * (rhos[commitment_idx] * powers_of_r[j]);
            }
            ++commitment_idx;
        }
        return std::make_tuple(positive_accumulator, positive_accumulator);
    };
    auto gemini_claim = Gemini::reduce_verification(multivariate_challenge,
                                                    batched_evaluation,
                                                    batched_commitment_unshifted,
                                                    batched_commitment_to_be_shifted,
                                                    transcript,
                                                    update_simulated_commitments);
    // info("Verifier transcript");
    // transcript.print();
    // size_t i = 0;
    // for (auto& claim : gemini_claim) {
    //     info("PCS claim ",
    //          i,
    //          ": ",
    //          PCS::verify(pcs_verification_key, claim, transcript, "NOTSHPLONK:" + std::to_string(i)) ? "true" :
    //          "false", " / ", claim.commitment);
    //     i++;
    // }
    // return false;
    // Produce a Shplonk claim: commitment [Q] - [Q_z], evaluation zero (at random challenge z)
    auto shplonk_claim = Shplonk::reduce_verification(pcs_verification_key, gemini_claim, transcript);

    // // Verify the Shplonk claim with KZG or IPA
    return PCS::verify(pcs_verification_key, shplonk_claim, transcript);
}

template class GoblinTranslatorVerifier_<honk::flavor::GoblinTranslatorBasic>;

} // namespace proof_system::honk
