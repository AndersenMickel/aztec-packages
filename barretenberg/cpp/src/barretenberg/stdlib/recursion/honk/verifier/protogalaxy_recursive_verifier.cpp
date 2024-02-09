#include "protogalaxy_recursive_verifier.hpp"
#include "barretenberg/polynomials/polynomial.hpp"
#include "barretenberg/proof_system/library/grand_product_delta.hpp"
#include "barretenberg/stdlib/recursion/honk/verifier/recursive_instances.hpp"
namespace bb::stdlib::recursion::honk {

template <class VerifierInstances>
void ProtoGalaxyRecursiveVerifier_<VerifierInstances>::receive_and_finalise_instance(
    const std::shared_ptr<Instance>& inst, const std::string& domain_separator)
{
    // Get circuit parameters and the public inputs
    const auto instance_size = transcript->template receive_from_prover<uint32_t>(domain_separator + "_instance_size");
    const auto public_input_size =
        transcript->template receive_from_prover<uint32_t>(domain_separator + "_public_input_size");
    inst->instance_size = uint32_t(instance_size.get_value());
    inst->log_instance_size = static_cast<size_t>(numeric::get_msb(inst->instance_size));
    inst->public_input_size = uint32_t(public_input_size.get_value());

    for (size_t i = 0; i < inst->public_input_size; ++i) {
        auto public_input_i =
            transcript->template receive_from_prover<FF>(domain_separator + "_public_input_" + std::to_string(i));
        inst->public_inputs.emplace_back(public_input_i);
    }

    const auto pub_inputs_offset =
        transcript->template receive_from_prover<uint32_t>(domain_separator + "_pub_inputs_offset");

    inst->pub_inputs_offset = uint32_t(pub_inputs_offset.get_value());

    // Get commitments to first three wire polynomials
    auto labels = inst->commitment_labels;
    auto& witness_commitments = inst->witness_commitments;
    witness_commitments.w_l = transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.w_l);
    witness_commitments.w_r = transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.w_r);
    witness_commitments.w_o = transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.w_o);

    if constexpr (IsGoblinFlavor<Flavor>) {
        witness_commitments.ecc_op_wire_1 =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.ecc_op_wire_1);
        witness_commitments.ecc_op_wire_2 =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.ecc_op_wire_2);
        witness_commitments.ecc_op_wire_3 =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.ecc_op_wire_3);
        witness_commitments.ecc_op_wire_4 =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.ecc_op_wire_4);
        witness_commitments.calldata =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.calldata);
        witness_commitments.calldata_read_counts =
            transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.calldata_read_counts);
    }

    // Get challenge for sorted list batching and wire four memory records commitment
    auto eta = transcript->get_challenge(domain_separator + "_eta");
    witness_commitments.sorted_accum =
        transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.sorted_accum);
    witness_commitments.w_4 = transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.w_4);

    // Get permutation challenges and commitment to permutation and lookup grand products
    auto [beta, gamma] = transcript->get_challenges(domain_separator + "_beta", domain_separator + "_gamma");

    // If Goblin (i.e. using DataBus) receive commitments to log-deriv inverses polynomial
    if constexpr (IsGoblinFlavor<Flavor>) {
        witness_commitments.lookup_inverses = transcript->template receive_from_prover<Commitment>(
            domain_separator + "_" + commitment_labels.lookup_inverses);
    }

    witness_commitments.z_perm =
        transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.z_perm);
    witness_commitments.z_lookup =
        transcript->template receive_from_prover<Commitment>(domain_separator + "_" + labels.z_lookup);

    // Compute correction terms for grand products
    const FF public_input_delta = compute_public_input_delta<Flavor>(
        inst->public_inputs, beta, gamma, inst->instance_size, inst->pub_inputs_offset);
    const FF lookup_grand_product_delta = compute_lookup_grand_product_delta<FF>(beta, gamma, inst->instance_size);
    inst->relation_parameters =
        RelationParameters<FF>{ eta, beta, gamma, public_input_delta, lookup_grand_product_delta };

    // Get the relation separation challenges
    for (size_t idx = 0; idx < NUM_SUBRELATIONS - 1; idx++) {
        inst->alphas[idx] = transcript->get_challenge(domain_separator + "_alpha_" + std::to_string(idx));
    }
}

// TODO(https://github.com/AztecProtocol/barretenberg/issues/795): The rounds prior to actual verifying are common
// between decider and folding verifier and could be somehow shared so we do not duplicate code so much.
template <class VerifierInstances> void ProtoGalaxyRecursiveVerifier_<VerifierInstances>::prepare_for_folding()
{
    auto index = 0;
    auto inst = instances[0];
    auto domain_separator = std::to_string(index);
    if (!inst->is_accumulator) {
        receive_and_finalise_instance(inst, domain_separator);
        inst->target_sum = 0;
        auto beta = transcript->get_challenge(domain_separator + "_initial_gate_challenge");
        std::vector<FF> gate_challenges(inst->log_instance_size);
        gate_challenges[0] = beta;
        for (size_t i = 1; i < inst->log_instance_size; i++) {
            gate_challenges[i] = gate_challenges[i - 1].sqr();
        }
        inst->gate_challenges = gate_challenges;
    }
    index++;

    for (auto it = instances.begin() + 1; it != instances.end(); it++, index++) {
        auto inst = *it;
        auto domain_separator = std::to_string(index);
        receive_and_finalise_instance(inst, domain_separator);
    }
}

template <class VerifierInstances>
std::shared_ptr<typename VerifierInstances::Instance> ProtoGalaxyRecursiveVerifier_<
    VerifierInstances>::verify_folding_proof(const HonkProof& proof)
{
    using Transcript = typename Flavor::Transcript;
    using ElementNative = typename Flavor::Curve::ElementNative;
    using AffineElementNative = typename Flavor::Curve::AffineElementNative;

    transcript = std::make_shared<Transcript>(builder, proof);
    prepare_for_folding();

    auto delta = transcript->get_challenge("delta");
    auto accumulator = get_accumulator();
    auto deltas = compute_round_challenge_pows(accumulator->log_instance_size, delta);

    std::vector<FF> perturbator_coeffs(accumulator->log_instance_size + 1);
    for (size_t idx = 1; idx <= accumulator->log_instance_size; idx++) {
        perturbator_coeffs[idx] = transcript->template receive_from_prover<FF>("perturbator_" + std::to_string(idx));
    }

    perturbator_coeffs[0] = accumulator->target_sum;

    FF perturbator_challenge = transcript->get_challenge("perturbator_challenge");

    auto perturbator_at_challenge = evaluate_perturbator(perturbator_coeffs, perturbator_challenge);
    // The degree of K(X) is dk - k - 1 = k(d - 1) - 1. Hence we need  k(d - 1) evaluations to represent it.
    std::array<FF, VerifierInstances::BATCHED_EXTENDED_LENGTH - VerifierInstances::NUM> combiner_quotient_evals;
    for (size_t idx = 0; idx < VerifierInstances::BATCHED_EXTENDED_LENGTH - VerifierInstances::NUM; idx++) {
        combiner_quotient_evals[idx] = transcript->template receive_from_prover<FF>(
            "combiner_quotient_" + std::to_string(idx + VerifierInstances::NUM));
    }
    Univariate<FF, VerifierInstances::BATCHED_EXTENDED_LENGTH, VerifierInstances::NUM> combiner_quotient(
        combiner_quotient_evals);
    FF combiner_challenge = transcript->get_challenge("combiner_quotient_challenge");
    auto combiner_quotient_at_challenge = combiner_quotient.evaluate(combiner_challenge); // fine recursive i think

    auto vanishing_polynomial_at_challenge = combiner_challenge * (combiner_challenge - FF(1));
    auto lagranges = std::vector<FF>{ FF(1) - combiner_challenge, combiner_challenge };

    auto next_accumulator = std::make_shared<Instance>();
    next_accumulator->instance_size = accumulator->instance_size;
    next_accumulator->log_instance_size = accumulator->log_instance_size;
    next_accumulator->is_accumulator = true;

    // Compute next folding parameters and verify against the ones received from the prover
    next_accumulator->target_sum =
        perturbator_at_challenge * lagranges[0] + vanishing_polynomial_at_challenge * combiner_quotient_at_challenge;
    next_accumulator->gate_challenges =
        update_gate_challenges(perturbator_challenge, accumulator->gate_challenges, deltas);

    // Compute ϕ and verify against the data received from the prover
    auto& acc_witness_commitments = next_accumulator->witness_commitments;
    auto witness_labels = commitment_labels.get_witness();
    size_t comm_idx = 0;
    auto random_generator = Commitment::from_witness(builder, AffineElementNative(ElementNative::random_element()));
    for (auto& comm : acc_witness_commitments.get_all()) {
        comm = random_generator;
        size_t inst = 0;
        for (auto& instance : instances) {
            comm = comm + instance->witness_commitments.get_all()[comm_idx] * lagranges[inst];
            inst++;
        }
        comm -= random_generator;
        comm_idx++;
    }

    next_accumulator->public_input_size = instances[0]->public_input_size;
    next_accumulator->public_inputs = std::vector<FF>(next_accumulator->public_input_size, 0);
    size_t public_input_idx = 0;
    for (auto& public_input : next_accumulator->public_inputs) {
        size_t inst = 0;
        for (auto& instance : instances) {
            public_input += instance->public_inputs[public_input_idx] * lagranges[inst];
            inst++;
        }
        public_input_idx++;
    }

    size_t alpha_idx = 0;
    for (auto& alpha : next_accumulator->alphas) {
        alpha = FF(0);
        size_t instance_idx = 0;
        for (auto& instance : instances) {
            alpha += instance->alphas[alpha_idx] * lagranges[instance_idx];
            instance_idx++;
        }
        alpha_idx++;
    }

    auto& expected_parameters = next_accumulator->relation_parameters;
    for (size_t inst_idx = 0; inst_idx < VerifierInstances::NUM; inst_idx++) {
        auto instance = instances[inst_idx];
        expected_parameters.eta += instance->relation_parameters.eta * lagranges[inst_idx];
        expected_parameters.beta += instance->relation_parameters.beta * lagranges[inst_idx];
        expected_parameters.gamma += instance->relation_parameters.gamma * lagranges[inst_idx];
        expected_parameters.public_input_delta +=
            instance->relation_parameters.public_input_delta * lagranges[inst_idx];
        expected_parameters.lookup_grand_product_delta +=
            instance->relation_parameters.lookup_grand_product_delta * lagranges[inst_idx];
    }

    next_accumulator->verification_key =
        std::make_shared<VerificationKey>(instances[0]->instance_size, instances[0]->public_input_size);
    auto vk_labels = commitment_labels.get_precomputed();
    size_t vk_idx = 0;
    for (auto& expected_vk : next_accumulator->verification_key->get_all()) {
        size_t inst = 0;
        expected_vk = random_generator;
        for (auto& instance : instances) {
            expected_vk = expected_vk + instance->verification_key->get_all()[vk_idx] * lagranges[inst];
            inst++;
        }
        expected_vk -= random_generator;
        vk_idx++;
    }

    return next_accumulator;
}

// template class ProtoGalaxyRecursiveVerifier_<VerifierInstances_<UltraRecursiveFlavor_<GoblinUltraCircuitBuilder>,
// 2>>;
template class ProtoGalaxyRecursiveVerifier_<
    RecursiveVerifierInstances_<GoblinUltraRecursiveFlavor_<GoblinUltraCircuitBuilder>, 2>>;
} // namespace bb::stdlib::recursion::honk