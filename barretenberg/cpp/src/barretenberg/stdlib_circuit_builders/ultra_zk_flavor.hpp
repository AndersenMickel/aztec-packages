#pragma once

#include "barretenberg/stdlib_circuit_builders/ultra_flavor.hpp"

namespace bb {
/*! \brief The child class of UltraFlavor that runs with ZK Sumcheck. Most of the properties of UltraFlavor are
inherited without any changes, except for the MAX_PARTIAL_RELATION_LENGTH which is now computed as a maximum of
SUBRELATION_PARTIAL_LENGTHS incremented by the corresponding SUBRELATION_WITNESS_DEGREES over all relations included in
UltraFlavor, which also affects the size of ExtendedEdges univariate containers.
Moreover, the container SumcheckTupleOfTuplesOfUnivariates is resized to reflect that masked
witness polynomials are of degree at most \f$2\$ in each variable, and hence, for any subrelation, the corresponding
univariate accumuluator size has to be increased by the subrelation's witness degree.
See
*
*/
class UltraFlavorWithZK : public bb::UltraFlavor {

  public:
    // This flavor runs with ZK Sumcheck
    static constexpr bool HasZK = true;
    // Compute the maximum over all partial subrelation lengths incremented by the corresponding subrelation witness
    // degrees for the Relations inherited from UltraFlavor
    static constexpr size_t MAX_PARTIAL_RELATION_LENGTH = compute_max_total_zk_relation_length<Relations>();
    // Determine the number of evaluations of Prover and Libra Polynomials that the Prover sends to the Verifier in
    // the rounds of ZK Sumcheck.
    static constexpr size_t BATCHED_RELATION_PARTIAL_LENGTH = MAX_PARTIAL_RELATION_LENGTH + 1;
    // Construct the container for the subrelations' contributions
    using SumcheckTupleOfTuplesOfUnivariates = decltype(create_zk_sumcheck_tuple_of_tuples_of_univariates<Relations>());
    // Re-define ExtendedEdges to account for the incremented MAX_PARTIAL_RELATION_LENGTH
    using ExtendedEdges = ProverUnivariates<MAX_PARTIAL_RELATION_LENGTH>;

    // Add masking polynomials to the proving key
    class ProvingKey : public bb::UltraFlavor::ProvingKey {
      public:
        // Add extra features here
        std::array<FF, NUM_ALL_WITNESS_ENTITIES> eval_masking_scalars;
        std::vector<bb::Univariate<FF, BATCHED_RELATION_PARTIAL_LENGTH>> libra_univariates;
        using UltraFlavor::ProvingKey::ProvingKey;
    };

    class VerificationKey : public bb::UltraFlavor::VerificationKey {
      public:
        std::array<Commitment, NUM_ALL_WITNESS_ENTITIES> eval_masking_commitments;
        FF challenge_factor;

        using UltraFlavor::VerificationKey::VerificationKey;
    };
};
} // namespace bb