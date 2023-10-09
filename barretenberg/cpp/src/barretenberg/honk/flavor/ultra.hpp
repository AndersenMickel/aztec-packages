#pragma once
#include "barretenberg/ecc/curves/bn254/g1.hpp"
#include "barretenberg/honk/pcs/kzg/kzg.hpp"
#include "barretenberg/polynomials/barycentric.hpp"
#include "barretenberg/polynomials/univariate.hpp"

#include "barretenberg/honk/transcript/transcript.hpp"
#include "barretenberg/polynomials/evaluation_domain.hpp"
#include "barretenberg/polynomials/polynomial.hpp"
#include "barretenberg/proof_system/circuit_builder/ultra_circuit_builder.hpp"
#include "barretenberg/proof_system/flavor/flavor.hpp"
#include "barretenberg/proof_system/relations/auxiliary_relation.hpp"
#include "barretenberg/proof_system/relations/elliptic_relation.hpp"
#include "barretenberg/proof_system/relations/gen_perm_sort_relation.hpp"
#include "barretenberg/proof_system/relations/lookup_relation.hpp"
#include "barretenberg/proof_system/relations/permutation_relation.hpp"
#include "barretenberg/proof_system/relations/ultra_arithmetic_relation.hpp"

namespace proof_system::honk::flavor {

class Ultra {
  public:
    using CircuitBuilder = UltraCircuitBuilder;
    using Curve = curve::BN254;
    using FF = Curve::ScalarField;
    using GroupElement = Curve::Element;
    using Commitment = Curve::AffineElement;
    using CommitmentHandle = Curve::AffineElement;
    using PCS = pcs::kzg::KZG<Curve>;
    using Polynomial = barretenberg::Polynomial<FF>;
    using PolynomialHandle = std::span<FF>;
    using CommitmentKey = pcs::CommitmentKey<Curve>;
    using VerifierCommitmentKey = pcs::VerifierCommitmentKey<Curve>;

    static constexpr size_t NUM_WIRES = CircuitBuilder::NUM_WIRES;
    // The number of multivariate polynomials on which a sumcheck prover sumcheck operates (including shifts). We often
    // need containers of this size to hold related data, so we choose a name more agnostic than `NUM_POLYNOMIALS`.
    // Note: this number does not include the individual sorted list polynomials.
    static constexpr size_t NUM_ALL_ENTITIES = 43;
    // The number of polynomials precomputed to describe a circuit and to aid a prover in constructing a satisfying
    // assignment of witnesses. We again choose a neutral name.
    static constexpr size_t NUM_PRECOMPUTED_ENTITIES = 25;
    // The total number of witness entities not including shifts.
    static constexpr size_t NUM_WITNESS_ENTITIES = 11;

    using GrandProductRelations =
        std::tuple<proof_system::UltraPermutationRelation<FF>, proof_system::LookupRelation<FF>>;
    // define the tuple of Relations that comprise the Sumcheck relation
    using Relations = std::tuple<proof_system::UltraArithmeticRelation<FF>,
                                 proof_system::UltraPermutationRelation<FF>,
                                 proof_system::LookupRelation<FF>,
                                 proof_system::GenPermSortRelation<FF>,
                                 proof_system::EllipticRelation<FF>,
                                 proof_system::AuxiliaryRelation<FF>>;

    static constexpr size_t MAX_RELATION_LENGTH = get_max_relation_length<Relations>();

    // MAX_RANDOM_RELATION_LENGTH = algebraic degree of sumcheck relation *after* multiplying by the `pow_zeta` random
    // polynomial e.g. For \sum(x) [A(x) * B(x) + C(x)] * PowZeta(X), relation length = 2 and random relation length = 3
    static constexpr size_t MAX_RANDOM_RELATION_LENGTH = MAX_RELATION_LENGTH + 1;
    static constexpr size_t NUM_RELATIONS = std::tuple_size<Relations>::value;

    // define the container for storing the univariate contribution from each relation in Sumcheck
    using RelationUnivariates = decltype(create_relation_univariates_container<FF, Relations>());
    using RelationValues = decltype(create_relation_values_container<FF, Relations>());

    // Whether or not the first row of the execution trace is reserved for 0s to enable shifts
    static constexpr bool has_zero_row = true;

  private:
    template <typename DataType, typename HandleType>
    /**
     * @brief A base class labelling precomputed entities and (ordered) subsets of interest.
     * @details Used to build the proving key and verification key.
     */
    class PrecomputedEntities : public PrecomputedEntities_<DataType, HandleType, NUM_PRECOMPUTED_ENTITIES> {
      public:
        DataType& q_m = std::get<0>(this->_data);
        DataType& q_c = std::get<1>(this->_data);
        DataType& q_l = std::get<2>(this->_data);
        DataType& q_r = std::get<3>(this->_data);
        DataType& q_o = std::get<4>(this->_data);
        DataType& q_4 = std::get<5>(this->_data);
        DataType& q_arith = std::get<6>(this->_data);
        DataType& q_sort = std::get<7>(this->_data);
        DataType& q_elliptic = std::get<8>(this->_data);
        DataType& q_aux = std::get<9>(this->_data);
        DataType& q_lookup = std::get<10>(this->_data);
        DataType& sigma_1 = std::get<11>(this->_data);
        DataType& sigma_2 = std::get<12>(this->_data);
        DataType& sigma_3 = std::get<13>(this->_data);
        DataType& sigma_4 = std::get<14>(this->_data);
        DataType& id_1 = std::get<15>(this->_data);
        DataType& id_2 = std::get<16>(this->_data);
        DataType& id_3 = std::get<17>(this->_data);
        DataType& id_4 = std::get<18>(this->_data);
        DataType& table_1 = std::get<19>(this->_data);
        DataType& table_2 = std::get<20>(this->_data);
        DataType& table_3 = std::get<21>(this->_data);
        DataType& table_4 = std::get<22>(this->_data);
        DataType& lagrange_first = std::get<23>(this->_data);
        DataType& lagrange_last = std::get<24>(this->_data);

        static constexpr CircuitType CIRCUIT_TYPE = CircuitBuilder::CIRCUIT_TYPE;

        std::vector<HandleType> get_selectors() override
        {
            return { q_m, q_c, q_l, q_r, q_o, q_4, q_arith, q_sort, q_elliptic, q_aux, q_lookup };
        };
        std::vector<HandleType> get_sigma_polynomials() override { return { sigma_1, sigma_2, sigma_3, sigma_4 }; };
        std::vector<HandleType> get_id_polynomials() override { return { id_1, id_2, id_3, id_4 }; };

        std::vector<HandleType> get_table_polynomials() { return { table_1, table_2, table_3, table_4 }; };
    };

    /**
     * @brief Container for all witness polynomials used/constructed by the prover.
     * @details Shifts are not included here since they do not occupy their own memory.
     */
    template <typename DataType, typename HandleType>
    class WitnessEntities : public WitnessEntities_<DataType, HandleType, NUM_WITNESS_ENTITIES> {
      public:
        DataType& w_l = std::get<0>(this->_data);
        DataType& w_r = std::get<1>(this->_data);
        DataType& w_o = std::get<2>(this->_data);
        DataType& w_4 = std::get<3>(this->_data);
        DataType& sorted_1 = std::get<4>(this->_data);
        DataType& sorted_2 = std::get<5>(this->_data);
        DataType& sorted_3 = std::get<6>(this->_data);
        DataType& sorted_4 = std::get<7>(this->_data);
        DataType& sorted_accum = std::get<8>(this->_data);
        DataType& z_perm = std::get<9>(this->_data);
        DataType& z_lookup = std::get<10>(this->_data);

        std::vector<HandleType> get_wires() override { return { w_l, w_r, w_o, w_4 }; };
        // The sorted concatenations of table and witness data needed for plookup.
        std::vector<HandleType> get_sorted_polynomials() { return { sorted_1, sorted_2, sorted_3, sorted_4 }; };
    };

    /**
     * @brief A base class labelling all entities (for instance, all of the polynomials used by the prover during
     * sumcheck) in this Honk variant along with particular subsets of interest
     * @details Used to build containers for: the prover's polynomial during sumcheck; the sumcheck's folded
     * polynomials; the univariates consturcted during during sumcheck; the evaluations produced by sumcheck.
     *
     * Symbolically we have: AllEntities = PrecomputedEntities + WitnessEntities + "ShiftedEntities". It could be
     * implemented as such, but we have this now.
     */
    template <typename DataType, typename HandleType>
    class AllEntities : public AllEntities_<DataType, HandleType, NUM_ALL_ENTITIES> {
      public:
        DataType& q_c = std::get<0>(this->_data);
        DataType& q_l = std::get<1>(this->_data);
        DataType& q_r = std::get<2>(this->_data);
        DataType& q_o = std::get<3>(this->_data);
        DataType& q_4 = std::get<4>(this->_data);
        DataType& q_m = std::get<5>(this->_data);
        DataType& q_arith = std::get<6>(this->_data);
        DataType& q_sort = std::get<7>(this->_data);
        DataType& q_elliptic = std::get<8>(this->_data);
        DataType& q_aux = std::get<9>(this->_data);
        DataType& q_lookup = std::get<10>(this->_data);
        DataType& sigma_1 = std::get<11>(this->_data);
        DataType& sigma_2 = std::get<12>(this->_data);
        DataType& sigma_3 = std::get<13>(this->_data);
        DataType& sigma_4 = std::get<14>(this->_data);
        DataType& id_1 = std::get<15>(this->_data);
        DataType& id_2 = std::get<16>(this->_data);
        DataType& id_3 = std::get<17>(this->_data);
        DataType& id_4 = std::get<18>(this->_data);
        DataType& table_1 = std::get<19>(this->_data);
        DataType& table_2 = std::get<20>(this->_data);
        DataType& table_3 = std::get<21>(this->_data);
        DataType& table_4 = std::get<22>(this->_data);
        DataType& lagrange_first = std::get<23>(this->_data);
        DataType& lagrange_last = std::get<24>(this->_data);
        DataType& w_l = std::get<25>(this->_data);
        DataType& w_r = std::get<26>(this->_data);
        DataType& w_o = std::get<27>(this->_data);
        DataType& w_4 = std::get<28>(this->_data);
        DataType& sorted_accum = std::get<29>(this->_data);
        DataType& z_perm = std::get<30>(this->_data);
        DataType& z_lookup = std::get<31>(this->_data);
        DataType& table_1_shift = std::get<32>(this->_data);
        DataType& table_2_shift = std::get<33>(this->_data);
        DataType& table_3_shift = std::get<34>(this->_data);
        DataType& table_4_shift = std::get<35>(this->_data);
        DataType& w_l_shift = std::get<36>(this->_data);
        DataType& w_r_shift = std::get<37>(this->_data);
        DataType& w_o_shift = std::get<38>(this->_data);
        DataType& w_4_shift = std::get<39>(this->_data);
        DataType& sorted_accum_shift = std::get<40>(this->_data);
        DataType& z_perm_shift = std::get<41>(this->_data);
        DataType& z_lookup_shift = std::get<42>(this->_data);

        std::vector<HandleType> get_wires() override { return { w_l, w_r, w_o, w_4 }; };
        // Gemini-specific getters.
        std::vector<HandleType> get_unshifted() override
        {
            return { q_c,           q_l,   q_r,      q_o,     q_4,     q_m,          q_arith, q_sort,
                     q_elliptic,    q_aux, q_lookup, sigma_1, sigma_2, sigma_3,      sigma_4, id_1,
                     id_2,          id_3,  id_4,     table_1, table_2, table_3,      table_4, lagrange_first,
                     lagrange_last, w_l,   w_r,      w_o,     w_4,     sorted_accum, z_perm,  z_lookup

            };
        };
        std::vector<HandleType> get_to_be_shifted() override
        {
            return { table_1, table_2, table_3, table_4, w_l, w_r, w_o, w_4, sorted_accum, z_perm, z_lookup };
        };
        std::vector<HandleType> get_shifted() override
        {
            return { table_1_shift, table_2_shift, table_3_shift,      table_4_shift, w_l_shift,     w_r_shift,
                     w_o_shift,     w_4_shift,     sorted_accum_shift, z_perm_shift,  z_lookup_shift };
        };

        AllEntities() = default;

        AllEntities(const AllEntities& other)
            : AllEntities_<DataType, HandleType, NUM_ALL_ENTITIES>(other){};

        AllEntities(AllEntities&& other)
            : AllEntities_<DataType, HandleType, NUM_ALL_ENTITIES>(other){};

        AllEntities& operator=(const AllEntities& other)
        {
            if (this == &other) {
                return *this;
            }
            AllEntities_<DataType, HandleType, NUM_ALL_ENTITIES>::operator=(other);
            return *this;
        }

        AllEntities& operator=(AllEntities&& other)
        {
            AllEntities_<DataType, HandleType, NUM_ALL_ENTITIES>::operator=(other);
            return *this;
        }

        ~AllEntities() = default;
    };

  public:
    /**
     * @brief The proving key is responsible for storing the polynomials used by the prover.
     * @note TODO(Cody): Maybe multiple inheritance is the right thing here. In that case, nothing should eve inherit
     * from ProvingKey.
     */
    class ProvingKey : public ProvingKey_<PrecomputedEntities<Polynomial, PolynomialHandle>,
                                          WitnessEntities<Polynomial, PolynomialHandle>> {
      public:
        // Expose constructors on the base class
        using Base = ProvingKey_<PrecomputedEntities<Polynomial, PolynomialHandle>,
                                 WitnessEntities<Polynomial, PolynomialHandle>>;
        using Base::Base;

        std::vector<uint32_t> memory_read_records;
        std::vector<uint32_t> memory_write_records;

        // The plookup wires that store plookup read data.
        std::array<PolynomialHandle, 3> get_table_column_wires() { return { w_l, w_r, w_o }; };
    };

    /**
     * @brief The verification key is responsible for storing the the commitments to the precomputed (non-witnessk)
     * polynomials used by the verifier.
     *
     * @note Note the discrepancy with what sort of data is stored here vs in the proving key. We may want to resolve
     * that, and split out separate PrecomputedPolynomials/Commitments data for clarity but also for portability of our
     * circuits.
     */
    using VerificationKey = VerificationKey_<PrecomputedEntities<Commitment, CommitmentHandle>>;

    /**
     * @brief A container for polynomials handles; only stores spans.
     */
    using ProverPolynomials = AllEntities<PolynomialHandle, PolynomialHandle>;

    /**
     * @brief A container for storing the partially evaluated multivariates produced by sumcheck.
     */
    class PartiallyEvaluatedMultivariates : public AllEntities<Polynomial, PolynomialHandle> {

      public:
        PartiallyEvaluatedMultivariates() = default;
        PartiallyEvaluatedMultivariates(const size_t circuit_size)
        {
            // Storage is only needed after the first partial evaluation, hence polynomials of size (n / 2)
            for (auto& poly : this->_data) {
                poly = Polynomial(circuit_size / 2);
            }
        }
    };

    /**
     * @brief A container for univariates produced during the hot loop in sumcheck.
     * @todo TODO(#390): Simplify this by moving MAX_RELATION_LENGTH?
     */
    template <size_t MAX_RELATION_LENGTH>
    using ExtendedEdges = AllEntities<barretenberg::Univariate<FF, MAX_RELATION_LENGTH>,
                                      barretenberg::Univariate<FF, MAX_RELATION_LENGTH>>;

    /**
     * @brief A container for the polynomials evaluations produced during sumcheck, which are purported to be the
     * evaluations of polynomials committed in earlier rounds.
     */
    class ClaimedEvaluations : public AllEntities<FF, FF> {
      public:
        using Base = AllEntities<FF, FF>;
        using Base::Base;
        ClaimedEvaluations(std::array<FF, NUM_ALL_ENTITIES> _data_in) { this->_data = _data_in; }
    };

    /**
     * @brief A container for commitment labels.
     * @note It's debatable whether this should inherit from AllEntities. since most entries are not strictly needed. It
     * has, however, been useful during debugging to have these labels available.
     *
     */
    class CommitmentLabels : public AllEntities<std::string, std::string> {
      public:
        CommitmentLabels()
        {
            w_l = "W_L";
            w_r = "W_R";
            w_o = "W_O";
            w_4 = "W_4";
            z_perm = "Z_PERM";
            z_lookup = "Z_LOOKUP";
            sorted_accum = "SORTED_ACCUM";

            // The ones beginning with "__" are only used for debugging
            q_c = "__Q_C";
            q_l = "__Q_L";
            q_r = "__Q_R";
            q_o = "__Q_O";
            q_4 = "__Q_4";
            q_m = "__Q_M";
            q_arith = "__Q_ARITH";
            q_sort = "__Q_SORT";
            q_elliptic = "__Q_ELLIPTIC";
            q_aux = "__Q_AUX";
            q_lookup = "__Q_LOOKUP";
            sigma_1 = "__SIGMA_1";
            sigma_2 = "__SIGMA_2";
            sigma_3 = "__SIGMA_3";
            sigma_4 = "__SIGMA_4";
            id_1 = "__ID_1";
            id_2 = "__ID_2";
            id_3 = "__ID_3";
            id_4 = "__ID_4";
            table_1 = "__TABLE_1";
            table_2 = "__TABLE_2";
            table_3 = "__TABLE_3";
            table_4 = "__TABLE_4";
            lagrange_first = "__LAGRANGE_FIRST";
            lagrange_last = "__LAGRANGE_LAST";
        };
    };

    class VerifierCommitments : public AllEntities<Commitment, CommitmentHandle> {
      public:
        VerifierCommitments(std::shared_ptr<VerificationKey> verification_key, VerifierTranscript<FF> transcript)
        {
            static_cast<void>(transcript);
            q_m = verification_key->q_m;
            q_l = verification_key->q_l;
            q_r = verification_key->q_r;
            q_o = verification_key->q_o;
            q_4 = verification_key->q_4;
            q_c = verification_key->q_c;
            q_arith = verification_key->q_arith;
            q_sort = verification_key->q_sort;
            q_elliptic = verification_key->q_elliptic;
            q_aux = verification_key->q_aux;
            q_lookup = verification_key->q_lookup;
            sigma_1 = verification_key->sigma_1;
            sigma_2 = verification_key->sigma_2;
            sigma_3 = verification_key->sigma_3;
            sigma_4 = verification_key->sigma_4;
            id_1 = verification_key->id_1;
            id_2 = verification_key->id_2;
            id_3 = verification_key->id_3;
            id_4 = verification_key->id_4;
            table_1 = verification_key->table_1;
            table_2 = verification_key->table_2;
            table_3 = verification_key->table_3;
            table_4 = verification_key->table_4;
            lagrange_first = verification_key->lagrange_first;
            lagrange_last = verification_key->lagrange_last;
        }
    };

    class FoldingParameters {
      public:
        FF gate_separation_challenge;
        FF target_sum;
    };

    class Transcript : public BaseTranscript<FF> {
      public:
        uint32_t circuit_size;
        uint32_t public_input_size;
        uint32_t pub_inputs_offset;
        FF public_input_0;
        GroupElement w_l_comm;
        GroupElement w_r_comm;
        GroupElement w_o_comm;
        GroupElement sorted_accum_comm;
        GroupElement w_4_comm;
        GroupElement z_perm_comm;
        GroupElement z_lookup_comm;
        std::vector<barretenberg::Univariate<FF, MAX_RELATION_LENGTH>> sumcheck_univariates;
        std::array<FF, NUM_ALL_ENTITIES> sumcheck_evaluations;
        std::vector<GroupElement> gemini_univariate_comms;
        std::vector<FF> gemini_a_evals;
        GroupElement shplonk_q_comm;
        GroupElement kzg_w_comm;

      private:
        template <typename T> inline TranscriptObjectType convertTypeToEnum([[maybe_unused]] T _)
        {
            if constexpr (std::same_as<T, uint32_t>) {
                return UInt32Obj;
            } else if constexpr (std::same_as<T, FF>) {
                return FieldElementObj;
            } else if constexpr (std::same_as<T, GroupElement>) {
                return GroupElementObj;
            } else if constexpr (std::same_as<T, Univariate<FF, MAX_RELATION_LENGTH>>) {
                return SumcheckUnivariateObj;
            } else if constexpr (std::same_as<T, std::array<FF, NUM_ALL_ENTITIES>>) {
                return SumcheckEvalObj;
            } else {
                throw_or_abort("Received unknown type in convertTypeToEnum");
            }
        }

        template <typename T> T convertTypePtrFromEnum(TranscriptObjectType enum_type, void* obj_ptr)
        {
            switch (enum_type) {
            case UInt32Obj:
                return (static_cast<uint32_t*>(obj_ptr));
            case FieldElementObj:
                return (static_cast<FF*>(obj_ptr));
            case GroupElementObj:
                return (static_cast<GroupElement*>(obj_ptr));
            case SumcheckUnivariateObj:
                return (static_cast<Univariate<FF, MAX_RELATION_LENGTH>*>(obj_ptr));
            case SumcheckEvalObj:
                return (static_cast<std::array<FF, NUM_ALL_ENTITIES>*>(obj_ptr));
            default:
                throw_or_abort("Received unknown enum type in convertTypePtrFromEnum");
            }
        }

        void setUpStructure(uint32_t circuit_size)
        {
            // construct the vector
            auto log_n = numeric::get_msb(circuit_size);
            // resize the vectors to be the correct size based on circuit size
            sumcheck_univariates.resize(log_n);
            gemini_univariate_comms.resize(log_n);
            gemini_a_evals.resize(log_n);

            ordered_objects.emplace_back("circuit_size", &circuit_size, convertTypeToEnum(circuit_size));
            ordered_objects.emplace_back("public_input_size", &public_input_size, convertTypeToEnum(public_input_size));
            ordered_objects.emplace_back("pub_inputs_offset", &pub_inputs_offset, convertTypeToEnum(pub_inputs_offset));
            ordered_objects.emplace_back("public_input_0", &public_input_0, convertTypeToEnum(public_input_0));
            ordered_objects.emplace_back("w_l_comm", &w_l_comm, convertTypeToEnum(w_l_comm));
            ordered_objects.emplace_back("w_r_comm", &w_r_comm, convertTypeToEnum(w_r_comm));
            ordered_objects.emplace_back("w_o_comm", &w_o_comm, convertTypeToEnum(w_o_comm));
            ordered_objects.emplace_back("sorted_accum_comm", &sorted_accum_comm, convertTypeToEnum(sorted_accum_comm));
            ordered_objects.emplace_back("w_4_comm", &w_4_comm, convertTypeToEnum(w_4_comm));
            ordered_objects.emplace_back("z_perm_comm", &z_perm_comm, convertTypeToEnum(z_perm_comm));
            ordered_objects.emplace_back("z_lookup_comm", &z_lookup_comm, convertTypeToEnum(z_lookup_comm));
            for (size_t i = 0; i < log_n; ++i) {
                std::string idx = std::to_string(i);
                ordered_objects.emplace_back(
                    "sumcheck_univariate_" + idx, &sumcheck_univariates[i], convertTypeToEnum(sumcheck_univariates[i]));
            }
            ordered_objects.emplace_back(
                "sumcheck_evaluations", &sumcheck_evaluations, convertTypeToEnum(sumcheck_evaluations));
            for (size_t i = 0; i < log_n; ++i) {
                std::string idx = std::to_string(i);
                ordered_objects.emplace_back("gemini_univariate_comm_" + idx,
                                             &gemini_univariate_comms[i],
                                             convertTypeToEnum(gemini_univariate_comms[i]));
            }
            for (size_t i = 0; i < log_n; ++i) {
                std::string idx = std::to_string(i);
                ordered_objects.emplace_back(
                    "gemini_a_eval_" + idx, &gemini_a_evals[i], convertTypeToEnum(gemini_a_evals[i]));
            }
            ordered_objects.emplace_back("shplonk_q_comm", &shplonk_q_comm, convertTypeToEnum(shplonk_q_comm));
            ordered_objects.emplace_back("kzg_w_comm", &kzg_w_comm, convertTypeToEnum(kzg_w_comm));
        }
    };
};

} // namespace proof_system::honk::flavor
