#include "pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
namespace proof_system::plonk::stdlib {

using namespace barretenberg;
using namespace proof_system;

template <typename C>
field_t<C> pedersen_hash<C>::hash(const std::vector<field_t>& inputs, const GeneratorContext context)
{
    using cycle_scalar = typename cycle_group::cycle_scalar;
    using Curve = EmbeddedCurve;

    const auto base_points = context.generators->get(inputs.size(), context.offset, context.domain_separator);

    std::vector<cycle_scalar> scalars;
    std::vector<cycle_group> points;
    scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(field_t(inputs.size())));
    points.emplace_back(crypto::pedersen_hash_base<Curve>::length_generator);
    for (size_t i = 0; i < inputs.size(); ++i) {
        scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(inputs[i]));
        // constructs constant cycle_group objects (non-witness)
        points.emplace_back(base_points[i]);
    }

    auto result = cycle_group::batch_mul(scalars, points);
    return result.x;
}

// TODO skip range checks
template <typename C>
field_t<C> pedersen_hash<C>::hash_skip_field_validation(const std::vector<field_t>& inputs,
                                                        const GeneratorContext context)
{
    using cycle_scalar = typename cycle_group::cycle_scalar;
    using Curve = EmbeddedCurve;

    const auto base_points = context.generators->get(inputs.size(), context.offset, context.domain_separator);

    std::vector<cycle_scalar> scalars;
    std::vector<cycle_group> points;
    scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(field_t(inputs.size())));
    points.emplace_back(crypto::pedersen_hash_base<Curve>::length_generator);
    for (size_t i = 0; i < inputs.size(); ++i) {
        scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(inputs[i]));
        // constructs constant cycle_group objects (non-witness)
        points.emplace_back(base_points[i]);
    }

    for (auto& x : scalars) {
        x._skip_primality_test = true;
    }
    auto result = cycle_group::batch_mul(scalars, points);
    return result.x;
}

/**
 * Compress a byte_array.
 *
 * If the input values are all zero, we return the array length instead of "0\"
 * This is because we require the inputs to regular pedersen compression function are nonzero (we use this method to
 * hash the base layer of our merkle trees)
 */
template <typename C>
field_t<C> pedersen_hash<C>::hash_buffer(const stdlib::byte_array<C>& input, GeneratorContext context)
{
    const size_t num_bytes = input.size();
    const size_t bytes_per_element = 31;
    size_t num_elements = static_cast<size_t>(num_bytes % bytes_per_element != 0) + (num_bytes / bytes_per_element);

    std::vector<field_t> elements;
    for (size_t i = 0; i < num_elements; ++i) {
        size_t bytes_to_slice = 0;
        if (i == num_elements - 1) {
            bytes_to_slice = num_bytes - (i * bytes_per_element);
        } else {
            bytes_to_slice = bytes_per_element;
        }
        auto element = static_cast<field_t>(input.slice(i * bytes_per_element, bytes_to_slice));
        elements.emplace_back(element);
    }
    std::cout << "CIRCUIT BEGIN" << std::endl;
    for (auto& x : elements) {
        std::cout << x << std::endl;
    }
    std::cout << "CIRCUIT END" << std::endl;
    field_t hashed;
    if (elements.size() < 2) {
        hashed = hash(elements, context);
    } else {
        hashed = hash({ elements[0], elements[1] }, context);
        for (size_t i = 2; i < elements.size(); ++i) {
            hashed = hash({ hashed, elements[i] }, context);
        }
    }

    // bool_t is_zero(true);
    // for (const auto& element : elements) {
    //     is_zero = is_zero && element.is_zero();
    // }

    // field_t output = field_t::conditional_assign(is_zero, field_t(num_bytes), hashed);
    return hashed;
}

template <typename C>
field_t<C> pedersen_hash<C>::hash(const std::vector<std::pair<field_t, GeneratorContext>>& input_pairs)
{

    using cycle_scalar = typename cycle_group::cycle_scalar;

    std::vector<cycle_scalar> scalars;
    std::vector<cycle_group> points;
    scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(field_t(input_pairs.size())));
    points.emplace_back(crypto::pedersen_hash_base<EmbeddedCurve>::length_generator);
    for (auto& [scalar, context] : input_pairs) {
        scalars.emplace_back(cycle_scalar::create_from_bn254_scalar(scalar));
        // constructs constant cycle_group objects (non-witness)
        points.emplace_back(context.generators->get(1, context.offset, context.domain_separator)[0]);
    }

    return cycle_group::batch_mul(scalars, points).x;
}
INSTANTIATE_STDLIB_TYPE(pedersen_hash);

} // namespace proof_system::plonk::stdlib
