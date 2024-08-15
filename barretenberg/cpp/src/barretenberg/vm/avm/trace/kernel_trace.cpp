#include "barretenberg/vm/avm/trace/kernel_trace.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/vm/avm/generated/full_row.hpp"
#include "barretenberg/vm/avm/trace/common.hpp"
#include "barretenberg/vm/avm/trace/finalization.hpp"
#include "barretenberg/vm/avm/trace/trace.hpp"
#include "barretenberg/vm/constants.hpp"

#include <cstdint>
#include <sys/types.h>

// For the meantime, we do not fire around the public inputs as a vector or otherwise
// Instead we fire them around as a fixed length array from the kernel, as that is how they will be

namespace bb::avm_trace {

void AvmKernelTraceBuilder::reset()
{
    kernel_input_selector_counter.clear();
    kernel_output_selector_counter.clear();
}

FF AvmKernelTraceBuilder::perform_kernel_input_lookup(uint32_t selector)
{
    FF result = std::get<0>(public_inputs)[selector];
    kernel_input_selector_counter[selector]++;
    return result;
}

void AvmKernelTraceBuilder::perform_kernel_output_lookup(uint32_t write_offset,
                                                         uint32_t side_effect_counter,
                                                         const FF& value,
                                                         const FF& metadata)
{
    std::get<KERNEL_OUTPUTS_VALUE>(public_inputs)[write_offset] = value;
    std::get<KERNEL_OUTPUTS_SIDE_EFFECT_COUNTER>(public_inputs)[write_offset] = side_effect_counter;
    std::get<KERNEL_OUTPUTS_METADATA>(public_inputs)[write_offset] = metadata;

    // Lookup counts
    kernel_output_selector_counter[write_offset]++;
}

// We want to be able to get the return value from the public inputs column
// Get the return value, this will be places in ia
// We read from the public inputs that were provided to the kernel
FF AvmKernelTraceBuilder::op_address()
{
    return perform_kernel_input_lookup(ADDRESS_SELECTOR);
}
FF AvmKernelTraceBuilder::op_storage_address()
{
    return perform_kernel_input_lookup(STORAGE_ADDRESS_SELECTOR);
}

FF AvmKernelTraceBuilder::op_sender()
{
    return perform_kernel_input_lookup(SENDER_SELECTOR);
}

FF AvmKernelTraceBuilder::op_function_selector()
{
    return perform_kernel_input_lookup(FUNCTION_SELECTOR_SELECTOR);
}

FF AvmKernelTraceBuilder::op_transaction_fee()
{
    return perform_kernel_input_lookup(TRANSACTION_FEE_SELECTOR);
}

FF AvmKernelTraceBuilder::op_chain_id()
{
    return perform_kernel_input_lookup(CHAIN_ID_SELECTOR);
}

FF AvmKernelTraceBuilder::op_version()
{
    return perform_kernel_input_lookup(VERSION_SELECTOR);
}

FF AvmKernelTraceBuilder::op_block_number()
{
    return perform_kernel_input_lookup(BLOCK_NUMBER_SELECTOR);
}

FF AvmKernelTraceBuilder::op_coinbase()
{
    return perform_kernel_input_lookup(COINBASE_SELECTOR);
}

FF AvmKernelTraceBuilder::op_timestamp()
{
    return perform_kernel_input_lookup(TIMESTAMP_SELECTOR);
}

FF AvmKernelTraceBuilder::op_fee_per_da_gas()
{
    return perform_kernel_input_lookup(FEE_PER_DA_GAS_SELECTOR);
}

FF AvmKernelTraceBuilder::op_fee_per_l2_gas()
{
    return perform_kernel_input_lookup(FEE_PER_L2_GAS_SELECTOR);
}

// TODO(https://github.com/AztecProtocol/aztec-packages/issues/6481): need to process hint from avm in order to know if
// output should be set to true or not
void AvmKernelTraceBuilder::op_note_hash_exists(uint32_t clk,
                                                uint32_t side_effect_counter,
                                                const FF& note_hash,
                                                uint32_t result)
{

    uint32_t offset = START_NOTE_HASH_EXISTS_WRITE_OFFSET + note_hash_exists_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, note_hash, FF(result));
    note_hash_exists_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::NOTE_HASH_EXISTS,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_emit_note_hash(uint32_t clk, uint32_t side_effect_counter, const FF& note_hash)
{
    uint32_t offset = START_EMIT_NOTE_HASH_WRITE_OFFSET + emit_note_hash_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, note_hash, FF(0));
    emit_note_hash_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::EMIT_NOTE_HASH,
    };
    kernel_trace.push_back(entry);
}

// TODO(https://github.com/AztecProtocol/aztec-packages/issues/6481): need to process hint from avm in order to know if
// output should be set to true or not
void AvmKernelTraceBuilder::op_nullifier_exists(uint32_t clk,
                                                uint32_t side_effect_counter,
                                                const FF& nullifier,
                                                uint32_t result)
{
    uint32_t offset = 0;
    if (result == 1) {
        offset = START_NULLIFIER_EXISTS_OFFSET + nullifier_exists_offset;
        nullifier_exists_offset++;
    } else {
        offset = START_NULLIFIER_NON_EXISTS_OFFSET + nullifier_non_exists_offset;
        nullifier_non_exists_offset++;
    }
    perform_kernel_output_lookup(offset, side_effect_counter, nullifier, FF(result));

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::NULLIFIER_EXISTS,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_emit_nullifier(uint32_t clk, uint32_t side_effect_counter, const FF& nullifier)
{
    uint32_t offset = START_EMIT_NULLIFIER_WRITE_OFFSET + emit_nullifier_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, nullifier, FF(0));
    emit_nullifier_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::EMIT_NULLIFIER,
    };
    kernel_trace.push_back(entry);
}

// TODO(https://github.com/AztecProtocol/aztec-packages/issues/6481): need to process hint from avm in order to know if
// output should be set to true or not
void AvmKernelTraceBuilder::op_l1_to_l2_msg_exists(uint32_t clk,
                                                   uint32_t side_effect_counter,
                                                   const FF& message,
                                                   uint32_t result)
{
    uint32_t offset = START_L1_TO_L2_MSG_EXISTS_WRITE_OFFSET + l1_to_l2_msg_exists_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, message, FF(result));
    l1_to_l2_msg_exists_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::L1_TO_L2_MSG_EXISTS,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_emit_unencrypted_log(uint32_t clk, uint32_t side_effect_counter, const FF& log_hash)
{
    uint32_t offset = START_EMIT_UNENCRYPTED_LOG_WRITE_OFFSET + emit_unencrypted_log_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, log_hash, FF(0));
    emit_unencrypted_log_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::EMIT_UNENCRYPTED_LOG,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_emit_l2_to_l1_msg(uint32_t clk,
                                                 uint32_t side_effect_counter,
                                                 const FF& l2_to_l1_msg,
                                                 const FF& recipient)
{
    uint32_t offset = START_EMIT_L2_TO_L1_MSG_WRITE_OFFSET + emit_l2_to_l1_msg_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, l2_to_l1_msg, recipient);
    emit_l2_to_l1_msg_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::EMIT_L2_TO_L1_MSG,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_sload(uint32_t clk, uint32_t side_effect_counter, const FF& slot, const FF& value)
{
    uint32_t offset = START_SLOAD_WRITE_OFFSET + sload_write_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, value, slot);
    sload_write_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::SLOAD,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::op_sstore(uint32_t clk, uint32_t side_effect_counter, const FF& slot, const FF& value)
{
    uint32_t offset = START_SSTORE_WRITE_OFFSET + sstore_write_offset;
    perform_kernel_output_lookup(offset, side_effect_counter, value, slot);
    sstore_write_offset++;

    KernelTraceEntry entry = {
        .clk = clk,
        .kernel_out_offset = offset,
        .q_kernel_output_lookup = true,
        .operation = KernelTraceOpType::SSTORE,
    };
    kernel_trace.push_back(entry);
}

void AvmKernelTraceBuilder::finalize(std::vector<AvmFullRow<FF>>& main_trace)
{
    // Write the kernel trace into the main trace
    // 1. The write offsets are constrained to be non changing over the entire trace, so we fill in the values
    // until we hit an operation that changes one of the write_offsets (a relevant opcode)
    // 2. Upon hitting the clk of each kernel operation we copy the values into the main trace
    // 3. When an increment is required, we increment the value in the next row, then continue the process until
    // the end
    // 4. Whenever we hit the last row, we zero all write_offsets such that the shift relation will succeed

    // Index 0 corresponds here to the first active row of the main execution trace.
    // Initialization of side_effect_counter occurs occurs on this row.
    main_trace.at(0).kernel_side_effect_counter = initial_side_effect_counter;

    // This index is required to retrieve the right side effect counter after an external call.
    size_t external_call_cnt = 0;

    iterate_with_padding_action(
        kernel_trace,
        main_trace,
        // Action to be performed on each kernel trace entry
        [&](size_t src_idx, size_t dst_idx) {
            const auto& src = kernel_trace.at(src_idx);
            auto& dest = main_trace.at(dst_idx);

            // Operation selectors
            switch (src.operation) {
            case KernelTraceOpType::NOTE_HASH_EXISTS:
                dest.main_sel_op_note_hash_exists = 1;
                break;
            case KernelTraceOpType::EMIT_NOTE_HASH:
                dest.main_sel_op_emit_note_hash = 1;
                break;
            case KernelTraceOpType::NULLIFIER_EXISTS:
                dest.main_sel_op_nullifier_exists = 1;
                break;
            case KernelTraceOpType::EMIT_NULLIFIER:
                dest.main_sel_op_emit_nullifier = 1;
                break;
            case KernelTraceOpType::L1_TO_L2_MSG_EXISTS:
                dest.main_sel_op_l1_to_l2_msg_exists = 1;
                break;
            case KernelTraceOpType::EMIT_UNENCRYPTED_LOG:
                dest.main_sel_op_emit_unencrypted_log = 1;
                break;
            case KernelTraceOpType::EMIT_L2_TO_L1_MSG:
                dest.main_sel_op_emit_l2_to_l1_msg = 1;
                break;
            case KernelTraceOpType::SLOAD:
                dest.main_sel_op_sload = 1;
                break;
            case KernelTraceOpType::SSTORE:
                dest.main_sel_op_sstore = 1;
                break;
            default:
                throw_or_abort("Invalid operation selector");
            }

            // We have reached the last main trace row.
            if (main_trace.size() < dst_idx + 1) {
                return;
            }

            auto& next = main_trace.at(dst_idx + 1);
            // Increment the write offset counter for the following row
            next.kernel_note_hash_exist_write_offset =
                dest.kernel_note_hash_exist_write_offset + dest.main_sel_op_note_hash_exists;
            next.kernel_emit_note_hash_write_offset =
                dest.kernel_emit_note_hash_write_offset + dest.main_sel_op_emit_note_hash;
            next.kernel_emit_nullifier_write_offset =
                dest.kernel_emit_nullifier_write_offset + dest.main_sel_op_emit_nullifier;
            next.kernel_nullifier_exists_write_offset =
                dest.kernel_nullifier_exists_write_offset + (dest.main_sel_op_nullifier_exists * dest.main_ib);
            next.kernel_nullifier_non_exists_write_offset =
                dest.kernel_nullifier_non_exists_write_offset +
                (dest.main_sel_op_nullifier_exists * (FF(1) - dest.main_ib));
            next.kernel_l1_to_l2_msg_exists_write_offset =
                dest.kernel_l1_to_l2_msg_exists_write_offset + dest.main_sel_op_l1_to_l2_msg_exists;
            next.kernel_emit_l2_to_l1_msg_write_offset =
                dest.kernel_emit_l2_to_l1_msg_write_offset + dest.main_sel_op_emit_l2_to_l1_msg;
            next.kernel_emit_unencrypted_log_write_offset =
                dest.kernel_emit_unencrypted_log_write_offset + dest.main_sel_op_emit_unencrypted_log;
            next.kernel_sload_write_offset = dest.kernel_sload_write_offset + dest.main_sel_op_sload;
            next.kernel_sstore_write_offset = dest.kernel_sstore_write_offset + dest.main_sel_op_sstore;

            // The side effect counter will increment regardless of the offset value
            next.kernel_side_effect_counter = dest.kernel_side_effect_counter + 1;
        },
        // Action to be performed on each row of the main trace
        // when there is no corresponding kernel trace entry
        [&](size_t dst_idx) {
            const auto& prev = main_trace.at(dst_idx - 1);
            auto& dest = main_trace.at(dst_idx);

            dest.kernel_note_hash_exist_write_offset = prev.kernel_note_hash_exist_write_offset;
            dest.kernel_emit_note_hash_write_offset = prev.kernel_emit_note_hash_write_offset;
            dest.kernel_nullifier_exists_write_offset = prev.kernel_nullifier_exists_write_offset;
            dest.kernel_nullifier_non_exists_write_offset = prev.kernel_nullifier_non_exists_write_offset;
            dest.kernel_emit_nullifier_write_offset = prev.kernel_emit_nullifier_write_offset;
            dest.kernel_emit_l2_to_l1_msg_write_offset = prev.kernel_emit_l2_to_l1_msg_write_offset;
            dest.kernel_emit_unencrypted_log_write_offset = prev.kernel_emit_unencrypted_log_write_offset;
            dest.kernel_l1_to_l2_msg_exists_write_offset = prev.kernel_l1_to_l2_msg_exists_write_offset;
            dest.kernel_sload_write_offset = prev.kernel_sload_write_offset;
            dest.kernel_sstore_write_offset = prev.kernel_sstore_write_offset;

            // Adjust side effect counter after an external call
            if (prev.main_sel_op_external_call == 1) {
                dest.kernel_side_effect_counter =
                    hints.externalcall_hints.at(external_call_cnt).end_side_effect_counter;
                external_call_cnt++;
            } else {
                dest.kernel_side_effect_counter = prev.kernel_side_effect_counter;
            }
        });
}

// Public Input Columns Inclusion
// Crucial to add these columns after the extra row was added.
void AvmKernelTraceBuilder::finalize_columns(std::vector<AvmFullRow<FF>>& main_trace) const
{
    // Write lookup counts for inputs
    for (uint32_t i = 0; i < KERNEL_INPUTS_LENGTH; i++) {
        auto value = kernel_input_selector_counter.find(i);
        if (value != kernel_input_selector_counter.end()) {
            auto& dest = main_trace.at(i);
            dest.lookup_into_kernel_counts = FF(value->second);
            dest.kernel_q_public_input_kernel_add_to_table = FF(1);
        }
    }

    // Copy the kernel input public inputs
    for (size_t i = 0; i < KERNEL_INPUTS_LENGTH; i++) {
        main_trace.at(i).kernel_kernel_inputs = std::get<KERNEL_INPUTS>(public_inputs).at(i);
    }

    // Write lookup counts for outputs
    for (uint32_t i = 0; i < KERNEL_OUTPUTS_LENGTH; i++) {
        auto value = kernel_output_selector_counter.find(i);
        if (value != kernel_output_selector_counter.end()) {
            auto& dest = main_trace.at(i);
            dest.kernel_output_lookup_counts = FF(value->second);
            dest.kernel_q_public_input_kernel_out_add_to_table = FF(1);
        }
    }

    // Copy the kernel outputs counts into the main trace
    for (size_t i = 0; i < KERNEL_OUTPUTS_LENGTH; i++) {
        main_trace.at(i).kernel_kernel_value_out = std::get<KERNEL_OUTPUTS_VALUE>(public_inputs).at(i);

        main_trace.at(i).kernel_kernel_side_effect_out =
            std::get<KERNEL_OUTPUTS_SIDE_EFFECT_COUNTER>(public_inputs).at(i);

        main_trace.at(i).kernel_kernel_metadata_out = std::get<KERNEL_OUTPUTS_METADATA>(public_inputs).at(i);
    }
}

} // namespace bb::avm_trace
