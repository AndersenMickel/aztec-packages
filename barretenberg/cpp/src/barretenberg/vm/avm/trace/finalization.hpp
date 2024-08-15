#pragma once

#include "barretenberg/common/assert.hpp"
#include <cstdint>

namespace bb::avm_trace {

/**
 * @brief Iterates over the main trace and an event trace and performs an action.
 * @details This function iterates on the main trace and an event trace in tandem.
 *          The idea is that if the clk of the event and the main trace row match,
 *          we apply the "mapping function". However, if the clk of the event trace
 *          is ahead of the main trace, then we apply the "padding function" on the
 *          main trace, and advance to the next main trace row.
 */
template <typename S, typename D, typename M, typename P>
void iterate_with_padding_action(const S& src, D& main_trace, M&& fmap, P&& fpad)
{
    size_t src_idx = 0;
    size_t dst_idx = 0;
    while (src_idx < src.size() && dst_idx < main_trace.size()) {
        const auto& src_elem = src.at(src_idx);
        auto& dst_elem = main_trace.at(dst_idx);

        if (FF(src_elem.clk) == dst_elem.main_clk) {
            fmap(src_idx, dst_idx);
            ++src_idx;
            ++dst_idx;
        } else if (FF(src_elem.clk) > dst_elem.main_clk) {
            fpad(dst_idx);
            ++dst_idx;
        } else {
            ASSERT("src_elem.clk < dst_elem.clk, shouldn't happen");
        }

        if (dst_elem.main_sel_last == 1) {
            // We are done with the main trace, stop.
            break;
        }
    }
}

} // namespace bb::avm_trace