#include <algorithm>
#include <iterator>

#include "barretenberg/smt_verification/circuit/circuit.hpp"
#include "barretenberg/stdlib/primitives/uint/uint.hpp"
#include "barretenberg/smt_verification/util/smt_util.hpp"

const std::vector<std::vector<bb::fr>> add_unique_output = {
{0, 0},           // zero_circuit1, zero_circuit2
{1, 1},           // one_circuit1, one_circuit2
{0, 0},           // a_circuit1, a_circuit2
{0, 0},           // var_3_circuit1, var_3_circuit2
{0, 0},           // var_4_circuit1, var_4_circuit2
{0, 0},           // var_5_circuit1, var_5_circuit2
{0, 0},           // var_6_circuit1, var_6_circuit2
{0, 0},           // var_7_circuit1, var_7_circuit2
{0, 0},           // var_8_circuit1, var_8_circuit2
{0, 0},           // var_9_circuit1, var_9_circuit2
{0, 0},           // var_10_circuit1, var_10_circuit2
{0, 0},           // var_11_circuit1, var_11_circuit2
{0, 0},           // var_12_circuit1, var_12_circuit2
{0, 0},           // var_13_circuit1, var_13_circuit2
{0, 0},           // var_14_circuit1, var_14_circuit2
{0, 0},           // var_15_circuit1, var_15_circuit2
{0, 0},           // var_16_circuit1, var_16_circuit2
{0, 0},           // var_17_circuit1, var_17_circuit2
{0, 0},           // var_18_circuit1, var_18_circuit2
{0, 0},           // var_19_circuit1, var_19_circuit2
{0, 0},           // var_20_circuit1, var_20_circuit2
{0, 0},           // var_21_circuit1, var_21_circuit2
{0, 0},           // var_22_circuit1, var_22_circuit2
{0, 0},           // var_23_circuit1, var_23_circuit2
{0, 0},           // var_24_circuit1, var_24_circuit2
{0, 0},           // var_25_circuit1, var_25_circuit2
{0, 0},           // var_26_circuit1, var_26_circuit2
{0, 0},           // var_27_circuit1, var_27_circuit2
{0, 0},           // var_28_circuit1, var_28_circuit2
{0, 0},           // var_29_circuit1, var_29_circuit2
{0, 0},           // var_30_circuit1, var_30_circuit2
{0, 0},           // var_31_circuit1, var_31_circuit2
{0, 0},           // var_32_circuit1, var_32_circuit2
{0, 0},           // var_33_circuit1, var_33_circuit2
{0, 0},           // var_34_circuit1, var_34_circuit2
{0, 0},           // var_35_circuit1, var_35_circuit2
{0, 0},           // var_36_circuit1, var_36_circuit2
{0, 0},           // var_37_circuit1, var_37_circuit2
{0, 0},           // var_38_circuit1, var_38_circuit2
{0, 0},           // var_39_circuit1, var_39_circuit2
{0, 0},           // var_40_circuit1, var_40_circuit2
{0, 0},           // var_41_circuit1, var_41_circuit2
{0, 0},           // var_42_circuit1, var_42_circuit2
{0, 0},           // var_43_circuit1, var_43_circuit2
{0, 0},           // var_44_circuit1, var_44_circuit2
{0, 0},           // var_45_circuit1, var_45_circuit2
{0, 0},           // var_46_circuit1, var_46_circuit2
{0, 0},           // var_47_circuit1, var_47_circuit2
{0, 0},           // var_48_circuit1, var_48_circuit2
{0, 0},           // var_49_circuit1, var_49_circuit2
{0, 0},           // var_50_circuit1, var_50_circuit2
{0, 0},           // var_51_circuit1, var_51_circuit2
{0, 0},           // var_52_circuit1, var_52_circuit2
{0, 0},           // var_53_circuit1, var_53_circuit2
{0, 0},           // var_54_circuit1, var_54_circuit2
{0, 0},           // var_55_circuit1, var_55_circuit2
{0, 0},           // var_56_circuit1, var_56_circuit2
{0, 0},           // var_57_circuit1, var_57_circuit2
{0, 0},           // var_58_circuit1, var_58_circuit2
{0, 0},           // var_59_circuit1, var_59_circuit2
{0, 0},           // var_60_circuit1, var_60_circuit2
{0, 0},           // var_61_circuit1, var_61_circuit2
{0, 0},           // var_62_circuit1, var_62_circuit2
{0, 0},           // var_63_circuit1, var_63_circuit2
{0, 0},           // var_64_circuit1, var_64_circuit2
{0, 0},           // a_circuit1 ,a_circuit2 -> 2
{0, 0},           // b_circuit1, b_circuit2
{0, 0},           // var_67_circuit1, var_67_circuit2
{0, 0},           // var_68_circuit1, var_68_circuit2
{0, 0},           // var_69_circuit1, var_69_circuit2
{0, 0},           // var_70_circuit1, var_70_circuit2
{0, 0},           // var_71_circuit1, var_71_circuit2
{0, 0},           // var_72_circuit1, var_72_circuit2
{0, 0},           // var_73_circuit1, var_73_circuit2
{0, 0},           // var_74_circuit1, var_74_circuit2
{0, 0},           // var_75_circuit1, var_75_circuit2
{0, 0},           // var_76_circuit1, var_76_circuit2
{0, 0},           // var_77_circuit1, var_77_circuit2
{0, 0},           // var_78_circuit1, var_78_circuit2
{0, 0},           // var_79_circuit1, var_79_circuit2
{0, 0},           // var_80_circuit1, var_80_circuit2
{0, 0},           // var_81_circuit1, var_81_circuit2
{0, 0},           // var_82_circuit1, var_82_circuit2
{0, 0},           // var_83_circuit1, var_83_circuit2
{0, 0},           // var_84_circuit1, var_84_circuit2
{0, 0},           // var_85_circuit1, var_85_circuit2
{0, 0},           // var_86_circuit1, var_86_circuit2
{0, 0},           // var_87_circuit1, var_87_circuit2
{0, 0},           // var_88_circuit1, var_88_circuit2
{0, 0},           // var_89_circuit1, var_89_circuit2
{0, 0},           // var_90_circuit1, var_90_circuit2
{0, 0},           // var_91_circuit1, var_91_circuit2
{0, 0},           // var_92_circuit1, var_92_circuit2
{0, 0},           // var_93_circuit1, var_93_circuit2
{0, 0},           // var_94_circuit1, var_94_circuit2
{0, 0},           // var_95_circuit1, var_95_circuit2
{0, 0},           // var_96_circuit1, var_96_circuit2
{0, 0},           // var_97_circuit1, var_97_circuit2
{0, 0},           // var_98_circuit1, var_98_circuit2
{0, 0},           // var_99_circuit1, var_99_circuit2
{0, 0},           // var_100_circuit1, var_100_circuit2
{0, 0},           // var_101_circuit1, var_101_circuit2
{0, 0},           // var_102_circuit1, var_102_circuit2
{0, 0},           // var_103_circuit1, var_103_circuit2
{0, 0},           // var_104_circuit1, var_104_circuit2
{0, 0},           // var_105_circuit1, var_105_circuit2
{0, 0},           // var_106_circuit1, var_106_circuit2
{0, 0},           // var_107_circuit1, var_107_circuit2
{0, 0},           // var_108_circuit1, var_108_circuit2
{0, 0},           // var_109_circuit1, var_109_circuit2
{0, 0},           // var_110_circuit1, var_110_circuit2
{0, 0},           // var_111_circuit1, var_111_circuit2
{0, 0},           // var_112_circuit1, var_112_circuit2
{0, 0},           // var_113_circuit1, var_113_circuit2
{0, 0},           // var_114_circuit1, var_114_circuit2
{0, 0},           // var_115_circuit1, var_115_circuit2
{0, 0},           // var_116_circuit1, var_116_circuit2
{0, 0},           // var_117_circuit1, var_117_circuit2
{0, 0},           // var_118_circuit1, var_118_circuit2
{0, 0},           // var_119_circuit1, var_119_circuit2
{0, 0},           // var_120_circuit1, var_120_circuit2
{0, 0},           // var_121_circuit1, var_121_circuit2
{0, 0},           // var_122_circuit1, var_122_circuit2
{0, 0},           // var_123_circuit1, var_123_circuit2
{0, 0},           // var_124_circuit1, var_124_circuit2
{0, 0},           // var_125_circuit1, var_125_circuit2
{0, 0},           // var_126_circuit1, var_126_circuit2
{0, 0},           // var_127_circuit1, var_127_circuit2
{0, 0},           // var_128_circuit1, var_128_circuit2
{0, 0},           // b_circuit1 ,b_circuit2 -> 66
{-bb::fr(2).pow(32), 0},           // c_circuit1, c_circuit2
{1, 0},           // var_131_circuit1, var_131_circuit2
{0, 0},           // var_132_circuit1, var_132_circuit2
{0, 0},           // var_133_circuit1, var_133_circuit2
};

const std::vector<std::vector<bb::fr>> add_unique_witness = {
{0, 0},           // zero_circuit1, zero_circuit2
{1, 1},           // one_circuit1, one_circuit2
{0, 0},           // a_circuit1, a_circuit2
{0, 0},           // var_3_circuit1, var_3_circuit2
{0, 0},           // var_4_circuit1, var_4_circuit2
{0, 0},           // var_5_circuit1, var_5_circuit2
{0, 0},           // var_6_circuit1, var_6_circuit2
{0, 0},           // var_7_circuit1, var_7_circuit2
{0, 0},           // var_8_circuit1, var_8_circuit2
{0, 0},           // var_9_circuit1, var_9_circuit2
{0, 0},           // var_10_circuit1, var_10_circuit2
{0, 0},           // var_11_circuit1, var_11_circuit2
{0, 0},           // var_12_circuit1, var_12_circuit2
{0, 0},           // var_13_circuit1, var_13_circuit2
{0, 0},           // var_14_circuit1, var_14_circuit2
{0, 0},           // var_15_circuit1, var_15_circuit2
{0, 0},           // var_16_circuit1, var_16_circuit2
{0, 0},           // var_17_circuit1, var_17_circuit2
{0, 0},           // var_18_circuit1, var_18_circuit2
{0, 0},           // var_19_circuit1, var_19_circuit2
{0, 0},           // var_20_circuit1, var_20_circuit2
{0, 0},           // var_21_circuit1, var_21_circuit2
{0, 0},           // var_22_circuit1, var_22_circuit2
{0, 0},           // var_23_circuit1, var_23_circuit2
{0, 0},           // var_24_circuit1, var_24_circuit2
{0, 0},           // var_25_circuit1, var_25_circuit2
{0, 0},           // var_26_circuit1, var_26_circuit2
{0, 0},           // var_27_circuit1, var_27_circuit2
{0, 0},           // var_28_circuit1, var_28_circuit2
{0, 0},           // var_29_circuit1, var_29_circuit2
{0, 0},           // var_30_circuit1, var_30_circuit2
{0, 0},           // var_31_circuit1, var_31_circuit2
{0, 0},           // var_32_circuit1, var_32_circuit2
{0, 0},           // var_33_circuit1, var_33_circuit2
{0, 0},           // var_34_circuit1, var_34_circuit2
{0, 0},           // var_35_circuit1, var_35_circuit2
{0, 0},           // var_36_circuit1, var_36_circuit2
{0, 0},           // var_37_circuit1, var_37_circuit2
{0, 0},           // var_38_circuit1, var_38_circuit2
{0, 0},           // var_39_circuit1, var_39_circuit2
{0, 0},           // var_40_circuit1, var_40_circuit2
{0, 0},           // var_41_circuit1, var_41_circuit2
{0, 0},           // var_42_circuit1, var_42_circuit2
{0, 0},           // var_43_circuit1, var_43_circuit2
{0, 0},           // var_44_circuit1, var_44_circuit2
{0, 0},           // var_45_circuit1, var_45_circuit2
{0, 0},           // var_46_circuit1, var_46_circuit2
{0, 0},           // var_47_circuit1, var_47_circuit2
{0, 0},           // var_48_circuit1, var_48_circuit2
{0, 0},           // var_49_circuit1, var_49_circuit2
{0, 0},           // var_50_circuit1, var_50_circuit2
{0, 0},           // var_51_circuit1, var_51_circuit2
{0, 0},           // var_52_circuit1, var_52_circuit2
{0, 0},           // var_53_circuit1, var_53_circuit2
{0, 0},           // var_54_circuit1, var_54_circuit2
{0, 0},           // var_55_circuit1, var_55_circuit2
{0, 0},           // var_56_circuit1, var_56_circuit2
{0, 0},           // var_57_circuit1, var_57_circuit2
{0, 0},           // var_58_circuit1, var_58_circuit2
{0, 0},           // var_59_circuit1, var_59_circuit2
{0, 0},           // var_60_circuit1, var_60_circuit2
{0, 0},           // var_61_circuit1, var_61_circuit2
{0, 0},           // var_62_circuit1, var_62_circuit2
{0, 0},           // var_63_circuit1, var_63_circuit2
{0, 0},           // var_64_circuit1, var_64_circuit2
{0, 0},           // a_circuit1 ,a_circuit2 -> 2
{0, 0},           // b_circuit1, b_circuit2
{0, 0},           // var_67_circuit1, var_67_circuit2
{0, 0},           // var_68_circuit1, var_68_circuit2
{0, 0},           // var_69_circuit1, var_69_circuit2
{0, 0},           // var_70_circuit1, var_70_circuit2
{0, 0},           // var_71_circuit1, var_71_circuit2
{0, 0},           // var_72_circuit1, var_72_circuit2
{0, 0},           // var_73_circuit1, var_73_circuit2
{0, 0},           // var_74_circuit1, var_74_circuit2
{0, 0},           // var_75_circuit1, var_75_circuit2
{0, 0},           // var_76_circuit1, var_76_circuit2
{0, 0},           // var_77_circuit1, var_77_circuit2
{0, 0},           // var_78_circuit1, var_78_circuit2
{0, 0},           // var_79_circuit1, var_79_circuit2
{0, 0},           // var_80_circuit1, var_80_circuit2
{0, 0},           // var_81_circuit1, var_81_circuit2
{0, 0},           // var_82_circuit1, var_82_circuit2
{0, 0},           // var_83_circuit1, var_83_circuit2
{0, 0},           // var_84_circuit1, var_84_circuit2
{0, 0},           // var_85_circuit1, var_85_circuit2
{0, 0},           // var_86_circuit1, var_86_circuit2
{0, 0},           // var_87_circuit1, var_87_circuit2
{0, 0},           // var_88_circuit1, var_88_circuit2
{0, 0},           // var_89_circuit1, var_89_circuit2
{0, 0},           // var_90_circuit1, var_90_circuit2
{0, 0},           // var_91_circuit1, var_91_circuit2
{0, 0},           // var_92_circuit1, var_92_circuit2
{0, 0},           // var_93_circuit1, var_93_circuit2
{0, 0},           // var_94_circuit1, var_94_circuit2
{0, 0},           // var_95_circuit1, var_95_circuit2
{0, 0},           // var_96_circuit1, var_96_circuit2
{0, 0},           // var_97_circuit1, var_97_circuit2
{0, 0},           // var_98_circuit1, var_98_circuit2
{0, 0},           // var_99_circuit1, var_99_circuit2
{0, 0},           // var_100_circuit1, var_100_circuit2
{0, 0},           // var_101_circuit1, var_101_circuit2
{0, 0},           // var_102_circuit1, var_102_circuit2
{0, 0},           // var_103_circuit1, var_103_circuit2
{0, 0},           // var_104_circuit1, var_104_circuit2
{0, 0},           // var_105_circuit1, var_105_circuit2
{0, 0},           // var_106_circuit1, var_106_circuit2
{0, 0},           // var_107_circuit1, var_107_circuit2
{0, 0},           // var_108_circuit1, var_108_circuit2
{0, 0},           // var_109_circuit1, var_109_circuit2
{0, 0},           // var_110_circuit1, var_110_circuit2
{0, 0},           // var_111_circuit1, var_111_circuit2
{0, 0},           // var_112_circuit1, var_112_circuit2
{0, 0},           // var_113_circuit1, var_113_circuit2
{0, 0},           // var_114_circuit1, var_114_circuit2
{0, 0},           // var_115_circuit1, var_115_circuit2
{0, 0},           // var_116_circuit1, var_116_circuit2
{0, 0},           // var_117_circuit1, var_117_circuit2
{0, 0},           // var_118_circuit1, var_118_circuit2
{0, 0},           // var_119_circuit1, var_119_circuit2
{0, 0},           // var_120_circuit1, var_120_circuit2
{0, 0},           // var_121_circuit1, var_121_circuit2
{0, 0},           // var_122_circuit1, var_122_circuit2
{0, 0},           // var_123_circuit1, var_123_circuit2
{0, 0},           // var_124_circuit1, var_124_circuit2
{0, 0},           // var_125_circuit1, var_125_circuit2
{0, 0},           // var_126_circuit1, var_126_circuit2
{0, 0},           // var_127_circuit1, var_127_circuit2
{0, 0},           // var_128_circuit1, var_128_circuit2
{0, 0},           // b_circuit1 ,b_circuit2 -> 66
{-bb::fr(2).pow(33), 0},           // c_circuit1, c_circuit2
{2, 0},           // var_131_circuit1, var_131_circuit2
{0, 0},           // var_132_circuit1, var_132_circuit2
{2, 0},           // var_133_circuit1, var_133_circuit2
};

std::vector<std::vector<uint32_t>> add_unique_witness2 = {
{0, 0},           //zero_circuit1, zero_circuit2
{1, 1},           //one_circuit1, one_circuit2
{0, 0},           //a_circuit1, a_circuit2
{0, 0},           //var_3_circuit1, var_3_circuit2
{0, 0},           //var_4_circuit1, var_4_circuit2
{0, 0},           //var_5_circuit1, var_5_circuit2
{0, 0},           //var_6_circuit1, var_6_circuit2
{0, 0},           //var_7_circuit1, var_7_circuit2
{0, 0},           //var_8_circuit1, var_8_circuit2
{0, 0},           //var_9_circuit1, var_9_circuit2
{0, 0},           //var_10_circuit1, var_10_circuit2
{0, 0},           //var_11_circuit1, var_11_circuit2
{0, 0},           //var_12_circuit1, var_12_circuit2
{0, 0},           //var_13_circuit1, var_13_circuit2
{0, 0},           //var_14_circuit1, var_14_circuit2
{0, 0},           //var_15_circuit1, var_15_circuit2
{0, 0},           //var_16_circuit1, var_16_circuit2
{0, 0},           //var_17_circuit1, var_17_circuit2
{0, 0},           //var_18_circuit1, var_18_circuit2
{0, 0},           //var_19_circuit1, var_19_circuit2
{0, 0},           //var_20_circuit1, var_20_circuit2
{0, 0},           //var_21_circuit1, var_21_circuit2
{0, 0},           //var_22_circuit1, var_22_circuit2
{0, 0},           //var_23_circuit1, var_23_circuit2
{0, 0},           //var_24_circuit1, var_24_circuit2
{0, 0},           //var_25_circuit1, var_25_circuit2
{0, 0},           //var_26_circuit1, var_26_circuit2
{0, 0},           //var_27_circuit1, var_27_circuit2
{0, 0},           //var_28_circuit1, var_28_circuit2
{0, 0},           //var_29_circuit1, var_29_circuit2
{0, 0},           //var_30_circuit1, var_30_circuit2
{0, 0},           //var_31_circuit1, var_31_circuit2
{0, 0},           //var_32_circuit1, var_32_circuit2
{0, 0},           //var_33_circuit1, var_33_circuit2
{0, 0},           //var_34_circuit1, var_34_circuit2
{0, 0},           //var_35_circuit1, var_35_circuit2
{0, 0},           //var_36_circuit1, var_36_circuit2
{0, 0},           //var_37_circuit1, var_37_circuit2
{0, 0},           //var_38_circuit1, var_38_circuit2
{0, 0},           //var_39_circuit1, var_39_circuit2
{0, 0},           //var_40_circuit1, var_40_circuit2
{0, 0},           //var_41_circuit1, var_41_circuit2
{0, 0},           //var_42_circuit1, var_42_circuit2
{0, 0},           //var_43_circuit1, var_43_circuit2
{0, 0},           //var_44_circuit1, var_44_circuit2
{0, 0},           //var_45_circuit1, var_45_circuit2
{0, 0},           //var_46_circuit1, var_46_circuit2
{0, 0},           //var_47_circuit1, var_47_circuit2
{0, 0},           //var_48_circuit1, var_48_circuit2
{0, 0},           //var_49_circuit1, var_49_circuit2
{0, 0},           //var_50_circuit1, var_50_circuit2
{0, 0},           //var_51_circuit1, var_51_circuit2
{0, 0},           //var_52_circuit1, var_52_circuit2
{0, 0},           //var_53_circuit1, var_53_circuit2
{0, 0},           //var_54_circuit1, var_54_circuit2
{0, 0},           //var_55_circuit1, var_55_circuit2
{0, 0},           //var_56_circuit1, var_56_circuit2
{0, 0},           //var_57_circuit1, var_57_circuit2
{0, 0},           //var_58_circuit1, var_58_circuit2
{0, 0},           //var_59_circuit1, var_59_circuit2
{0, 0},           //var_60_circuit1, var_60_circuit2
{0, 0},           //var_61_circuit1, var_61_circuit2
{0, 0},           //var_62_circuit1, var_62_circuit2
{0, 0},           //var_63_circuit1, var_63_circuit2
{0, 0},           //var_64_circuit1, var_64_circuit2
{0, 1},           //var_65_circuit1, var_65_circuit2
{0, 0},           //b_circuit1, b_circuit2
{0, 0},           //var_67_circuit1, var_67_circuit2
{0, 0},           //var_68_circuit1, var_68_circuit2
{0, 0},           //var_69_circuit1, var_69_circuit2
{0, 0},           //var_70_circuit1, var_70_circuit2
{0, 0},           //var_71_circuit1, var_71_circuit2
{0, 0},           //var_72_circuit1, var_72_circuit2
{0, 0},           //var_73_circuit1, var_73_circuit2
{0, 0},           //var_74_circuit1, var_74_circuit2
{0, 0},           //var_75_circuit1, var_75_circuit2
{0, 0},           //var_76_circuit1, var_76_circuit2
{0, 0},           //var_77_circuit1, var_77_circuit2
{0, 0},           //var_78_circuit1, var_78_circuit2
{0, 0},           //var_79_circuit1, var_79_circuit2
{0, 0},           //var_80_circuit1, var_80_circuit2
{0, 0},           //var_81_circuit1, var_81_circuit2
{0, 0},           //var_82_circuit1, var_82_circuit2
{0, 0},           //var_83_circuit1, var_83_circuit2
{0, 0},           //var_84_circuit1, var_84_circuit2
{0, 0},           //var_85_circuit1, var_85_circuit2
{0, 0},           //var_86_circuit1, var_86_circuit2
{0, 0},           //var_87_circuit1, var_87_circuit2
{0, 0},           //var_88_circuit1, var_88_circuit2
{0, 0},           //var_89_circuit1, var_89_circuit2
{0, 0},           //var_90_circuit1, var_90_circuit2
{0, 0},           //var_91_circuit1, var_91_circuit2
{0, 0},           //var_92_circuit1, var_92_circuit2
{0, 0},           //var_93_circuit1, var_93_circuit2
{0, 0},           //var_94_circuit1, var_94_circuit2
{0, 0},           //var_95_circuit1, var_95_circuit2
{0, 0},           //var_96_circuit1, var_96_circuit2
{0, 0},           //var_97_circuit1, var_97_circuit2
{0, 0},           //var_98_circuit1, var_98_circuit2
{0, 0},           //var_99_circuit1, var_99_circuit2
{0, 0},           //var_100_circuit1, var_100_circuit2
{0, 0},           //var_101_circuit1, var_101_circuit2
{0, 0},           //var_102_circuit1, var_102_circuit2
{0, 0},           //var_103_circuit1, var_103_circuit2
{0, 0},           //var_104_circuit1, var_104_circuit2
{0, 0},           //var_105_circuit1, var_105_circuit2
{0, 0},           //var_106_circuit1, var_106_circuit2
{0, 0},           //var_107_circuit1, var_107_circuit2
{0, 0},           //var_108_circuit1, var_108_circuit2
{0, 0},           //var_109_circuit1, var_109_circuit2
{0, 0},           //var_110_circuit1, var_110_circuit2
{0, 0},           //var_111_circuit1, var_111_circuit2
{0, 0},           //var_112_circuit1, var_112_circuit2
{0, 0},           //var_113_circuit1, var_113_circuit2
{0, 0},           //var_114_circuit1, var_114_circuit2
{0, 0},           //var_115_circuit1, var_115_circuit2
{0, 0},           //var_116_circuit1, var_116_circuit2
{0, 0},           //var_117_circuit1, var_117_circuit2
{0, 0},           //var_118_circuit1, var_118_circuit2
{0, 0},           //var_119_circuit1, var_119_circuit2
{0, 0},           //var_120_circuit1, var_120_circuit2
{0, 0},           //var_121_circuit1, var_121_circuit2
{0, 0},           //var_122_circuit1, var_122_circuit2
{0, 0},           //var_123_circuit1, var_123_circuit2
{0, 0},           //var_124_circuit1, var_124_circuit2
{0, 0},           //var_125_circuit1, var_125_circuit2
{0, 0},           //var_126_circuit1, var_126_circuit2
{0, 0},           //var_127_circuit1, var_127_circuit2
{0, 0},           //var_128_circuit1, var_128_circuit2
{0, 0},           //var_129_circuit1, var_129_circuit2
{0, 0},           //c_circuit1, c_circuit2
{0, 0},           //var_131_circuit1, var_131_circuit2
{0, 0},           //var_132_circuit1, var_132_circuit2
{0, 0},           //var_133_circuit1, var_133_circuit2
};