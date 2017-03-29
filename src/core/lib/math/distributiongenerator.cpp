#include "distributiongenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

template<typename IntType, typename VecType>
std::once_flag DistributionGenerator<IntType,VecType>::m_flag;

template<typename IntType, typename VecType>
std::shared_ptr<std::mt19937> DistributionGenerator<IntType,VecType>::m_prng = nullptr;

template class DistributionGenerator<BigBinaryInteger,BigBinaryVector>;
template class DistributionGenerator<native64::BigBinaryInteger,native64::BigBinaryVector>;

} // namespace lbcrypto
