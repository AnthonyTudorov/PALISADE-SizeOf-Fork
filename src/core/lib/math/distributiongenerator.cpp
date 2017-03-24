#include "distributiongenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

std::once_flag DistributionGenerator::m_flag;
std::shared_ptr<std::mt19937> DistributionGenerator::m_prng = nullptr;

} // namespace lbcrypto
