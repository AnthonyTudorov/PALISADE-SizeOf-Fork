#include "distributiongenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

std::once_flag PseudoRandomNumberGenerator::m_flag;

std::shared_ptr<std::mt19937> PseudoRandomNumberGenerator::m_prng = nullptr;

} // namespace lbcrypto
