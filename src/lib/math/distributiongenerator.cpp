#include "distributiongenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

std::once_flag DistributionGenerator::m_flag;
std::shared_ptr<std::mt19937> DistributionGenerator::m_prng = nullptr;

DistributionGenerator::DistributionGenerator () {
	// Currently does nothing, but here for forward compatibility.
}

std::mt19937 & DistributionGenerator::GetPRNG () {
	std::call_once(DistributionGenerator::m_flag, [] () {
		std::random_device rd;
		DistributionGenerator::m_prng.reset(new std::mt19937(rd()));
	});

	return * DistributionGenerator::m_prng;
}

} // namespace lbcrypto
