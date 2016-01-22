#include "discretedistributiongenerator.h"
#include "backend.h"

namespace lbcrypto {

DiscreteDistributionGenerator::DiscreteDistributionGenerator() : DistributionGenerator() {
	this->SetModulus(BigBinaryInteger::ONE);
}

DiscreteDistributionGenerator::DiscreteDistributionGenerator (const BigBinaryInteger & modulus) : DistributionGenerator () {
	this->SetModulus(modulus);
}

void DiscreteDistributionGenerator::SetModulus (const BigBinaryInteger & modulus) {
	m_modulus = modulus;
}

} // namespace lbcrypto
