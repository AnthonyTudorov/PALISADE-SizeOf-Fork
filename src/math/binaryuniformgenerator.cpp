#include "binaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

std::bernoulli_distribution BinaryUniformGenerator::m_distribution = std::bernoulli_distribution(0.5);

BigBinaryInteger BinaryUniformGenerator::GenerateInteger () {
	return (m_distribution(GetPRNG()) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
}

BigBinaryVector BinaryUniformGenerator::GenerateVector (const usint size) {
	BigBinaryVector v(size);
	v.SetModulus(BigBinaryInteger::TWO);
	for (usint i = 0; i < size; i++) {
		v.SetValAtIndex(i, GenerateInteger());
	}
	return v;
}

} // namespace lbcrypto
