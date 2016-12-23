#include "../crypto/cryptocontext.h"
#include "binaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

std::bernoulli_distribution BinaryUniformGenerator::m_distribution = std::bernoulli_distribution(0.5);

BigBinaryInteger BinaryUniformGenerator::GenerateInteger () const {
	return (m_distribution(GetPRNG()) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
}

BigBinaryVector BinaryUniformGenerator::GenerateVector (const usint size, const BigBinaryInteger &modulus) const {
	BigBinaryVector v(size);
	v.SetModulus(modulus);

	for (usint i = 0; i < size; i++) {
		v.SetValAtIndex(i, GenerateInteger());
	}
	return v;
}


BinaryUniformGenerator::~BinaryUniformGenerator(){
	// defied since there is a virtual member

}

} // namespace lbcrypto
