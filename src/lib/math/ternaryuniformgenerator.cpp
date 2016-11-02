#include "ternaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

std::uniform_int_distribution<int> TernaryUniformGenerator::m_distribution = std::uniform_int_distribution<int>(-1,1);

BigBinaryVector TernaryUniformGenerator::GenerateVector (const usint size, const BigBinaryInteger &modulus) const {
	
	BigBinaryVector v(size);
	v.SetModulus(modulus);
	int32_t randomNumber;

	for (usint i = 0; i < size; i++) {
		randomNumber = m_distribution(GetPRNG());
		if (randomNumber < 0)
			v[i] = modulus - BigBinaryInteger::ONE;
		else
			v[i] = BigBinaryInteger(randomNumber);
	}

	return v;
}


TernaryUniformGenerator::~TernaryUniformGenerator(){
	// defied since there is a virtual member

}

} // namespace lbcrypto
