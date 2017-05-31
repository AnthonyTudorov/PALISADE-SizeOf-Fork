#include "ternaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

template<typename IntType, typename VecType>
std::uniform_int_distribution<int> TernaryUniformGeneratorImpl<IntType,VecType>::m_distribution = std::uniform_int_distribution<int>(-1,1);

template<typename IntType, typename VecType>
VecType TernaryUniformGeneratorImpl<IntType,VecType>::GenerateVector (const usint size, const IntType &modulus) const {
	
	VecType v(size);
	v.SetModulus(modulus);
	int32_t randomNumber;

	for (usint i = 0; i < size; i++) {
		randomNumber = m_distribution(PseudoRandomNumberGenerator::GetPRNG());
		if (randomNumber < 0)
			v[i] = modulus - 1;
		else
			v[i] = IntType(randomNumber);
	}

	return v;
}

} // namespace lbcrypto
