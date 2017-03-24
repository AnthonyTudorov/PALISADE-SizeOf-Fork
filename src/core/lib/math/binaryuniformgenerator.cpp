#include "binaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

template<typename IntType, typename VecType>
std::bernoulli_distribution BinaryUniformGeneratorImpl<IntType,VecType>::m_distribution = std::bernoulli_distribution(0.5);

template<typename IntType, typename VecType>
IntType BinaryUniformGeneratorImpl<IntType,VecType>::GenerateInteger () const {
	return (m_distribution(GetPRNG()) ? IntType(IntType::ONE) : IntType(IntType::ZERO));
}

template<typename IntType, typename VecType>
VecType BinaryUniformGeneratorImpl<IntType,VecType>::GenerateVector (const usint size, const IntType &modulus) const {
	VecType v(size);
	v.SetModulus(modulus);

	for (usint i = 0; i < size; i++) {
		v.SetValAtIndex(i, GenerateInteger());
	}
	return v;
}


template<typename IntType, typename VecType>
BinaryUniformGeneratorImpl<IntType,VecType>::~BinaryUniformGeneratorImpl(){
	// defied since there is a virtual member

}

} // namespace lbcrypto
