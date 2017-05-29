/*
 * lattice-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "../math/backend.h"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"

namespace native_int {
template class NativeInteger<uint64_t>;
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::ZERO = (0);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::ONE = (1);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::TWO = (2);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::THREE = (3);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::FOUR = (4);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::FIVE = (5);

template<> std::function<unique_ptr<NativeInteger<uint64_t>>()> NativeInteger<uint64_t>::Allocator = [](){
	return lbcrypto::make_unique<NativeInteger<uint64_t>>();
};

}

#include "elemparams.cpp"
#include "ilparams.cpp"
#include "ilvector2n.cpp"

namespace cpu_int {
template class BigBinaryVectorImpl<native_int::NativeInteger<uint64_t>>;
}

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
}

namespace lbcrypto {
template class ILParamsImpl<BigBinaryInteger>;

template class ILVectorImpl<BigBinaryInteger,BigBinaryInteger,BigBinaryVector,ILParams>;

//template<>
//ILVectorImpl<native_int::BinaryInteger,native_int::BinaryInteger,native_int::BinaryVector,native_int::ILParams>::ILVectorImpl(const shared_ptr<ILDCRTParams> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format) {
//	throw std::logic_error("cannot use this constructor with a native vector");
//}

}

// FIXME the MATH_BACKEND check is a hack and needs to go away
#if MATHBACKEND != 7
namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector>;
template class BinaryUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector>;
template class TernaryUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector>;
template class DiscreteUniformGeneratorImpl<native_int::BinaryInteger,native_int::BinaryVector>;

template class ILVectorImpl<native_int::BinaryInteger,native_int::BinaryInteger,native_int::BinaryVector,ILNativeParams>;
template class ILParamsImpl<native_int::BinaryInteger>;
}
#endif
