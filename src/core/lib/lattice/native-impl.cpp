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

namespace native64 {
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

#include "ilparams.cpp"
#include "ilvector2n.cpp"

namespace cpu_int {
template class BigBinaryVectorImpl<native64::NativeInteger<uint64_t>>;
}

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
}

//namespace lbcrypto {
//template class ILParamsImpl<BigBinaryInteger>;
//
//template class ILVectorImpl<BigBinaryInteger,BigBinaryInteger,BigBinaryVector,ILParams>;
//}

// FIXME the MATH_BACKEND check is a hack and needs to go away
#if MATHBACKEND != 7
namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class BinaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class TernaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;

template class ILVectorImpl<native64::BigBinaryInteger,native64::BigBinaryInteger,native64::BigBinaryVector,ILNativeParams>;
template class ILParamsImpl<native64::BigBinaryInteger>;
}
#endif
