/*
 * lattice-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "ilparams.cpp"
#include "ilvector2n.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/binaryuniformgenerator.cpp"
#include "math/ternaryuniformgenerator.cpp"


namespace native64 {
template class NativeInteger<uint64_t>;
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::ZERO = NativeInteger<uint64_t>(0);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::ONE = NativeInteger<uint64_t>(1);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::TWO = NativeInteger<uint64_t>(2);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::THREE = NativeInteger<uint64_t>(3);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::FOUR = NativeInteger<uint64_t>(4);
template<> const NativeInteger<uint64_t> NativeInteger<uint64_t>::FIVE = NativeInteger<uint64_t>(5);
template<> std::function<unique_ptr<NativeInteger<uint64_t>>()> NativeInteger<uint64_t>::Allocator = [](){
	return lbcrypto::make_unique<NativeInteger<uint64_t>>();
};
}

namespace cpu_int {
//template class BigBinaryVector<native64::NativeInteger<uint64_t>>;
}

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
//template class DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
//template class BinaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
//template class TernaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
//template class DiscreteUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;

}

namespace lbcrypto {
template class ILParamsImpl<BigBinaryInteger>;
//template class ILParamsImpl<native64::BigBinaryInteger>;

template class ILVectorImpl<BigBinaryInteger,BigBinaryVector,ILParams>;
//template class ILVectorImpl<native64::BigBinaryInteger,native64::BigBinaryVector,ILNativeParams>;
}
