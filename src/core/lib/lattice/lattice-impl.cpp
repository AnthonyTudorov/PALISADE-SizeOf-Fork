/*
 * lattice-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "ilvector2n.cpp"
#include "math/discretegaussiangenerator.cpp"


namespace native64 {
template class NativeInteger<uint64_t>;
template<typename T> const NativeInteger<T> NativeInteger<T>::ZERO = NativeInteger(0);
template<typename T> const NativeInteger<T> NativeInteger<T>::ONE = NativeInteger(1);
template<typename T> const NativeInteger<T> NativeInteger<T>::TWO = NativeInteger(2);
template<typename T> const NativeInteger<T> NativeInteger<T>::THREE = NativeInteger(3);
template<typename T> const NativeInteger<T> NativeInteger<T>::FOUR = NativeInteger(4);
template<typename T> const NativeInteger<T> NativeInteger<T>::FIVE = NativeInteger(5);
}

namespace cpu_int {
template class BigBinaryVector<native64::NativeInteger<uint64_t>>;
}

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class BinaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class TernaryUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>;
}

namespace lbcrypto {
template class ILParamsImpl<BigBinaryInteger>;
template class ILParamsImpl<native64::BigBinaryInteger>;

template class ILVectorImpl<BigBinaryInteger,BigBinaryVector,ILParams>;
template class ILVectorImpl<native64::BigBinaryInteger,native64::BigBinaryVector,ILNativeParams>;
}
