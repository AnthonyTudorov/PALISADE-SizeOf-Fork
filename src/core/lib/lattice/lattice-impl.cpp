/*
 * lattice-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "ilvector2n.cpp"

namespace native64 {
template class NativeInteger<uint64_t>;
}

namespace cpu_int {
template class BigBinaryVector<native64::NativeInteger<uint64_t>>;
}

namespace lbcrypto {
template class ILVectorImpl<BigBinaryInteger,BigBinaryVector,ILParams>;
template class ILVectorImpl<native64::BigBinaryInteger,native64::BigBinaryVector,ILNativeParams>;
}
