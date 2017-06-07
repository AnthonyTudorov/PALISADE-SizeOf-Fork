/*
 * ilvectorarray2n-impl.cpp
 *
 *  Created on: Mar 26, 2017
 *      Author: gerardryan
 */


#include "elemparams.cpp"
#include "ildcrtparams.cpp"
#include "../encoding/encodingparams.cpp"
#include "ilvector2n.cpp"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"
#include "ildcrt2n.cpp"

// This creates all the necessary class implementations for ILDCRT2n

namespace lbcrypto {

template class ElemParams<native_int::BinaryInteger>;
template class ILParamsImpl<native_int::BinaryInteger>;
template class ILDCRTParams<BigBinaryInteger>;
template class EncodingParamsImpl<BigBinaryInteger>;
template class ILDCRTImpl<BigBinaryInteger, BigBinaryInteger, BigBinaryVector, ILDCRTParams<BigBinaryInteger>>;

}



