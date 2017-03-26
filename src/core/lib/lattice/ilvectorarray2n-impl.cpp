/*
 * ilvectorarray2n-impl.cpp
 *
 *  Created on: Mar 26, 2017
 *      Author: gerardryan
 */


#include "ilparams.cpp"
#include "ilvector2n.cpp"
#include "ilvectorarray2n.cpp"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"

// This creates all the necessary class implementations for ILVectorArray2n

namespace lbcrypto {

template class ILVectorArrayImpl<BigBinaryInteger,native64::BigBinaryInteger,native64::BigBinaryVector,ILDCRTParams>;

}



