/*
 * lattice-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "ilparams.cpp"
#include "ilvector2n.cpp"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"

// This creates all the necessary class implementations for BigBinaryInteger

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;

}

namespace lbcrypto {
template class ILParamsImpl<BigBinaryInteger>;
template class ILVectorImpl<BigBinaryInteger,BigBinaryVector,ILParams>;
}
