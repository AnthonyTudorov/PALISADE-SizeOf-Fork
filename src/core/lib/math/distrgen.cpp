/*
 * distrgen.cpp
 *
 *  Created on: Mar 26, 2017
 *      Author: gerardryan
 */

#include "distrgen.h"

namespace lbcrypto {

template<typename IntType,typename VecType>
BinaryUniformGeneratorImpl<IntType,VecType>	GeneratorContainer<IntType,VecType>::bug;

template<typename IntType,typename VecType>
DiscreteGaussianGeneratorImpl<IntType,VecType>	GeneratorContainer<IntType,VecType>::dgg;

template<typename IntType,typename VecType>
DiscreteUniformGeneratorImpl<IntType,VecType>	GeneratorContainer<IntType,VecType>::dug;

template<typename IntType,typename VecType>
TernaryUniformGeneratorImpl<IntType,VecType>	GeneratorContainer<IntType,VecType>::tug;

template class GeneratorContainer<BigBinaryInteger,BigBinaryVector>;
template class GeneratorContainer<native64::BigBinaryInteger,native64::BigBinaryVector>;

}

