//
// Created by matt on 12/11/15.
//

#include "BinaryUniformDistribution.h"
#include <random>

namespace lbcrypto {

    template<class G>
    BigBinaryInteger BinaryUniformDistribution<G>::nextInteger () {
        std::bernoulli_distribution distribution(0.5);
        return (distribution(this->generator) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
    }

    template<class G>
    BigBinaryVector BinaryUniformDistribution<G>::nextVector (size_t size) {
        BigBinaryVector randBigBinaryVector(size);
        for(usint index = 0; index < size; ++index) {
            randBigBinaryVector.SetValAtIndex(index, this->nextInteger());
        }
        return randBigBinaryVector;
    }
}