//
// Created by matt on 12/11/15.
//

#include "BinaryUniformGenerator.h"
#include <random>

namespace lbcrypto {

    BigBinaryInteger BinaryUniformGenerator::generateInteger () {
        std::bernoulli_distribution distribution(0.5);
        return (distribution(this->getPRNG()) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
    }

    BigBinaryVector BinaryUniformGenerator::generateVector (const usint size) {
        BigBinaryVector randBigBinaryVector(size);
        for(usint index = 0; index < size; index++) {
            randBigBinaryVector.SetValAtIndex(index, this->generateInteger());
        }
        return randBigBinaryVector;
    }
}