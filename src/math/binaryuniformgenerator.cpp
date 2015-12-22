//
// Created by matt on 12/11/15.
//

#include "binaryuniformgenerator.h"
#include <random>

namespace lbcrypto {

BigBinaryInteger BinaryUniformGenerator::GenerateInteger () {
    std::bernoulli_distribution distribution(0.5);
    return (distribution(this->GetPRNG()) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
}

BigBinaryVector BinaryUniformGenerator::GenerateVector (const usint size) {
    BigBinaryVector randBigBinaryVector(size);
    for(usint index = 0; index < size; index++) {
        randBigBinaryVector.SetValAtIndex(index, this->GenerateInteger());
    }
    return randBigBinaryVector;
}

} // namespace lbcrypto