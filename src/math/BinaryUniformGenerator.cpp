//
// Created by matt on 12/10/15.
//

#include "BinaryUniformGenerator.h"

#include <random>

namespace lbcrypto {

    BinaryUniformGenerator::BinaryUniformGenerator () {}

    BigBinaryInteger BinaryUniformGenerator::GenerateInteger () const {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::bernoulli_distribution distribution(0.5);
        return (distribution(gen) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO));
    }

    BigBinaryVector BinaryUniformGenerator::GenerateVector (usint size) const {
        BigBinaryVector randBigBinaryVector(size);
        for(usint index = 0; index<size; ++index) {
            BigBinaryInteger temp(GenerateInteger());
            randBigBinaryVector.SetValAtIndex(index, temp);
        }
        return randBigBinaryVector;
    }

}