#include "DiscreteDistributionGenerator.h"
#include "backend.h"

namespace lbcrypto {
    DiscreteDistributionGenerator::DiscreteDistributionGenerator (const BigBinaryInteger & modulus) : DistributionGenerator () {
        this->setModulus(modulus);
    }

    void DiscreteDistributionGenerator::setModulus (const BigBinaryInteger & modulus) {
        this->modulus = modulus;
    }
}