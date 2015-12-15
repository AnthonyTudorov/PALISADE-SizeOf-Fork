#include "DiscreteDistributionGenerator.h"
#include "backend.h"

namespace lbcrypto {
    DiscreteDistributionGenerator::DiscreteDistributionGenerator (const BigBinaryInteger & modulus) : DistributionGenerator () {
        this->modulus = modulus;
    }
}