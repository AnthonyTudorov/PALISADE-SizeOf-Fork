#include "DiscreteDistributionGenerator.h"
#include "backend.h"

namespace lbcrypto {

    DiscreteDistributionGenerator::DiscreteDistributionGenerator (const BigBinaryInteger & modulus) : DistributionGenerator () {
        this->SetModulus(modulus);
    }

    void DiscreteDistributionGenerator::SetModulus (const BigBinaryInteger & modulus) {
        this->modulus_ = modulus;
    }

} // namespace lbcrypto