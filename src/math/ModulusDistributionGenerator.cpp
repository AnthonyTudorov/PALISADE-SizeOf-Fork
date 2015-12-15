#include "ModulusDistributionGenerator.h"
#include "backend.h"

namespace lbcrypto {
    ModulusDistributionGenerator::ModulusDistributionGenerator (const BigBinaryInteger & modulus) {
        this->modulus = modulus;
    }
}