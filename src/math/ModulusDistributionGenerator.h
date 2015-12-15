//
// Created by matt on 12/10/15.
//

#ifndef MODULUS_DISTRIBUTION_GENERATOR_H
#define MODULUS_DISTRIBUTION_GENERATOR_H

#include "backend.h"
#include "DistributionGenerator.h"
#include <math.h>
#include <random>

#include <bitset>
#include <string>

namespace lbcrypto {

    class ModulusDistributionGenerator : protected DistributionGenerator {
    public:

        ModulusDistributionGenerator (const BigBinaryInteger & modulus);

    protected:
        BigBinaryInteger modulus;
    };
}

#endif // MODULUS_DISTRIBUTION_GENERATOR_H
