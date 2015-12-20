//
// Created by matt on 12/10/15.
//

#ifndef LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_

#include "backend.h"
#include "DistributionGenerator.h"
#include <math.h>
#include <random>

#include <bitset>
#include <string>

namespace lbcrypto {

    /**
     * @brief Abstract class for Discrete Distribution Generators.
     */
    class DiscreteDistributionGenerator : protected DistributionGenerator {
    public:
        /**
         * @brief         Constructor for Discrete Distribution Generators that sets the discrete modulus.
         * @param modulus The modulus to use to generate discrete values.
         */
        DiscreteDistributionGenerator (const BigBinaryInteger & modulus);

        /**
         * @brief         Sets the modulus of the distribution.
         * @param modulus The new modulus to use to generate discrete values.
         */
        void SetModulus (const BigBinaryInteger &modulus);

    protected:
        /**
         * The modulus value that should be used to generate discrete values.
         */
        BigBinaryInteger modulus_;
    };
}

#endif // LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_
