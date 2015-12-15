//
// Created by matt on 12/11/15.
//

#ifndef BINARY_UNIFORM_GENERATOR_H
#define BINARY_UNIFORM_GENERATOR_H

#include "DistributionGenerator.h"

namespace lbcrypto {
    /**
     * @brief A generator of the Binary Uniform Distribution.
     */
    class BinaryUniformGenerator : public DistributionGenerator {

    public:
        /**
         * @brief Basic constructor for Binary Uniform Generator.
         */
        BinaryUniformGenerator () : DistributionGenerator () {}

        /**
         * @brief  Generates a random value within the Binary Uniform Distribution.
         * @return A random value within this Binary Uniform Distribution.
         */
        BigBinaryInteger generateInteger ();

        /**
         * @brief  Generates a vector of random values within the Binary Uniform Distribution.
         * @return A vector of random values within this Binary Uniform Distribution.
         */
        BigBinaryVector  generateVector  (const usint size);

    };
}


#endif // BINARY_UNIFORM_GENERATOR_H
