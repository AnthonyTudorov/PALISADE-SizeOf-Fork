//
// Created by matt on 12/10/15.
//

#ifndef BINARY_UNIFORM_GENERATOR_H
#define BINARY_UNIFORM_GENERATOR_H

#include "backend.h"

namespace lbcrypto {
/**
 * @brief The class for binary uniform distribution generator.
 */
    class BinaryUniformGenerator {
    public:
        /**
         * Basic constructor.
         */
        BinaryUniformGenerator (); //srand(time(NULL)) is called here

        /**
         * Destructor.
         */
        ~BinaryUniformGenerator () { };

        /**
         * Returns a generated integer.
         *
         * @return a generated integer.
         */
        BigBinaryInteger GenerateInteger () const;

        /**
         * Returns a generated vector.
         *
         * @param size the number of values to return.
         * @return vector of values generated with the distribution.
         */
        BigBinaryVector GenerateVector (usint size) const;
    };
}

#endif // BINARY_UNIFORM_GENERATOR_H
