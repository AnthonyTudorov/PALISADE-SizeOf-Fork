//
// Created by matt on 12/10/15.
//

#ifndef DISCRETE_UNIFORM_GENERATOR_H
#define DISCRETE_UNIFORM_GENERATOR_H

#include "backend.h"
#include "ModulusDistributionGenerator.h"

namespace lbcrypto {
/**
 * @brief The class for discrete Uniform distribution generator over Zq.
 */
    class DiscreteUniformGenerator : protected ModulusDistributionGenerator {
    public:
        /**
         * Basic constructor.
         */
        DiscreteUniformGenerator (const BigBinaryInteger & modulus); //srand(time(NULL)) is called here

        //ACCESSORS

        //int GetMean() const;

        /**
         * Returns a generated integer.
         *
         * @return a generated integer.
         */
        BigBinaryInteger generateInteger ();

        /**
         * Returns a generated vector.
         *
         * @param size the number of values to return.
         * @return vector of values generated with the distribution.
         */
        BigBinaryVector generateVector (const usint size);

    private:

        static const usint MINVAL = 0;
        // This code does not work in VS 2012 - need to find a solution
        //static const usint LENOFMAX = std::numeric_limits<usint>::digits;
        //static const usint MAXVAL = std::numeric_limits<usint>::max();
        // this is a quick fix in the meantime, should get rid of these magic values though...
        static const usint LENOFMAX = 16;
        static const usint MAXVAL   = 65535; // 2^16-1 = 65535

        //usint moduloLength;
        //usint noOfIter;
        //usint remainder;
        //void InitializeVals(modulus);
    };
}

#endif // DISCRETE_UNIFORM_GENERATOR_H
