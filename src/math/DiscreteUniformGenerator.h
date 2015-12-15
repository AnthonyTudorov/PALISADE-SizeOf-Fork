//
// Created by matt on 12/10/15.
//

#ifndef DISCRETE_UNIFORM_GENERATOR_H
#define DISCRETE_UNIFORM_GENERATOR_H

#include "backend.h"
#include "DiscreteDistributionGenerator.h"

namespace lbcrypto {
    /**
     * @brief The class for Discrete Uniform Distribution generator over Zq.
     */
    class DiscreteUniformGenerator : protected DiscreteDistributionGenerator {
    public:
        /**
         * @brief         Constructs a new DiscreteUniformGenerator with the given modulus.
         * @param modulus The modulus to be used when generating discrete values.
         */
        DiscreteUniformGenerator (const BigBinaryInteger & modulus);

        /**
         * Required by DistributionGenerator.
         */
        BigBinaryInteger generateInteger ();

        /**
         * Required by DistributionGenerator.
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
