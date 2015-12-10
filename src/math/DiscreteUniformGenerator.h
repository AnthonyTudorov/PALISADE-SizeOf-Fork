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
    class DiscreteUniformGenerator : ModulusDistributionGenerator {
    public:
        /**
         * Basic constructor.
         */
        DiscreteUniformGenerator (); //srand(time(NULL)) is called here


        /**
         * Destructor.
         */
        ~DiscreteUniformGenerator ();

        //ACCESSORS

        //int GetMean() const;

        /**
         * Returns a generated integer.
         *
         * @return a generated integer.
         */
        BigBinaryInteger GenerateInteger (const BigBinaryInteger &modulus) const;

        /**
         * Returns a generated vector.
         *
         * @param size the number of values to return.
         * @return vector of values generated with the distribution.
         */
        BigBinaryVector GenerateVector (usint size, const BigBinaryInteger &modulus) const;

    private:
        BigBinaryInteger m_modulus;

        static const usint MINVAL = 0;
        //This code does not work in VS 2012 - need to find a solution
        //static const usint LENOFMAX = std::numeric_limits<usint>::digits;
        //static const usint MAXVAL = std::numeric_limits<usint>::max();

        static const usint LENOFMAX = 16;
        static const usint MAXVAL = 65535;
        //2^16-1 = 65535

        //usint moduloLength;
        //usint noOfIter;
        //usint remainder;
        //void InitializeVals(modulus);
    };
}

#endif // DISCRETE_UNIFORM_GENERATOR_H
