//
// Created by matt on 12/10/15.
//

#ifndef LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_

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
         * @brief         Sets the modulus. Overrides parent function
         * @param modulus The new modulus.
         */
        void SetModulus (const BigBinaryInteger & modulus);
        /**
         * @brief Required by DistributionGenerator.
         */
        BigBinaryInteger GenerateInteger ();

        /**
         * @brief Required by DistributionGenerator.
         */
        BigBinaryVector GenerateVector (const usint size);

    private:

        static const usint CHUNK_MIN = 0;
        // This code does not work in VS 2012 - need to find a solution
        //static const usint CHUNK_WIDTH = std::numeric_limits<usint>::digits;
        //static const usint CHUNK_MAX = std::numeric_limits<usint>::max();
        // this is a quick fix in the meantime, should get rid of these magic values though...
        static const usint CHUNK_WIDTH = 16;
        static const usint CHUNK_MAX   = 65535; // 2^16-1 = 65535

        usint remaining_width_ = 0;
        usint chunks_per_value_ = 0;
        std::uniform_int_distribution<usint> distribution_;

        //usint moduloLength;
        //usint noOfIter;
        //usint remainder;
        //void InitializeVals(modulus);
    };
}

#endif // LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
