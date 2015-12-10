//
// Created by matt on 12/10/15.
//

#ifndef PALISADE_STUDENT_EDITION_MODULUSDISTRIBUTIONGENERATOR_H
#define PALISADE_STUDENT_EDITION_MODULUSDISTRIBUTIONGENERATOR_H

#include "backend.h"
#include <math.h>
#include <random>

#include <bitset>
#include <string>

namespace lbcrypto {
/**
 * @brief The class for random number distribution generator
 */
    class ModulusDistributionGenerator {
    public:

        /**
         * Basic virtual method.
         *
         * @return a return value set to 0.
         */
        virtual BigBinaryInteger GenerateInteger (const BigBinaryInteger &modulus) = 0;

        /**
         * Basic virtual method.
         *
         * @return a return value set to 0.
         */
        virtual BigBinaryVector GenerateVector (usint size, const BigBinaryInteger &modulus) = 0;

        /**
         *  Interface requires virtual destructor.
         */
        virtual ~ModulusDistributionGenerator () = 0;
    };

    inline ModulusDistributionGenerator::~ModulusDistributionGenerator () { };
}

#endif //PALISADE_STUDENT_EDITION_MODULUSDISTRIBUTIONGENERATOR_H
