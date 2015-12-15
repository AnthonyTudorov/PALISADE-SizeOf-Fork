//
// Created by matt on 12/11/15.
//

#ifndef BINARY_UNIFORM_GENERATOR_H
#define BINARY_UNIFORM_GENERATOR_H

#include "DistributionGenerator.h"

namespace lbcrypto {
    class BinaryUniformGenerator : public DistributionGenerator {

    public:

        BinaryUniformGenerator () : DistributionGenerator () {}
        BigBinaryInteger generateInteger ();
        BigBinaryVector  generateVector  (const usint size);

    };
}


#endif // BINARY_UNIFORM_GENERATOR_H
