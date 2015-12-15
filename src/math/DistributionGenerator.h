//
// Created by matt on 12/10/15.
//

#ifndef DISTRIBUTION_GENERATOR_H
#define DISTRIBUTION_GENERATOR_H

#include "backend.h"
#include <memory>
#include <mutex>
#include <random>

namespace lbcrypto {
    class DistributionGenerator {
    public:

        virtual BigBinaryInteger generateInteger () = 0;
        virtual BigBinaryVector  generateVector  (const usint size) = 0;

        DistributionGenerator ();

    protected:
        static std::mt19937 & getPRNG ();
        static std::shared_ptr<std::mt19937> prng;
        static std::once_flag flag;

    private:


    };
}

#endif // DISTRIBUTION_GENERATOR_H
