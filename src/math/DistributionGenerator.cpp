//
// Created by matt on 12/10/15.
//

#include "DistributionGenerator.h"
#include "backend.h"
#include <random>

namespace lbcrypto {

    std::once_flag DistributionGenerator::flag;
    std::shared_ptr<std::mt19937> DistributionGenerator::prng = nullptr;

    DistributionGenerator::DistributionGenerator () {
        // Currently does nothing, but here for forward compatibility.
    }

    std::mt19937 & DistributionGenerator::getPRNG () {
        std::call_once(DistributionGenerator::flag, [] {
            std::random_device rd;
            DistributionGenerator::prng.reset(new std::mt19937(rd()));
        });

        return *prng;
    }
}