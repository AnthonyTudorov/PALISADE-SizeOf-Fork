//
// Created by matt on 12/10/15.
//

#include "DistributionGenerator.h"
#include "backend.h"
#include <random>

namespace lbcrypto {

    DistributionGenerator::DistributionGenerator () { }

    std::mt19937 & DistributionGenerator::getGenerator () {
        std::call_once(DistributionGenerator::flag, [] {
            std::random_device rd;
            DistributionGenerator::generator.reset(new std::mt19937(rd()));
        });

        return *DistributionGenerator::generator;
    }
}