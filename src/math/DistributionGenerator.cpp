//
// Created by matt on 12/10/15.
//

#include "DistributionGenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

    std::once_flag DistributionGenerator::flag_;
    std::shared_ptr<std::mt19937> DistributionGenerator::prng_ = nullptr;

    DistributionGenerator::DistributionGenerator () {
        // Currently does nothing, but here for forward compatibility.
    }

    std::mt19937 & DistributionGenerator::GetPRNG () {
        std::call_once(DistributionGenerator::flag_, [] {
            std::random_device rd;
            DistributionGenerator::prng_.reset(new std::mt19937(rd()));
        });

        return * DistributionGenerator::prng_;
    }
}