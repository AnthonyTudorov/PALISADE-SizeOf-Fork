//
// Created by matt on 12/10/15.
//

#include "DistributionGenerator.h"
#include <random>
#include "backend.h"

namespace lbcrypto {

    DistributionGenerator::DistributionGenerator () {
        std::random_device rd;
        this->generator = std::mt19937(rd());
    }



    template<class D>
    BigBinaryInteger DistributionGenerator::nextInt () {
        D d(this->generator);
        return d.nextInt();
    }
}