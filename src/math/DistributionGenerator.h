//
// Created by matt on 12/10/15.
//

#ifndef PALISADE_STUDENT_EDITION_DISTRIBUTIONGENERATOR_H
#define PALISADE_STUDENT_EDITION_DISTRIBUTIONGENERATOR_H

#include "backend.h"
#include <memory>
#include <mutex>
#include <random>
namespace lbcrypto {
    class DistributionGenerator {
    public:

        static DistributionGenerator & getInstance () {
            std::call_once(DistributionGenerator::flag, [] {
                DistributionGenerator::instance.reset(new DistributionGenerator());
            });

            return *DistributionGenerator::instance;
        }

        template<class D>
        BigBinaryInteger nextInt ();

    private:

        static std::shared_ptr<DistributionGenerator> instance;
        static std::once_flag flag;

        std::mt19937 generator;

        DistributionGenerator ();

        DistributionGenerator (const DistributionGenerator &other) = delete;

        DistributionGenerator &operator= (const DistributionGenerator &other) = delete;
    };
}

#endif //PALISADE_STUDENT_EDITION_DISTRIBUTIONGENERATOR_H
