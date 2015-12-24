//
// Created by matt on 12/11/15.
//

#ifndef LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_
#define LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_

#include "distributiongenerator.h"

namespace lbcrypto {

/**
 * @brief A generator of the Binary Uniform Distribution.
 */
class BinaryUniformGenerator : public DistributionGenerator {

public:
    /**
     * @brief Basic constructor for Binary Uniform Generator.
     */
    BinaryUniformGenerator () : DistributionGenerator () {}

    /**
     * @brief  Generates a random value within the Binary Uniform Distribution.
     * @return A random value within this Binary Uniform Distribution.
     */
    BigBinaryInteger GenerateInteger ();

    /**
     * @brief  Generates a vector of random values within the Binary Uniform Distribution.
     * @return A vector of random values within this Binary Uniform Distribution.
     */
    BigBinaryVector GenerateVector  (const usint size);

};

} // namespace lbcrypto


#endif // LBCRYPTO_MATH_BINARYUNIFORMGENERATOR_H_
