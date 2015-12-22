//
// Created by matt on 12/10/15.
//

#ifndef LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_

#include "backend.h"
#include <memory>
#include <mutex>
#include <random>

namespace lbcrypto {

/**
 * @brief Abstract class describing generator requirements.
 *
 * The Distribution Generator defines the methods that must be implemented by a real generator.
 * It also holds the single PRNG, which should be called by all child class when generating a random number is required.
 *
 */
class DistributionGenerator {
public:

    /**
     * @brief The generic constructor for a Distribution Generator.
     *
     * For now, this constructor should be blank. Classes extending this class should also extend this constructor.
     */
    DistributionGenerator ();

    /**
     * @brief  Generates a single random value in the distribution.
     * @return The resulting value.
     */
    virtual BigBinaryInteger GenerateInteger () = 0;

    /**
     * @brief       Generates a vector of values in the distribution.
     * @param  size The size of the vector to create.
     * @return      The resulting vector of values.
     */
    virtual BigBinaryVector  GenerateVector (const usint size) = 0;

protected:
    /**
     * @brief  Returns the singleton PRNG. This should be used to generate all random numbers in implementing classes.
     * @return The singleton PRNG.
     */
    static std::mt19937 &GetPRNG ();

private:
    /**
     * A shared pointer to the singleton prng.
     */
    static std::shared_ptr<std::mt19937> prng_;

    /**
     * The flag that is used to ensure the prng is only constructed once.
     */
    static std::once_flag flag_;

};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
