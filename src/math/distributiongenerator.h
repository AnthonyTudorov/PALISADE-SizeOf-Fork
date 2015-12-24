/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* @section DESCRIPTION
* This code provides basic structure for distribution generators. This should be inherited by all other distribution generators.
*/

#ifndef LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_

#include <memory>
#include <mutex>
#include <random>
#include "backend.h"

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
