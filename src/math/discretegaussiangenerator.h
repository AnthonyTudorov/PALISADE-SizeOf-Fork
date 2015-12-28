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
* This code provides generation of discrete gaussian distributions.
*/

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_

#include "backend.h"
#include "discretedistributiongenerator.h"

namespace lbcrypto {

/**
 * @brief The class for Discrete Gaussion Distribution generator.
 */
class DiscreteGaussianGenerator : DiscreteDistributionGenerator {
public:

	/**
	* Default constructor.
	*/
	DiscreteGaussianGenerator();

    /**
     * @brief         Basic constructor for specifying distribution parameter and modulus.
     * @param modulus The modulus to use to generate discrete values.
     * @param std     The standard deviation for this Gaussian Distribution.
     */
    DiscreteGaussianGenerator (const BigBinaryInteger & modulus, const sint std);

    /**
     * @brief Initializes the generator.
     */
    void Initialize ();

    /**
     * @brief  Returns the standard deviation of the generator.
     * @return The analytically obtained standard deviation of the generator.
     */
    sint GetStd () const;

    /**
     * @brief     Sets the standard deviation of the generator.
     * @param std The analytic standard deviation of the generator.
     */
    void SetStd (const sint std);

    /**
     * @brief      Returns a generated char vector.
     * @param size The number of values to return.
     * @return     A pointer to an array of schar values generated with the distribution.
     */
    schar * GenerateCharVector (usint size) const;

    /**
     * @brief  Returns a generated integer.
     * @return A random value within this Discrete Gaussian Distribution.
     */
    BigBinaryInteger GenerateInteger ();

    /**
     * @brief           Generates a vector of random values within this Discrete Gaussian Distribution.
     *
     * @param  size     The number of values to return.
     * @return          The vector of values within this Discrete Gaussian Distribution.
     */
    BigBinaryVector GenerateVector (usint size);

    /**
     * @brief               Generates a vector of random, positive values within this Discrete Gaussian Distribution.
     * @param  vectorLength The number of values to return.
     * @param  &modValue    The number of values to return.
     * @return              The vector of positive values within this Discrete Gaussian Distribution.
     */
    static BigBinaryVector DiscreteGaussianPositiveGenerator (usint vectorLength, const BigBinaryInteger &modValue);

private:
    usint FindInVector (const std::vector<double> &S, double search) const;

    //Gyana to add precomputation methods and data members
    //all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
    double m_a;

    void InitiateVals ();

    std::vector<double> vals_;

    /**
     * The standard deviation of the distribution.
     */
    sint std_;
};

}  // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
