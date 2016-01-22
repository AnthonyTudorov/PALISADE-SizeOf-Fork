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
* This code provides generation of discrete distributions. This code should be inherited in all other discrete distribution generators.
*/

#ifndef LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_

#include "distributiongenerator.h"
#include <math.h>
#include <random>
#include <bitset>
#include <string>
#include "backend.h"

namespace lbcrypto {

/**
* @brief Abstract class for Discrete Distribution Generators.
*/
class DiscreteDistributionGenerator : protected DistributionGenerator {
public:

	/**
	* Default constructor.
	*/
	DiscreteDistributionGenerator();

	/**
	* @brief         Constructor for Discrete Distribution Generators that sets the discrete modulus.
	* @param modulus The modulus to use to generate discrete values.
	*/
	DiscreteDistributionGenerator (const BigBinaryInteger & modulus);

	/**
	* @brief         Sets the modulus of the distribution.
	* @param modulus The new modulus to use to generate discrete values.
	*/
	virtual void SetModulus (const BigBinaryInteger &modulus);

protected:
	/**
	* The modulus value that should be used to generate discrete values.
	*/
	BigBinaryInteger m_modulus;

};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEDISTRIBUTIONGENERATOR_H_
