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
* This code provides generation of uniform distibutions of discrete values.
*/

#ifndef LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_

#include "backend.h"
#include "distributiongenerator.h"
#include <random>

namespace lbcrypto {

/**
* @brief The class for Discrete Uniform Distribution generator over Zq.
*/
class DiscreteUniformGenerator : protected DistributionGenerator {
public:
	/**
	* @brief         Constructs a new DiscreteUniformGenerator with the given modulus.
	* @param modulus The modulus to be used when generating discrete values.
	*/
	DiscreteUniformGenerator (const BigBinaryInteger & modulus);

	/**
	* @brief         Sets the modulus. Overrides parent function
	* @param modulus The new modulus.
	*/
	void SetModulus (const BigBinaryInteger & modulus);

	/**
	* @brief Required by DistributionGenerator.
	*/
	BigBinaryInteger GenerateInteger () const;

	/**
	* @brief Required by DistributionGenerator.
	*/
	BigBinaryVector GenerateVector (const usint size) const;

private:
	static const usint CHUNK_MIN = 0;
	// This code does not work in VS 2012 - need to find a solution
	//static const usint CHUNK_WIDTH = std::numeric_limits<usint>::digits;
	//static const usint CHUNK_MAX = std::numeric_limits<usint>::max();
	// this is a quick fix in the meantime, should get rid of these magic values though...
	static const usint CHUNK_WIDTH = 16;
	static const usint CHUNK_MAX   = 65535; // 2^16-1 = 65535

	usint m_remainingWidth;
	usint m_chunksPerValue;
	std::uniform_int_distribution<usint> m_distribution;

	/**
	* The modulus value that should be used to generate discrete values.
	*/
	BigBinaryInteger m_modulus;

};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEUNIFORMGENERATOR_H_
