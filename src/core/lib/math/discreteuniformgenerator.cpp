/*
 * @file discreteuniformgenerator.cpp This code provides generation of uniform distibutions of discrete values. 
 * Discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
 
#include "discreteuniformgenerator.h"
#include "distributiongenerator.h"
#include <sstream>
#include <bitset>
#include "backend.h"

namespace lbcrypto {

template<typename IntType, typename VecType>
std::uniform_int_distribution<uint32_t> DiscreteUniformGeneratorImpl<IntType, VecType>::m_distribution = std::uniform_int_distribution<uint32_t>(CHUNK_MIN, CHUNK_MAX);

template<typename IntType, typename VecType>
DiscreteUniformGeneratorImpl<IntType,VecType>::DiscreteUniformGeneratorImpl ()
	: DistributionGenerator<IntType,VecType>() {

	SetModulus(0);
}

template<typename IntType, typename VecType>
void DiscreteUniformGeneratorImpl<IntType,VecType>::SetModulus (const IntType & modulus) {

	m_modulus = modulus;

	// Update values that depend on modulus.
	usint modulusWidth = m_modulus.GetMSB();
	// Get the number of chunks in the modulus
	// 1 is subtracted to make sure the last chunk is fully used by the modulus
	m_chunksPerValue = (modulusWidth-1) / CHUNK_WIDTH;
}

template<typename IntType, typename VecType>
IntType DiscreteUniformGeneratorImpl<IntType,VecType>::GenerateInteger () const {

	// result is initialized to 0
	IntType result;
	
	//temp is used for intermediate multiprecision computations
	IntType temp;

	//stores current random number generated by built-in C++ 11 uniform generator (used for 32-bit unsigned integers)
	uint32_t value;

	if( m_modulus == 0 ) {
		throw std::logic_error("0 modulus?");
	}

	do {

		result = 0;

		// Generate random uint32_t "limbs" of the BigInteger
		for (usint i = 0; i < m_chunksPerValue; i++) {
			//Generate an unsigned long integer
			value = m_distribution(PseudoRandomNumberGenerator::GetPRNG());
			// converts value to IntType
			temp = value;
			//Move it to the appropriate chunk of the big integer
			temp <<= i*CHUNK_WIDTH;
			//Add it to the current big integer storing the result
			result += temp;
		}

		//work with the remainder - after all 32-bit chunks were processed
		temp = m_modulus >> m_chunksPerValue*CHUNK_WIDTH;

		// Generate a uniform number for the remainder
		// If not 1, i.e., the modulus is either 1 or a power of 2*CHUNK_WIDTH
		if (temp.GetMSB() != 1)
		{
			uint32_t bound = temp.ConvertToInt();

			// built-in generator for the most significant chunk of the multiprecision number
			std::uniform_int_distribution<uint32_t>  distribution = std::uniform_int_distribution<uint32_t>(CHUNK_MIN, bound);

			value = distribution(PseudoRandomNumberGenerator::GetPRNG());
			// converts value to IntType
			temp = value;
			//Move it to the appropriate chunk of the big integer
			temp <<= m_chunksPerValue*CHUNK_WIDTH;
			//Add it to the current big integer storing the result
			result += temp;

		}

	} while (result >= m_modulus);// deals with the rare scenario when the bits in the most significant chunk are the same
						   // and the bits in the following chunk of the result are larger than in the modulus

	return result;
}

template<typename IntType, typename VecType>
VecType DiscreteUniformGeneratorImpl<IntType,VecType>::GenerateVector(const usint size) const {

	VecType v(size,m_modulus);

	for (usint i = 0; i < size; i++) {
	  IntType temp(this->GenerateInteger());
	  v.at(i)= temp;
	}

	return v;

}

} // namespace lbcrypto
