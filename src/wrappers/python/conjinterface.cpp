/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers:
*		Dr. Yuriy Polyakov, <polyakov@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2016, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
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
*
* Python wrapper class for conjunction obfuscator
*/

#include "conjinterface.h"

namespace pycrypto {

	void Obfuscator::Initialize(const std::string inputstring, size_t n, size_t chunkSize)
	{
		
		uint32_t base = 1<<20;
		
		m_clearPattern = ClearPattern(inputstring);

		m_obfuscatedPattern.SetChunkSize(chunkSize);
		m_obfuscatedPattern.SetLength(m_clearPattern.GetLength());
		m_obfuscatedPattern.SetBase(base);
		//m_obfuscatedPattern.SetRootHermiteFactor(1.006); - Not used yet

		// Create the noise generator
		double stdDev = lbcrypto::SIGMA;
		typename lbcrypto::DCRTPoly::DggType dgg(stdDev);	

		// Create the ternary uniform distribution generator
		typename lbcrypto::DCRTPoly::TugType tug;
		
		// Parameter generation
		std::cout << "Started parameter generation..." << std::endl;
		m_algorithm.ParamsGen(dgg, &m_obfuscatedPattern, n);					//Finds q using the correctness constraint for the given value of n
		std::cout << "Ended parameter generation" << std::endl;

		// Key generation
		std::cout << "\nStarted key generation..." << std::endl;
		m_algorithm.KeyGen(dgg, &m_obfuscatedPattern);
		std::cout << "Ended key generation" << std::endl;

		// Obfuscation
		std::cout << "\nStarted obfuscation..." << std::endl;
		m_algorithm.Obfuscate(m_clearPattern, dgg, tug, &m_obfuscatedPattern);
		std::cout << "Ended obfuscation" << std::endl;

	}

	bool Obfuscator::Evaluate(const std::string testString) 
	{
		return m_algorithm.Evaluate(m_obfuscatedPattern, testString);
	}

	bool Obfuscator::EvaluateClear(const std::string testString)
	{
		return m_algorithm.Evaluate(m_clearPattern, testString);
	}

}

