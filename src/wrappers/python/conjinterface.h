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

#ifndef PYCRYPTO_WRAPPERS_PYTHON_CONJINTERFACE_H
#define PYCRYPTO_WRAPPERS_PYTHON_CONJINTERFACE_H

#define BOOST_PYTHON_STATIC_LIB //needed for Windows

#include <iostream>
#include <fstream>

#include "../../trapdoor/lib/obfuscation/lweconjunctionobfuscatev3.h"
#include "../../trapdoor/lib/obfuscation/lweconjunctionobfuscatev3.cpp"
#include "time.h"
#include <chrono>
#include "utils/debug.h"

#include <boost/python.hpp>


namespace pycrypto {

	typedef lbcrypto::LWEConjunctionObfuscationAlgorithm<lbcrypto::Poly> ObfAlgorithm;
	typedef lbcrypto::ObfuscatedLWEConjunctionPattern<lbcrypto::Poly> ObfPattern;
	typedef lbcrypto::ClearLWEConjunctionPattern<lbcrypto::Poly> ClearPattern;

	class Obfuscator {

	public:

		Obfuscator() {};

		~Obfuscator() {};

		void Initialize(const std::string inputstring, size_t n, size_t chunksize);

		bool Evaluate(const std::string teststring);

		bool EvaluateClear(const std::string teststring);

	private:

		ObfPattern m_obfuscatedPattern;

		ClearPattern m_clearPattern;

		ObfAlgorithm m_algorithm;

	};

}

#endif