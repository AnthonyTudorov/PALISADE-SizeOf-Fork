/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
 *
 * This file contains abstract classes for program obfuscators.
 */

#ifndef LBCRYPTO_OBFUSCATE_OBFUSCATELP_H
#define LBCRYPTO_OBFUSCATE_OBFUSCATELP_H

//Includes Section
#include <vector>
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "encoding/plaintext.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {


	/**
	 * @brief Abstract interface class for patterns (common for cleartext and conjunction patterns)
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class Pattern{
	}; 


	/**
	 * @brief Abstract interface class for conjunction patterns (common for cleartext and conjunction patterns)
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ConjunctionPattern : public Pattern<Element>{
		public:
			/**
			 * Method to return the length of the pattern.
			 *
			 * @return the length of the pattern.
			 */
			virtual usint GetLength() const=0;
	}; 

	/**
	 * @brief Class for cleartext patterns; includes methods specific to clear patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ClearPattern {
	};

	/**
	 * @brief Class for obfuscated patterns; includes methods specific to obfuscated patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ObfuscatedPattern {
	};


	/*
	 * @brief Abstract interface for encryption algorithm
	 * @tparam Element a ring element.
	 
	template <class Element>
	class ObfuscationAlgorithm {
		public:	

			/*
			 * Method for evaluating the pattern
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			
			virtual bool Evaluate(const ObfuscatedPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const;

			/*
			 * Method for evaluating the pattern
			 *
			 * @param &clearPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 			virtual bool Evaluate(const ClearPattern<Element> &clearPattern,
				 const std::string &testString) const;

	};
	*/

} // namespace lbcrypto ends
#endif
