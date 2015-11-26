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
 * This file contains the core public key interface functionality.
 */

#ifndef LBCRYPTO_OBFUSCATE_OBFUSCATELP_H
#define LBCRYPTO_OBFUSCATE_OBFUSCATELP_H

//Includes Section
#include <vector>
#include "../lattice/ideals.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../encoding/ptxtencoding.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {


	/**
	 * @brief Abstract interface class for patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class Pattern{
	}; 


	/**
	 * @brief Abstract interface class for patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ConjunctionPattern : public Pattern<Element>{
		protected:
			/**
			 * @brief The length of the conjunction pattern.
			 */
			usint m_length = 0;
		public:
			/**
			 * Method to define conjunction pattern.
			 */
			explicit ConjunctionPattern() {m_length=0;};

			/**
			 * Method to define conjunction pattern.
			 */
			~ConjunctionPattern() {};

			/**
			 * Method to return the length of the pattern.
			 *
			 * @return the length of the pattern.
			 */
			usint getLength() {return m_length;};
	}; 

	/**
	 * @brief Class for cleartext patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ClearPattern : public Pattern<Element>{
	};

	/**
	 * @brief Class for obfuscated patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ObfuscatedPattern : public Pattern<Element>{
	};


	/**
	 * @brief Abstract interface for encryption algorithm
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ObfuscationAlgorithm {
		public:	

			/**
			 * Method to obfuscate the cleartext pattern into an obfuscated pattern.
			 *
			 * @param &clearPattern cleartext pattern to obfuscate.
			 * @param &dg discrete Gaussian generator.
			 * @param *obfuscatedPattern the obfuscated pattern.
			 */
			virtual void Obfuscate(const ClearPattern<Element> &clearPattern, 
				DiscreteGaussianGenerator &dg, 
				ConjunctionPattern<Element> *obfuscatedPattern) const = 0;

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			virtual bool Evaluate(const ObfuscatedPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const = 0;

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &clearPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			virtual bool Evaluate(const ClearPattern<Element> &clearPattern,
				 const std::string &testString) const = 0;

	};

} // namespace lbcrypto ends
#endif
