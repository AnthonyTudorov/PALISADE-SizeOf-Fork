/**0
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_05
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
 * This code provides the core entropic ring lwe obfuscation capability for conjunctions.
 */

#ifndef LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATE_H
#define LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATE_H

//Includes Section
#include "obfuscatelp.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../math/backend.h"
#include "../lattice/ideals.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {


	/**
	 * @brief Class for cleartext patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ClearLWEConjunctionPattern : public ClearPattern<Element>, public ConjunctionPattern<Element>{
		protected:
			std::string m_patternString = "";
		public:
			/**
			 * Method to define conjunction pattern.
			 *
			 * @param len the length of the pattern.
			 */
			explicit ClearLWEConjunctionPattern(const std::string patternString);

			/**
			 * Method to return the pattern's string representation.
			 *
			 * @return the string representation.
			 */
			std::string getPatternString();

			/**
			 * Gets the ring at a specific location
			 * @param index the index of the pattern to return a value for.
			 * @param *ring the ring value to get.
			 */
			std::string GetIndex(usint index, Element *ring);
	};

	/**
	 * @brief Class for obfuscated patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ObfuscatedLWEConjunctionPattern : public ObfuscatedPattern<Element>, public ConjunctionPattern<Element>{
		public:
			/**
			 * Method to define conjunction pattern.
			 *
			 * @param len the length of the pattern.
			 */
			explicit ObfuscatedLWEConjunctionPattern(usint len);
			
			/**
			 * Sets the ring at a specific location
			 * @param row the row of the ring element.
			 * @param column the column of the ring element.
			 * @param &ring the ring value to set.
			 */
			void SetIndex(usint row, usint column, const Element &ring);

			/**
			 * Gets the ring at a specific location
			 * @param row the row of the ring element.
			 * @param column the column of the ring element.
			 * @param *ring the ring value to get.
			 */
			void GetIndex(usint row, usint column, Element *ring);


		private:
			Element ***ringArray = NULL;
			Element *ringComparator = NULL;

	};


	/**
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LWEConjunctionObfuscationAlgorithm : public ObfuscationAlgorithm<Element>{
		public:	

			/**
			 * Method to obfuscate the cleartext pattern into an obfuscated pattern.
			 *
			 * @param &clearPattern cleartext pattern to obfuscate.
			 * @param &dg discrete Gaussian generator.
			 * @param *obfuscatedPattern the obfuscated pattern.
			 */
			void Obfuscate(const ClearLWEConjunctionPattern<Element> &clearPattern, 
				DiscreteGaussianGenerator &dg, 
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern) const = 0;

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &clearPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool Evaluate(const ClearLWEConjunctionPattern<Element> &clearPattern,
				 const std::string &testString) const = 0;

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool Evaluate(const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const = 0;

	};

} // namespace lbcrypto ends
#endif
