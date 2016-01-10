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
#include <vector>
#include "obfuscatelp.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../math/backend.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../lattice/matrix.h"
#include "../lattice/trapdoor.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

static function<unique_ptr<ILVector2n>()> secureIL2nAlloc() {
	usint m = 16;
	//BigBinaryInteger secureModulus("67108913");
	//BigBinaryInteger secureRootOfUnity("61564");
	BigBinaryInteger secureModulus("61");
	BigBinaryInteger secureRootOfUnity("6");
	return ILVector2n::MakeAllocator(
        	ILParams(
	        m, secureModulus, secureRootOfUnity),
	        EVALUATION
        );
/*
    BigBinaryInteger secureModulus("8590983169");
    BigBinaryInteger secureRootOfUnity("4810681236");
    return ILVector2n::MakeAllocator(
        ILParams(
        2048, secureModulus, secureRootOfUnity),
        EVALUATION
        );
*/
};

	/**
	 * @brief Class for cleartext patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ClearLWEConjunctionPattern : public ClearPattern<Element>, public ConjunctionPattern<Element>{
		public:
			/**
			 * Method to define conjunction pattern.
			 *
			 * @param patternString the string the plaintext pattern.
			 */
			explicit ClearLWEConjunctionPattern(const std::string patternString);

			/**
			 * Method to return the pattern's string representation.
			 *
			 * @return the string representation.
			 */
			std::string GetPatternString() const;

			/**
			 * Gets character at a specific location
			 * @param index the index of the pattern to return a value for.
			 * @return the character at an index
			 */
			char GetIndex(usint index) const;

			/**
			 * Gets the pattern length.
			 * @return the length of the pattern.
			 */
			usint GetLength() const;
		private:
			std::string m_patternString = "";
	};

	/**
	 * @brief Class for obfuscated patterns
	 * @tparam Element a ring element.
	 */
	// Yuriy: We need to add four methods: GetS, GetR, GetS1, GetR1 + private members for those + possible setters/constructors
	// dimension of S1 and R1 - matrices of ring elements
	// dmension of S and R - matrices of matrices of ring elements
	// clean up the hierarchy - both obfuscatedpattern and conjunction pattern inherit from the same abstract class - can be confusing if methods are
	// in the abstract class  - multiple inheritance issue

	template <class Element>
	class ObfuscatedLWEConjunctionPattern : public ObfuscatedPattern<Element>, public ConjunctionPattern<Element>{
		public:
			/**
			 * Method to define conjunction pattern.
			 *
			 * @param &cryptoParams the parameters being used.
			 */
			explicit ObfuscatedLWEConjunctionPattern(ILParams &cryptoParams) {
				this->SetParameters(&cryptoParams);
				this->m_length = 0;

				//usint m = this->GetLogModulus();
				//this->m_Sl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
				//this->m_Rl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);

			}

			/**
			 * Gets the ring at a specific location
			 * @param row the row of the ring element.
			 * @param column the column of the ring element.
			 * @param *ring the ring value to get.
			 */
			void GetIndex(usint row, usint column, Element *ring);

			/**
			 * Sets crypto params.
			 *
			 * @param *cryptoParams parameters.
			 */
			void SetParameters(ILParams *cryptoParams) { m_cryptoParameters = cryptoParams;}

			/**
			 * Gets crypto params.
			 *
			 * @return parameters.
			 */
			ILParams *GetParameters() { return m_cryptoParameters;}

			/**
			 * Gets the ring dimension
			 * @return the ring dimension
			 */
			usint GetRingDimension() const;

			/**
			 * Gets the pattern length
			 * @return the pattern length
			 */
			usint GetLength() const {return m_length;}

			/**
			 * Sets the pattern length
			 * @param length the length;
			 */
			void SetLength(usint length);

			/**
			 * Gets the modulus
			 * @return the modulus
			 */
			const BigBinaryInteger GetModulus() const;

			/**
			 * Gets the correctness constraint.
			 * @return the constraint
			 */
			const double GetConstraint() const {
				double modulusDbl = this->GetModulus().ConvertToDouble();
				return modulusDbl/8.0;
			};

			/**
			 * Sets the modulus
			 * @param &modulus the modulus
			 */
			void SetModulus(BigBinaryInteger &modulus);

			/**
			 * Gets the log of the modulus
			 * @return the log of the modulus
			 */
			usint GetLogModulus() const;

			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @param &S0_vec the S0 vector from the obfuscated pattern definition.
			 * @param &S1_vec the S1 vector from the obfuscated pattern definition.
			 * @param &R0_vec the R0 vector from the obfuscated pattern definition.
			 * @param &R1_vec the S1 vector from the obfuscated pattern definition.
			 * @param &Sl the Sl vector from the obfuscated pattern definition.
			 * @param &Rl the Rl vector from the obfuscated pattern definition.
			 */
			void SetMatrices(vector<ILMat<Element>> &S0_vec,
					vector<ILMat<Element>> &S1_vec,
					vector<ILMat<Element>> &R0_vec,
					vector<ILMat<Element>> &R1_vec,
					ILMat<Element> &Sl,
					ILMat<Element> &Rl) {

				this->m_S0_vec = &S0_vec;
				this->m_S1_vec = &S1_vec;

				this->m_R0_vec = &R0_vec;
				this->m_R1_vec = &R1_vec;

				this->m_Sl = &Sl;
				this->m_Rl = &Rl;
			}

			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @return the S_l matrix.
			 */
			void GetS(usint i, char testVal,ILMat<Element> &Sib) const {
				if (testVal == 1) {
					Sib = this->m_S0_vec[i];
				} else {
					Sib = this->m_S1_vec[i];
				}
			}

			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @return the R_l matrix.
			 */
			void GetR(usint i, char testVal,ILMat<Element> &Rib) const {
				if (testVal == 1) {
					Rib = this->m_R0_vec[i];
				} else {
					Rib = this->m_R1_vec[i];
				}
			}

			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @return the S_l matrix.
			 */
			void GetSl(ILMat<Element> &Sl) const {
				Sl = this->m_Sl;
			}

			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @return the R_l matrix.
			 */
			void GetRl(ILMat<Element> &Rl) const {
				Rl = this->m_Rl;
			}

		private:

			usint m_length;
			ILParams *m_cryptoParameters;

			vector<ILMat<Element>> *m_S0_vec;
			vector<ILMat<Element>> *m_S1_vec;
			vector<ILMat<Element>> *m_R0_vec;
			vector<ILMat<Element>> *m_R1_vec;
			ILMat<Element> *m_Sl;
			ILMat<Element> *m_Rl;

	};


	/**
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
	// Yuriy: Add the Encode method; see the Latex file for the interface
	template <class Element>
	class LWEConjunctionObfuscationAlgorithm { // : public ObfuscationAlgorithm<Element>{
		public:

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &clearPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool Evaluate(const ClearLWEConjunctionPattern<Element> &clearPattern,
				 const std::string &testString) const;

			/**
			 * Method to obfuscate the cleartext pattern into an obfuscated pattern.
			 *
			 * @param &clearPattern cleartext pattern to obfuscate.
			 * @param &dgg discrete Gaussian generator.
			 * @param &dug discrete uniform generator.
			 * @param &bug binary uniform generator.
			 * @param *obfuscatedPattern the obfuscated pattern.
			 */
			void Obfuscate(const ClearLWEConjunctionPattern<Element> &clearPattern,
				DiscreteGaussianGenerator &dgg,
				DiscreteUniformGenerator &dug,
				ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern) const;

			/**
			 * Method to obfuscate the cleartext pattern into an obfuscated pattern.
			 *
			 * @param &Ai starting key.
			 * @param &Aj ending key.
			 * @param &Ti Trapdoor.
			 * @param &elem a ring element.
			 * @return the encoded element.
			 */
			void Encode(
				const ILMat<Element> &Ai,
				const ILMat<Element> &Aj,
				const TrapdoorPair &Ti,
				const Element &elem,
				ILMat<Element> &encodedElem) const;

			/**
			 * Method for evaluating the pattern
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool Evaluate(const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const;
	};

} // namespace lbcrypto ends
#endif
