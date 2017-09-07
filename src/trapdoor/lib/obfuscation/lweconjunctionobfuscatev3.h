/**0
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Elementakov, <Elementakov@njit.edu>
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

#ifndef LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATEV3_H
#define LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATEV3_H

#include <cmath>
#include <vector>
#include "obfuscatelp.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "math/backend.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "../sampling/trapdoor.h"

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
	class ClearLWEConjunctionPattern : public ClearPattern<Element>, public ConjunctionPattern<Element> {
	public:

		/**
		* Default constructor
		*/
		ClearLWEConjunctionPattern() : m_patternString("") {};

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
		// stores the local instance of the pattern string
		std::string m_patternString;
	};


	/**
	 * @brief Class for obfuscated patterns
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class ObfuscatedLWEConjunctionPattern : public ObfuscatedPattern<Element>, public ConjunctionPattern<Element>{
		public:

			/**
			 * Constructor
			 */
			explicit ObfuscatedLWEConjunctionPattern(); 

			/**
			 * Destructor
			 */
			~ObfuscatedLWEConjunctionPattern(); 

			/**
			 * Method to define conjunction pattern.
			 *
			 * @param elemParams the parameters being used.
			 */
			explicit ObfuscatedLWEConjunctionPattern(shared_ptr<typename Element::Params> elemParams);

			/**
			 * Constructor with element params and chunk size
			 *
			 * @param elemParams the parameters being used.
			 */
			explicit ObfuscatedLWEConjunctionPattern(shared_ptr<typename Element::Params> elemParams, usint chunkSize);

			/**
			 * Sets elements params.
			 *
			 * @param elemParams parameters.
			 */
			void SetParameters(shared_ptr<typename Element::Params> elemParams) { m_elemParams = elemParams;}

			/**
			 * Gets element params.
			 *
			 * @return parameters.
			 */
			const shared_ptr<typename Element::Params> GetParameters() const { return m_elemParams;}

			/**
			 * Gets the ring dimension
			 * @return the ring dimension
			 */
			usint GetRingDimension() const;

			/**
			* Gets the root Hermite Factor
			* @return the root Hermite factor
			*/
			double GetRootHermiteFactor() const { return m_rootHermiteFactor;  }

			/**
			 * Gets the pattern length
			 * @return the pattern length
			 */
			usint GetLength() const {return m_length;}

			/**
			 * Gets the number of bits encoded by one encoding matrix
			 * @return the number of bits
			 */
			usint GetChunkSize() const {return m_chunkSize;}

			/**
			 * Sets the pattern length
			 * @param length the length;
			 */
			void SetLength(usint length);

			/**
			* Sets the root Hermite factor
			* @param rootHermiteFactor lattice root Hermite factor;
			*/
			void SetRootHermiteFactor(double rootHermiteFactor) { m_rootHermiteFactor = rootHermiteFactor; };

			/**
			 * Sets the number of bits encoded using conjunction obfuscator
			 * @param bits number of bits;
			 */
			void SetChunkSize(usint bits) {m_chunkSize = bits;}

			/**
			 * Gets the modulus
			 * @return the modulus
			 */
			const typename Element::Integer GetModulus() const;

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
			void SetModulus(typename Element::Integer &modulus);

			/**
			 * Gets the log of the modulus
			 * @return the log of the modulus
			 */
			usint GetLogModulus() const;

			/**
			 * Sets the key matrices that are used for the obfuscated pattern.
			 * @param pk - vector of public keys.
			 * @param ek - vector of encoding keys.
			 * @param sigma - vector of perturbation matrices.
			 */
			void SetKeys(shared_ptr<std::vector<Matrix<Element>>> pk, shared_ptr<std::vector<RLWETrapdoorPair<Element>>>   ek) {
				this->m_pk = pk;
				this->m_ek = ek;
			}


			/**
			 * Sets the matrices that define the obfuscated pattern.
			 * @param S0_vec the S0 vector from the obfuscated pattern definition.
			 * @param S1_vec the S1 vector from the obfuscated pattern definition.
			 * @param R0_vec the R0 vector from the obfuscated pattern definition.
			 * @param R1_vec the S1 vector from the obfuscated pattern definition.
			 * @param Sl the Sl vector from the obfuscated pattern definition.
			 * @param Rl the Rl vector from the obfuscated pattern definition.
			 */
			void SetMatrices(shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> S_vec,
				shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> R0_vec,
				shared_ptr<Matrix<Element>> Sl, shared_ptr<Matrix<Element>> Rl);

			/**
			 * Gets the S_l matrix used to "close" the conjunction obfuscator.
			 * @return the S_l matrix.
			 */
			shared_ptr<Matrix<Element>>  GetSl() const {
				//this->m_Sl->PrintValues();
				return this->m_Sl;
			}

			/**
			 * Gets the collection of public keys.
			 * @return public keys.
			 */
			const std::vector<Matrix<Element>> &GetPublicKeys() const {
				return *(this->m_pk);
			}

			/**
			 * Gets the collection of private keys.
			 * @return private keys.
			 */
			const std::vector<RLWETrapdoorPair<Element>> &GetEncodingKeys() const {
				return *(this->m_ek);
			}

			/**
			 * Gets the R_l matrix used to "close" the conjunction obfuscator.
			 * @return the R_l matrix.
			 */
			shared_ptr<Matrix<Element>>  GetRl() const {
				return this->m_Rl;
			}

			/**
			 * Gets the S matrix that defines the obfuscated pattern.
			 * @return the S_ib matrix.
			 */
			shared_ptr<Matrix<Element>> GetS(usint i, const std::string &testVal) const;

			/**
			 * Gets the matrices that define the obfuscated pattern.
			 * @return the R_ib matrix.
			 */
			shared_ptr<Matrix<Element>> GetR(usint i, const std::string &testVal) const;

			/**
			* Gets the base for G-sampling
			* @return the base
			*/
			usint GetBase() const { return m_base; }

			/**
			* Sets the base for G-sampling
			* @param base to be set;
			*/
			void SetBase(usint base) { m_base = base; }

		private:

			//length of the pattern
			usint m_length;
			shared_ptr<typename Element::Params> m_elemParams;

			//lattice security parameter
			double m_rootHermiteFactor;

			//number of bits encoded by one matrix
			usint m_chunkSize;

			//base for G-sampling
			usint m_base;

			shared_ptr<vector< vector<shared_ptr<Matrix<Element>>> >> m_S_vec;
			shared_ptr<vector< vector<shared_ptr<Matrix<Element>>> >> m_R_vec;
			shared_ptr<Matrix<Element>> m_Sl;
			shared_ptr<Matrix<Element>> m_Rl;

			shared_ptr<std::vector<Matrix<Element>>> m_pk;
			shared_ptr<std::vector<RLWETrapdoorPair<Element>>>   m_ek;

	};


	/**
	 * @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
	 * @tparam Element a ring element.
	 */
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
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &clearPattern cleartext pattern to obfuscate.
			 * @param &dgg discrete Gaussian generator.
			 * @param &tug ternary uniform generator.
			 */
			void Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				typename Element::DggType &dgg,
				typename Element::TugType &tug,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern, bool optimized = true) const;

			/**
			* Method to generate parameters.
			*
			* @param &dgg the discrete Gaussian Generator.
			* @param &obfuscatedPattern the obfuscated pattern.
			*/
			void ParamsGen(typename Element::DggType &dgg,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern, uint32_t n = 0) const;

			/**
			 * Method to generate keys.
			 *
			 * @param &dgg the discrete Gaussian Generator.
			 * @param &obfuscatedPattern the obfuscated pattern.
			 */
			void KeyGen(typename Element::DggType &dgg,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern) const;

			/**
			 * Method to obfuscate the cleartext pattern into an obfuscated pattern.
			 *
			 * @param &Ai starting key.
			 * @param &Aj ending key.
			 * @param &Ti Trapdoor.
			 * @param &elem a ring element.
			 * @param &dgg the discrete Gaussian Generator.
			 * @param &dggLargeSigma the discrete Gaussian Generator for perturbation sampling.
			 * @param &dggEncoding DGG generator for encoding random ring elements.
			 * @param base used in G-sampling
			 */
			shared_ptr<Matrix<Element>> Encode(
				const Matrix<Element> &Ai,
				const Matrix<Element> &Aj,
				const RLWETrapdoorPair<Element> &Ti,
				const Element &elemS,
				typename Element::DggType &dgg,
				typename Element::DggType &dggLargeSigma,
				typename Element::DggType &EdggEncoding,
				uint32_t base = 2) const;

			/**
			 * Method for evaluating the pattern - before matrix-vector optimization
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool EvaluateV2(const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const;

			/**
			 * Method for evaluating the pattern, using the trick of multiplying a chain of matrix
			 * multiplications by a vector.
			 *
			 * @param &obfuscatedPattern the obfuscated pattern.
			 * @param &testString cleartext pattern to test for.
			 * @param useRandomVector, if 1, menas that a vector of random 1s and 0s should be used.
			 * Else, a vector of all 1s should be used.
			 * @param useLargeConstraint means that the contraint q/8 should be multiplied by the sqrt of m.
			 * @return true if the string matches the pattern and false otherwise.
			 */
			bool EvaluateACS(const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
					const std::string &testString, const int useRandomVector) const;

			/**
			* Method for evaluating the pattern
			*
			* @param &obfuscatedPattern the obfuscated pattern.
			* @param &testString cleartext pattern to test for.
			* @return true if the string matches the pattern and false otherwise.
			*/
			bool Evaluate(const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				 const std::string &testString) const;

		private:

			/**
			* Method to create element parameters for given q and n
			*
			* @param &q estimated value of modulus (based on correctness & security constraints)
			* @param &n estimated ring dimension (based on correctness & security constraints).
			*/
			shared_ptr<typename Element::Params> GenerateElemParams(double q, uint32_t n) const;

	};

} // namespace lbcrypto ends
#endif
