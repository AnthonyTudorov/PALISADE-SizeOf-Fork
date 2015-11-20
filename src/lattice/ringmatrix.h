/**
* @file
* @author	TPOC: 
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers: 
				Dr. Yuriy Polyakov <polyakov@njit.edu>
				Hadi Sajjadpour <ss2959@njit.edu>

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
* This file contains the ILVector2n Matrix for Matrices of Ring operations.
*/

#ifndef LBCRYPTO_CRYPTO_RINGMATRIX_H
#define LBCRYPTO_CRYPTO_RINGMATRIX_H

//Includes Section
#include "il2n.h"
#include "ideals.h"
#include "../crypto/pubkeylp.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	 * @brief Main Ring Matrix class.
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class RingMatrix {
	public:

		/**
		 * Default constructor
		 */
		RingMatrix() : m_cryptoParameters(NULL) {}

		/**
		 * Default constructor
		 * @param dimension the dimensionality of the matrix
		 */
		explicit RingMatrix(usint dimension);

		/**
		* Copy constructor
		*/
		explicit RingMatrix(const RingMatrix<Element> &RingMatrix);

		/**
		* Moveable copy constructor
		*/
		RingMatrix(RingMatrix<Element> &&RingMatrix); 

		/**
		 * Destructor
		 */
		~RingMatrix(){}

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		RingMatrix<Element>& operator=(const RingMatrix<Element> &rhs);

		/**
		* Moveable Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		RingMatrix<Element>& operator=(RingMatrix<Element> &&rhs);

		/**
		* Get a reference to crypto parameters.
		* @return the crypto parameters.
		*/
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

		/**
		* Get the dimension.
		* @return the dimension
		*/
		usint GetDimension() const { return m_dimension; }

		/**
		* Get current estimate of estimate norm
		* @return the current estimate of RingMatrix norm.
		*/
		const BigBinaryInteger &GetNorm();

		/**
		* Get the element
		* @param row the row of the index
		* @param column the column of the index
		* @return the ring element.
		*/
		const Element &GetElement(usint row, usint column) const { return ringMatrix[row][column]; }

		/**
		* Sets a reference to crypto parameters.
		*
		* @param &cryptoParameters is crypto params passed by reference.
		*/
		void SetCryptoParameters(const LPCryptoParameters<Element> &cryptoParameters) { m_cryptoParameters = &cryptoParameters; }

		/**
		* Sets the data element.
		*
		* @param &element is a polynomial ring element.
		* @param row the row of the index
		* @param column the column of the index
		*/
		void SetElement(const Element &element, usint row, usint column) { ringMatrix[row][column] = element; }

		/**
		 * Matrix modulus multiplication.
		 *
		 * @param &b is the RingMatrix to multiply.
		 * @return is the result of the modulus multiplication operation.
		 */
		RingMatrix<Element> ModMul(const RingMatrix<Element> &ringMatrix) const;

	
	private:

		//pointer to crypto parameters
		const LPCryptoParameters<Element> *m_cryptoParameters;

		//size of matrix
		usint m_dimension=1;

		//ring matrix
		Element ***ringMatrix = NULL;

	};

} // namespace lbcrypto ends
#endif
