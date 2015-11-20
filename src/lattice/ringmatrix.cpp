//LAYER 3 : RingMatrix REPRESENTATION
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Hadi Sajjadpour <ss2959@njit.edu>
Description:	
	This code provides the core proxy re-encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "ringmatrix.h"

namespace lbcrypto {

	// copy constructor
	template <class Element>
	RingMatrix<Element>::RingMatrix(usint dimension) {
		//m_cryptoParameters = RingMatrix.m_cryptoParameters;
		//m_element = RingMatrix.m_element;
		this->m_dimension = dimension;

		// Create 2D array of pointers:
		this->m_ringMatrix = new Element**[this->m_dimension];
		for (usint i = 0; i < this->m_dimension; ++i) {
			this->m_ringMatrix[i] = new Element*[m_dimension];
		}

		// Null out the pointers contained in the array:
		for (usint i = 0; i < this->m_dimension; ++i) {
			for (usint j = 0; j < this->m_dimension; ++j) {
				this->m_ringMatrix[i][j] = NULL;
			}
		}
	}


	// copy constructor
	template <class Element>
	RingMatrix<Element>::RingMatrix(const RingMatrix<Element> &ringMatrix) {
		this->m_cryptoParameters = ringMatrix.m_cryptoParameters;
		//this->m_element = RingMatrix.m_element;
		this->m_dimension = ringMatrix.m_dimension;

		// Create 2D array of pointers:
		this->m_ringMatrix = new Element**[this->m_dimension];
		for (usint i = 0; i < this->m_dimension; ++i) {
			this->m_ringMatrix[i] = new Element*[m_dimension];
		}

		// Null out the pointers contained in the array:
		for (usint i = 0; i < this->m_dimension; ++i) {
			for (usint j = 0; j < this->m_dimension; ++j) {
				this->m_ringMatrix[i][j] = ringMatrix.m_ringMatrix[i][j];
			}
		}

	}



	template <class Element>
	RingMatrix<Element> RingMatrix<Element>::ModMul(const RingMatrix<Element> &ringMatrix) const {

		RingMatrix<Element> returnMatrix(this->m_dimension);
		returnMatrix.setCryptoParams(this->m_cryptoParameters);

		// Null out the pointers contained in the array:
		for (usint i = 0; i < this->m_dimension; ++i) {
			for (usint j = 0; j < this->m_dimension; ++j) {				
				Element result = this->m_ringMatrix[i][0].Times(ringMatrix->m_ringMatrix[0][j]);
				for (usint k = 1; k < this->m_dimension; ++k) {
					Element sum = result.Plus(this->m_ringMatrix[i][k].Times(ringMatrix->m_ringMatrix[k][j]));
					result = sum;
					~sum;
				}
				ringMatrix->m_ringMatrix[i][j] = result;
			}
		}


	}



}  // namespace lbcrypto ends
