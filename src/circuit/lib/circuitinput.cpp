/**
 * @file circuitinput.cpp -- Representation of objects into and out of a circuit
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * This code provides support for input and output of a circuit
 *
 */


#include "circuitinput.h"
#include "cryptocontext.h"

namespace lbcrypto {

template<typename Element>
std::ostream& operator<<(std::ostream& out, const CircuitObject<Element>& obj)
{
	switch (obj.GetType()) {
	case INT:
		out << "Integer not implemented"; break;
	case RATIONAL:
		out << "Rational not implemented"; break;
	case VECTOR_INT:
		out << obj.GetIntVecValue(); break;
	case VECTOR_RAT:
		out << "Vector of Rational not implemented"; break;
	case MATRIX_INT:
		out << "Matrix of Integer not implemented"; break;
	case MATRIX_RAT:
		out << "Matrix of Rational not implemented"; break;
	default:
		out << "UNKNOWN TYPE"; break;
	}

	return out;
}

template<typename Element>
void CircuitObject<Element>::DecryptAndPrint(shared_ptr<CryptoContext<Element>> cc, shared_ptr<LPPrivateKey<Element>> key, std::ostream& out) const
{
	const size_t n = 10;

	switch( this->t ) {
	case VECTOR_INT:
	{
		shared_ptr<Plaintext> result;
		cc->Decrypt(key, GetIntVecValue(), &result);

		size_t i;
		for( i=0; i < n && i < cc->GetRingDimension(); i++ )
			out << result->GetCoefPackedValue()[i] << " ";
		out << (( i == n ) ? "..." : " ") << std::endl;
	}
	break;

	case MATRIX_RAT:
	{
		shared_ptr<Matrix<shared_ptr<Plaintext>>> numerator;
		shared_ptr<Matrix<shared_ptr<Plaintext>>> denominator;
		cc->DecryptMatrix(key, GetIntMatValue(), &numerator, &denominator);

		size_t r, c, i;
		for( r=0; r < GetIntMatValue()->GetRows(); r++ ) {
			out << "Row " << r << std::endl;
			for( c=0; c < GetIntMatValue()->GetCols(); c++ ) {
				out << "Col " << c << ": ([";
				for( i=0; i < n && i < cc->GetRingDimension(); i++ ) {
					out << (*numerator)(r,c)->GetCoefPackedValue()[i] << " ";
				}
				out << (( i == n ) ? "..." : "");
				out << "]/[";
				for( i=0; i < n && i < cc->GetRingDimension(); i++ ) {
					out << (*denominator)(r,c)->GetCoefPackedValue()[i] << " ";
				}
				out << (( i == n ) ? "..." : "");
				out << "])  ";
			}
			out << std::endl;
		}
	}
		break;

	default:
		throw std::logic_error("type not supported");
	}
}

}
