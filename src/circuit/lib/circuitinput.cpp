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
	out << obj.GetType() << ": ";
	switch (obj.GetType()) {
	case INT:
		out << obj.GetIntValue(); break;
	case PLAINTEXT:
		out << obj.GetPlaintextValue(); break;
	case CIPHERTEXT:
		out << obj.GetCiphertextValue(); break;
	default:
		out << "print not implemented"; break;
	}

	return out;
}

template<typename Element>
void CircuitObject<Element>::DecryptAndPrint(CryptoContext<Element> cc, LPPrivateKey<Element> key, std::ostream& out) const
{
	switch( this->t ) {
	case INT:
	{
		out << this->GetIntValue();
	}
	break;

	case PLAINTEXT:
	{
		out << this->GetPlaintextValue();
	}
	break;

	case CIPHERTEXT:
	{
		Plaintext result;
		cc->Decrypt(key, this->GetCiphertextValue(), &result);
		out << result;
	}
	break;

	case MATRIX_RAT:
	{
		shared_ptr<Matrix<Plaintext>> numerator;
		shared_ptr<Matrix<Plaintext>> denominator;
		cc->DecryptMatrix(key, this->GetMatrixRtValue(), &numerator, &denominator);

		for( size_t r=0; r < this->GetMatrixRtValue()->GetRows(); r++ ) {
			out << "Row " << r << std::endl;
			for( size_t c=0; c < this->GetMatrixRtValue()->GetCols(); c++ ) {
				out << "Col " << c << " n/d = ";
				out << (*numerator)(r,c) << " / ";
				out << (*denominator)(r,c) << std::endl;
			}
		}
	}
		break;

	default:
		throw std::logic_error("type not supported");
	}
}

}
