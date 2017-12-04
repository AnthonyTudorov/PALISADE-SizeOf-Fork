/**
 * @file circuitinput.h -- Representation of objects into and out of a circuit
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

#ifndef SRC_CIRCUIT_CIRCUITINPUT_H_
#define SRC_CIRCUIT_CIRCUITINPUT_H_

#include "palisade.h"
#include <memory>
#include <iostream>
using std::shared_ptr;
using namespace lbcrypto;

typedef enum wire_type {
    INT,
    RATIONAL,
    VECTOR_INT,
    VECTOR_RAT,
	MATRIX_INT,
	MATRIX_RAT,
    UNKNOWN
} wire_type;

inline std::ostream& operator<<(std::ostream& out, const wire_type& ty)
{
	switch (ty) {
	case INT:
		out << "Integer"; break;
	case RATIONAL:
		out << "Rational"; break;
	case VECTOR_INT:
		out << "Vector of Integer"; break;
	case VECTOR_RAT:
		out << "Vector of Rational"; break;
	case MATRIX_INT:
		out << "Matrix of Integer"; break;
	case MATRIX_RAT:
		out << "Matrix of Rational"; break;
	default:
		out << "UNKNOWN TYPE"; break;
	}

	return out;
}

namespace lbcrypto {

template<typename Element>
class CircuitObject {
	wire_type	t;
	BigInteger	ival;
	BigInteger	dval;
	Ciphertext<Element> ct;
	shared_ptr<RationalCiphertext<Element>> rct;
	shared_ptr<Matrix<Ciphertext<Element>>> mct;
	shared_ptr<Matrix<RationalCiphertext<Element>>> mrct;

public:
	CircuitObject() : t(UNKNOWN) {}
	CircuitObject(const BigInteger& ival) : t(INT), ival(ival) {}
	CircuitObject(const BigInteger& ival, const BigInteger& dval) : t(RATIONAL), ival(ival), dval(dval) {}
	CircuitObject(const Ciphertext<Element> ct) : t(VECTOR_INT), ct(ct) {}
	CircuitObject(const shared_ptr<RationalCiphertext<Element>> rct) : t(VECTOR_RAT), rct(rct) {}
	CircuitObject(const shared_ptr<Matrix<Ciphertext<Element>>> mct) : t(MATRIX_INT), mct(mct) {}
	CircuitObject(const shared_ptr<Matrix<RationalCiphertext<Element>>> mrct) : t(MATRIX_RAT), mrct(mrct) {}

	wire_type GetType() const { return t; }
	void SetType(wire_type t) {
		ct.reset();
		rct.reset();
		mct.reset();
		mrct.reset();
		this->t = t;
	}
	Ciphertext<Element> GetIntVecValue() const { return ct; }
	shared_ptr<Matrix<RationalCiphertext<Element>>> GetIntMatValue() const { return mrct; }

	void DecryptAndPrint(CryptoContext<Element> cc, shared_ptr<LPPrivateKey<Element>> key, std::ostream& out) const;
};

}

#endif
