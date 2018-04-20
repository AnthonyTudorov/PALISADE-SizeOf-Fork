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
	RAT,
	VECTOR_INT,
	VECTOR_RAT,
	MATRIX_INT,
	MATRIX_RAT,
	PLAINTEXT,
	CIPHERTEXT,
	RATIONALCIPHERTEXT,
	UNKNOWN
} wire_type;

inline std::ostream& operator<<(std::ostream& out, const wire_type& ty)
{
	switch (ty) {
	case INT:
		out << "Integer"; break;
	case RAT:
		out << "Rational"; break;
	case VECTOR_INT:
		out << "Vector of Integer"; break;
	case VECTOR_RAT:
		out << "Vector of Rational"; break;
	case MATRIX_INT:
		out << "Matrix of Integer"; break;
	case MATRIX_RAT:
		out << "Matrix of Rational"; break;
	case PLAINTEXT:
		out << "Plaintext"; break;
	case CIPHERTEXT:
		out << "Ciphertext"; break;
	case RATIONALCIPHERTEXT:
		out << "Rational Ciphertext"; break;
	case UNKNOWN:
		out << "Unknown"; break;
	}

	return out;
}

namespace lbcrypto {

template<typename Element>
class CircuitObject {
	wire_type	t;
	usint		ival = 0;
	Plaintext	pt;
	Ciphertext<Element> ct;

	//	shared_ptr<RationalCiphertext<Element>> rct;
	//	shared_ptr<Matrix<Ciphertext<Element>>> mct;

	shared_ptr<Matrix<RationalCiphertext<Element>>> mrct;
	shared_ptr<Matrix<Plaintext>> numerator;
	shared_ptr<Matrix<Plaintext>> denominator;


public:
	CircuitObject() : t(UNKNOWN) {}
	CircuitObject(usint ival) : t(INT), ival(ival) {}
	CircuitObject(const Plaintext pt) : t(PLAINTEXT), pt(pt) {}
	CircuitObject(const Ciphertext<Element> ct) : t(CIPHERTEXT), ct(ct) {}
	//	CircuitObject(const shared_ptr<RationalCiphertext<Element>> rct) : t(VECTOR_RAT), rct(rct) {}
	//	CircuitObject(const shared_ptr<Matrix<Ciphertext<Element>>> mct) : t(MATRIX_INT), mct(mct) {}
	CircuitObject(const shared_ptr<Matrix<RationalCiphertext<Element>>> mrct) : t(MATRIX_RAT), mrct(mrct) {}

	wire_type GetType() const { return t; }

	void SetType(wire_type t) {
		pt.reset();
		ct.reset();
		//		rct.reset();
		//		mct.reset();
		mrct.reset();
		this->t = t;
	}

	void SetPlaintext(Plaintext p) {
		pt = p;
	}

	// unary minus
	CircuitObject<Element> operator-() const {
		switch( this->GetType() ) {
		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();
			return cc->EvalNegate(op1);
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();
			return cc->EvalNegateMatrix(op1);
		}
		break;

		default:
			PALISADE_THROW(type_error, "Unary minus operation not available for this operand's type");
		}
	}

	CircuitObject<Element> operator+(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalAdd(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalAdd(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalAdd(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalAddMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Addition operation not available for left-hand operand's type");
		}
	}

	CircuitObject<Element> operator-(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalSub(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalSub(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalSub(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalSubMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Subtraction operation not available for left-hand operand's type");
		}
	}


	CircuitObject<Element> operator*(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalMult(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalMult(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalMult(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalMultMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Multiply operation not available for left-hand operand's type");
		}
	}

	CircuitObject<Element> operator>>(const CircuitObject<Element>& other) const {
		if( this->GetType() != CIPHERTEXT )
			PALISADE_THROW(type_error, "Right shift operation not available for left-hand operand's type");
		if( other.GetType() != INT )
			PALISADE_THROW(type_error, "Right shift operation has wrong type for right-hand operand");
		auto cc = this->GetCiphertextValue()->GetCryptoContext();

		return cc->EvalRightShift(this->GetCiphertextValue(), other.GetIntValue());
	}

	friend ostream& operator<<(ostream& out, const CircuitObject<Element>& e) {
		LPPrivateKey<Element> key;
		return e.Display(out, key);
	}

	ostream& Display(ostream& out, LPPrivateKey<Element>& key) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
			out << this->GetPlaintextValue();
			break;

		case INT:
			out << this->GetIntValue();
			break;

		case CIPHERTEXT: {
			if( key ) {
				auto ct = this->GetCiphertextValue();
				auto cc = ct->GetCryptoContext();
				Plaintext result;
				cc->Decrypt(key, ct, &result);
				out << result;
			}
			else {
				out << "CIPHERTEXT";
			}
		}
		break;

		case MATRIX_RAT: {
			if( key ) {
				auto op1 = this->GetMatrixRtValue();
				auto cc = (*op1)(0,0).GetCryptoContext();

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
			else {
				out << "MATRIX";
			}
		}
		break;

		default:
			out << "<<<Don't know how to print a " << this->GetType() << ">>>";
			break;
		}
		return out;
	}

	usint GetIntValue() const { return ival; }
	Plaintext GetPlaintextValue() const { return pt; }
	Ciphertext<Element> GetCiphertextValue() const { return ct; }
	shared_ptr<Matrix<RationalCiphertext<Element>>> GetMatrixRtValue() const { return mrct; }

	void SetPlaintext(Plaintext p) {
		pt = p;
	}

	// unary minus
	CircuitObject<Element> operator-() const {
		switch( this->GetType() ) {
		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();
			return cc->EvalNegate(op1);
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();
			return cc->EvalNegateMatrix(op1);
		}
		break;

		default:
			PALISADE_THROW(type_error, "Unary minus operation not available for this operand's type");
		}
	}

	CircuitObject<Element> operator+(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalAdd(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalAdd(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalAdd(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalAddMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Addition operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Addition operation not available for left-hand operand's type");
		}
	}

	CircuitObject<Element> operator-(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalSub(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalSub(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalSub(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalSubMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Subtraction operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Subtraction operation not available for left-hand operand's type");
		}
	}


	CircuitObject<Element> operator*(const CircuitObject<Element>& other) const {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT: {
			auto op1 = this->GetPlaintextValue();
			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				auto cc = op2->GetCryptoContext();

				return cc->EvalMult(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Plaintext and right-hand operand's type");
			}
		}
		break;

		case CIPHERTEXT: {
			auto op1 = this->GetCiphertextValue();
			auto cc = op1->GetCryptoContext();

			switch( other.GetType() ) {
			case CIPHERTEXT:
			{
				auto op2 = other.GetCiphertextValue();
				return cc->EvalMult(op1, op2);
			}
			break;

			case PLAINTEXT:
			case INT:
			{
				auto op2 = other.GetPlaintextValue();
				return cc->EvalMult(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Ciphertext and right-hand operand's type");
			}
		}
		break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();

			switch( other.GetType() ) {
			case MATRIX_RAT:
			{
				auto op2 = other.GetMatrixRtValue();

				return cc->EvalMultMatrix(op1, op2);
			}
			break;

			default:
				PALISADE_THROW(type_error, "Multiply operation not available for Matrix<RationalCiphertext> and right-hand operand's type");
			}
		}
		break;

		default:
			PALISADE_THROW(type_error, "Multiply operation not available for left-hand operand's type");
		}
	}

	CircuitObject<Element> operator>>(const CircuitObject<Element>& other) const {
		if( this->GetType() != CIPHERTEXT )
			PALISADE_THROW(type_error, "Right shift operation not available for left-hand operand's type");
		if( other.GetType() != INT )
			PALISADE_THROW(type_error, "Right shift operation has wrong type for right-hand operand");
		auto cc = this->GetCiphertextValue()->GetCryptoContext();

		return cc->EvalRightShift(this->GetCiphertextValue(), other.GetIntValue());
	}

	// decrypts any ciphertexts and saves the results
	void Decrypt(LPPrivateKey<Element> key) {
		switch( this->GetType() ) {
		case PLAINTEXT:
		case INT:
			break;

		case MATRIX_RAT: {
			auto op1 = this->GetMatrixRtValue();
			auto cc = (*op1)(0,0).GetCryptoContext();
			cc->DecryptMatrix(key, this->GetMatrixRtValue(), &numerator, &denominator);
		}
			break;

		case CIPHERTEXT: {
			auto ct = this->GetCiphertextValue();
			auto cc = ct->GetCryptoContext();
			cc->Decrypt(key, ct, &pt);
		}
		break;

		default:
			break;
		}
	}

	friend ostream& operator<<(ostream& out, const CircuitObject<Element>& e) {
		switch( e.GetType() ) {
		case PLAINTEXT:
			out << e.GetPlaintextValue();
			break;

		case INT:
			out << e.GetIntValue();
			break;

		case CIPHERTEXT: {
			if( e.GetPlaintextValue() ) {
				out << e.GetPlaintextValue();
			}
			else {
				out << "CIPHERTEXT";
			}
		}
		break;

		case MATRIX_RAT: {
			auto n = e.GetNumerator();
			auto d = e.GetDenominator();
			if( n ) {
				for( size_t r=0; r < e.GetMatrixRtValue()->GetRows(); r++ ) {
					out << "Row " << r << std::endl;
					for( size_t c=0; c < e.GetMatrixRtValue()->GetCols(); c++ ) {
						out << "Col " << c << " n/d = ";
						out << (*n)(r,c) << " / ";
						out << (*d)(r,c) << std::endl;
					}
				}
			}
			else {
				out << "MATRIX";
			}
		}
		break;

		default:
			out << "<<<Don't know how to print a " << e.GetType() << ">>>";
			break;
		}
		return out;
	}

	usint GetIntValue() const { return ival; }
	Plaintext GetPlaintextValue() const { return pt; }
	Ciphertext<Element> GetCiphertextValue() const { return ct; }
	shared_ptr<Matrix<RationalCiphertext<Element>>> GetMatrixRtValue() const { return mrct; }
	shared_ptr<Matrix<Plaintext>> GetNumerator() const { return numerator; }
	shared_ptr<Matrix<Plaintext>> GetDenominator() const { return denominator; }
};

}

#endif
