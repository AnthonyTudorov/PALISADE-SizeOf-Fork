#ifndef __TYPE_H__
#define __TYPE_H__

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


class CircuitObject {
	wire_type	t;
	BigBinaryInteger	ival;
	BigBinaryInteger	dval;
	shared_ptr<Ciphertext<ILDCRT2n>> ct;
	shared_ptr<RationalCiphertext<ILDCRT2n>> rct;
	shared_ptr<Matrix<Ciphertext<ILDCRT2n>>> mct;
	shared_ptr<Matrix<RationalCiphertext<ILDCRT2n>>> mrct;

public:
	CircuitObject() : t(UNKNOWN) {}
	CircuitObject(const BigBinaryInteger& ival) : t(INT), ival(ival) {}
	CircuitObject(const BigBinaryInteger& ival, const BigBinaryInteger& dval) : t(RATIONAL), ival(ival), dval(dval) {}
	CircuitObject(const shared_ptr<Ciphertext<ILDCRT2n>> ct) : t(VECTOR_INT), ct(ct) {}
	CircuitObject(const shared_ptr<RationalCiphertext<ILDCRT2n>> rct) : t(VECTOR_RAT), rct(rct) {}
	CircuitObject(const shared_ptr<Matrix<Ciphertext<ILDCRT2n>>> mct) : t(MATRIX_INT), mct(mct) {}
	CircuitObject(const shared_ptr<Matrix<RationalCiphertext<ILDCRT2n>>> mrct) : t(MATRIX_RAT), mrct(mrct) {}

	wire_type GetType() const { return t; }
	void SetType(wire_type t) {
		ct.reset();
		rct.reset();
		mct.reset();
		mrct.reset();
		this->t = t;
	}
	shared_ptr<Ciphertext<ILDCRT2n>> GetIntVecValue() const { return ct; }

	friend std::ostream& operator<<(std::ostream& out, const CircuitObject& obj);
};

#endif
