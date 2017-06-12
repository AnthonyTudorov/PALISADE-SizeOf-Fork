/*
 * circuitinput.cpp
 *
 *  Created on: Jun 11, 2017
 *      Author: gerardryan
 */

#include "circuitinput.h"
#include "cryptocontext.h"

std::ostream& operator<<(std::ostream& out, const CircuitObject& obj)
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

