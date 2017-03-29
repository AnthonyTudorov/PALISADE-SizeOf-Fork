/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Jerry Ryan <gwryan@njit.edu>
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
 * This code provides a int array abstraction.
 *
 */

#include "intplaintextencoding.h"

namespace lbcrypto {

// Forms a binary array from an integer; represents the integer as a binary polynomial
IntPlaintextEncoding::IntPlaintextEncoding(uint32_t value)
{
	for (size_t i = 0; i < 32; i++)
	{
		// gets i-th bit of the 32-bit integer
		this->push_back((value >> i) & 1);
	}
}

void IntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
{
	int padlen = 0;
	uint32_t mod = modulus.ConvertToInt();

	if( length == 0 ) length = this->size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > this->size() ) {
		padlen = (startFrom + length) - this->size();
		length = length - padlen;
	}

	BigBinaryVector temp(ilVector->GetParams()->GetCyclotomicOrder()/2,ilVector->GetModulus());

	Format format = COEFFICIENT;

	for (usint i = 0; i < length; i++) {
		uint32_t entry = this->at(i + startFrom);
		if( entry >= mod )
			throw std::logic_error("Cannot encode integer at position " + std::to_string(i) + " because it is >= plaintext modulus " + std::to_string(mod));
		BigBinaryInteger Val = BigBinaryInteger( entry );
		temp.SetValAtIndex(i, Val);
	}

	//BigBinaryInteger Num = modulus - BigBinaryInteger::ONE;
	for( usint i=0; i<padlen; i++ ) {
		temp.SetValAtIndex(i+length, BigBinaryInteger::ZERO);
		//temp.SetValAtIndex(i + length, Num);
		//if( i == 0 )
		//	Num = BigBinaryInteger::ZERO;
	}

	ilVector->SetValues(temp,format);
}

void IntPlaintextEncoding::Encode(const native64::BigBinaryInteger &modulus, native64::ILVector2n *ilVector, size_t start_from, size_t length) const {}

void IntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVector, size_t start_from, size_t length) const {}


void IntPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n *ilVector) {

	for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
		this->push_back( ilVector->GetValues().GetValAtIndex(i).ConvertToInt() );
	}
}

void IntPlaintextEncoding::Decode(const native64::BigBinaryInteger &modulus, native64::ILVector2n *ilVector) {}
void IntPlaintextEncoding::Decode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVector) {}


size_t
IntPlaintextEncoding::GetChunksize(const usint cyc, const BigBinaryInteger&) const
{
	return cyc/2;
}

// Evaluates the array of integers as a polynomial at x = 2
int32_t IntPlaintextEncoding::EvalToInt(uint32_t modulus) const
{
	int32_t result = 0;
	uint32_t powerFactor = 1;
	uint32_t half(modulus >> 1);
	for (size_t i = 0; i < this->size(); i++) {

		// deal with unsigned representation
		if (this->at(i) < half)
			result += powerFactor * this->at(i);
		else
			result -= powerFactor * (modulus - this->at(i));

		// multiply the power factor by 2
		powerFactor <<= 1;
	}
	return result;
}

}
