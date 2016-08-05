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

void IntPlaintextEncoding::Encode(const BigBinaryInteger&, ILVectorArray2n*, size_t, size_t) const{
	throw std::logic_error("Operation not implemented");
}


void IntPlaintextEncoding::Decode(const BigBinaryInteger&, ILVectorArray2n&){
	throw std::logic_error("Operation not implemented");
}


void IntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
{
	int padlen = 0;

	if( length == 0 ) length = this->size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > this->size() ) {
		padlen = (startFrom + length) - this->size();
		length = length - padlen;
	}

	BigBinaryVector temp(ilVector->GetParams().GetCyclotomicOrder()/2,ilVector->GetModulus());

	Format format = COEFFICIENT;


	for (usint i = 0; i < length; i++) {
		BigBinaryInteger Val = BigBinaryInteger( this->at(i + startFrom) );
		temp.SetValAtIndex(i, Val);
	}

	BigBinaryInteger padVal(0x80);
	for (usint i = 0; i < padlen; i++ ) {
		temp.SetValAtIndex(i+length, padVal);
		padVal = 0;
	}

	ilVector->SetValues(temp,format);
}

void IntPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n &ilVector) {
	//TODO-Nishanth: Hard-coding rootofUnity for now. Need to find a way to figure out how to set the correct rootOfUnity.
	ilVector.SwitchModulus(modulus, BigBinaryInteger::ONE);
	std::vector<uint32_t> intArray(ilVector.GetValues().GetLength());
	for (usint i = 0; i<ilVector.GetValues().GetLength(); i++) {
		this->push_back( ilVector.GetValues().GetValAtIndex(i).ConvertToInt() );
	}
}

void
IntPlaintextEncoding::Unpad()
{
	usint nPadding = 0;
	for (auto it = this->rbegin(); it != this->rend(); ++it) {
		nPadding++;
		if (*it == 0x80) {
			break;
		}
	}
	this->resize(this->size() - nPadding, 0);
}


}
