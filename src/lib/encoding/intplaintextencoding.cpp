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

void IntPlaintextEncoding::Encode(const BigBinaryInteger& modulus, ILVectorArray2n *element, size_t startFrom, size_t length) const{
	//TODO - OPTIMIZE CODE. Please take a look at line 114 temp.SetModulus
	ILVector2n encodedSingleCrt = element->GetElementAtIndex(0);

	Encode(modulus, &encodedSingleCrt, startFrom, length);
	BigBinaryVector tempBBV(encodedSingleCrt.GetValues());

	std::vector<ILVector2n> encodeValues;
	encodeValues.reserve(element->GetNumOfElements());

	for (usint i = 0; i<element->GetNumOfElements(); i++) {
		ILParams ilparams(element->GetElementAtIndex(i).GetCyclotomicOrder(), element->GetElementAtIndex(i).GetModulus(), element->GetElementAtIndex(i).GetRootOfUnity());
		ILVector2n temp(ilparams);
		tempBBV = encodedSingleCrt.GetValues();
		tempBBV.SetModulus(ilparams.GetModulus());
		temp.SetValues(tempBBV, encodedSingleCrt.GetFormat());
		temp.SignedMod(ilparams.GetModulus());
		encodeValues.push_back(temp);
	}

	ILVectorArray2n elementNew(encodeValues);
	*element = elementNew;

}


void IntPlaintextEncoding::Decode(const BigBinaryInteger& modulus, ILVectorArray2n &ilVectorArray2n){
	ILVector2n interpolatedDecodedValue = ilVectorArray2n.InterpolateIlArrayVector2n();
	Decode(modulus, interpolatedDecodedValue);
	BigBinaryVector tempBBV(interpolatedDecodedValue.GetValues());


	std::vector<ILVector2n> encodeValues;
	encodeValues.reserve(ilVectorArray2n.GetNumOfElements());

	for (usint i = 0; i<ilVectorArray2n.GetNumOfElements(); i++) {
		ILParams ilparams(ilVectorArray2n.GetElementAtIndex(i).GetCyclotomicOrder(), ilVectorArray2n.GetElementAtIndex(i).GetModulus(), ilVectorArray2n.GetElementAtIndex(i).GetRootOfUnity());
		ILVector2n temp(ilparams);
		tempBBV = interpolatedDecodedValue.GetValues();
		tempBBV.SetModulus(ilparams.GetModulus());
		temp.SetValues(tempBBV, interpolatedDecodedValue.GetFormat());
		temp.SignedMod(ilparams.GetModulus());
		encodeValues.push_back(temp);
	}

	ILVectorArray2n elementNew(encodeValues);
	ilVectorArray2n = elementNew;
}


void IntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t start_from, size_t length) const {

	if( length == 0 ) length = this->size();

	BigBinaryVector temp(ilVector->GetParams().GetCyclotomicOrder()/2,ilVector->GetModulus());

	Format format = COEFFICIENT;

	for (usint i = start_from; i < length; i++) {
		temp.SetValAtIndex(i, BigBinaryInteger(this->at(i)));
	}

	ilVector->SetValues(temp,format);
}

void IntPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n &ilVector) {
	ilVector = ilVector.SignedMod(modulus);
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
		if (*it == 0) {
			++nPadding;
		} else {
			break;
		}
	}
	this->resize(this->size() - nPadding, 0);
}


}
