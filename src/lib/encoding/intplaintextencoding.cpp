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

#include "../crypto/cryptocontext.h"
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


void IntPlaintextEncoding::Decode(const BigBinaryInteger& modulus, ILVectorArray2n *ilVectorArray2n){
	bool dbg_flag = false;
	DEBUG("in Int DECODE IlVectorArray2n");

	ILVector2n interpolatedDecodedValue = ilVectorArray2n->InterpolateIlArrayVector2n();
	DEBUG("A");
	Decode(modulus, &interpolatedDecodedValue);
	DEBUG("B");
	BigBinaryVector tempBBV(interpolatedDecodedValue.GetValues());
	DEBUG("C");


	std::vector<ILVector2n> encodeValues;
	encodeValues.reserve(ilVectorArray2n->GetNumOfElements());
	DEBUG("D");
	for (usint i = 0; i<ilVectorArray2n->GetNumOfElements(); i++) {
	  		    DEBUG("i "<<i);
		ILParams ilparams(ilVectorArray2n->GetElementAtIndex(i).GetCyclotomicOrder(), ilVectorArray2n->GetElementAtIndex(i).GetModulus(), ilVectorArray2n->GetElementAtIndex(i).GetRootOfUnity());
		DEBUG("a");
		ILVector2n temp(ilparams);
		DEBUG("b");
		tempBBV = interpolatedDecodedValue.GetValues();
		DEBUG("c");
		tempBBV.SetModulus(ilparams.GetModulus());
		DEBUG("d");
		temp.SetValues(tempBBV, interpolatedDecodedValue.GetFormat());
		DEBUG("e");
		temp.SignedMod(ilparams.GetModulus());
		DEBUG("f");
		encodeValues.push_back(temp);
		DEBUG("g");
	}

	ILVectorArray2n elementNew(encodeValues);
	*ilVectorArray2n = elementNew;
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

	BigBinaryVector temp(ilVector->GetParams().GetCyclotomicOrder()/2,ilVector->GetModulus());

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

void IntPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n *ilVector) {
	*ilVector = ilVector->SignedMod(modulus);
	std::vector<uint32_t> intArray(ilVector->GetValues().GetLength());
	for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
		this->push_back( ilVector->GetValues().GetValAtIndex(i).ConvertToInt() );
	}
}

size_t
IntPlaintextEncoding::GetChunksize(const usint cyc, const BigBinaryInteger&) const
{
	return cyc/2;
}

}
