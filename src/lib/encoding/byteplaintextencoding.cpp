/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>,
 *	Kevin King <4kevinking@gmail.com>
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
 * This code provides a byte array abstraction.
 *
 */

#include "byteplaintextencoding.h"

namespace lbcrypto {

BytePlaintextEncoding::BytePlaintextEncoding(const char* cstr) {
	std::string s(cstr);
	*this = s;
}

BytePlaintextEncoding::BytePlaintextEncoding(const char* cstr, usint len) {
	std::string s(cstr, len);
	*this = s;
}

BytePlaintextEncoding& BytePlaintextEncoding::operator=(const std::string& s) {
	BytePlaintextEncoding rhs(s);
	operator=(rhs);
	return *this;
}

BytePlaintextEncoding& BytePlaintextEncoding::operator=(const char* cstr) {
	std::string s(cstr);
	operator=(s);
	return *this;
}

void
BytePlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
{
	int		padlen = 0;

	// default values mean "do it all"
	if( length == 0 ) length = this->size();

	// length is usually chunk size; if start + length would go past the end of the item, add padding
	if( (startFrom + length) > this->size() ) {
		padlen = (startFrom + length) - this->size();
		length = length - padlen;
	}

	usint mod = modulus.ConvertToInt();
	usint p = ceil((float)log((double)255) / log((double)mod));

	BigBinaryVector temp(p*(length+padlen));
	temp.SetModulus(ilVector->GetModulus());
	Format format = COEFFICIENT;

	for (usint i = 0; i<length; i++) {
		usint actualPos = i + startFrom;
		usint actualPosP = i * p;
		usint Num = this->at(actualPos);
		usint exp = mod, Rem = 0;
		for (usint j = 0; j<p; j++) {
			Rem = Num%exp;
			temp.SetValAtIndex(actualPosP + j, UintToBigBinaryInteger((Rem / (exp / mod))));
			Num -= Rem;
			exp *= mod;
		}
	}

	usint Num = 0x80;
	for( usint i=0; i<padlen; i++ ) {
		usint actualPos = (i + length) * p;
		usint exp = mod, Rem = 0;
		for (usint j = 0; j<p; j++) {
			Rem = Num%exp;
			temp.SetValAtIndex(actualPos + j, UintToBigBinaryInteger((Rem / (exp / mod))));
			Num -= Rem;
			exp *= mod;
		}
		Num = 0x00;
	}

	ilVector->SetValues(temp,format);
}

void
BytePlaintextEncoding::Decode(const BigBinaryInteger &modulus, ILVector2n &ilVector)
{
	//TODO-Nishanth: Hard-coding rootofUnity for now. Need to find a way to figure out how to set the correct rootOfUnity.
	ilVector.SwitchModulus(modulus, BigBinaryInteger::ONE);

	usint mod = modulus.ConvertToInt();
	usint p = ceil((float)log((double)255) / log((double)mod));
	usint resultant_char;

	for (usint i = 0; i<ilVector.GetValues().GetLength(); i = i + p) {
		usint exp = 1;
		resultant_char = 0;
		for (usint j = 0; j<p; j++) {
			resultant_char += ilVector.GetValues().GetValAtIndex(i + j).ConvertToInt()*exp;
			exp *= mod;
		}
		this->push_back(resultant_char);
	}
}

void
BytePlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVectorArray2n *element, size_t startFrom, size_t length) const
{
	//TODO - OPTIMIZE CODE. Please take a look at line 114 temp.SetModulus
	ILVector2n temp = element->GetElementAtIndex (0);

	BigBinaryInteger symbol(modulus);
	Encode(symbol, &temp, startFrom, length);

	std::vector<ILVector2n> symbolVals;

	for(usint i=0;i<element->GetNumOfElements();i++){
		ILParams ilparams(element->GetElementAtIndex(i).GetCyclotomicOrder(), element->GetElementAtIndex(i).GetModulus(), element->GetElementAtIndex(i).GetRootOfUnity());
		ILVector2n ilVector(ilparams);
		temp.SwitchModulus( ilparams.GetModulus(), ilparams.GetRootOfUnity() );

		// temp.SetModulus(ilparams.GetModulus());
		ilVector.SetValues(temp.GetValues(),temp.GetFormat());
		symbolVals.push_back(ilVector);
	}

	ILVectorArray2n elementNew(symbolVals);
	*element = elementNew;

}

void
BytePlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVectorArray2n &ilVectorArray2n){

	ILVector2n interpolatedDecodedValue = ilVectorArray2n.InterpolateIlArrayVector2n();

	//interpolatedDecodedValue.DecodeElement(text, modulus);
	Decode(modulus, interpolatedDecodedValue);
}

void
BytePlaintextEncoding::Unpad()
{
	usint nPadding = 0;
	for (sint i = this->size() - 1; i >= 0; --i) {
		nPadding++;
		if (this->at(i) == 0x80) {
			break;
		}
	}
	this->resize(this->size() - nPadding, 0);
}

}
