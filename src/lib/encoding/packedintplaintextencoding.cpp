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

//#include "../crypto/cryptocontext.h"
#include "packedintplaintextencoding.h"

namespace lbcrypto {

	BigBinaryInteger PackedIntPlaintextEncoding::initRoot = BigBinaryInteger(0);

	std::vector<usint> PackedIntPlaintextEncoding::rootOfUnityTable = std::vector<usint>();

void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger& modulus, ILVectorArray2n *element, size_t startFrom, size_t length) const{
	//TODO - OPTIMIZE CODE. Please take a look at line 114 temp.SetModulus
	ILVector2n encodedSingleCrt = element->GetElementAtIndex(0);

	Encode(modulus, &encodedSingleCrt, startFrom, length);
	BigBinaryVector tempBBV(encodedSingleCrt.GetValues());

	std::vector<ILVector2n> encodeValues;
	encodeValues.reserve(element->GetNumOfElements());

	for (usint i = 0; i<element->GetNumOfElements(); i++) {
		ILVector2n temp(element->GetElementAtIndex(i).GetParams());
		tempBBV = encodedSingleCrt.GetValues();
		tempBBV.SetModulus(temp.GetModulus());
		temp.SetValues(tempBBV, encodedSingleCrt.GetFormat());
		temp.SignedMod(temp.GetModulus());
		encodeValues.push_back(temp);
	}

	ILVectorArray2n elementNew(encodeValues);
	*element = elementNew;

}


void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger& modulus, ILVectorArray2n *ilVectorArray2n){

	const ILVector2n &ilVector = ilVectorArray2n->GetElementAtIndex(0);
	for (usint i = 0; i<ilVector.GetValues().GetLength(); i++) {
		this->push_back(ilVector.GetValues().GetValAtIndex(i).ConvertToInt());
	}

}


void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
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

void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n *ilVector) {

	for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
		this->push_back( ilVector->GetValues().GetValAtIndex(i).ConvertToInt() );
	}
}

size_t PackedIntPlaintextEncoding::GetChunksize(const usint cyc, const BigBinaryInteger& ptm) const
{
	return cyc/2;
}

void PackedIntPlaintextEncoding::Pack(const BigBinaryInteger &modulus, const usint m) {
	
	usint n = m / 2; //ring dimension

	BigBinaryVector rootOfUnity(n, modulus);

	usint modInt = modulus.ConvertToInt();

	//Do the precomputation if not initialized
	if (this->initRoot.GetMSB() == 0) {
		this->initRoot = RootOfUnity(m, modulus);
		this->rootOfUnityTable.reserve(n);
		rootOfUnityTable.push_back(initRoot.ConvertToInt());
		usint omegaSquare = (rootOfUnityTable[0] * rootOfUnityTable[0]) % modInt;
		for (usint i = 1; i < n; i ++) {
			rootOfUnityTable.push_back((rootOfUnityTable[i-1]*omegaSquare) % modInt);
		}

	}
	

	BigBinaryVector Xvals(n, modulus);
	BigBinaryInteger nInverse(n);
	nInverse = nInverse.ModInverse(modulus);
	
	//Initialize Xvals
	std::vector<usint> rowVals(n, nInverse.ConvertToInt());
	std::vector<usint> finalVals(n, 0);
	std::reverse(this->begin(), this->end());
	
	for (usint i = 0; i < n; i++) {
		//multiply the rowVals with coefficient vectors
		usint sum = std::inner_product(rowVals.begin(), rowVals.end(), this->begin(), 0);	
		finalVals.at(i) = sum%modulus.ConvertToInt();
		std::transform(rowVals.begin(), rowVals.end(), rootOfUnityTable.begin(), rowVals.begin(), std::multiplies<usint>());
	}

	*this = finalVals;

}

void PackedIntPlaintextEncoding::Unpack(const BigBinaryInteger &modulus, const usint m) {
	usint n = m / 2; //ring dimension

	BigBinaryVector rootOfUnity(n, modulus);

	for (usint i = 1; i < m; i += 2) {
		rootOfUnity.SetValAtIndex((i - 1) / 2, initRoot.ModExp(BigBinaryInteger(i), modulus));
	}

	std::vector<usint> finalVals;
	finalVals.reserve(n);

	for (usint i = 0; i < n; i++) {
		BigBinaryInteger sum(0);
		for (usint j = 0; j < n; j++) {
			sum = sum + BigBinaryInteger(this->at(j))*rootOfUnity.GetValAtIndex(i).ModExp(BigBinaryInteger(n-1-j),modulus);
		}
		sum = sum.Mod(modulus);
		finalVals.push_back(sum.ConvertToInt());
	}


	*this = finalVals;

}

}
