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

	void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
	{
		int padlen = 0;
		uint32_t mod = modulus.ConvertToInt();

		if (length == 0) length = this->size();

		// length is usually chunk size; if start + length would go past the end of the item, add padding
		if ((startFrom + length) > this->size()) {
			padlen = (startFrom + length) - this->size();
			length = length - padlen;
		}

		BigBinaryVector temp(ilVector->GetParams()->GetCyclotomicOrder() / 2, ilVector->GetModulus());

		Format format = COEFFICIENT;

		for (usint i = 0; i < length; i++) {
			uint32_t entry = this->at(i + startFrom);
			if (entry >= mod)
				throw std::logic_error("Cannot encode integer at position " + std::to_string(i) + " because it is >= plaintext modulus " + std::to_string(mod));
			BigBinaryInteger Val = BigBinaryInteger(entry);
			temp.SetValAtIndex(i, Val);
		}

		//BigBinaryInteger Num = modulus - BigBinaryInteger::ONE;
		for (usint i = 0; i<padlen; i++) {
			temp.SetValAtIndex(i + length, BigBinaryInteger::ZERO);
			//temp.SetValAtIndex(i + length, Num);
			//if( i == 0 )
			//	Num = BigBinaryInteger::ZERO;
		}

		ilVector->SetValues(temp, Format::EVALUATION); //output was in coefficient format

		this->Pack(ilVector, modulus);//ilVector coefficients are packed and resulting ilVector is in COEFFICIENT form.

	}

	void PackedIntPlaintextEncoding::Encode(const native64::BigBinaryInteger &modulus, native64::ILVector2n *ilVector, size_t start_from, size_t length) const {}
	void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVector, size_t start_from, size_t length) const {}


	void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger &modulus, ILVector2n *ilVector) {

		this->Unpack(ilVector, modulus); //Format is in COEFFICIENT

		for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
			this->push_back(ilVector->GetValues().GetValAtIndex(i).ConvertToInt());
		}

	}

	void PackedIntPlaintextEncoding::Decode(const native64::BigBinaryInteger &modulus, native64::ILVector2n *ilVector) {}
	void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVector) {}

	size_t PackedIntPlaintextEncoding::GetChunksize(const usint cyc, const BigBinaryInteger& ptm) const
	{
		return cyc / 2;
	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint n = ring->GetParams()->GetCyclotomicOrder() / 2; //ring dimension

															   //Do the precomputation if not initialized
		if (this->initRoot.GetMSB() == 0) {
			this->initRoot = RootOfUnity<BigBinaryInteger>(n << 1, modulus);
		}

		//initRoot = BigBinaryInteger::TWO;

		BigBinaryInteger qMod(ring->GetParams()->GetModulus());

		BigBinaryVector packedVector(ring->GetValues());

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(modulus);

		packedVector = ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().InverseTransform(packedVector, initRoot, n << 1);

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

	void PackedIntPlaintextEncoding::Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint n = ring->GetParams()->GetCyclotomicOrder() / 2; //ring dimension

		BigBinaryInteger qMod(ring->GetParams()->GetModulus());

		BigBinaryVector packedVector(ring->GetValues());

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(modulus);

		packedVector = ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().ForwardTransform(packedVector, initRoot, n << 1);

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

}
