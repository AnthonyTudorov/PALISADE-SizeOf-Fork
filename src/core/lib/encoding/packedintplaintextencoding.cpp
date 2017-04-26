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
	BigBinaryInteger PackedIntPlaintextEncoding::bigMod = BigBinaryInteger(0);
	BigBinaryInteger PackedIntPlaintextEncoding::bigRoot = BigBinaryInteger(0);

	std::vector<usint> PackedIntPlaintextEncoding::rootOfUnityTable = std::vector<usint>();

	void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
	{
		int padlen = 0;
		uint64_t mod = modulus.ConvertToInt();

		if (length == 0) length = this->size();

		// length is usually chunk size; if start + length would go past the end of the item, add padding
		if ((startFrom + length) > this->size()) {
			padlen = (startFrom + length) - this->size();
			length = length - padlen;
		}

		BigBinaryVector temp(ilVector->GetRingDimension(), ilVector->GetModulus());

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

	void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger &modulus, ILVector2n *ilVector) {

		this->Unpack(ilVector, modulus); //Format is in COEFFICIENT

		for (usint i = 0; i<ilVector->GetValues().GetLength(); i++) {
			this->push_back(ilVector->GetValues().GetValAtIndex(i).ConvertToInt());
		}

	}

	void PackedIntPlaintextEncoding::Decode(const BigBinaryInteger &modulus, native64::ILVector2n *ilVector) {}

	size_t PackedIntPlaintextEncoding::GetChunksize(const usint ring, const BigBinaryInteger& ptm) const
	{
		return ring;
	}

	void PackedIntPlaintextEncoding::Destroy()
	{
		initRoot = BigBinaryInteger::ZERO;
		rootOfUnityTable.clear();
		bigMod = BigBinaryInteger::ZERO;
		bigRoot = BigBinaryInteger::ZERO;
	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint n = ring->GetRingDimension(); //ring dimension
		usint m = ring->GetCyclotomicOrder();//cyclotomic order
															   //Do the precomputation if not initialized
		const auto params = ring->GetParams();

		if (this->initRoot.GetMSB() == 0 ) {
			if (params->OrderIsPowerOfTwo()) {
				this->initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
			}
			else {
				this->initRoot = RootOfUnity<BigBinaryInteger>(2*m, modulus);
				usint nttDim = pow(2, ceil(log2(2 * m - 1)));;
				this->bigMod = FindPrimeModulus<BigBinaryInteger>(nttDim , log2(nttDim) + 2 * modulus.GetMSB());
				this->bigRoot = RootOfUnity<BigBinaryInteger>(nttDim, bigMod);
				auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);
				ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulus);
			}
		}

		//initRoot = BigBinaryInteger::TWO;

		BigBinaryInteger qMod(ring->GetModulus());

		BigBinaryVector packedVector(ring->GetValues());

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			packedVector = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(packedVector, initRoot, m);
		}
		else {
			packedVector = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(packedVector, initRoot,bigMod,bigRoot,m);
		}		

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

	void PackedIntPlaintextEncoding::Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint n = ring->GetRingDimension(); //ring dimension
		usint m = ring->GetCyclotomicOrder(); //ring cyclotomic order

		BigBinaryInteger qMod(ring->GetModulus());

		BigBinaryVector packedVector(ring->GetValues());

		auto params = ring->GetParams();

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			packedVector = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(packedVector, initRoot, m);
		}
		else {
			packedVector = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(packedVector, initRoot, bigMod,bigRoot,m);
		}		

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

}
