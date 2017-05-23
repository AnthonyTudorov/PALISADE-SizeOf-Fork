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

	std::vector<BigBinaryVector> PackedIntPlaintextEncoding::coefficientsCRT = std::vector<BigBinaryVector>();

	BigBinaryVector PackedIntPlaintextEncoding::rootList = BigBinaryVector();

	void PackedIntPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t startFrom, size_t length) const
	{
		size_t padlen = 0;
		uint64_t mod = modulus.ConvertToInt();

		if (length == 0) length = this->size();

		// length is usually chunk size; if start + length would go past the end of the item, add padding
		if ((startFrom + length) > this->size()) {
			padlen = (startFrom + length) - this->size();
			length = length - padlen;
		}

		BigBinaryVector temp(ilVector->GetRingDimension(), ilVector->GetModulus());

		for (size_t i = 0; i < length; i++) {
			uint32_t entry = this->at(i + startFrom);
			if (entry >= mod)
				throw std::logic_error("Cannot encode integer at position " + std::to_string(i) + " because it is >= plaintext modulus " + std::to_string(mod));
			BigBinaryInteger Val = BigBinaryInteger(entry);
			temp.SetValAtIndex(i, Val);
		}

		//BigBinaryInteger Num = modulus - BigBinaryInteger::ONE;
		for (size_t i = 0; i<padlen; i++) {
			temp.SetValAtIndex(i + length, BigBinaryInteger(0));
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


	size_t PackedIntPlaintextEncoding::GetChunksize(const usint ring, const BigBinaryInteger& ptm) const
	{
		return ring;
	}

	void PackedIntPlaintextEncoding::Destroy()
	{
		initRoot = BigBinaryInteger(0);
		rootOfUnityTable.clear();
		bigMod = BigBinaryInteger(0);
		bigRoot = BigBinaryInteger(0);
		coefficientsCRT.clear();
		rootList = BigBinaryVector();
	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint m = ring->GetCyclotomicOrder();//cyclotomic order
															   //Do the precomputation if not initialized
		const auto params = ring->GetParams();

		if (this->initRoot.GetMSB() == 0 ) {
			if (params->OrderIsPowerOfTwo()) {
				this->initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
			}
			else {
				//this->initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
				this->initRoot = BigBinaryInteger(7);
				while (!MillerRabinPrimalityTest(initRoot) || GreatestCommonDivisor<usint>(initRoot.ConvertToInt(),m)!=1)
				{
					this->initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
				}
			}
			//std::cout << initRoot << std::endl;
			//this->initRoot = BigBinaryInteger(7);
		}

		//initRoot = BigBinaryInteger::TWO;

		BigBinaryInteger qMod(ring->GetModulus());

		BigBinaryVector slotValues(ring->GetValues());

		//std::cout << packedVector << std::endl;

		slotValues.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			slotValues = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(slotValues, initRoot, m);
		}
		else {
			if (this->coefficientsCRT.size() == 0) {
				this->InitializeCRTCoefficients(m,modulus);
			}
			
			BigBinaryVector packedVector(coefficientsCRT.at(0)*slotValues.GetValAtIndex(0));
			for (usint i = 1; i < n; i++) {
				packedVector += coefficientsCRT.at(i)*slotValues.GetValAtIndex(i);
			}
			slotValues = std::move(packedVector);
		}

		slotValues.SetModulus(qMod);

		ring->SetValues(slotValues, Format::COEFFICIENT);

		//ring->PrintValues();

	}


	BigBinaryVector PackedIntPlaintextEncoding::GetRootVector(const BigBinaryInteger &modulus, usint cycloOrder) const {
		auto tList = GetTotientList(cycloOrder);
		BigBinaryVector rootList(tList.size(),modulus);
		for (usint i = 0; i < tList.size(); i++) {
			auto val = this->initRoot.ModExp(BigBinaryInteger(tList.at(i)), modulus);
			rootList.SetValAtIndex(i, val);
		}
		
		return rootList;
	}

	void PackedIntPlaintextEncoding::InitializeCRTCoefficients(usint cycloOrder,const BigBinaryInteger &modulus) const{
		usint n = GetTotient(cycloOrder);
		auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(cycloOrder, modulus);
		auto rootList = GetRootVector(modulus, cycloOrder);
		std::vector<BigBinaryVector> coefficients;
		for (usint i = 0; i < n; i++) {
			auto coeffRow = SyntheticPolynomialDivision(cycloPoly, rootList.GetValAtIndex(i), modulus);
			auto x = SyntheticRemainder(coeffRow, rootList.GetValAtIndex(i), modulus);
			x = x.ModInverse(modulus);
			coeffRow = coeffRow*x;
			coefficients.push_back(std::move(coeffRow));
		}
		BigBinaryVector slotValues(n, modulus);
		for (usint i = 0; i < n; i++) {
			slotValues.SetValAtIndex(i, BigBinaryInteger(i + 1));
		}
		BigBinaryVector packedVector(coefficients.at(0)*slotValues.GetValAtIndex(0));
		for (usint i = 1; i < n; i++) {
			packedVector += coefficients.at(i)*slotValues.GetValAtIndex(i);
		}
		auto yPow = PolynomialPower(packedVector, this->initRoot.ConvertToInt());
		auto permPacked = PolyMod(yPow, cycloPoly, modulus);
		auto perm = SyntheticPolyRemainder(permPacked, rootList, modulus);
		auto newRootList = FindPermutedSlots(slotValues, perm, rootList);
		coefficients.clear();
		for (usint i = 0; i < n; i++) {
			auto coeffRow = SyntheticPolynomialDivision(cycloPoly, newRootList.GetValAtIndex(i), modulus);
			auto x = SyntheticRemainder(coeffRow, newRootList.GetValAtIndex(i), modulus);
			x = x.ModInverse(modulus);
			coeffRow = coeffRow*x;
			coefficients.push_back(std::move(coeffRow));
		}
		this->coefficientsCRT = std::move(coefficients);
		this->rootList = std::move(newRootList);
	}

	BigBinaryVector PackedIntPlaintextEncoding::FindPermutedSlots(const BigBinaryVector &orig, const BigBinaryVector & perm, const BigBinaryVector & rootList) const{
		BigBinaryVector newRootList(rootList.GetLength(), rootList.GetModulus());
		usint idx = 0;
		while (perm.GetValAtIndex(idx) != BigBinaryInteger::ONE)
			idx++;
		usint n = rootList.GetLength();
		for (usint i = 0; i < n; i++) {
			newRootList.SetValAtIndex(i, rootList.GetValAtIndex(idx));
			idx = perm.GetValAtIndex(idx).ConvertToInt()-1;
		}
		return newRootList;
	}

	void PackedIntPlaintextEncoding::Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint m = ring->GetCyclotomicOrder(); // cyclotomic order

		BigBinaryInteger qMod(ring->GetModulus());

		BigBinaryVector packedVector(ring->GetValues());

		auto params = ring->GetParams();

		//std::cout << packedVector << std::endl;

		packedVector.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			packedVector = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(packedVector, initRoot, m);
		}
		else {
			packedVector = SyntheticPolyRemainder(packedVector, this->rootList, modulus);
		}		

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

}
