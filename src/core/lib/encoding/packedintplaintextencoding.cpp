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

	std::map<BigBinaryInteger, BigBinaryInteger> PackedIntPlaintextEncoding::m_initRoot;

	std::map<BigBinaryInteger, std::vector<BigBinaryVector>> PackedIntPlaintextEncoding::m_coefficientsCRT;

	std::map<BigBinaryInteger, BigBinaryVector> PackedIntPlaintextEncoding::m_rootList;

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
		m_initRoot.clear();
		m_coefficientsCRT.clear();
		m_rootList.clear();
	}

	void PackedIntPlaintextEncoding::SetParams(const BigBinaryInteger &modulus, usint m)
	{

		if (m_initRoot[modulus].GetMSB() == 0) {


			//initRoot = BigBinaryInteger(7);
			BigBinaryInteger initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
			while (GreatestCommonDivisor<usint>(initRoot.ConvertToInt(), m) != 1 || !IsGenerator<BigBinaryInteger>(initRoot, BigBinaryInteger(m)))
			{
				initRoot = RootOfUnity<BigBinaryInteger>(m, modulus);
				//std::cout << "candidate: " << initRoot << std::endl;
			}

			m_initRoot[modulus] = initRoot;
			//std::cout << "root found" << initRoot << std::endl;

			InitializeCRTCoefficients(m, modulus);

		}


	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint m = ring->GetCyclotomicOrder();//cyclotomic order
															   //Do the precomputation if not initialized
		const auto params = ring->GetParams();

		if (this->m_initRoot[modulus].GetMSB() == 0 ) {
			if (params->OrderIsPowerOfTwo())
				m_initRoot[modulus] = RootOfUnity<BigBinaryInteger>(m, modulus);
			else
				SetParams(modulus, m);
			//std::cout << "generator? = " << IsGenerator<BigBinaryInteger>(this->initRoot, BigBinaryInteger(m)) << std::endl;
			//std::cout << "root found" << initRoot << std::endl;
		}

		BigBinaryInteger qMod(ring->GetModulus());

		BigBinaryVector slotValues(ring->GetValues());

		//std::cout << packedVector << std::endl;

		slotValues.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			slotValues = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(slotValues, m_initRoot[modulus], m);
		}
		else {
			
			BigBinaryVector packedVector(m_coefficientsCRT[modulus].at(0)*slotValues.GetValAtIndex(0));
			for (usint i = 1; i < n; i++) {
				packedVector += m_coefficientsCRT[modulus].at(i)*slotValues.GetValAtIndex(i);
			}
			slotValues = std::move(packedVector);
		}

		slotValues.SetModulus(qMod);

		ring->SetValues(slotValues, Format::COEFFICIENT);

		//ring->PrintValues();

	}


	BigBinaryVector PackedIntPlaintextEncoding::GetRootVector(const BigBinaryInteger &modulus, usint cycloOrder) {
		auto tList = GetTotientList(cycloOrder);
		BigBinaryVector rootList(tList.size(),modulus);
		for (usint i = 0; i < tList.size(); i++) {
			auto val = m_initRoot[modulus].ModExp(BigBinaryInteger(tList.at(i)), modulus);
			rootList.SetValAtIndex(i, val);
		}
		
		return rootList;
	}

	void PackedIntPlaintextEncoding::InitializeCRTCoefficients(usint cycloOrder,const BigBinaryInteger &modulus){
		usint n = GetTotient(cycloOrder);
		auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(cycloOrder, modulus);
		auto rootListInit = GetRootVector(modulus, cycloOrder);
		std::vector<BigBinaryVector> coefficients;
		for (usint i = 0; i < n; i++) {
			auto coeffRow = SyntheticPolynomialDivision(cycloPoly, rootListInit.GetValAtIndex(i), modulus);
			auto x = SyntheticRemainder(coeffRow, rootListInit.GetValAtIndex(i), modulus);
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

		auto perm = SyntheticPolyPowerMod(packedVector,m_initRoot[modulus],rootListInit);

		auto newRootList = FindPermutedSlots(slotValues, perm, rootListInit);

		coefficients.clear();
		for (usint i = 0; i < n; i++) {
			auto coeffRow = SyntheticPolynomialDivision(cycloPoly, newRootList.GetValAtIndex(i), modulus);
			auto x = SyntheticRemainder(coeffRow, newRootList.GetValAtIndex(i), modulus);
			x = x.ModInverse(modulus);
			coeffRow = coeffRow*x;
			coefficients.push_back(std::move(coeffRow));
		}
		m_coefficientsCRT[modulus] = std::move(coefficients);
		m_rootList[modulus] = std::move(newRootList);
	}

	BigBinaryVector PackedIntPlaintextEncoding::FindPermutedSlots(const BigBinaryVector &orig, const BigBinaryVector & perm, const BigBinaryVector & rootList){
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

		packedVector.SetModulus(modulus);

		if (params->OrderIsPowerOfTwo()) {
			packedVector = ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(packedVector, m_initRoot[modulus], m);
		}
		else {
			packedVector = SyntheticPolyRemainder(packedVector, m_rootList[modulus], modulus);
		}		

		packedVector.SetModulus(qMod);

		ring->SetValues(packedVector, Format::COEFFICIENT);

	}

	BigBinaryVector PackedIntPlaintextEncoding::SyntheticPolyPowerMod(const BigBinaryVector &input, const BigBinaryInteger &power, const BigBinaryVector &rootListInit) {

		usint n = input.GetLength();
		const auto &modulus = input.GetModulus();
		BigBinaryVector result(n,modulus);

		//Precompute the Barrett mu parameter
		BigBinaryInteger temp(BigBinaryInteger::ONE);
		temp <<= 2 * modulus.GetMSB() + 3;
		BigBinaryInteger mu = temp.DividedBy(modulus);

		for (usint i = 0; i < n; i++) {
			auto &root = rootListInit.GetValAtIndex(i);
			auto pow(root.ModExp(power, modulus));
			auto val = input.GetValAtIndex(n - 1);
			for (int j = n-2; j > -1; j--) {
				val = input.GetValAtIndex(j) + pow*val;
				val = val.ModBarrett(modulus,mu);
			}

			result.SetValAtIndex(i, val);
		}
		
		return result;
	}

}
