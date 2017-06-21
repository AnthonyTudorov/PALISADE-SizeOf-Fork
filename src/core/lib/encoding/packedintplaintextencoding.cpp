/*
 * @file packedintplaintextencoding.cpp Represents and defines plaintext encodings in Palisade with bit packing capabilities.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

 //#include "../crypto/cryptocontext.h"
#include "packedintplaintextencoding.h"

namespace lbcrypto {

	std::map<native_int::BinaryInteger, native_int::BinaryInteger> PackedIntPlaintextEncoding::m_initRoot;

	std::map<native_int::BinaryInteger, usint> PackedIntPlaintextEncoding::m_automorphismGenerator;

	std::map<native_int::BinaryInteger, std::vector<native_int::BinaryVector>> PackedIntPlaintextEncoding::m_coefficientsCRT;

	std::map<native_int::BinaryInteger, native_int::BinaryVector> PackedIntPlaintextEncoding::m_rootList;

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
		m_automorphismGenerator.clear();
		m_coefficientsCRT.clear();
		m_rootList.clear();
	}

	void PackedIntPlaintextEncoding::SetParams(const BigBinaryInteger &modulus, usint m)
	{

		native_int::BinaryInteger modulusNI(modulus.ConvertToInt()); //native int modulus

		if (m_initRoot[modulusNI].GetMSB() == 0) {
			native_int::BinaryInteger initRoot = RootOfUnity<native_int::BinaryInteger>(m, modulusNI);
			native_int::BinaryInteger mm(m); // Hackish typecast
			native_int::BinaryInteger automorphismGenerator = FindGeneratorCyclic<native_int::BinaryInteger>(mm);

			m_initRoot[modulusNI] = initRoot;
			m_automorphismGenerator[modulusNI] = automorphismGenerator.ConvertToInt();
			//std::cout << "root found" << initRoot << std::endl;

			InitializeCRTCoefficients(m, modulusNI);

		}

	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint n = ring->GetRingDimension(); //ring dimension
		usint m = ring->GetCyclotomicOrder();//cyclotomic order
											 //Do the precomputation if not initialized
		const auto params = ring->GetParams();

		native_int::BinaryInteger modulusNI(modulus.ConvertToInt());

		if (this->m_initRoot[modulusNI].GetMSB() == 0) {
			if (params->OrderIsPowerOfTwo())
				m_initRoot[modulusNI] = RootOfUnity<native_int::BinaryInteger>(m, modulusNI);
			else
				SetParams(modulus, m);
			//std::cout << "generator? = " << IsGenerator<BigBinaryInteger>(this->initRoot, BigBinaryInteger(m)) << std::endl;
			//std::cout << "root found" << initRoot << std::endl;
		}

		BigBinaryInteger qMod(ring->GetModulus());

		native_int::BinaryVector slotValues(ring->GetValues().GetLength(),modulusNI);

		for (usint i = 0; i < ring->GetRingDimension(); i++) {
			slotValues.SetValAtIndex(i, ring->GetValAtIndex(i).ConvertToInt());
		}

		//std::cout << packedVector << std::endl;

		if (params->OrderIsPowerOfTwo()) {
			slotValues = ChineseRemainderTransformFTT<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().InverseTransform(slotValues, m_initRoot[modulusNI], m);
		}
		else {

			native_int::BinaryVector packedVector(m_coefficientsCRT[modulusNI].at(0)*slotValues.GetValAtIndex(0));
			for (usint i = 1; i < n; i++) {
				packedVector += m_coefficientsCRT[modulusNI].at(i)*slotValues.GetValAtIndex(i);
			}
			slotValues = std::move(packedVector);
		}

		//slotValues.SetModulus(qMod);
		BigBinaryVector slotValuesRing(ring->GetRingDimension(), qMod);

		//copy values into the slotValuesRing
		for (usint i = 0; i < ring->GetRingDimension(); i++) {
			slotValuesRing.SetValAtIndex(i, BigBinaryInteger(slotValues.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(slotValuesRing, Format::COEFFICIENT);

		//ring->PrintValues();

	}


	native_int::BinaryVector PackedIntPlaintextEncoding::GetRootVector(const native_int::BinaryInteger &modulus, usint cycloOrder) {
		auto tList = GetTotientList(cycloOrder);
		native_int::BinaryVector rootList(tList.size(), modulus);
		for (usint i = 0; i < tList.size(); i++) {
			auto val = m_initRoot[modulus].ModExp(native_int::BinaryInteger(tList.at(i)), modulus);
			rootList.SetValAtIndex(i, val);
		}

		return rootList;
	}

	void PackedIntPlaintextEncoding::InitializeCRTCoefficients(usint cycloOrder, const native_int::BinaryInteger &modulus) {
		usint n = GetTotient(cycloOrder);
		auto cycloPoly = GetCyclotomicPolynomial<native_int::BinaryVector, native_int::BinaryInteger>(cycloOrder, modulus);
		auto rootListInit = GetRootVector(modulus, cycloOrder);
		std::vector<native_int::BinaryVector> coefficients;
		for (usint i = 0; i < n; i++) {
			auto coeffRow = SyntheticPolynomialDivision(cycloPoly, rootListInit.GetValAtIndex(i), modulus);
			auto x = SyntheticRemainder(coeffRow, rootListInit.GetValAtIndex(i), modulus);
			x = x.ModInverse(modulus);
			coeffRow = coeffRow*x;
			coefficients.push_back(std::move(coeffRow));
		}
		native_int::BinaryVector slotValues(n, modulus);
		for (usint i = 0; i < n; i++) {
			slotValues.SetValAtIndex(i, native_int::BinaryInteger(i + 1));
		}
		native_int::BinaryVector packedVector(coefficients.at(0)*slotValues.GetValAtIndex(0));
		for (usint i = 1; i < n; i++) {
			packedVector += coefficients.at(i)*slotValues.GetValAtIndex(i);
		}

		auto perm = SyntheticPolyPowerMod(packedVector, m_automorphismGenerator[modulus], rootListInit);

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

	native_int::BinaryVector PackedIntPlaintextEncoding::FindPermutedSlots(const native_int::BinaryVector &orig, const native_int::BinaryVector & perm, const native_int::BinaryVector & rootList) {
		native_int::BinaryVector newRootList(rootList.GetLength(), rootList.GetModulus());
		usint idx = 0;
		while (perm.GetValAtIndex(idx) != native_int::BinaryInteger::ONE)
			idx++;
		usint n = rootList.GetLength();
		for (usint i = 0; i < n; i++) {
			newRootList.SetValAtIndex(i, rootList.GetValAtIndex(idx));
			idx = perm.GetValAtIndex(idx).ConvertToInt() - 1;
		}
		return newRootList;
	}

	void PackedIntPlaintextEncoding::Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const {

		usint m = ring->GetCyclotomicOrder(); // cyclotomic order

		BigBinaryInteger qMod(ring->GetModulus());

		native_int::BinaryInteger modulusNI(modulus.ConvertToInt());

		native_int::BinaryVector packedVector(ring->GetRingDimension(),modulusNI);

		for (usint i = 0; i < ring->GetRingDimension(); i++) {
			packedVector.SetValAtIndex(i, native_int::BinaryInteger(ring->GetValAtIndex(i).ConvertToInt()));
		}


		auto params = ring->GetParams();

		if (params->OrderIsPowerOfTwo()) {
			packedVector = ChineseRemainderTransformFTT<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().ForwardTransform(packedVector, m_initRoot[modulusNI], m);
		}
		else {
			packedVector = SyntheticPolyRemainder(packedVector, m_rootList[modulusNI], modulusNI);
		}

		BigBinaryVector packedVectorRing(ring->GetRingDimension(), qMod);

		for (usint i = 0; i < ring->GetRingDimension(); i++) {
			packedVectorRing.SetValAtIndex(i, BigBinaryInteger(packedVector.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(packedVectorRing, Format::COEFFICIENT);

	}

	native_int::BinaryVector PackedIntPlaintextEncoding::SyntheticPolyPowerMod(const native_int::BinaryVector &input, const native_int::BinaryInteger &power, const native_int::BinaryVector &rootListInit) {

		usint n = input.GetLength();
		const auto &modulus = input.GetModulus();
		native_int::BinaryVector result(n, modulus);

		//Precompute the Barrett mu parameter
		native_int::BinaryInteger temp(native_int::BinaryInteger::ONE);
		temp <<= 2 * modulus.GetMSB() + 3;
		native_int::BinaryInteger mu = temp.DividedBy(modulus);

		for (usint i = 0; i < n; i++) {
			auto &root = rootListInit.GetValAtIndex(i);
			auto pow(root.ModExp(power, modulus));
			auto val = input.GetValAtIndex(n - 1);
			for (int j = n - 2; j > -1; j--) {
				val = input.GetValAtIndex(j) + pow*val;
				val = val.ModBarrett(modulus, mu);
			}

			result.SetValAtIndex(i, val);
		}

		return result;
	}

}