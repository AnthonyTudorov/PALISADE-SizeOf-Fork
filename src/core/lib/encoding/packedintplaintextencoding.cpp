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
	std::map<native_int::BinaryInteger, native_int::BinaryInteger> PackedIntPlaintextEncoding::m_bigModulus;
	std::map<native_int::BinaryInteger, native_int::BinaryInteger> PackedIntPlaintextEncoding::m_bigRoot;

	std::map<native_int::BinaryInteger, usint> PackedIntPlaintextEncoding::m_automorphismGenerator;
	std::map<native_int::BinaryInteger, std::vector<usint>> PackedIntPlaintextEncoding::m_toCRTPerm;
	std::map<native_int::BinaryInteger, std::vector<usint>> PackedIntPlaintextEncoding::m_fromCRTPerm;

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
		m_bigModulus.clear();
		m_bigRoot.clear();

		m_automorphismGenerator.clear();
		m_toCRTPerm.clear();
		m_fromCRTPerm.clear();
	}

	void PackedIntPlaintextEncoding::SetParams(const BigBinaryInteger &modulus, usint m)
	{
		native_int::BinaryInteger modulusNI(modulus.ConvertToInt()); //native int modulus

		//initialize the CRT coefficients if not initialized
#pragma omp critical
{
		if (!(m & (m-1))){ // Check if m is a power of 2
			// Power of two: m/2-point FTT. So we need the mth root of unity
			m_initRoot[modulusNI] = RootOfUnity<native_int::BinaryInteger>(m, modulusNI);
		} else {
			// std::cout << "Setting Parameters for PackedIntPlaintextEncoding" << std::endl;
			// std::cout << modulusNI << " " << m << std::endl;
			// Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity
			native_int::BinaryInteger initRoot = RootOfUnity<native_int::BinaryInteger>(2*m, modulusNI);
			m_initRoot[modulusNI] = initRoot;
			// std::cout << m_initRoot[modulusNI] << std::endl;

			// Find a compatible big-modulus and root of unity for CRTArb
			usint nttDim = pow(2, ceil(log2(2*m - 1)));
			if ((modulusNI.ConvertToInt()-1) % nttDim == 0){
				m_bigModulus[modulusNI] = modulusNI;
			} else {
				usint bigModulusSize = ceil(log2(2*m - 1)) + 2*modulusNI.GetMSB() + 1;
				m_bigModulus[modulusNI] = FindPrimeModulus<native_int::BinaryInteger>(nttDim, bigModulusSize);
			}
			// std::cout << m_bigModulus[modulusNI] << std::endl;
			m_bigRoot[modulusNI] = RootOfUnity<native_int::BinaryInteger>(nttDim, m_bigModulus[modulusNI]);
			// std::cout << m_bigRoot[modulusNI] << std::endl;

			// Find a generator for the automorphism group
			native_int::BinaryInteger M(m); // Hackish typecast
			native_int::BinaryInteger automorphismGenerator = FindGeneratorCyclic<native_int::BinaryInteger>(M);
			m_automorphismGenerator[modulusNI] = automorphismGenerator.ConvertToInt();
			// std::cout << m_automorphismGenerator[modulusNI] << std::endl;

			// Create the permutations that interchange the automorphism and crt ordering
			usint phim = GetTotient(m);
			auto tList = GetTotientList(m);
			auto tIdx = std::vector<usint>(m, -1);
			for(usint i=0; i<phim; i++){
				tIdx[tList[i]] = i;
			}

			m_toCRTPerm[modulusNI] = std::vector<usint>(phim);
			m_fromCRTPerm[modulusNI] = std::vector<usint>(phim);

			usint curr_index = 1;
			for (usint i=0; i<phim; i++){
				m_toCRTPerm[modulusNI][tIdx[curr_index]] = i;
				m_fromCRTPerm[modulusNI][i] = tIdx[curr_index];

				curr_index = curr_index*m_automorphismGenerator[modulusNI] % m;
			}

			/*
			for (usint i=0; i<phim; i++){
				std::cout << tList[i] << " ";
			}
			std::cout << std::endl;
			for (usint i=0; i<phim; i++){
				std::cout << m_toCRTPerm[modulusNI][i] << " ";
			}
			std::cout << std::endl;
			for (usint i=0; i<phim; i++){
				std::cout << m_fromCRTPerm[modulusNI][i] << " ";
			}
			std::cout << std::endl;
			*/
		}
}

	}

	void PackedIntPlaintextEncoding::Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const {
		usint m = ring->GetCyclotomicOrder();//cyclotomic order
		native_int::BinaryInteger modulusNI(modulus.ConvertToInt());//native int modulus

		//Do the precomputation if not initialized
		if (this->m_initRoot[modulusNI].GetMSB() == 0) {
			SetParams(modulus, m);
		}

		usint phim = ring->GetRingDimension(); //ring dimension

		//copy values from ring to the vector
		native_int::BinaryVector slotValues(phim, modulusNI);
		for (usint i = 0; i < phim; i++) {
			slotValues.SetValAtIndex(i, ring->GetValAtIndex(i).ConvertToInt());
		}

		//std::cout << packedVector << std::endl;

		if (!(m & (m-1))) { // Check if m is a power of 2
			//power of 2 cyclotomics can use inverse CRT as packing function.
			slotValues = ChineseRemainderTransformFTT<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().InverseTransform(slotValues, m_initRoot[modulusNI], m);
		} else {
			// Arbitrary cyclotomic use CRTArb
			// Permute to CRT Order
			native_int::BinaryVector permutedSlots(phim, modulusNI);
			for (usint i = 0; i < phim; i++) {
				permutedSlots.SetValAtIndex(i, slotValues.GetValAtIndex(m_toCRTPerm[modulusNI][i]));
			}

			// Transform eval-representation to coeff
			slotValues = ChineseRemainderTransformArb<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().
					InverseTransform(permutedSlots, m_initRoot[modulusNI], m_bigModulus[modulusNI], m_bigRoot[modulusNI], m);
		}

		//copy values into the slotValuesRing
		BigBinaryVector slotValuesRing(phim, ring->GetModulus());
		for (usint i = 0; i < phim; i++) {
			slotValuesRing.SetValAtIndex(i, BigBinaryInteger(slotValues.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(slotValuesRing, Format::COEFFICIENT);

		//ring->PrintValues();

	}

	void PackedIntPlaintextEncoding::Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const {
		usint m = ring->GetCyclotomicOrder(); // cyclotomic order
		native_int::BinaryInteger modulusNI(modulus.ConvertToInt()); //native int modulus

		//Do the precomputation if not initialized
		if (this->m_initRoot[modulusNI].GetMSB() == 0) {
			SetParams(modulus, m);
		}

		usint phim = ring->GetRingDimension(); //ring dimension

		//copy aggregate plaintext values
		native_int::BinaryVector packedVector(phim, modulusNI);
		for (usint i = 0; i < phim; i++) {
			packedVector.SetValAtIndex(i, native_int::BinaryInteger(ring->GetValAtIndex(i).ConvertToInt()));
		}

		if (!(m & (m-1))) { // Check if m is a power of 2
			//power of 2 cyclotomics can use forward CRT for getting slot values
			packedVector = ChineseRemainderTransformFTT<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().ForwardTransform(packedVector, m_initRoot[modulusNI], m);
		} else {
			// Arbitrary cyclotomic use CRTArb
			// Transform coeff to eval representation
			native_int::BinaryVector permutedSlots(phim, modulusNI);
			permutedSlots = ChineseRemainderTransformArb<native_int::BinaryInteger, native_int::BinaryVector>::GetInstance().
					ForwardTransform(packedVector, m_initRoot[modulusNI], m_bigModulus[modulusNI], m_bigRoot[modulusNI], m);

			// Permute to automorphism Order
			for (usint i = 0; i < phim; i++) {
				packedVector.SetValAtIndex(i, permutedSlots.GetValAtIndex(m_fromCRTPerm[modulusNI][i]));
			}
		}

		BigBinaryVector packedVectorRing(phim, ring->GetModulus());

		for (usint i = 0; i < phim; i++) {
			packedVectorRing.SetValAtIndex(i, BigBinaryInteger(packedVector.GetValAtIndex(i).ConvertToInt()));
		}

		ring->SetValues(packedVectorRing, Format::COEFFICIENT);

	}

}
