// LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
6/1/2015 5:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Description:
This code provides basic lattice ideal manipulation functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "ilvectorarray2n.h"
#include <fstream>

namespace lbcrypto {

	lbcrypto::ILVectorArray2n::ILVectorArray2n() : m_vectors(NULL), m_format(EVALUATION),m_params()
	{
	}


	lbcrypto::ILVectorArray2n::ILVectorArray2n(const ElemParams & params) : m_params(static_cast<const ILDCRTParams&>(params)), m_vectors(NULL), m_format(EVALUATION)
	{

	}

	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &element)  {
		this->m_params = element.m_params;
		this->m_format = element.m_format;
		this->m_vectors = element.m_vectors;

	}

	ILVectorArray2n::ILVectorArray2n(const ILDCRTParams& params, std::vector<ILVector2n>& levels, Format format)
	{
		m_vectors = levels;
		m_params = params;
		m_format = format;
	}

	lbcrypto::ILVectorArray2n::ILVectorArray2n(ILVector2n element, const ILDCRTParams & params, Format format)
	{
		m_params = params;
		m_format = format;
		m_vectors.resize(params.GetModuli().size());
	   
		usint i = 0;

		usint size = params.GetModuli().size();

		ILVector2n temp();
/*
		for (i = 0; i < size; i++) {
		
			

			ILParams ilParams2(m_params.GetCyclotomicOrder(), (BigBinaryInteger(m_params.GetModuli()[i])), BigBinaryInteger(m_params.GetRootsOfUnity()[i]));
			
			m_vectors[i] = element;
			m_vectors[i].SetParams(ilParams2);
			m_vectors[i].SetModulus(m_params.GetModuli()[i]);
		
		}
*/

	//	ChangeModuliOfIlVectorsToMatchDBLCRT();

	}

	lbcrypto::ILVectorArray2n::ILVectorArray2n(DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	{

		const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);

		m_vectors.resize(m_params.GetModuli().size());

		for (usint i = 0; i < m_params.GetModuli().size(); i++) {

			BigBinaryInteger rootOfUnity(m_params.GetRootsOfUnity()[i]);
			usint cyclotomicOrder = m_params.GetCyclotomicOrder();
			BigBinaryInteger modulus(m_params.GetModuli()[i]);


			ILParams ilParams(cyclotomicOrder, modulus, rootOfUnity);

			ILVector2n ilvector(dgg, ilParams, m_format);

			m_vectors[i] = ilvector;
			m_vectors[i].SetModulus(m_params.GetModuli()[i]);

		}


	}

	ILVectorArray2n & lbcrypto::ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
	{
		if (this != &rhs) {
			if (m_vectors.empty()) {
				m_vectors.resize(rhs.GetParams().GetModuli().size());
			}
				this->m_vectors = rhs.m_vectors;			
			    this->m_params = rhs.m_params;
			    this->m_format = rhs.m_format;
				
		}

		return *this;

	}

	lbcrypto::ILVectorArray2n::~ILVectorArray2n()
	{
		//	delete m_vectors;
	}
	ILVector2n lbcrypto::ILVectorArray2n::GetValues(usint i) const
	{
		return m_vectors[i];
	}
	Format lbcrypto::ILVectorArray2n::GetFormat()
	{
		return m_format;
	}

	const ILDCRTParams & lbcrypto::ILVectorArray2n::GetParams() const
	{
		return m_params;
	}


	void lbcrypto::ILVectorArray2n::SetValues(std::vector<ILVector2n>& values, Format format)
	{
		m_vectors = values;
		m_format = format;
	}
	ILVectorArray2n lbcrypto::ILVectorArray2n::MultiplicativeInverse() const
	{

		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i] = tmp.m_vectors[i].MultiplicativeInverse();

		}

		return tmp;
	}

	ILVectorArray2n lbcrypto::ILVectorArray2n::Plus(const BigBinaryInteger & element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {

			tmp.m_vectors[i] = (tmp.GetValues(i)).Plus(element).Mod(m_params.GetModuli()[i]);

		}

		return tmp;
	}

	ILVectorArray2n lbcrypto::ILVectorArray2n::ModByTwo() const
	{
		//BigBinaryVector bigVector(m_vectors.size());

		//ILVectorArray2n tmp(*this);

		//ILVector2n bigILVector2n(tmp.InterpolateIlArrayVector2n());

		return *this;
	}



	ILVectorArray2n lbcrypto::ILVectorArray2n::Plus(const ILVectorArray2n & element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {

			tmp.m_vectors[i] = ((tmp.GetValues(i)).Plus(element.GetValues(i))).Mod(m_params.GetModuli()[i]);

		}
		return tmp;
	}

	ILVectorArray2n lbcrypto::ILVectorArray2n::Times(const ILVectorArray2n & element) const
	{

		ILVectorArray2n tmp(*this);
		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i].SetValues(((m_vectors[i].GetValues()).ModMul(element.m_vectors[i].GetValues())), m_format);


		}
		return tmp;

		//return ILVectorArray2n();
	}

	ILVectorArray2n lbcrypto::ILVectorArray2n::Times(const BigBinaryInteger & element) const
	{
	//	ILVector2n tmp(*this);
	//	*tmp.m_values = m_values->ModMul(element);
	//	return tmp;

		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {

			(tmp.m_vectors[i].Times(element)).Mod(m_params.GetModuli()[i]);
		}

		return tmp;
	}
	

	void lbcrypto::ILVectorArray2n::DecodeElement(ByteArrayPlaintextEncoding * text, const BigBinaryInteger & modulus) const
	{
	}
	void lbcrypto::ILVectorArray2n::EncodeElement(const ByteArrayPlaintextEncoding & encoded, const BigBinaryInteger & modulus)
	{
	}
	/*ILDCRTParams& ILVectorArray2n::GetParams() const
	{
	return m_params;
	}*/
	/*Switch format simply calls IlVector2n's switchformat*/
	void ILVectorArray2n::SwitchFormat() {

		if (m_format == COEFFICIENT) {

			m_format = EVALUATION;
		}
		else {
			m_format = COEFFICIENT;
		}

		for (usint i = 0; i < m_vectors.size(); i++) {
			m_vectors[i].SwitchFormat();
		}
	}

	BigBinaryInteger lbcrypto::ILVectorArray2n::CalculateChineseRemainderInterpolationCoefficient(usint i)
	{

		BigBinaryInteger pIndex(m_params.GetModuli()[i]);


		BigBinaryInteger bigModulus(m_params.GetModulus());


		BigBinaryInteger divideBigModulusByIndexModulus;

		divideBigModulusByIndexModulus = bigModulus.DividedBy(pIndex);


		BigBinaryInteger modularInverse;

		modularInverse = divideBigModulusByIndexModulus.ModInverse(pIndex);


		BigBinaryInteger results;

		results = divideBigModulusByIndexModulus.Times(modularInverse);

		return results;
	}

	ILVector2n lbcrypto::ILVectorArray2n::InterpolateIlArrayVector2n()
	{

		std::vector<std::vector<BigBinaryInteger>> vectorOfvectors(m_params.GetCyclotomicOrder()/2);

		vectorOfvectors = BuildChineseRemainderInterpolationVector(vectorOfvectors);

		usint sizeOfCoefficientVector = m_params.GetCyclotomicOrder() / 2;

		BigBinaryVector coefficients(sizeOfCoefficientVector);

		BigBinaryInteger temp(0);

		for (usint i = 0; i < sizeOfCoefficientVector; i++) {

			temp = CalculateInterpolationSum(vectorOfvectors, i);


			coefficients.SetValAtIndex(i, BigBinaryInteger(temp));

		}

		usint m = m_params.GetCyclotomicOrder();
		BigBinaryInteger modulus;
		modulus = m_params.GetModulus();
		BigBinaryInteger rootOfUnity;
		rootOfUnity = m_params.GetRootOfUnity();

	//	std::cout << "M_PARAM MODULUS" << m_params.GetModulus() << std::endl;
	//	std::cout << "M_PARAM CYCLOTOMIC ORDER" << m_params.GetCyclotomicOrder() << std::endl;


		ILParams ilParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);
		

		ILVector2n polynomialReconstructed(ilParams);
		polynomialReconstructed.SetValues(coefficients,m_format);

		return polynomialReconstructed;
	}


	void lbcrypto::ILVectorArray2n::ChangeModuliOfIlVectorsToMatchDBLCRT()
	{
		if (m_vectors.size() != m_params.GetModuli().size()) return;


		for (usint j = 0; j < m_vectors.size(); j++) {

			m_vectors[j].SetModulus(m_params.GetModuli()[j]);

		}

	}

	std::vector<BigBinaryInteger> lbcrypto::ILVectorArray2n::BuildChineseRemainderInterpolationVectorForRow(usint i)
	{
		usint j = 0;
		usint size = m_vectors.size();
		std::vector<BigBinaryInteger> vAtIndexi(size);

		for (j = 0; j < size; j++) {
			vAtIndexi[j] = m_vectors[j].GetIndexAt(i);
		}

		return vAtIndexi;

	}

	std::vector<std::vector<BigBinaryInteger>> lbcrypto::ILVectorArray2n::BuildChineseRemainderInterpolationVector(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors)
	{

		//		std::vector<std::vector<BigBinaryInteger>> vectorOfvectors(m_vectors.size());
		//usint sizeOfVector = m_vectors[0].GetLength();
		usint cyclotomicOrder = m_params.GetCyclotomicOrder() / 2;
		for (usint i = 0; i < cyclotomicOrder; i++) {
			vectorOfvectors[i] = BuildChineseRemainderInterpolationVectorForRow(i);
		}

		return vectorOfvectors;
	}

	bool lbcrypto::ILVectorArray2n::InverseExists() const
	{
	

		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}


		return true;
	}

	BigBinaryInteger lbcrypto::ILVectorArray2n::CalculateInterpolationSum(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index)
	{

		BigBinaryInteger results;

		for (usint i = 0; i < m_vectors.size(); i++) {

		
			BigBinaryInteger multiplyValue;

			multiplyValue = vectorOfvectors[index][i].Times(CalculateChineseRemainderInterpolationCoefficient(i));

		
			results = (results.Plus((multiplyValue)));
		

		}



		results = results.Mod(m_params.GetModulus());


		return results;

	}

	BigBinaryInteger lbcrypto::ILVectorArray2n::CalculatInterpolateModulu(BigBinaryInteger value, usint index)
	{
		return value.Mod(m_params.GetCRI()[index]);
	}



} // namespace lbcrypto ends
