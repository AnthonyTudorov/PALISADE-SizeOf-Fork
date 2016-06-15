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

	ILVectorArray2n::ILVectorArray2n() : m_vectors(NULL), m_format(EVALUATION),m_params()
	{
	}


	ILVectorArray2n::ILVectorArray2n(const ElemParams & params) : m_params(static_cast<const ILDCRTParams&>(params)), m_format(EVALUATION)
	{
		m_vectors.resize(m_params.GetModuli().size());
		for (usint i = 0; i < m_vectors.size(); i++) {
			usint m = m_params.GetCyclotomicOrder();
			BigBinaryInteger modulus(m_params.GetModuli()[i]);
			BigBinaryInteger rootOfUnity(m_params.GetRootsOfUnity()[i]);

			ILParams ilParams0(m, modulus, rootOfUnity);
			
			m_vectors[i].SetParams(ilParams0);
			
			BigBinaryVector tmp(m_params.GetCyclotomicOrder() / 2, m_params.GetModuli()[i]);
		//	std::cout << "value of cyclotomic order is : " << m_params.GetCyclotomicOrder() << std::endl;

			m_vectors[i].SetValues(tmp, m_format);
		//	std::cout << "size of bigbinaryvector is : " << m_vectors[i].GetValues().GetLength() << std::endl;

		}
		

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

	ILVectorArray2n::ILVectorArray2n(ILVector2n element, const ILDCRTParams & params, Format format)
	{
		m_params = params;
		m_format = format;
		m_vectors.resize(params.GetModuli().size());

		usint i = 0;

		usint size = params.GetModuli().size();

		ILVector2n temp();
		for (i = 0; i < size; i++) {

			BigBinaryInteger a(m_params.GetModuli()[i]);
			BigBinaryInteger b(m_params.GetRootsOfUnity()[i]);
			ILParams ilParams2(m_params.GetCyclotomicOrder(), a, b);

			m_vectors[i] = element;
			m_vectors[i].SetParams(ilParams2);
			m_vectors[i].SetModulus(m_params.GetModuli()[i]);


		}

	//	ChangeModuliOfIlVectorsToMatchDBLCRT();

	}




	ILVectorArray2n::ILVectorArray2n(const DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	{

		const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);


		m_vectors.resize(m_params.GetModuli().size());
		m_format = format;
	//	ILDCRTParams params2 = m_params;
	////	usint m2 = 32;

	//	BigBinaryInteger bigMod;
	//	bigMod = m_params.GetModulus();
	//	std::cout << bigMod << std::endl;

	//	BigBinaryInteger bigRoot = RootOfUnity(m_params.GetCyclotomicOrder(), bigMod);
	//	ILParams testParams(m_params.GetCyclotomicOrder(), bigMod, bigRoot);
	//	BigBinaryVector ilTestValues(m_params.GetCyclotomicOrder()/2, bigMod);
	//	ILVector2n ilTestFor(testParams);


	/*if(!isKey){*/
		//dgg.Initialize();
		sint* dggValues = dgg.GenerateIntVector(m_params.GetCyclotomicOrder()/2);
	
	/*	for(usint j = 0; j < m_params.GetCyclotomicOrder()/2; j++){
			
				if((int)dggValues[j] < 0){
					int k = (int)dggValues[j];
					k = k * (-1);
					BigBinaryInteger temp(k);
					temp = bigMod - temp;
					ilTestValues.SetValAtIndex(j,temp);
				}

				else{				
					int k = (int)dggValues[j];
					BigBinaryInteger temp(k);
					ilTestValues.SetValAtIndex(j,temp);
				}

			}*/
		
	//	ilTestFor.SetValues(ilTestValues,Format::COEFFICIENT);
	////	ilTestFor.SwitchFormat();
	//	ilTestFor.GetMeghdar();
	//	std::cout << std::endl;

	//	ilTestFor.SwitchFormat();
	//	
	//	std::cout << std::endl;
	//	ilTestFor.GetMeghdar();


		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			for(usint j = 0; j < m_params.GetCyclotomicOrder()/2; j++){
			
				if((int)dggValues[j] < 0){
					int k = (int)dggValues[j];
					k = k * (-1);
					BigBinaryInteger temp(k);
					temp = m_params.GetModuli()[i] - temp;
					ilDggValues.SetValAtIndex(j,temp);
				}

				else{				
					int k = (int)dggValues[j];
					BigBinaryInteger temp(k);
					ilDggValues.SetValAtIndex(j,temp);
				}

			}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		//	std::cout << ilvector.GetModulus() << std::endl;
		//	ilvector.GetMeghdar();
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;

	}

			/*ILVector2n interpolatedDecodedValue = this->InterpolateIlArrayVector2n();		
			interpolatedDecodedValue.GetMeghdar();
			interpolatedDecodedValue.SwitchFormat();
			std::cout << std::endl;
			interpolatedDecodedValue.GetMeghdar();*/



	//else{
	//

	//	for (usint i = 0; i < m_params.GetModuli().size(); i++) {

	//		BigBinaryInteger rootOfUnity(m_params.GetRootsOfUnity()[i]);
	//		usint cyclotomicOrder = m_params.GetCyclotomicOrder();
	//		BigBinaryInteger modulus(m_params.GetModuli()[i]);


	//		ILParams ilParams(cyclotomicOrder, modulus, rootOfUnity);

	//		ILVector2n ilvector(isKey, dgg, ilParams, m_format);

	//		m_vectors[i] = ilvector;
	//		m_vectors[i].SetParams(ilParams);
	//	

	//	}

	//}

	}



	ILVectorArray2n & ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
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

	ILVectorArray2n::~ILVectorArray2n()
	{
		//	delete m_vectors;
	}
	ILVector2n lbcrypto::ILVectorArray2n::GetValues(usint i) const
	{
		return m_vectors[i];
	}
	Format ILVectorArray2n::GetFormat() const
	{
		return m_format;
	}

	const ILDCRTParams & ILVectorArray2n::GetParams() const
	{
		return m_params;
	}


	void ILVectorArray2n::SetValues(std::vector<ILVector2n>& values, Format format)
	{
		m_vectors = values;
		m_format = format;
	}
	ILVectorArray2n ILVectorArray2n::MultiplicativeInverse() const
	{

		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i] = tmp.m_vectors[i].MultiplicativeInverse();

		}

		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Plus(const BigBinaryInteger & element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {

			tmp.m_vectors[i] = (tmp.GetValues(i)).Plus(element).Mod(m_params.GetModuli()[i]);

		}

		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::ModByTwo() const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i] = m_vectors[i].ModByTwo();

		   }

		return tmp;
	}



	ILVectorArray2n ILVectorArray2n::Plus(const ILVectorArray2n & element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {

			tmp.m_vectors[i] = ((tmp.GetValues(i)).Plus(element.GetValues(i))).Mod(m_params.GetModuli()[i]);

		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Times(const ILVectorArray2n & element) const
	{

		ILVectorArray2n tmp(*this);
		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i].SetValues(((m_vectors[i].GetValues()).ModMul(element.m_vectors[i].GetValues())), m_format);
			//ILVector2n test = m_vectors[i] * element.m_vectors[i];
			//tmp.m_vectors[i].SetValues(test.GetValues(), m_format);


		}
		return tmp;

		//return ILVectorArray2n();
	}

	const ILVectorArray2n & ILVectorArray2n::operator+=(const ILVectorArray2n & element)
	{
		
		for (usint i = 0; i < m_vectors.size(); i++) {
			m_vectors[i] +=  element.m_vectors[i];
		}

		return *this;
	}

	ILVectorArray2n ILVectorArray2n::Times(const BigBinaryInteger & element) const
	{

		ILVectorArray2n tmp(*this);
//	std::cout<< "1.Printing internals ...  " <<m_params.GetModuli()[0] << std::endl;


		for (usint i = 0; i < m_vectors.size(); i++) {

			tmp.m_vectors[i] = ((element*tmp.m_vectors[i]).Mod(m_params.GetModuli()[i]));
			/*std::cout << "in times" << std::endl;
			tmp.m_vectors[i].SetModulus(m_params.GetModuli()[i]);
			std::cout<< tmp.m_vectors[i].GetModulus() << std::cout;			
			std::cout << "in times" << std::endl;*/

		}

		tmp.m_params= this->m_params;
	//	std::cout<< "2.Printing internals ... " << tmp.m_params.GetModuli()[0] << std::endl;
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Mod(const BigBinaryInteger & modulus) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].Mod(modulus);
		}
		return tmp;
	}
	
	void ILVectorArray2n::PrintValues() const{

		std::cout<<"---START PRINT DOUBLE CRT-- WITH SIZE" <<m_vectors.size() << std::endl;
//		std:: cout << "Printing values in ILVECTORARRAY2N" << std::endl;
		 for(usint i = 0; i < m_vectors.size();i++){
			std::cout<<"VECTOR " << i << std::endl;

			m_vectors[i].PrintValues();
		 }

		 std::cout<<"---END PRINT DOUBLE CRT--" << std::endl;

	}

//	void ILVectorArray2n::DecodeElement(ByteArrayPlaintextEncoding * text, const BigBinaryInteger & modulus) 
//	{
////		std::cout << "FROM BIG NBI::" << std::endl;
//
//		/*for (usint i = 0; i < m_vectors.size(); i++) {
//
//			m_vectors[i].DecodeElement(text, modulus);
//
//		}*/
////		std::cout << "END BIG::" << std::endl;
//
//
//		ILVector2n interpolatedDecodedValue = this->InterpolateIlArrayVector2n();
//		
////		interpolatedDecodedValue.GetMeghdar();
//
//
//		//interpolatedDecodedValue.ModByTwo();
//
//		//interpolatedDecodedValue.GetMeghdar();
//
//
//	//	interpolatedDecodedValue  = interpolatedDecodedValue.ModByTwo();
//
//	//	interpolatedDecodedValue.GetMeghdar();
//
//		interpolatedDecodedValue.DecodeElement(text, modulus);
//	//	m_vectors[0].DecodeElement(text, modulus);
//	/*	ILVectorArray2n returnValue(interpolatedDecodedValue, m_params, m_format);
//		*this = returnValue;*/
//
//
//	}
//	
//	void ILVectorArray2n::EncodeElement(const ByteArrayPlaintextEncoding & encoded, const BigBinaryInteger & modulus)
//	{
//	//	ILVector2n interpolatedEncodedValue = this->InterpolateIlArrayVector2n();
//	//	interpolatedEncodedValue.EncodeElement(encoded, modulus);
//		m_vectors[0].EncodeElement(encoded,modulus);
//		m_format = COEFFICIENT;
//	//	ILVectorArray2n returnValue(interpolatedEncodedValue, m_params, m_format);
//		ILVectorArray2n returnValue(m_vectors[0], m_params, m_format);
//		*this = returnValue;
//
//		return;
//	}
//



	ILVectorArray2n ILVectorArray2n::GetDigitAtIndexForBase(usint index, usint base) const{
		ILVectorArray2n tmp(*this);
		
		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].GetDigitAtIndexForBase(index,base);
		}

		return tmp;
		
	}

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

	BigBinaryInteger ILVectorArray2n::CalculateChineseRemainderInterpolationCoefficient(usint i)
	{

		BigBinaryInteger pIndex(m_params.GetModuli()[i]);
//		std::cout << pIndex << std::endl;

		BigBinaryInteger bigModulus(m_params.GetModulus());

 //  	std::cout << bigModulus << std::endl;

		BigBinaryInteger divideBigModulusByIndexModulus;

		divideBigModulusByIndexModulus = bigModulus.DividedBy(pIndex);

	//	std::cout << divideBigModulusByIndexModulus << std::endl;

		BigBinaryInteger modularInverse;
		
		/*if(divideBigModulusByIndexModulus > pIndex){
		
			divideBigModulusByIndexModulus = divideBigModulusByIndexModulus.Mod(pIndex);

		}*/

		modularInverse = divideBigModulusByIndexModulus.Mod(pIndex).ModInverse(pIndex);

	//	std::cout << modularInverse << std::endl;

		BigBinaryInteger results;

		results = divideBigModulusByIndexModulus.Times(modularInverse);

	//	std::cout << results << std::endl;

		return results;
	}

	ILVector2n ILVectorArray2n::InterpolateIlArrayVector2n()
	{

//		std::vector<std::vector<BigBinaryInteger>> vectorOfvectors(m_params.GetCyclotomicOrder()/2);

//		vectorOfvectors = BuildChineseRemainderInterpolationVector(vectorOfvectors);

		usint sizeOfCoefficientVector = m_params.GetCyclotomicOrder() / 2;

		BigBinaryVector coefficients(sizeOfCoefficientVector,m_params.GetModulus());

		BigBinaryInteger temp(0);

		std::vector<BigBinaryInteger> tempVector;

		for (usint i = 0; i < sizeOfCoefficientVector; i++) {
				
//			std::cout << "Start Calculating for vector" << i << std::endl;

			tempVector = BuildChineseRemainderInterpolationVectorForRow(i);

		//	temp = CalculateInterpolationSum2(vectorOfvectors, i);

			temp = CalculateInterpolationSum(tempVector, i);

			coefficients.SetValAtIndex(i, BigBinaryInteger(temp));

//			std::cout << "End Calculating for vector" << i << std::endl;

		}

		usint m = m_params.GetCyclotomicOrder();
		BigBinaryInteger modulus;
		modulus = m_params.GetModulus();
		BigBinaryInteger rootOfUnity;
		rootOfUnity = m_params.GetRootOfUnity();

		ILParams ilParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);
		

		ILVector2n polynomialReconstructed(ilParams);
		polynomialReconstructed.SetValues(coefficients,m_format);

		return polynomialReconstructed;
	}


	void ILVectorArray2n::ChangeModuliOfIlVectorsToMatchDBLCRT()
	{
		if (m_vectors.size() != m_params.GetModuli().size()) return;


		for (usint j = 0; j < m_vectors.size(); j++) {

			m_vectors[j].SetModulus(m_params.GetModuli()[j]);

		}

	}

	std::vector<BigBinaryInteger> ILVectorArray2n::BuildChineseRemainderInterpolationVectorForRow(usint i)
	{
		usint j = 0;
		usint size = m_vectors.size();
		std::vector<BigBinaryInteger> vAtIndexi(size);

		for (j = 0; j < size; j++) {
			vAtIndexi[j] = m_vectors[j].GetValAtIndex(i);
		}

		return vAtIndexi;

	}

	std::vector<std::vector<BigBinaryInteger>> ILVectorArray2n::BuildChineseRemainderInterpolationVector(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors)
	{

		//		std::vector<std::vector<BigBinaryInteger>> vectorOfvectors(m_vectors.size());
		//usint sizeOfVector = m_vectors[0].GetLength();
		usint cyclotomicOrder = m_params.GetCyclotomicOrder() / 2;
		for (usint i = 0; i < cyclotomicOrder; i++) {
			vectorOfvectors[i] = BuildChineseRemainderInterpolationVectorForRow(i);
		}

		return vectorOfvectors;
	}

	bool ILVectorArray2n::InverseExists() const
	{
	

		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}


		return true;
	}


	BigBinaryInteger ILVectorArray2n::CalculateInterpolationSum(std::vector<BigBinaryInteger>vectorOfBigInts, usint index)
	{
		BigBinaryInteger results("0");

		for (usint i = 0; i < m_vectors.size(); i++) {


			BigBinaryInteger multiplyValue;

			multiplyValue = vectorOfBigInts[i].Times(CalculateChineseRemainderInterpolationCoefficient(i));

			results = (results.Plus((multiplyValue)));


		}

		results = results.Mod(m_params.GetModulus());

		return results;


	}


	BigBinaryInteger ILVectorArray2n::CalculateInterpolationSum2(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index)
	{

		BigBinaryInteger results("0");

		for (usint i = 0; i < m_vectors.size(); i++) {

//			std::cout <<" Start for index " << i << std::endl;

			BigBinaryInteger multiplyValue;

			multiplyValue = vectorOfvectors[index][i].Times(CalculateChineseRemainderInterpolationCoefficient(i));

	//		std::cout <<  vectorOfvectors[index][i] << std::endl;

    //		std::cout << multiplyValue << std::endl;

			results = (results.Plus((multiplyValue)));
		
//			std::cout << results << std::endl;

//			std::cout <<" End for index " << i << std::endl;

		}



		results = results.Mod(m_params.GetModulus());

//		std::cout<< results << std::endl;

		return results;

	}

	BigBinaryInteger ILVectorArray2n::CalculatInterpolateModulu(BigBinaryInteger value, usint index)
	{
		return value.Mod(m_params.GetCRI()[index]);
	}


	// JSON FACILITY - Serialize Operation
	bool ILVectorArray2n::Serialize(Serialized* serObj, const CryptoContext*, const std::string fileFlag) const {

	

	//	std::unordered_map <std::string, std::string> serObj;

		return false;
	}

	// JSON FACILITY - Deserialize Operation
	bool ILVectorArray2n::Deserialize(const Serialized& serObj) {

		return false;
	
	}

} // namespace lbcrypto ends


