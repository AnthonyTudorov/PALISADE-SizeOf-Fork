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

	ILVectorArray2n::ILVectorArray2n(const ElemParams& params, const std::vector<ILVector2n>& levels, Format format)
	{
		const ILDCRTParams &castedParams = static_cast<const ILDCRTParams&>(params);

		m_vectors = levels;
		m_params = castedParams;
		m_format = format;
	}

	ILVectorArray2n::ILVectorArray2n(const ILVector2n& element, const ElemParams & params, Format format)
	{
		const ILDCRTParams &castedParams = static_cast<const ILDCRTParams&>(params);

		m_params = castedParams;
		m_format = format;
		m_vectors.resize(castedParams.GetModuli().size());

		usint i = 0;

		usint size = castedParams.GetModuli().size();

		ILVector2n temp();
		for (i = 0; i < size; i++) {

			BigBinaryInteger a(m_params.GetModuli()[i]);
			BigBinaryInteger b(m_params.GetRootsOfUnity()[i]);
			ILParams ilParams2(m_params.GetCyclotomicOrder(), a, b);
			

			m_vectors[i] = element;
			m_vectors[i].SetParams(ilParams2);
			m_vectors[i].SetModulus(m_params.GetModuli()[i]);
			

		}


	}




	ILVectorArray2n::ILVectorArray2n(const DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	{
		const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);

		m_vectors.resize(m_params.GetModuli().size());
		m_format = format;
	
	/*if(!isKey){*/
		//dgg.Initialize();
		sint* dggValues = dgg.GenerateCharVector(m_params.GetCyclotomicOrder()/2);

	
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
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;

		}
	
	  }

	///*uncomment this constructor and comment the consturctor above to eliminate noise. Noise generated sets the first index value at each tower to one, the rest to zero.*/
	//ILVectorArray2n::ILVectorArray2n(DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	//{

	//	const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);


	//	m_vectors.resize(m_params.GetModuli().size());
	//	m_format = format;

	//	dgg.Initialize();
	//	schar* dggValues = dgg.GenerateCharVector(m_params.GetCyclotomicOrder()/2);
	//
	//

	//	for(usint i = 0; i < m_vectors.size();i++){
	//	
	//		BigBinaryInteger modulus;
	//		modulus = m_params.GetModuli()[i];
	//		BigBinaryInteger rootOfUnity;
	//		rootOfUnity = m_params.GetRootsOfUnity()[i];

	//		ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
	//		ILVector2n ilvector(ilVectorDggValuesParams);

	//		BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

	//		ilDggValues.SetValAtIndex(0,BigBinaryInteger::ZERO);
	//		ilDggValues.SetValAtIndex(1,BigBinaryInteger::ONE);


	//		for(usint j = 2; j < m_params.GetCyclotomicOrder()/2; j++){
	//		
	//			if((int)dggValues[j] < 0){
	//				int k = (int)dggValues[j];
	//				k = k * (-1);
	//				BigBinaryInteger temp(k);
	//				temp = m_params.GetModuli()[i] - temp;
	//			//	ilDggValues.SetValAtIndex(j,temp);
	//				ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
	//			}

	//			else{				
	//				int k = (int)dggValues[j];
	//				BigBinaryInteger temp(k);
	//			//	ilDggValues.SetValAtIndex(j,temp);
	//				ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

	//			}

	//		}
	//		ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
	//	
	//		if(m_format == Format::EVALUATION){
	//			ilvector.SwitchFormat();
	//		}
	//		m_vectors[i] = ilvector;

	//}

	//}

		/*uncomment this constructor and comment the consturctor above to eliminate noise. Noise generated sets the first index value at each tower to one, the rest to zero.*/
	//ILVectorArray2n::ILVectorArray2n(const bool t, DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	//{

	//	const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);


	//	m_vectors.resize(m_params.GetModuli().size());
	//	m_format = format;

	//	dgg.Initialize();
	//	sint* dggValues = dgg.GenerateCharVector(m_params.GetCyclotomicOrder()/2);
	//
	//

	//	for(usint i = 0; i < m_vectors.size();i++){
	//	
	//		BigBinaryInteger modulus;
	//		modulus = m_params.GetModuli()[i];
	//		BigBinaryInteger rootOfUnity;
	//		rootOfUnity = m_params.GetRootsOfUnity()[i];

	//		ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
	//		ILVector2n ilvector(ilVectorDggValuesParams);

	//		BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

	//		ilDggValues.SetValAtIndex(0,BigBinaryInteger::ONE);

	//		for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
	//		
	//			if((int)dggValues[j] < 0){
	//				int k = (int)dggValues[j];
	//				k = k * (-1);
	//				BigBinaryInteger temp(k);
	//				temp = m_params.GetModuli()[i] - temp;
	//			//	ilDggValues.SetValAtIndex(j,temp);
	//				ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
	//			}

	//			else{				
	//				int k = (int)dggValues[j];
	//				BigBinaryInteger temp(k);
	//			//	ilDggValues.SetValAtIndex(j,temp);
	//				ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

	//			}

	//		}
	//		ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
	//	
	//		if(m_format == Format::EVALUATION){
	//			ilvector.SwitchFormat();
	//		}
	//		m_vectors[i] = ilvector;

	//}

	//}


	ILVectorArray2n::ILVectorArray2n(usint k, const DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	{

		const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);


		m_vectors.resize(m_params.GetModuli().size());
		m_format = format;

		sint* dggValues = dgg.GenerateCharVector(m_params.GetCyclotomicOrder()/2);

	
	
	if(k == 0){
		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			if(i == 0){

				ilDggValues.SetValAtIndex(0,BigBinaryInteger("17726"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("2"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("0"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("0"));

			}

			if(i == 1){
			
				ilDggValues.SetValAtIndex(0,BigBinaryInteger("17758"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("2"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("0"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("0"));
			
			}


			//for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
			//
			//	if((int)dggValues[j] < 0){
			//		int k = (int)dggValues[j];
			//		k = k * (-1);
			//		BigBinaryInteger temp(k);
			//		temp = m_params.GetModuli()[i] - temp;
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
			//	}

			//	else{				
			//		int k = (int)dggValues[j];
			//		BigBinaryInteger temp(k);
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

			//	}

			//}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;
			std::cout<<"root of unity" << ilvector.GetRootOfUnity() << std::endl;
		}
		}

	else if(k == 1){
		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			if(i == 0){

				ilDggValues.SetValAtIndex(0,BigBinaryInteger("2"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("4"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17725"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("3"));

			}

			if(i == 1){
			
				ilDggValues.SetValAtIndex(0,BigBinaryInteger("2"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("4"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17757"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("3"));
			
			}


			//for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
			//
			//	if((int)dggValues[j] < 0){
			//		int k = (int)dggValues[j];
			//		k = k * (-1);
			//		BigBinaryInteger temp(k);
			//		temp = m_params.GetModuli()[i] - temp;
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
			//	}

			//	else{				
			//		int k = (int)dggValues[j];
			//		BigBinaryInteger temp(k);
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

			//	}

			//}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;
			std::cout<<"root of unity" << ilvector.GetRootOfUnity() << std::endl;
		}
		}

	else if(k == 2){
		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			if(i == 0){

				ilDggValues.SetValAtIndex(0,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17725"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("2"));

			}

			if(i == 1){
			
				ilDggValues.SetValAtIndex(0,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17757"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("2"));
			
			}


			//for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
			//
			//	if((int)dggValues[j] < 0){
			//		int k = (int)dggValues[j];
			//		k = k * (-1);
			//		BigBinaryInteger temp(k);
			//		temp = m_params.GetModuli()[i] - temp;
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
			//	}

			//	else{				
			//		int k = (int)dggValues[j];
			//		BigBinaryInteger temp(k);
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

			//	}

			//}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;
			std::cout<<"root of unity" << ilvector.GetRootOfUnity() << std::endl;
		}
		}
	
	else if(k == 3){
		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			if(i == 0){

				ilDggValues.SetValAtIndex(0,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17725"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("2"));

			}

			if(i == 1){
			
				ilDggValues.SetValAtIndex(0,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("3"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("17757"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("2"));
			
			}


			//for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
			//
			//	if((int)dggValues[j] < 0){
			//		int k = (int)dggValues[j];
			//		k = k * (-1);
			//		BigBinaryInteger temp(k);
			//		temp = m_params.GetModuli()[i] - temp;
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
			//	}

			//	else{				
			//		int k = (int)dggValues[j];
			//		BigBinaryInteger temp(k);
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

			//	}

			//}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;
			std::cout<<"root of unity" << ilvector.GetRootOfUnity() << std::endl;
		}
		}
		else if(k == 4){
		for(usint i = 0; i < m_vectors.size();i++){
		
			BigBinaryInteger modulus;
			modulus = m_params.GetModuli()[i];
			BigBinaryInteger rootOfUnity;
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			if(i == 0){

				ilDggValues.SetValAtIndex(0,BigBinaryInteger("1"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("0"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("1"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("0"));

			}

			if(i == 1){
			
				ilDggValues.SetValAtIndex(0,BigBinaryInteger("1"));
				ilDggValues.SetValAtIndex(1,BigBinaryInteger("0"));
				ilDggValues.SetValAtIndex(2,BigBinaryInteger("1"));			
				ilDggValues.SetValAtIndex(3,BigBinaryInteger("0"));
			
			}


			//for(usint j = 1; j < m_params.GetCyclotomicOrder()/2; j++){
			//
			//	if((int)dggValues[j] < 0){
			//		int k = (int)dggValues[j];
			//		k = k * (-1);
			//		BigBinaryInteger temp(k);
			//		temp = m_params.GetModuli()[i] - temp;
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);
			//	}

			//	else{				
			//		int k = (int)dggValues[j];
			//		BigBinaryInteger temp(k);
			//	//	ilDggValues.SetValAtIndex(j,temp);
			//		ilDggValues.SetValAtIndex(j,BigBinaryInteger::ZERO);

			//	}

			//}
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT);
		
			if(m_format == Format::EVALUATION){
				ilvector.SwitchFormat();
			}
			m_vectors[i] = ilvector;
			std::cout<<"root of unity" << ilvector.GetRootOfUnity() << std::endl;
		}
		}

	}

	ILVectorArray2n & ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
	{
		if (this != &rhs) {
//			if (m_vectors.empty()) {
			m_vectors.resize(rhs.m_params.GetModuli().size());
	//		}
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
	const ILVector2n& ILVectorArray2n::GetValues(usint i) const
	{
		return m_vectors[i];
	}
	const std::vector<ILVector2n>& ILVectorArray2n::GetValues() const
	{
		return m_vectors;
	}
	Format ILVectorArray2n::GetFormat() const
	{
		return m_format;
	}

	const ElemParams & ILVectorArray2n::GetParams() const
	{
		return m_params;
	}

	ElemParams& ILVectorArray2n::AccessParams(){
		return this->m_params;
	}

	void ILVectorArray2n::SetParams(const ElemParams &params) {

		const ILDCRTParams &castedObj = dynamic_cast<const ILDCRTParams&>(params);
		
		m_params = castedObj;
		
		usint tempCyclotomicOrder;
		BigBinaryInteger tempModulus;
		BigBinaryInteger tempRootOfUnity;
		



		for(usint i = 0; i < this->GetLength();i++){
			
			tempCyclotomicOrder = m_params.GetCyclotomicOrder();
			tempModulus = m_params.GetModuli()[i];
			tempRootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams temp(tempCyclotomicOrder,tempModulus, tempRootOfUnity);
			m_vectors[i].SetParams(temp);
		
		}

		


	}

	void ILVectorArray2n::SetValues(const std::vector<ILVector2n>& values, Format format)
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
		//	tmp.m_vectors[i].PrintValues();

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
	

	void ILVectorArray2n::ModularOne(){

		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].ModularOne();
		}

	}


	void ILVectorArray2n::MakeSparse(const BigBinaryInteger &wFactor){

		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].MakeSparse(wFactor);
		}

	}

	void ILVectorArray2n::SetToTestValue(){
		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].SetToTestValue();
		}
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

		usint sizeOfCoefficientVector = m_params.GetCyclotomicOrder() / 2;

		BigBinaryVector coefficients(sizeOfCoefficientVector,m_params.GetModulus());

		BigBinaryInteger temp(0);

		std::vector<BigBinaryInteger> tempVector;

		for (usint i = 0; i < sizeOfCoefficientVector; i++) {
				
			tempVector = BuildChineseRemainderInterpolationVectorForRow(i);

			temp = CalculateInterpolationSum(tempVector, i);

			coefficients.SetValAtIndex(i, BigBinaryInteger(temp));

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

	void ILVectorArray2n::Decompose() {
		Format format(this->GetFormat());
		
		if(format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArray2n not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		usint cyclotomicOrder = this->m_params.GetCyclotomicOrder();
		std::vector<BigBinaryInteger> moduli = this->m_params.GetModuli();
		std::vector<BigBinaryInteger> rootsOfUnity = this->m_params.GetRootsOfUnity(); 

		for(int i=0; i < m_vectors.size(); i++) {
			ILParams ilvectorParams(cyclotomicOrder, moduli[i], rootsOfUnity[i]);
			 m_vectors[i].Decompose();
			 rootsOfUnity[i] = m_vectors[i].GetParams().GetRootOfUnity();
		}
		ILDCRTParams &castedParams = static_cast<ILDCRTParams&>(this->AccessParams());
		castedParams.SetRootsOfUnity(rootsOfUnity);
		castedParams.SetOrder(cyclotomicOrder/2);

	}

	void ILVectorArray2n::DropTower(usint index){
		
		if(index >= m_vectors.size()){
			throw std::out_of_range("Index of tower being removed is larger than ILVectorArray2n tower\n");
		}

		m_vectors.erase(m_vectors.begin() + index);

		BigBinaryInteger newBigModulus(m_params.GetModulus());
		newBigModulus = newBigModulus.DividedBy(m_params.GetModuli()[index]);
		m_params.SetModulus(newBigModulus);

		std::vector<BigBinaryInteger> temp_moduli(m_params.GetModuli());
		temp_moduli.erase(temp_moduli.begin() + index);
		m_params.SetModuli(temp_moduli);

		std::vector<BigBinaryInteger> temp_roots_of_unity(m_params.GetRootsOfUnity());
		temp_roots_of_unity.erase(temp_roots_of_unity.begin() + index);
		m_params.SetRootsOfUnity(temp_roots_of_unity);
	
	}

	void ILVectorArray2n::ModReduce() {

		if(this->GetFormat() != Format::EVALUATION) {
			throw std::logic_error("Mod Reduce function expects EVAL Formatted ILVectorArray2n. It was passed COEFF Formatted ILVectorArray2n.");
		}
		this->SwitchFormat();

		usint length = this->GetLength();
		usint lastTowerIndex = length - 1;
		const std::vector<BigBinaryInteger> &moduli = m_params.GetModuli();

		ILVector2n towerT(m_vectors[lastTowerIndex]);
		ILVector2n d(towerT);

		//TODO: Get the Plain text modulus properly!
		BigBinaryInteger p(BigBinaryInteger::TWO);
		BigBinaryInteger qt(m_params.GetModuli()[lastTowerIndex]);
		BigBinaryInteger v(qt.ModInverse(p));
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, p*qt));
		d.SwitchModulus(p*qt);

		ILVector2n delta(d.Times(a));

		for(usint i=0; i<length; i++) {
			ILVector2n temp(delta);
			temp.SwitchModulus(moduli[i]);
			m_vectors[i] += temp;
			/*delta.SwitchModulus(moduli[i]);
			m_vectors[i] += delta;*/
		}

		this->DropTower(lastTowerIndex);

		std::vector<BigBinaryInteger> qtInverseModQi(length-1);
		for(usint i=0; i<length-1; i++) {
			qtInverseModQi[i] =  qt > moduli[i] ? qt.Mod(moduli[i]).ModInverse(moduli[i]) : qt.ModInverse(moduli[i]);
			m_vectors[i] = qtInverseModQi[i] * m_vectors[i];
		}

		this->SwitchFormat();
	}



	usint ILVectorArray2n::GetLength() const {
		return m_vectors.size();
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

	
	bool ILVectorArray2n::InverseExists() const
	{
	

		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}


		return true;
	}


	BigBinaryInteger ILVectorArray2n::CalculateInterpolationSum(const std::vector<BigBinaryInteger>& vectorOfBigInts, usint index)
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


//	BigBinaryInteger ILVectorArray2n::CalculateInterpolationSum2(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index)
//	{
//
//		BigBinaryInteger results("0");
//
//		for (usint i = 0; i < m_vectors.size(); i++) {
//
////			std::cout <<" Start for index " << i << std::endl;
//
//			BigBinaryInteger multiplyValue;
//
//			multiplyValue = vectorOfvectors[index][i].Times(CalculateChineseRemainderInterpolationCoefficient(i));
//
//	//		std::cout <<  vectorOfvectors[index][i] << std::endl;
//
//    //		std::cout << multiplyValue << std::endl;
//
//			results = (results.Plus((multiplyValue)));
//		
////			std::cout << results << std::endl;
//
////			std::cout <<" End for index " << i << std::endl;
//
//		}
//
//
//
//		results = results.Mod(m_params.GetModulus());
//
////		std::cout<< results << std::endl;
//
//		return results;
//
//	}

	/*BigBinaryInteger ILVectorArray2n::CalculatInterpolateModulu(BigBinaryInteger value, usint index)
	{
		return value.Mod(m_params.GetCRI()[index]);
	}*/


	// JSON FACILITY - SetIdFlag Operation
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ILVectorArray2n::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	//	std::unordered_map <std::string, std::string> serializationMap;

		return serializationMap;
	}

	// JSON FACILITY - Serialize Operation
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ILVectorArray2n::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	

	//	std::unordered_map <std::string, std::string> serializationMap;

		return serializationMap;
	}

	// JSON FACILITY - Deserialize Operation
	void ILVectorArray2n::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

		
	
	}

} // namespace lbcrypto ends


