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

#include "ilvector2n.h"
#include <fstream>
#include <cmath>

namespace lbcrypto {

	//need to be added because m_dggSamples is static and not initialized
	std::vector<ILVector2n> ILVector2n::m_dggSamples;

	ILVector2n::ILVector2n() :m_values(NULL), m_format(EVALUATION) {

	}

	ILVector2n::ILVector2n(const ElemParams &params, Format format) : m_params(static_cast<const ILParams&>(params)), m_values(NULL), m_format(format) {
        usint vectorSize = m_params.GetCyclotomicOrder() / 2;
        m_values = new BigBinaryVector(vectorSize, m_params.GetModulus());
	}

	ILVector2n::ILVector2n(const ILVector2n &element) : m_params(element.m_params), m_format(element.m_format),
		m_values(new BigBinaryVector(*element.m_values)) {

	}

	ILVector2n::ILVector2n(ILVector2n &&element) : m_params(element.m_params), m_format(element.m_format),
		m_values(element.m_values) {
		element.m_values = NULL;
	}

	ILVector2n& ILVector2n::operator=(const ILVector2n &rhs) {

		if (this != &rhs) {
			if (m_values == NULL) {
				m_values = new BigBinaryVector(*rhs.m_values);
			}
			else {
				*this->m_values = *rhs.m_values;
			}
			this->m_params = rhs.m_params;
			this->m_format = rhs.m_format;
		}

		return *this;
	}

	ILVector2n& ILVector2n::operator=(ILVector2n &&rhs) {

		if (this != &rhs) {
			delete m_values;
			m_values = rhs.m_values;
			rhs.m_values = NULL;
			m_params = rhs.m_params;
			m_format = rhs.m_format;
		}

		return *this;
	}

	ILVector2n::ILVector2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format) :m_params(static_cast<const ILParams&>(params)) {
		/*
		//usint vectorSize = EulerPhi(params.GetCyclotomicOrder());
		usint vectorSize = params.GetCyclotomicOrder()/2;
		m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize));
		(*m_values).SetModulus(params.GetModulus());
		m_format = COEFFICIENT;
		//std::cout<<"before switchformat: "<<GetFormat()<<std::endl;
		if (format == EVALUATION)
		SwitchFormat();
		*/

		const ILParams &ilParams = static_cast<const ILParams&>(params);

		if (format == COEFFICIENT)
		{
			//usint vectorSize = EulerPhi(params.GetCyclotomicOrder());
			usint vectorSize = ilParams.GetCyclotomicOrder() / 2;
			m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize,ilParams.GetModulus()));
			(*m_values).SetModulus(params.GetModulus());
			m_format = COEFFICIENT;
		}
		else
		{
			if (m_dggSamples.size() == 0)
			{
				PreComputeDggSamples(dgg, ilParams);
			}
			ILVector2n randomElement = GetPrecomputedVector(ilParams);
			m_values = new BigBinaryVector(*randomElement.m_values);
			(*m_values).SetModulus(params.GetModulus());
			m_format = EVALUATION;
		}
	}


	ILVector2n::ILVector2n(DiscreteUniformGenerator &dug, const ElemParams &params, Format format) :m_params(static_cast<const ILParams&>(params)) {

		const ILParams &ilParams = static_cast<const ILParams&>(params);

		usint vectorSize = ilParams.GetCyclotomicOrder() / 2;
		m_values = new BigBinaryVector(dug.GenerateVector(vectorSize));
		(*m_values).SetModulus(params.GetModulus());

		m_format = COEFFICIENT;

		if (format == EVALUATION)
			this->SwitchFormat();

	}

	ILVector2n::ILVector2n(BinaryUniformGenerator &dbg, const ElemParams &params, Format format) :m_params(static_cast<const ILParams&>(params)) {

		const ILParams &ilParams = static_cast<const ILParams&>(params);

		usint vectorSize = ilParams.GetCyclotomicOrder() / 2;
		m_values = new BigBinaryVector(dbg.GenerateVector(vectorSize,params.GetModulus()));
		//(*m_values).SetModulus(params.GetModulus());

		m_format = COEFFICIENT;

		if (format == EVALUATION)
			this->SwitchFormat();

	}

	ILVector2n::~ILVector2n()
	{
		/*if(m_values!=NULL)
		m_values->~BigBinaryVector();*/
		delete m_values;
	}

	/*
		Print values an flush buffer after printing with new line.
		*/
	void ILVector2n::PrintValuesEndl() const {

	//std::cout << "Printing values in ILVECTOR2N" << std::endl;
		this->PrintValues();
		std::cout << std::endl;

	}

	/*
		Print values and don't flush before and don't print new line.
		*/
	void ILVector2n::PrintValues() const {

	//std::cout << "Printing values in ILVECTOR2N" << std::endl;
		if (m_values != NULL) {
			std::cout << *m_values;// << std::endl;
		}
		std::cout << " mod:" << m_values->GetModulus();

	}

	const BigBinaryInteger &ILVector2n::GetModulus() const {
		return m_params.GetModulus();
	}

	const BigBinaryVector &ILVector2n::GetValues() const {
		return *m_values;
	}

	const BigBinaryInteger &ILVector2n::GetRootOfUnity() {
		return m_params.GetRootOfUnity();
	}

	Format ILVector2n::GetFormat() const {
		return m_format;
	}

	const ILParams &ILVector2n::GetParams() const {
		return m_params;
	}

	const BigBinaryInteger& ILVector2n::GetValAtIndex(usint i) const
	{
		return m_values->GetValAtIndex(i);
	}

	usint ILVector2n::GetLength() const {
		return m_values->GetLength();
	}

	void ILVector2n::SetValues(const BigBinaryVector& values, Format format) {
		if (m_values != NULL) {
			delete m_values;
		}
		m_values = new BigBinaryVector(values);
		m_format = format;
	}

	void ILVector2n::SetModulus(const BigBinaryInteger &modulus) {


	//	if ((modulus) < m_params.GetModulus()) {

			BigBinaryVector bigVector = m_values->Mod(modulus);

			*m_values = bigVector;

	//	}

		m_params.SetModulus(modulus);


	}

	void ILVector2n::SetParams(const ILParams & params)
	{
		m_params = params;
	}




	// addition operation - PREV1
	ILVector2n ILVector2n::Plus(const BigBinaryInteger &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModAdd(element);
		return tmp;
	}


	// multiplication operation - PREV1
	ILVector2n ILVector2n::Times(const BigBinaryInteger &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModMul(element);
		return tmp;
	}

	// modulo operation - PREV1
	ILVector2n ILVector2n::Mod(const BigBinaryInteger & modulus) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->Mod(modulus);
		return tmp;
	}

	// modulo by two
	ILVector2n ILVector2n::ModByTwo() const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModByTwo();
		return tmp;
	}

	// check if inverse exists
	bool ILVector2n::InverseExists() const {
		for (usint i = 0; i < m_values->GetLength(); i++) {
			if ((m_values->GetValAtIndex(i) == BigBinaryInteger::ZERO) || (m_values->GetValAtIndex(i) == BigBinaryInteger::ONE))
				return false;
		}
		return true;
	}

	// check if inverse exists
	double ILVector2n::Norm() const {
		double retVal = 0.0;
		double locVal = 0.0;
		double q = m_params.GetModulus().ConvertToDouble();

		for (usint i = 0; i < m_values->GetLength(); i++) {
			if (m_values->GetValAtIndex(i) > (m_params.GetModulus()>>1))
			{
				locVal = q - (m_values->GetValAtIndex(i)).ConvertToDouble();
			}
			else
				locVal = (m_values->GetValAtIndex(i)).ConvertToDouble();
				
			if (locVal > retVal)
				retVal = locVal;
		}
		//std::cout << " Norm: " << retVal << std::endl;
		return retVal;
	}

	// VECTOR OPERATIONS

	// addition operation - PREV1
	ILVector2n ILVector2n::Plus(const ILVector2n &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModAdd(*element.m_values);
		return tmp;
	}

	ILVector2n ILVector2n::Minus(const ILVector2n &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModSub(*element.m_values);
		return tmp;
	}

	const ILVector2n& ILVector2n::operator+=(const ILVector2n &element) {
		*this->m_values = this->m_values->ModAdd(*element.m_values);
		return *this;
	}

	// multiplication operation - PREV1
	ILVector2n ILVector2n::Times(const ILVector2n &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModMul(*element.m_values);
		return tmp;
	}

	// multiplicative inverse operation
	ILVector2n ILVector2n::MultiplicativeInverse() const {
		ILVector2n tmp(*this);
		if (tmp.InverseExists()) {
			*tmp.m_values = m_values->ModInverse();
			return tmp;
		}

		else {
			throw std::logic_error("ILVector2n has no inverse\n");

		}
	}

	//automorphism operation
	ILVector2n ILVector2n::AutomorphismTransform(const usint &i) const {

		if (i % 2 == 0)
			throw std::logic_error("automorphism index should be odd\n");
		else
		{
			ILVector2n result(*this);

			usint m = m_params.GetCyclotomicOrder();
			//usint iInverse = ModInverse(i,m);
			//uschar sign;

			for (usint j = 1; j < m; j = j + 2)
			{

				//usint newIndex = (j*iInverse) % m;
				usint newIndex = (j*i) % m;

				result.m_values->SetValAtIndex((newIndex + 1)/2-1,this->m_values->GetValAtIndex((j+1)/2-1));

			}

			return result;
		}

	}

	// OTHER METHODS

	// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
	void ILVector2n::SwitchFormat() {

		if (m_format == COEFFICIENT) {

			m_format = EVALUATION;
			//std::cout << "starting CRT" << std::endl;
			/*std::cout << *m_values << std::endl;
			std::cout << m_params.GetRootOfUnity() << std::endl;
			std::cout << m_params.GetCyclotomicOrder() << std::endl;*/

			*m_values = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(*m_values, m_params.GetRootOfUnity(), m_params.GetCyclotomicOrder());

		}

		else {
			m_format = COEFFICIENT;
			*m_values = ChineseRemainderTransformFTT::GetInstance().InverseTransform(*m_values, m_params.GetRootOfUnity(), m_params.GetCyclotomicOrder());
		}

	}

    void ILVector2n::SetFormat(Format format) {
        if (m_format != format) {
            SwitchFormat();
        }
    }

	// get digit for a specific based - used for PRE scheme
	ILVector2n ILVector2n::GetDigitAtIndexForBase(usint index, usint base) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->GetDigitAtIndexForBase(index, base);
		return tmp;
	}

	//Precompute a sample of disrete gaussian polynomials
	void ILVector2n::PreComputeDggSamples(const DiscreteGaussianGenerator &dgg, const ILParams &params) {
	  if (m_dggSamples.size() == 0)
	    {
		for (usint i = 0; i < m_sampleSize; ++i)
		{
			ILVector2n current(params);
			usint vectorSize = params.GetCyclotomicOrder() / 2;
			current.m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize,params.GetModulus()));
			(*current.m_values).SetModulus(params.GetModulus());
			current.m_format = COEFFICIENT;

			auto start = std::chrono::steady_clock::now();

			current.SwitchFormat();

			if ((i>5) && (i < 9)) {
				auto end = std::chrono::steady_clock::now();
				auto diff = end - start;
				std::cout << "NTT time: " << std::chrono::duration <double, std::milli>(diff).count() << " ms" << std::endl;
			}

			m_dggSamples.push_back(current);
		}
	    }
	}

	//Select a precomputed vector randomly
	const ILVector2n ILVector2n::GetPrecomputedVector(const ILParams &params) {

		//std::default_random_engine generator;
		//std::uniform_real_distribution<int> distribution(0,SAMPLE_SIZE-1);
		//int randomIndex = distribution(generator);
		int randomIndex = rand() % SAMPLE_SIZE;
		//std::cout << "random index: " << randomIndex << std::endl;
		//std::cout << "random vector: " << m_dggSamples[randomIndex].GetValues() << std::endl;
		return m_dggSamples[randomIndex];

	}

	// JSON FACILITY - SetIdFlag Operation
	bool ILVector2n::SetIdFlag(SerializationMap& serializationMap, std::string flag) const {

		//Place holder

		return true;
	}

	// JSON FACILITY - Serialize Operation
	bool ILVector2n::Serialize(SerializationMap& serializationMap, std::string fileFlag) const {

		if( !this->GetValues().Serialize(serializationMap, "") )
			return false;

		SerializationMap::iterator vMap = serializationMap.find("BigBinaryVector");
		if( vMap == serializationMap.end() )
			return false;

		SerializationKV ilVector2nMap = vMap->second;
		ilVector2nMap.emplace("Format", "0");
		serializationMap.erase("BigBinaryVector");
		serializationMap.emplace("ILVector2n", ilVector2nMap);

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	//FIXME
	bool ILVector2n::Deserialize(const SerializationMap& serializationMap) {

		SerializationMap::const_iterator iMap = serializationMap.find("ILVector2n");
		if( iMap == serializationMap.end() ) return false;

		SerializationKV ilVector2nMap = iMap->second;

		iMap = serializationMap.find("ILParams");
		std::string ov = iMap->second.find("Order")->second;
		usint vectorLength = (stoi(ov)) / 2;
		BigBinaryVector vectorBBV = BigBinaryVector(vectorLength);

		std::unordered_map<std::string, std::unordered_map<std::string, std::string>> bbvSerializationMap;
		bbvSerializationMap.emplace("BigBinaryVector", ilVector2nMap);
		vectorBBV.Deserialize(bbvSerializationMap);
		this->SetValues(vectorBBV, Format(stoi(ilVector2nMap["Format"])));
		//std::cout << "Values " << this->GetValues() << std::endl;

		BigBinaryInteger bbiModulus(ilVector2nMap["Modulus"]);
		this->SetModulus(bbiModulus);

		ILParams json_ilParams;
		json_ilParams.Deserialize(serializationMap);
		this->SetParams(json_ilParams);
	}

} // namespace lbcrypto ends
