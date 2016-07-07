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
	std::vector<ILVector2n*> ILVector2n::m_dggSamples;

	ILVector2n::ILVector2n() :m_values(NULL), m_format(EVALUATION),m_empty(true) {

	}

	ILVector2n::ILVector2n(const ElemParams &params, Format format) : m_values(NULL), m_format(format), m_empty(true) {
		const ILParams &ilParam = dynamic_cast<const ILParams&>(params);
		m_params = ilParam;	
	}

	ILVector2n::ILVector2n(const ILVector2n &element) : m_params(element.m_params), m_format(element.m_format)
	{
			if(element.m_values==NULL){
				m_values = NULL;
				m_empty = true;
			}
			else{
				m_values = new BigBinaryVector(*element.m_values);
				m_empty = false;
			}
	}

	ILVector2n::ILVector2n(ILVector2n &&element) : m_params(element.m_params), m_format(element.m_format),
		m_values(element.m_values),m_empty(element.m_empty) {
		element.m_values = NULL;
		element.m_empty = true;
	}

	const ILVector2n& ILVector2n::operator=(const ILVector2n &rhs) {

		if (this != &rhs) {
			if (m_values == NULL && rhs.m_values!=NULL) {
					m_values = new BigBinaryVector(*rhs.m_values);
			}
			else if (rhs.m_values!=NULL){
				*this->m_values = *rhs.m_values;
			}
			this->m_params = rhs.m_params;
			this->m_format = rhs.m_format;
			m_empty = rhs.m_empty;
		}

		return *this;
	}

	const ILVector2n& ILVector2n::operator=(ILVector2n &&rhs) {

		if (this != &rhs) {
			delete m_values;
			m_values = rhs.m_values;
			rhs.m_values = NULL;
			m_params = rhs.m_params;
			m_format = rhs.m_format;
		}

		return *this;
	}

	ILVector2n::ILVector2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format) {
	
		m_params = dynamic_cast<const ILParams&>(params);

		if (format == COEFFICIENT)
		{
			//usint vectorSize = EulerPhi(params.GetCyclotomicOrder());
			usint vectorSize = params.GetCyclotomicOrder() / 2;
			m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize,params.GetModulus()));
			(*m_values).SetModulus(params.GetModulus());
			m_format = COEFFICIENT;
		}
		else
		{
			if (m_dggSamples.size() == 0)
			{
				PreComputeDggSamples(dgg, m_params);
			}
			const ILVector2n *randomElement = GetPrecomputedVector(m_params);
			m_values = new BigBinaryVector(*randomElement->m_values);
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

	ILVector2n::ILVector2n(BinaryUniformGenerator &bug, const ElemParams &params, Format format) :m_params(static_cast<const ILParams&>(params)) {

		const ILParams &ilParams = static_cast<const ILParams&>(params);

		usint vectorSize = ilParams.GetCyclotomicOrder() / 2;
		m_values = new BigBinaryVector(bug.GenerateVector(vectorSize,ilParams.GetModulus()));
		//(*m_values).SetModulus(ilParams.GetModulus());

		m_format = COEFFICIENT;

		if (format == EVALUATION)
			this->SwitchFormat();

	}

	ILVector2n ILVector2n::CloneWithParams() const {
		ILVector2n result(this->m_params,this->m_format);
		return std::move(result);
	}

	ILVector2n ILVector2n::CloneWithNoise(const DiscreteGaussianGenerator &dgg, Format format) const {
		ILVector2n result(dgg, m_params, format);
		return std::move(result);
	}

	const ILVector2n& ILVector2n::operator=(usint val) {
        m_format = COEFFICIENT;
        this->SetValAtIndex(0, val);
        for (size_t i = 1; i < m_values->GetLength(); ++i) {
            this->SetValAtIndex(i, 0);
        }
        this->SwitchFormat();
        return *this;
    }

	ILVector2n::~ILVector2n()
	{
		delete m_values;
	}

	/*
		Print values and don't flush before and don't print new line.
	*/
	void ILVector2n::PrintValues() const {
		if (m_values != NULL) {
			std::cout << *m_values;
		}
		std::cout << " mod:" << m_values->GetModulus() <<std::endl;
		std::cout << " rootOfUnity: " << this->GetRootOfUnity()<<std::endl;
		std::cout << std::endl;
	}

	const BigBinaryInteger &ILVector2n::GetModulus() const {
		return m_params.GetModulus();
	}

	const usint &ILVector2n::GetCyclotomicOrder() const{
		return m_params.GetCyclotomicOrder();
	}

	const BigBinaryVector &ILVector2n::GetValues() const {
		return *m_values;
	}

	const BigBinaryInteger &ILVector2n::GetRootOfUnity() const{
		return m_params.GetRootOfUnity();
	}

	Format ILVector2n::GetFormat() const {
		return m_format;
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

	void ILVector2n::SwitchModulus(const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity){
		m_values->SwitchModulus(modulus);
		m_params.SetModulus(modulus);
		m_params.SetRootOfUnity(rootOfUnity);
	}

	// addition operation - PREV1
	ILVector2n ILVector2n::Plus(const BigBinaryInteger &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModAddAtIndex(0, element);
		return tmp;
	}

	// subtraction operation - PREV1
	ILVector2n ILVector2n::Minus(const BigBinaryInteger &element) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModSub(element);
		return tmp;
	}


	// multiplication operation - PREV1
	ILVector2n ILVector2n::Times(const BigBinaryInteger &element) const {
		//std::cout<< "element: "<<element<< std::endl;
		ILVector2n tmp(*this);
		//tmp.PrintValues();
		*tmp.m_values = m_values->ModMul(element);
		return tmp;
	}

	// modulo operation - PREV1
	/*ILVector2n ILVector2n::Mod(const BigBinaryInteger & modulus) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->Mod(modulus);
		return tmp;
	}*/

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
		} else {
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
			if(m_values!=NULL)
				*m_values = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(*m_values, m_params.GetRootOfUnity(), m_params.GetCyclotomicOrder());
		} else {
			m_format = COEFFICIENT;
			if(m_values!=NULL)
				*m_values = ChineseRemainderTransformFTT::GetInstance().InverseTransform(*m_values, m_params.GetRootOfUnity(), m_params.GetCyclotomicOrder());
		}

	}

    void ILVector2n::SetFormat(const Format format) {
        if (m_format != format) {
            this->SwitchFormat();
        }
    }

	// get digit for a specific based - used for PRE scheme
	ILVector2n ILVector2n::GetDigitAtIndexForBase(usint index, usint base) const {
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->GetDigitAtIndexForBase(index, base);
		return tmp;
	}

	//Precompute a sample of discrete gaussian polynomials
	void ILVector2n::PreComputeDggSamples(const DiscreteGaussianGenerator &dgg, const ILParams &params) {
		if (m_dggSamples.size() == 0)
		{
			for (usint i = 0; i < m_sampleSize; ++i)
			{
				ILVector2n *current = new ILVector2n(params);
				usint vectorSize = params.GetCyclotomicOrder() / 2;
				current->m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize,params.GetModulus()));
				current->m_values->SetModulus(params.GetModulus());
				current->m_format = COEFFICIENT;

				current->SwitchFormat();

				m_dggSamples.push_back(current);
			}
		}
	}

	//Select a precomputed vector randomly
	const ILVector2n* ILVector2n::GetPrecomputedVector(const ILParams &params) {
		int randomIndex = rand() % SAMPLE_SIZE;
		return m_dggSamples[randomIndex];
	}

	void ILVector2n::AddILElementOne(){
		BigBinaryInteger tempValue;
		for(usint i = 0; i < m_params.GetCyclotomicOrder()/2; i++){
			tempValue = m_values->GetValAtIndex(i) + BigBinaryInteger::ONE; 
			tempValue = tempValue.Mod(m_params.GetModulus());
			m_values->SetValAtIndex(i,tempValue);
		}
	
	}

	
	void ILVector2n::MakeSparse(const BigBinaryInteger &wFactor){
		BigBinaryInteger modTemp;
		BigBinaryInteger tempValue;
		usint w;
		for(usint i = 0; i < m_params.GetCyclotomicOrder()/2;i++){
			w = wFactor.ConvertToInt();
			if(!(i%w == 0)){
				m_values->SetValAtIndex(i,BigBinaryInteger::ZERO);
			}
		}
	}

	// This function modifies ILVector2n to keep all the even indices. It reduces the ring dimension by half.
	void ILVector2n::Decompose() {
		
		Format format( m_format );
		
		if(format != Format::COEFFICIENT) {
			std::string errMsg = "ILVector2n not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		//Generation of new crypto parameters
		usint decomposedCyclotomicOrder = m_params.GetCyclotomicOrder()/2;
		m_params.SetRootOfUnity(RootOfUnity(decomposedCyclotomicOrder, GetModulus()));
		m_params.SetCyclotomicOrder(decomposedCyclotomicOrder);

		//Interleaving operation.
		BigBinaryVector decomposeValues(GetLength()/2, GetModulus());
		for(usint i = 0; i < GetLength();i=i+2){
			decomposeValues.SetValAtIndex(i/2, GetValues().GetValAtIndex(i));
		}

		SetValues(decomposeValues, m_format);
	}

	bool ILVector2n::IsEmpty() const{
		if(m_values==NULL)
			return true;

		return false;
	}

	// JSON FACILITY - Serialize Operation
	bool ILVector2n::Serialize(Serialized* serObj, const std::string) const {
		if( !serObj->IsObject() )
			return false;

		Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
		if( !this->GetValues().Serialize(&obj) )
			return false;

		if( !m_params.Serialize(&obj) )
			return false;

		obj.AddMember("Format", this->ToStr(this->GetFormat()), obj.GetAllocator());

		serObj->AddMember("ILVector2n", obj, serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	bool ILVector2n::Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator iMap = serObj.FindMember("ILVector2n");
		if( iMap == serObj.MemberEnd() ) return false;

		SerialItem::ConstMemberIterator pIt = iMap->value.FindMember("ILParams");
		if( pIt == iMap->value.MemberEnd() ) return false;

		Serialized parm(rapidjson::kObjectType);
		parm.AddMember(SerialItem(pIt->name,parm.GetAllocator()), SerialItem(pIt->value,parm.GetAllocator()), parm.GetAllocator());

		ILParams json_ilParams;
		if( !json_ilParams.Deserialize(parm) )
			return false;
		m_params = json_ilParams;

		usint vectorLength = this->m_params.GetCyclotomicOrder() / 2;

		BigBinaryVector vectorBBV = BigBinaryVector(vectorLength, m_params.GetModulus());

		SerialItem::ConstMemberIterator vIt = iMap->value.FindMember("BigBinaryVector");
		if( vIt == iMap->value.MemberEnd() ) {
			return false;
		}

		Serialized s(rapidjson::kObjectType);
		s.AddMember(SerialItem(vIt->name,s.GetAllocator()), SerialItem(vIt->value,s.GetAllocator()), s.GetAllocator());
		if( !vectorBBV.Deserialize(s) ) { //vIt->value) ) {
			return false;
		}

		if( (vIt = iMap->value.FindMember("Format")) == iMap->value.MemberEnd() ) return false;
		this->SetValues(vectorBBV, Format(atoi(vIt->value.GetString())));

		/*BigBinaryInteger bbiModulus(m_params.GetModulus());
		this->SetModulus(bbiModulus);*/

		return true;
	}

} // namespace lbcrypto ends
