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
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include "ilvector2n.h"
#include <fstream>
#include <cmath>


namespace lbcrypto {

	// static members
	template<typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorImpl<IntType,VecType,ParmType>> ILVectorImpl<IntType,VecType,ParmType>::m_dggSamples;

	template<typename IntType, typename VecType, typename ParmType>
	shared_ptr<ParmType> ILVectorImpl<IntType,VecType,ParmType>::m_dggSamples_params;

	template<typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorImpl<IntType,VecType,ParmType>> ILVectorImpl<IntType,VecType,ParmType>::m_tugSamples;

	template<typename IntType, typename VecType, typename ParmType>
	shared_ptr<ParmType> ILVectorImpl<IntType,VecType,ParmType>::m_tugSamples_params;

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl() : m_values(nullptr), m_format(EVALUATION) {
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const shared_ptr<ParmType> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format) {
		m_params = params;

		if (initializeElementToZero) {
			this->SetValuesToZero();
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(bool initializeElementToMax, const shared_ptr<ParmType> params, Format format) : m_values(nullptr), m_format(format) {
		m_params = params;

		if(initializeElementToMax) {
			this->SetValuesToMax();

		}
	}


	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, const shared_ptr<ParmType> params, Format format) {

		m_params = params;

		if (format == COEFFICIENT)
		{
			//usint vectorSize = EulerPhi(params.GetCyclotomicOrder());
			usint vectorSize = params->GetCyclotomicOrder() / 2;
			//TODO: use make_unique() throughout file;			
			unique_ptr<VecType> sp(new VecType(dgg.GenerateVector(vectorSize, params->GetModulus())));
            m_values = std::move(sp);
			(*m_values).SetModulus(params->GetModulus());
			m_format = COEFFICIENT;
		}
		else
		{ 
			PreComputeDggSamples(dgg, m_params);

			const ILVectorImpl randomElement = GetPrecomputedVector();
			unique_ptr<VecType> sp(new VecType(*randomElement.m_values));
      		m_values = std::move(sp);
			(*m_values).SetModulus(params->GetModulus());
			m_format = EVALUATION;
		}
	}


	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const DiscreteUniformGeneratorImpl<IntType,VecType> &dug, const shared_ptr<ParmType> params, Format format) {

		m_params = params;

		usint vectorSize = params->GetCyclotomicOrder() / 2;
		unique_ptr<VecType> sp(new VecType(dug.GenerateVector(vectorSize)));
		m_values = std::move(sp);
		(*m_values).SetModulus(params->GetModulus());

		m_format = COEFFICIENT;

		if (format == EVALUATION)
			this->SwitchFormat();

	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const BinaryUniformGeneratorImpl<IntType,VecType> &bug, const shared_ptr<ParmType> params, Format format) {
    bool dbg_flag = false;
		m_params = params;

		usint vectorSize = params->GetCyclotomicOrder() / 2;
		unique_ptr<VecType> sp(new VecType(bug.GenerateVector(vectorSize, params->GetModulus())));
    	m_values = std::move(sp);
		//(*m_values).SetModulus(ilParams.GetModulus());
    	DEBUG("why does this have no modulus");
		m_format = COEFFICIENT;

		if (format == EVALUATION)
			this->SwitchFormat();
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const TernaryUniformGeneratorImpl<IntType,VecType> &tug, const shared_ptr<ParmType> params, Format format) {

		m_params = params;

		if (format == COEFFICIENT)
		{
			//usint vectorSize = EulerPhi(params.GetCyclotomicOrder());
			usint vectorSize = params->GetCyclotomicOrder() / 2;
			unique_ptr<VecType> sp(new VecType(tug.GenerateVector(vectorSize, params->GetModulus())));
			m_values = std::move(sp);
			(*m_values).SetModulus(params->GetModulus());
			m_format = COEFFICIENT;
		}
		else
		{
			PreComputeTugSamples(tug, m_params);

			const ILVectorImpl randomElement = GetPrecomputedTugVector();
			unique_ptr<VecType> sp(new VecType(*randomElement.m_values));
      		m_values = std::move(sp);
			(*m_values).SetModulus(params->GetModulus());
			m_format = EVALUATION;
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(const ILVectorImpl &element) : m_params(element.m_params), m_format(element.m_format)
	{
   		bool dbg_flag = false;
    	if (!IsEmpty()){
      		DEBUG("in ctor & m_values was "<<*m_values);
    	} else {
      		DEBUG("in ctor & m_values are empty ");      
		}
    	if (element.m_values == nullptr) {
		     DEBUG("in ctor & m_values copy nullptr ");      
			 m_values = nullptr;
    	} else {
	  unique_ptr<VecType> sp(new VecType(*element.m_values)); //this is a copy
      		m_values = std::move(sp);
      		DEBUG("in ctor & m_values now "<<*m_values);
		}
	}

	//this is the move
	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::ILVectorImpl(ILVectorImpl &&element)
	 : m_params(element.m_params), 
	   m_format(element.m_format)
	   //m_values(element.m_values) //note this becomes move below
{
   bool dbg_flag = false;
    if (!IsEmpty()){
      DEBUG("in ctor && m_values was "<<*m_values);
    }else{
      DEBUG("in ctor && m_values was empty");
    }
    if (!element.IsEmpty()) {
      m_values = std::move(element.m_values);
      DEBUG("in ctor && m_values was "<<*m_values);

    } else{
      DEBUG("in ctor && m_values remains empty");
    }      
    //element.m_values = nullptr; //remove the reference (actually unnecessary with smart pointers now.
  }

	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator=(const ILVectorImpl &rhs) {

		if (this != &rhs) {
   		   if (m_values == nullptr && rhs.m_values != nullptr) {
			unique_ptr<VecType> sp(new VecType(*rhs.m_values)); 
			m_values = std::move(sp);
	      } else if (rhs.m_values != nullptr) {
			*this->m_values = *rhs.m_values; //this is a BBV copy
			}
			this->m_params = rhs.m_params;
			this->m_format = rhs.m_format;
		}

		return *this;
	}

	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator=(std::initializer_list<sint> rhs) {
		usint len = rhs.size();
		if (!IsEmpty()) {
			usint vectorLength = this->m_values->GetLength();

			for (usint j = 0; j < vectorLength; ++j) { // loops within a tower
				if (j < len) {
					SetValAtIndex(j, *(rhs.begin() + j));
				}
				else {
					SetValAtIndex(j, 0);
				}
			}

		}
		else {

			VecType temp(m_params->GetCyclotomicOrder() / 2);
			temp.SetModulus(m_params->GetModulus());
			temp = rhs;
			//this->SetValues(std::move(temp), m_format);
      		this->SetValues(temp, m_format); //rely on RVO instead of move
		}
		return *this;
	}


	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator=(ILVectorImpl &&rhs) {

		if (this != &rhs) {
      //if (m_values) //DBC removed delete,
      //delete m_values; no need to delete smart pointer.
      m_values = std::move(rhs.m_values); // copy reference
      //rhs.m_values = nullptr; 
			m_params = rhs.m_params;
			m_format = rhs.m_format;
		}

		return *this;
	}



	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::CloneParametersOnly() const {
		ILVectorImpl<IntType,VecType,ParmType> result(this->m_params, this->m_format);
		return std::move(result); //TODO should we instead rely on RVO? 
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format) const {
		ILVectorImpl<IntType,VecType,ParmType> result(dgg, m_params, format);
		return std::move(result);//TODO should we instead rely on RVO? 
	}

	//If this is in EVALUATION then just set all the values = val
	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator=(usint val) {
		m_format = EVALUATION;
		if (m_values = nullptr){
		  unique_ptr<VecType> sp(new VecType(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus()));
          m_values = std::move(sp);
        }
		for (size_t i = 0; i < m_values->GetLength(); ++i) {
			this->SetValAtIndex(i, val);
		}

		return *this;

	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType>::~ILVectorImpl()
	{
    //if (m_values)
    //  delete m_values; //DBC removed no need with  smart poiners
	}

	template<typename IntType, typename VecType, typename ParmType>
	const IntType &ILVectorImpl<IntType,VecType,ParmType>::GetModulus() const {
		return m_params->GetModulus();
	}

	template<typename IntType, typename VecType, typename ParmType>
	const usint ILVectorImpl<IntType,VecType,ParmType>::GetCyclotomicOrder() const {
		return m_params->GetCyclotomicOrder();
	}

	template<typename IntType, typename VecType, typename ParmType>
	const VecType &ILVectorImpl<IntType,VecType,ParmType>::GetValues() const {
		if (m_values == 0)
			throw std::logic_error("No values in ILVectorImpl");
		return *m_values;
	}

	template<typename IntType, typename VecType, typename ParmType>
	const IntType &ILVectorImpl<IntType,VecType,ParmType>::GetRootOfUnity() const {
		return m_params->GetRootOfUnity();
	}

	template<typename IntType, typename VecType, typename ParmType>
	Format ILVectorImpl<IntType,VecType,ParmType>::GetFormat() const {
		return m_format;
	}
#if MATHBACKEND !=6
	template<typename IntType, typename VecType, typename ParmType>
	const IntType& ILVectorImpl<IntType,VecType,ParmType>::GetValAtIndex(usint i) const
	{
		if (m_values == 0)
			throw std::logic_error("No values in ILVector2n");
		return m_values->GetValAtIndex(i);
	}
#else
	template<typename IntType, typename VecType, typename ParmType>
	const IntType ILVectorImpl<IntType,VecType,ParmType>::GetValAtIndex(usint i) const
  {
    bool dbg_flag = false;
    if( m_values == nullptr )
      throw std::logic_error("No values in ILVectorImpl");

    DEBUG("GetValAtIndex: m_values->GetValAtIndex("<<i<<") :"<<m_values->GetValAtIndex(i));
    const IntType tmp =  m_values->GetValAtIndex(i); //dbc tmp for debug
    DEBUG("GetValAtIndex: returning tmp "<<tmp);
    return tmp;
  }
#endif

	template<typename IntType, typename VecType, typename ParmType>
	usint ILVectorImpl<IntType,VecType,ParmType>::GetLength() const {
		if (m_values == 0)
			throw std::logic_error("No values in ILVectorImpl");
		return m_values->GetLength();
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SetValues(const VecType& values, Format format) {
  if (m_params->GetRootOfUnity() == IntType::ZERO || m_params->GetCyclotomicOrder() / 2 != values.GetLength() || m_params->GetModulus() != values.GetModulus()) {
      std::cout<<"ILVectorImpl::SetValues warning, mismatch in parameters"<<std::endl;
      if (m_params->GetRootOfUnity() == IntType::ZERO){
	std::cout<<"m_params->GetRootOfUnity "<<m_params->GetRootOfUnity()<<std::endl;}
      if (m_params->GetCyclotomicOrder() / 2 != values.GetLength()){
	std::cout<<"m_params->GetCyclotomicOrder/2 "<<m_params->GetCyclotomicOrder()/2<<std::endl;
	std::cout<<"!= values.GetLength()"<< values.GetLength() <<std::endl;
      }
      if ( m_params->GetModulus() != values.GetModulus()) {
	std::cout<<"m_params->GetModulus() "<<m_params->GetModulus()<<std::endl;
	std::cout<<"values->GetModulus() "<<values.GetModulus()<<std::endl;
      }
      //throw std::logic_error("Exisiting m_params do not match with the input parameter IntType& values.\n");
    // if (m_values != nullptr) { //dbc no need with smart pointers
    //   delete m_values;
    // }
    }
		unique_ptr<VecType> sp(new VecType(values));
    	m_values = std::move(sp);
		m_format = format;
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SetValuesToZero() {
		//if (m_values != NULL) { //dbc no need with smart pointers
		//	delete m_values;
		//}
	  unique_ptr<VecType> sp(new VecType(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus()));
    	m_values = std::move(sp);
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SetValuesToMax() {
		//if (m_values != NULL) { //dbc no need with smart pointers
		//	delete m_values;
		//}

		IntType max = m_params->GetModulus() - IntType::ONE;
		usint size = m_params->GetCyclotomicOrder()/2;
		unique_ptr<VecType> sp(new VecType(m_params->GetCyclotomicOrder()/2, m_params->GetModulus()));
    	m_values = std::move(sp);

		for (usint i = 0; i < size; i++) {
			IntType temp(max);
			//IntType temp("2475880078570760549798268928");
			//IntType temp("1111111111");
			m_values->SetValAtIndex(i, temp);
		}

	}


	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SetFormat(const Format format) {
		if (m_format != format) {
			this->SwitchFormat();
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Plus(const IntType &element) const {
		if (m_format != Format::COEFFICIENT)
			throw std::logic_error("ILVectorImpl::Plus can only be called in COEFFICIENT format.\n");

		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModAddAtIndex(0, element), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Minus(const IntType &element) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModSub(element), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Times(const IntType &element) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModMul(element), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::MultiplyAndRound(const IntType &p, const IntType &q) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().MultiplyAndRound(p, q), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::DivideAndRound(const IntType &q) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().DivideAndRound(q), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Negate() const {
		ILVectorImpl<IntType,VecType,ParmType> tmp( *this );
		*tmp.m_values = m_values->ModMul(this->m_params->GetModulus() - IntType::ONE);
		return std::move( tmp );
	}

	// VECTOR OPERATIONS

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Plus(const ILVectorImpl &element) const {
		ILVectorImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModAdd(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Minus(const ILVectorImpl &element) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModSub(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Times(const ILVectorImpl &element) const {
		ILVectorImpl<IntType,VecType,ParmType> tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModMul(*element.m_values), this->m_format );
		return std::move( tmp );
	}

	// FIXME: should the parms tests here be done in regular + as well as +=? or in neither place?
	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator+=(const ILVectorImpl &element) {
		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator+= called on ILVectorImpl's with different params.");

		if (m_values == nullptr) {
		  unique_ptr<VecType> sp(new VecType(*element.m_values));
      		m_values = std::move(sp);
			return *this;
		}

		SetValues( m_values->ModAdd(*element.m_values), this->m_format );

		return *this;
	}

	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator-=(const ILVectorImpl &element) {
		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator-= called on ILVectorImpl's with different params.");
		if (m_values == nullptr) {
		  unique_ptr<VecType> sp(new VecType(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus()));
			m_values = std::move(sp);
      //TODO:: is this a bug? it is not the same as +=
    
		}
		SetValues( m_values->ModSub(*element.m_values), this->m_format );
		return *this;
	}

	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType>& ILVectorImpl<IntType,VecType,ParmType>::operator*=(const ILVectorImpl &element) {

		if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
			throw std::logic_error("operator*= for ILVectorImpl is supported only in EVALUATION format.\n");

		if (!(*this->m_params == *element.m_params))
			throw std::logic_error("operator*= called on ILVectorImpl's with different params.");

		if (m_values == nullptr){
			unique_ptr<VecType> sp(new VecType(m_params->GetCyclotomicOrder() / 2, m_params->GetModulus()));
      		m_values = std::move(sp);
		}
		SetValues( m_values->ModMul(*element.m_values), this->m_format );

		return *this;
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::AddILElementOne() {
		if (m_format != Format::EVALUATION)
			throw std::runtime_error("ILVectorImpl::AddILElementOne cannot be called on a ILVectorImpl in COEFFICIENT format.");
		IntType tempValue;
		for (usint i = 0; i < m_params->GetCyclotomicOrder() / 2; i++) {
			tempValue = GetValues().GetValAtIndex(i) + IntType::ONE;
			tempValue = tempValue.Mod(m_params->GetModulus());
			m_values->SetValAtIndex(i, tempValue);
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::AutomorphismTransform(const usint &i) const {
		
		if (i % 2 == 0)
			throw std::logic_error("automorphism index should be odd\n");
		else
		{
			ILVectorImpl result(*this);
			usint m = m_params->GetCyclotomicOrder();

			for (usint j = 1; j < m; j = j + 2)
			{
				//usint newIndex = (j*iInverse) % m;
				usint newIndex = (j*i) % m;
				result.m_values->SetValAtIndex((newIndex + 1) / 2 - 1, GetValues().GetValAtIndex((j + 1) / 2 - 1));
			}
			return result;
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::Transpose() const {
		if (m_format == COEFFICIENT)
			throw std::logic_error("ILVectorImpl element transposition is currently implemented only in the Evaluation representation.");
		else
		{
			usint m = m_params->GetCyclotomicOrder();
			return AutomorphismTransform(2 * m - 1);
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::MultiplicativeInverse() const {
		ILVectorImpl tmp = CloneParametersOnly();
		if (InverseExists()) {
			tmp.SetValues( GetValues().ModInverse(), this->m_format );
			return std::move( tmp );
		}
		else {
			throw std::logic_error("ILVectorImpl has no inverse\n");
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::ModByTwo() const {
		ILVectorImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().ModByTwo(), this->m_format );
		return std::move( tmp );
	}
  //TODO: why is this called Signed Mod, should BBV.Mod be called signed mod too?

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::SignedMod(const IntType & modulus) const {
		ILVectorImpl tmp = CloneParametersOnly();
		tmp.SetValues( GetValues().Mod(modulus), this->m_format );
		return std::move( tmp );
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SwitchModulus(const IntType &modulus, const IntType &rootOfUnity) {
		if (m_values) {
			m_values->SwitchModulus(modulus);
			m_params = shared_ptr<ParmType>(new ParmType(m_params->GetCyclotomicOrder(), modulus, rootOfUnity));
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::SwitchFormat() {

    bool dbg_flag = false;
    if (m_values == nullptr) {
      std::string errMsg = "ILVector2n switch format to empty values";
      throw std::runtime_error(errMsg);
   }
    
		if (m_format == COEFFICIENT) {
			m_format = EVALUATION;
			//todo:: does this have an extra copy? 
			unique_ptr<VecType> sp(new VecType(ChineseRemainderTransformFTT<IntType,VecType>::GetInstance().ForwardTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetCyclotomicOrder())));
     		m_values = std::move(sp);		
		}
		else {
			m_format = COEFFICIENT;
			unique_ptr<VecType> sp(new VecType(ChineseRemainderTransformFTT<IntType,VecType>::GetInstance().InverseTransform(*m_values, m_params->GetRootOfUnity(), m_params->GetCyclotomicOrder())));
      		m_values = std::move(sp);
		}
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::PrintValues() const {
		if (m_values != nullptr) {
			std::cout << *m_values;
			std::cout << " mod:" << m_values->GetModulus() << std::endl;
		}
		if (m_params.get() != nullptr) {
			std::cout << " rootOfUnity: " << this->GetRootOfUnity() << std::endl;
		}
		else {
			std::cout << " something's odd: null m_params?!" << std::endl;
		}
		std::cout << std::endl;
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::MakeSparse(const IntType &wFactor) {
		IntType modTemp;
		IntType tempValue;
		usint w;
		if (m_values != 0) {
			for (usint i = 0; i < m_params->GetCyclotomicOrder() / 2;i++) {
				w = wFactor.ConvertToInt();
				if (i%w != 0) {
					m_values->SetValAtIndex(i, IntType::ZERO);
				}
			}
		}
	}

	// This function modifies ILVectorImpl to keep all the even indices. It reduces the ring dimension by half.
	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::Decompose() {

		Format format(m_format);

		if (format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorImpl not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}

		usint decomposedCyclotomicOrder = m_params->GetCyclotomicOrder() / 2;
		//Using the halving lemma propety of roots of unity to calculate the root of unity at half the cyclotomic order

		m_params = shared_ptr<ParmType>(new ParmType(decomposedCyclotomicOrder, m_params->GetModulus(), m_params->GetRootOfUnity()));

		//Interleaving operation.
		VecType decomposeValues(GetLength() / 2, GetModulus());
		for (usint i = 0; i < GetLength();i = i + 2) {
			decomposeValues.SetValAtIndex(i / 2, GetValues().GetValAtIndex(i));
		}

		SetValues(decomposeValues, m_format);
	}

	template<typename IntType, typename VecType, typename ParmType>
	bool ILVectorImpl<IntType,VecType,ParmType>::IsEmpty() const {
		if (m_values == nullptr)
			return true;

		return false;
	}

	template<typename IntType, typename VecType, typename ParmType>
	bool ILVectorImpl<IntType,VecType,ParmType>::InverseExists() const {
		for (usint i = 0; i < GetValues().GetLength(); i++) {
			if (m_values->GetValAtIndex(i) == IntType::ZERO)
				return false;
		}
		return true;
	}

	template<typename IntType, typename VecType, typename ParmType>
	double ILVectorImpl<IntType,VecType,ParmType>::Norm() const {
		double retVal = 0.0;
		double locVal = 0.0;
		double q = m_params->GetModulus().ConvertToDouble();

		for (usint i = 0; i < GetValues().GetLength(); i++) {
			if (m_values->GetValAtIndex(i) > (m_params->GetModulus() >> 1))
			{
				locVal = q - (m_values->GetValAtIndex(i)).ConvertToDouble();
			}
			else
				locVal = (m_values->GetValAtIndex(i)).ConvertToDouble();

			if (locVal > retVal)
				retVal = locVal;
		}
		return retVal;
	}

	template<typename IntType, typename VecType, typename ParmType>
	ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::GetDigitAtIndexForBase(usint index, usint base) const {
		ILVectorImpl tmp(*this);
		*tmp.m_values = GetValues().GetDigitAtIndexForBase(index, base);
		return tmp;
	}

	// Write vector x(current value of the ILVectorImpl object) as \sum\limits{ i = 0 }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and
	// return the vector of{ u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{ \log q / base } \rceil };
	// used as a subroutine in the relinearization procedure
	// baseBits is the number of bits in the base, i.e., base = 2^baseBits

	template<typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorImpl<IntType,VecType,ParmType>> ILVectorImpl<IntType,VecType,ParmType>::BaseDecompose(usint baseBits) const {
		
		usint nBits = m_params->GetModulus().GetLengthForBase(2);

		usint nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;

		ILVectorImpl<IntType,VecType,ParmType> xDigit(m_params);

		std::vector<ILVectorImpl<IntType,VecType,ParmType>> result;
		result.reserve(nWindows);
		// convert the polynomial to coefficient representation
		ILVectorImpl<IntType,VecType,ParmType> x(*this);
		if (x.GetFormat() == EVALUATION)
			x.SwitchFormat();

		for (usint i = 0; i < nWindows; ++i)
		{
			xDigit = x.GetDigitAtIndexForBase(i*baseBits + 1, 1 << baseBits);
			// convert the polynomial back to evaluation representation
			xDigit.SwitchFormat();
			result.push_back(xDigit);
		}

		return std::move(result);
	}

	// Generate a vector of ILVectorImpl's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current ILVectorImpl object;
	// used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
	// baseBits is the number of bits in the base, i.e., base = 2^baseBits

	template<typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorImpl<IntType,VecType,ParmType>> ILVectorImpl<IntType,VecType,ParmType>::PowersOfBase(usint baseBits) const {

		std::vector<ILVectorImpl<IntType,VecType,ParmType>> result;

		usint nBits = m_params->GetModulus().GetLengthForBase(2);

		usint nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;

		result.reserve(nWindows);

		for (usint i = 0; i < nWindows; ++i)
		{
			IntType pI(IntType::TWO.ModExp(IntType(i*baseBits), m_params->GetModulus()));
			result.push_back(pI*(*this));
		}

		return std::move(result);

	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::PreComputeDggSamples(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, const shared_ptr<ParmType> params) {
		if (m_dggSamples.size() == 0 || m_dggSamples_params != params)
		{
			DestroyPreComputedSamples();
			m_dggSamples_params = params;
			for (usint i = 0; i < m_sampleSize; ++i)
			{
				ILVectorImpl current(m_dggSamples_params);
				usint vectorSize = m_dggSamples_params->GetCyclotomicOrder() / 2;
				unique_ptr<VecType> sp(new VecType(dgg.GenerateVector(vectorSize, m_dggSamples_params->GetModulus())));
	    		current.m_values = std::move(sp);
				current.m_values->SetModulus(m_dggSamples_params->GetModulus());
				current.m_format = COEFFICIENT;

				current.SwitchFormat();

				m_dggSamples.push_back(current);
			}
		}
	}

	//Select a precomputed vector randomly
	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::GetPrecomputedVector() {

		//std::default_random_engine generator;
		//std::uniform_real_distribution<int> distribution(0,SAMPLE_SIZE-1);
		//int randomIndex = distribution(generator);

		int randomIndex = rand() % SAMPLE_SIZE;
		return m_dggSamples[randomIndex];
	}

	template<typename IntType, typename VecType, typename ParmType>
	void ILVectorImpl<IntType,VecType,ParmType>::PreComputeTugSamples(const TernaryUniformGeneratorImpl<IntType,VecType> &tug, const shared_ptr<ParmType> params) {
		if (m_tugSamples.size() == 0 || m_tugSamples_params != params)
		{
			DestroyPreComputedTugSamples();
			m_tugSamples_params = params;
			for (usint i = 0; i < m_sampleSize; ++i)
			{
				ILVectorImpl current(m_tugSamples_params);
				usint vectorSize = m_tugSamples_params->GetCyclotomicOrder() / 2;
				unique_ptr<VecType> sp(new VecType(tug.GenerateVector(vectorSize, m_tugSamples_params->GetModulus())));
	    		current.m_values = std::move(sp);
				current.m_values->SetModulus(m_tugSamples_params->GetModulus());
				current.m_format = COEFFICIENT;

				current.SwitchFormat();

				m_tugSamples.push_back(current);
			}
		}
	}

	//Select a precomputed vector randomly
	template<typename IntType, typename VecType, typename ParmType>
	const ILVectorImpl<IntType,VecType,ParmType> ILVectorImpl<IntType,VecType,ParmType>::GetPrecomputedTugVector() {

		int randomIndex = rand() % SAMPLE_SIZE;
		return m_tugSamples[randomIndex];
	}


	// JSON FACILITY - Serialize Operation
	template<typename IntType, typename VecType, typename ParmType>
	bool ILVectorImpl<IntType,VecType,ParmType>::Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
		if (!this->GetValues().Serialize(&obj))
			return false;

		if (!m_params->Serialize(&obj))
			return false;

		obj.AddMember("Format", std::to_string(this->GetFormat()), obj.GetAllocator());

		serObj->AddMember("ILVectorImpl", obj.Move(), serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	template<typename IntType, typename VecType, typename ParmType>
	bool ILVectorImpl<IntType,VecType,ParmType>::Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator iMap = serObj.FindMember("ILVectorImpl");
		if (iMap == serObj.MemberEnd()) return false;

		SerialItem::ConstMemberIterator pIt = iMap->value.FindMember("ParmType");
		if (pIt == iMap->value.MemberEnd()) return false;

		Serialized parm(rapidjson::kObjectType);
		parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

		shared_ptr<ParmType> json_ilParams(new ParmType());
		if (!json_ilParams->Deserialize(parm))
			return false;
		m_params = json_ilParams;

		usint vectorLength = this->m_params->GetCyclotomicOrder() / 2;

		VecType vectorBBV = VecType(vectorLength, m_params->GetModulus());

		SerialItem::ConstMemberIterator vIt = iMap->value.FindMember("VecType");
		if (vIt == iMap->value.MemberEnd()) {
			return false;
		}

		Serialized s(rapidjson::kObjectType);
		s.AddMember(SerialItem(vIt->name, s.GetAllocator()), SerialItem(vIt->value, s.GetAllocator()), s.GetAllocator());
		if (!vectorBBV.Deserialize(s)) { //vIt->value) ) {
			return false;
		}

		if ((vIt = iMap->value.FindMember("Format")) == iMap->value.MemberEnd()) return false;
		this->SetValues(vectorBBV, Format(atoi(vIt->value.GetString())));

		return true;
	}

} // namespace lbcrypto ends
