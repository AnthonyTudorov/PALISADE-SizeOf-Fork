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
Nishant Pasham, np386@njit.edu
Hadi Sajjadpour, ss2959@njit.edu
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
#include <memory>
using std::shared_ptr;
using std::string;
#include "../utils/serializablehelper.h"
#include "../utils/debug.h"

namespace lbcrypto {

	/*CONSTRUCTORS*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl() : m_format(EVALUATION), m_cyclotomicOrder(0), m_modulus(1) {}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const shared_ptr<ParmType> dcrtParams, Format format, bool initializeElementToZero)
	{
		m_cyclotomicOrder = dcrtParams->GetCyclotomicOrder();
		m_format = format;
		m_modulus = dcrtParams->GetModulus();
		m_params = dcrtParams;

		size_t vecSize = dcrtParams->GetParams().size();
		m_vectors.reserve(vecSize);
		
		for (usint i = 0; i < vecSize; i++) {
			m_vectors.push_back(std::move(ILVectorType(dcrtParams->GetParams()[i],format,initializeElementToZero)));
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const ILVectorArrayImpl &element)  {
		m_format = element.m_format;
		m_vectors = element.m_vectors;
		m_modulus = element.m_modulus;
		m_cyclotomicOrder = element.m_cyclotomicOrder;
		m_params = element.m_params;
	}
	
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::fillVectorArrayFromBigVector(const ILVector2n &element, const shared_ptr<ParmType> params) {

		size_t vecCount = params->GetParams().size();
		m_vectors.reserve(vecCount);

		// fill up with vectors with the proper moduli
		for(usint i = 0; i < vecCount; i++ ) {
			ILVectorType newvec(params->GetParams()[i], m_format, true);
			m_vectors.push_back( std::move(newvec) );
		}

		// need big ints out of the little ints for the modulo operations, below
		std::vector<ModType> bigmods;
		bigmods.reserve(vecCount);
		for( usint i = 0; i < vecCount; i++ )
			bigmods.push_back( ModType(params->GetParams()[i]->GetModulus().ConvertToInt()) );

		// copy each coefficient mod the new modulus
		for(usint p = 0; p < element.GetLength(); p++ ) {
			for( usint v = 0; v < vecCount; v++ ) {
				m_vectors[v].SetValAtIndex(p, (element.GetValAtIndex(p) % bigmods[v]).ConvertToInt());
			}
		}

		std::cout << "Large vector: " << element.GetModulus() << std::endl;
		for( int r=0; r<element.GetLength(); r++ )
			std::cout << "   " << element.GetValAtIndex(r);
		std::cout << std::endl;
		std::cout << "New vector: " << this->GetModulus() << std::endl;
		for( int v = 0; v < m_vectors.size(); v++ ) {
			std::cout << "tower " << v << " modulus " << m_vectors[v].GetModulus() << std::endl;
			for( int r=0; r<m_vectors[v].GetLength(); r++ )
				std::cout << "   " << m_vectors[v].GetValAtIndex(r);
			std::cout << std::endl;
		}
	}

	/* Construct from a single ILVector2n. The format is derived from the passed in ILVector2n.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const ILVector2n &element, const shared_ptr<ParmType> params)
	{
		Format format;
		try{
			format = element.GetFormat();
		}
		catch (const std::exception& e) {
			throw std::logic_error("There is an issue with the format of ILVectors passed to the constructor of ILVectorArrayImpl");
		}

		if( element.GetCyclotomicOrder() != params->GetCyclotomicOrder() )
			throw std::logic_error("Cyclotomic order mismatch on input vector and parameters");

		m_format = format;
		m_modulus = params->GetModulus();
		m_cyclotomicOrder = params->GetCyclotomicOrder();
		m_params = params;

		fillVectorArrayFromBigVector(element, params);

	}

	/* Construct from a single Native ILVector2n. The format is derived from the passed in ILVector2n.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const ILVectorType &element, const shared_ptr<ParmType> params)
	{
		Format format;
		try{
			format = element.GetFormat();
		}
		catch (const std::exception& e) {
			throw std::logic_error("There is an issue with the format of ILVectors passed to the constructor of ILVectorArrayImpl");
		}

		if( element.GetCyclotomicOrder() != params->GetCyclotomicOrder() )
			throw std::logic_error("Cyclotomic order mismatch on input vector and parameters");

		m_format = format;
		m_modulus = params->GetModulus();
		m_cyclotomicOrder = params->GetCyclotomicOrder();
		m_params = params;

		for( int i=0; i < params->GetParams().size(); i++ ) {
			m_vectors.push_back( element );
			m_vectors[i].SwitchModulus( (*params)[i]->GetModulus(), (*params)[i]->GetRootOfUnity() );
		}
	}

	/* Construct using an tower of ILVectro2ns. The params and format for the ILVectorArrayImpl will be derived from the towers.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const std::vector<ILVectorType> &towers)
	{
		usint cyclotomicOrder = towers.at(0).GetCyclotomicOrder();
		for (usint i = 1; i < towers.size(); i++) {
			if ( towers.at(i).GetCyclotomicOrder() != cyclotomicOrder ) {
				throw std::logic_error(std::string("ILVectors provided to ILVectorArrayImpl must have the same ring dimension"));
			}
		}

		shared_ptr<ParmType> p( new ParmType(towers.size()) );
		p->SetCyclotomicOrder(cyclotomicOrder);

		m_modulus = ModType::ONE;

		for (usint i = 0; i<towers.size(); i++) {
			(*p)[i] = towers.at(i).GetParams();
			m_modulus = m_modulus * ModType(towers.at(i).GetModulus().ConvertToInt());
		}

		m_params = p;
		m_vectors = towers;
		m_format = m_vectors[0].GetFormat();
		m_cyclotomicOrder = cyclotomicOrder;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(DistributionGeneratorType gtype, const shared_ptr<ParmType> params, Format format) {

		if( gtype == BinaryUniformGen || gtype == TernaryUniformGen )
			throw std::logic_error("Generator not supported");

		// create a dummy parm to use in the ILVector2n world
		shared_ptr<ILParams> parm( new ILParams(params->GetCyclotomicOrder(), params->GetModulus()) );

		m_params = params;
		m_cyclotomicOrder = params->GetCyclotomicOrder();
		m_modulus = params->GetModulus();

		ILVector2n randomElement( parm );
		VecType randVec;
		usint vectorSize = params->GetCyclotomicOrder() / 2;

		if( gtype == DiscreteUniformGen ) {
			randVec = VecType(GeneratorContainer<ModType,VecType>::GetGenerator(gtype).GenerateVector(vectorSize, params->GetModulus()));
			randVec.SetModulus(m_modulus);
			m_format = COEFFICIENT;

			if( format == EVALUATION )
				this->SwitchFormat();

			randomElement.SetValues( randVec, m_format );
		}
		else {
			if( format == COEFFICIENT ) {
				randVec = VecType(GeneratorContainer<ModType,VecType>::GetGenerator(gtype).GenerateVector(vectorSize, params->GetModulus()));
				m_format = COEFFICIENT;
				randomElement.SetValues( randVec, m_format );
			}
			else {
				if( gtype == DiscreteGaussianGen ) {
					ILVector2n::PreComputeDggSamples(GeneratorContainer<ModType,VecType>::GetGenerator(gtype), parm);
				}

				randomElement = ILVector2n::GetPrecomputedVector();
				m_format = EVALUATION;
			}
		}

		fillVectorArrayFromBigVector(randomElement, params);
	}


	/*The dgg will be the seed to populate the towers of the ILVectorArrayImpl with random numbers. The algorithm to populate the towers can be seen below.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const DiscreteGaussianGeneratorImpl<IntType,VecType> & dgg, const shared_ptr<ParmType> dcrtParams, Format format)
	{
		m_modulus = dcrtParams->GetModulus();
		m_cyclotomicOrder= dcrtParams->GetCyclotomicOrder();
		m_format = format;
		m_params = dcrtParams;

		size_t vecSize = dcrtParams->GetParams().size();
		m_vectors.reserve(vecSize);

		//dgg generating random values
		
		std::shared_ptr<sint> dggValues = dgg.GenerateIntVector(dcrtParams->GetCyclotomicOrder()/2);

		IntType temp;

		for(usint i = 0; i < vecSize; i++){
			
			native64::BigBinaryVector ilDggValues(dcrtParams->GetCyclotomicOrder()/2, dcrtParams->GetParams()[i]->GetModulus());

			ILVectorType ilvector(dcrtParams->GetParams()[i]);


			for(usint j = 0; j < dcrtParams->GetCyclotomicOrder()/2; j++){
				// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
				int k = (dggValues.get())[j];
				if(k < 0){
					k *= (-1);
					temp = k;
					temp = IntType(dcrtParams->GetParams()[i]->GetModulus().ConvertToInt()) - temp;
				}
				//if greater than or equal to zero, set it the value generated
				else{				
					temp = k;
				}
				ilDggValues.SetValAtIndex(j,temp.ConvertToInt());
			}

			ilvector.SetValues(ilDggValues, Format::COEFFICIENT); // the random values are set in coefficient format
			if(m_format == Format::EVALUATION){  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
				ilvector.SwitchFormat();
			}
			m_vectors.push_back(ilvector);
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(DiscreteUniformGeneratorImpl<IntType,VecType> &dug, const shared_ptr<ParmType> dcrtParams, Format format) {

		m_modulus = dcrtParams->GetModulus();
		m_cyclotomicOrder = dcrtParams->GetCyclotomicOrder();
		m_format = format;
		m_params = dcrtParams;

		dug.SetModulus(dcrtParams->GetModulus());

		// create a dummy parm to use in the ILVector2n world
		shared_ptr<ILParams> parm( new ILParams(dcrtParams->GetCyclotomicOrder(), dcrtParams->GetModulus(), BigBinaryInteger::ONE) );

		// create an Element to pull from
		ILVector2n element( parm );
		element.SetValues( dug.GenerateVector(m_cyclotomicOrder / 2), m_format );

		fillVectorArrayFromBigVector(element, m_params);
//		size_t numberOfTowers = dcrtParams->GetParams().size();
//		m_vectors.reserve(numberOfTowers);
//
//		IntType temp;
//
//		for (usint i = 0; i < numberOfTowers; i++) {
//
//
//			ILVectorType ilvector(dcrtParams->GetParams()[i]);
//
//			//BigBinaryVector ilDggValues(params.GetCyclotomicOrder() / 2, modulus);
//			vals.SwitchModulus(dcrtParams->GetParams()[i]->GetModulus());
//
//			ilvector.SetValues(vals , Format::COEFFICIENT); // the random values are set in coefficient format
//			if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
//				ilvector.SwitchFormat();
//			}
//			m_vectors.push_back(ilvector);
//
//		}

	}

	/*Move constructor*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const ILVectorArrayImpl &&element){
		m_format = element.m_format;
		m_modulus = std::move(element.m_modulus);
		m_cyclotomicOrder = element.m_cyclotomicOrder;
		m_vectors = std::move(element.m_vectors);
		m_params = std::move(element.m_params);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::CloneParametersOnly() const{
		
		ILVectorArrayImpl res(this->m_params, this->m_format);
		return std::move(res);
//		std::vector<ILVectorType> result;
//		result.reserve(m_vectors.size());
//
//		for(usint i=0;i<m_vectors.size();i++){
//			result.push_back(std::move(m_vectors.at(i).CloneParametersOnly()));
//		}
//
//		ILVectorArrayImpl res(result);
//
//		return std::move(res);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format) const {

		ILVectorArrayImpl res = CloneParametersOnly();

		ILVector2n randomElement = ILVector2n::GetPrecomputedVector();
		VecType randVec = VecType(randomElement.GetValues());
		
		// create an Element to pull from
		// create a dummy parm to use in the ILVector2n world
		shared_ptr<ILParams> parm( new ILParams(m_params->GetCyclotomicOrder(), m_params->GetModulus(), BigBinaryInteger::ONE) );
		ILVector2n element( parm );
		element.SetValues( randVec, m_format );

		res.fillVectorArrayFromBigVector(element, m_params);

		return std::move(res);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const usint ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetCyclotomicOrder() const {
		return m_cyclotomicOrder;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ModType &ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetModulus() const {
		return m_modulus;
	}

	// DESTRUCTORS

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::~ILVectorArrayImpl() {}

	// GET ACCESSORS
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const typename ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorType& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetElementAtIndex (usint i) const
	{
		if(m_vectors.empty())
			throw std::logic_error("ILVectorArrayImpl's towers are not initialized.");
		if(i > m_vectors.size()-1)
			throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
		return m_vectors[i];
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	usint ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetNumOfElements() const {
		return m_vectors.size();
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const std::vector<typename ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetAllElements() const
	{
		return m_vectors;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	Format ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::GetFormat() const
	{
		return m_format;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::BaseDecompose(usint baseBits) const {
		
		std::vector< std::vector<ILVectorType> > baseDecomposeElementWise;

		std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> result;

		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> zero(this->CloneParametersOnly());
		zero = { 0,0 };
				
		for (usint i= 0 ; i <  this->m_vectors.size(); i++) {
			baseDecomposeElementWise.push_back(std::move(this->m_vectors.at(i).BaseDecompose(baseBits)));
		}

		usint maxTowerVectorSize = baseDecomposeElementWise.back().size();

		for (usint i = 0; i < maxTowerVectorSize; i++) {
			ILVectorArrayImpl<ModType,IntType,VecType,ParmType> temp;
			for (usint j = 0; j < this->m_vectors.size(); j++) {
				if (i<baseDecomposeElementWise.at(j).size())
					temp.m_vectors.insert(temp.m_vectors.begin()+j,baseDecomposeElementWise.at(j).at(i));
				else
					temp.m_vectors.insert(temp.m_vectors.begin() + j, zero.m_vectors.at(j));
			}
			result.push_back(std::move(temp));
		}

		return std::move(result);

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::PowersOfBase(usint baseBits) const {

		std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> result;

		std::vector< std::vector<ILVectorType> > towerVals;

		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> zero(this->CloneParametersOnly());
		zero = {0,0};
		

		for (usint i = 0; i < this->m_vectors.size(); i++) {
			towerVals.insert(towerVals.begin()+i,std::move(this->m_vectors[i].PowersOfBase(baseBits)) );
		}

		usint maxTowerVectorSize = towerVals.back().size();

		for (usint i = 0; i < maxTowerVectorSize; i++) {
			ILVectorArrayImpl<ModType,IntType,VecType,ParmType> temp;
			for (usint j = 0; j < this->m_vectors.size(); j++) {
				if(i<towerVals.at(j).size())
					temp.m_vectors.insert(temp.m_vectors.begin()+j,towerVals.at(j).at(i));
				else
					temp.m_vectors.insert(temp.m_vectors.begin() + j, zero.m_vectors.at(j));
			}
			result.push_back(std::move(temp));
		}

		return std::move(result);
	}

	/*VECTOR OPERATIONS*/

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::MultiplicativeInverse() const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ModByTwo() const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].ModByTwo();
		}
		return std::move(tmp);
	}

//	template<typename ModType, typename IntType, typename VecType, typename ParmType>
//	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::SignedMod(const IntType & modulus) const
//	{
//		ILVectorArrayImpl tmp(*this);
//
//		for (usint i = 0; i < m_vectors.size(); i++) {
//			tmp.m_vectors[i] = m_vectors[i].SignedMod(modulus);
//		}
//		return std::move(tmp);
//	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Plus(const ILVectorArrayImpl &element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element.GetElementAtIndex (i);
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Negate() const {
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(this->CloneParametersOnly());
		tmp.m_vectors.clear();

		for (usint i = 0; i < this->m_vectors.size(); i++) {
			tmp.m_vectors.push_back(std::move(this->m_vectors.at(i).Negate()));
		}

		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Minus(const ILVectorArrayImpl &element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.GetElementAtIndex (i);
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator+=(const ILVectorArrayImpl &rhs)
	{
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			this->m_vectors.at(i) += rhs.GetElementAtIndex(i);
		}
		return *this;

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator-=(const ILVectorArrayImpl &rhs) {
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			this->m_vectors.at(i) -= rhs.GetElementAtIndex(i);
		}
		return *this;

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator*=(const ILVectorArrayImpl &element) {
		for (usint i = 0; i < this->m_vectors.size(); i++) {
			this->m_vectors.at(i) *= element.m_vectors.at(i);
		}

		return *this;

	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator==(const ILVectorArrayImpl &rhs) const {
		//check if the format's are the same
		if (m_format != rhs.m_format) {
                return false;
          }

		if (m_modulus != rhs.m_modulus) {
                return false;
          }
	
		if (m_cyclotomicOrder != rhs.m_cyclotomicOrder) {
                return false;
          }

		if (m_vectors.size() != rhs.m_vectors.size()) {
                return false;
          }

		//check if the towers are the same
		else return (m_vectors == rhs.GetAllElements());
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType> & ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator=(const ILVectorArrayImpl & rhs)
	{
		if (this != &rhs) {
			m_vectors = rhs.m_vectors;			
			m_format = rhs.m_format;	
			m_modulus = rhs.m_modulus;
			m_cyclotomicOrder = rhs.m_cyclotomicOrder;
			m_params = rhs.m_params;
		}
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType> & ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator=(ILVectorArrayImpl&& rhs)
	{
		if (this != &rhs) {
			m_vectors = std::move(rhs.m_vectors);
			m_format = std::move(rhs.m_format);
			m_modulus = std::move(rhs.m_modulus);
			m_cyclotomicOrder = std::move(rhs.m_cyclotomicOrder);
			m_params = std::move(rhs.m_params);
		}
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator=(std::initializer_list<sint> rhs){
		usint len = rhs.size();
		if(!IsEmpty()){
			usint vectorLength = this->m_vectors[0].GetLength();
			for(usint i = 0;i < m_vectors.size(); ++i){ // this loops over each tower
				for(usint j = 0; j < vectorLength; ++j) { // loops within a tower
					if(j<len) {
						this->m_vectors[i].SetValAtIndex(j, *(rhs.begin()+j));
					} else {
						this->m_vectors[i].SetValAtIndex(j,0);
					}
				}
			}
		}
		else{
			for(usint i=0;i<m_vectors.size();i++){
				native64::BigBinaryVector temp(m_cyclotomicOrder/2);
				temp.SetModulus(m_vectors.at(i).GetModulus());
				temp = rhs;
				m_vectors.at(i).SetValues(std::move(temp),m_format);
			}

		}
		return *this;
	}

	/*SCALAR OPERATIONS*/

	// FIXME which Int do we add to an ILVectorArray2n?
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Plus(const IntType &element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element.ConvertToInt(); // (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Minus(const IntType &element) const {
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.ConvertToInt(); //(element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Times(const ILVectorArrayImpl & element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			//ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
			tmp.m_vectors[i].SetValues(((m_vectors[i].GetValues()).ModMul(element.m_vectors[i].GetValues())), m_format);
			
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Times(const IntType &element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = tmp.m_vectors[i] * element.ConvertToInt(); // (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::MultiplyAndRound(const IntType &p, const IntType &q) const
	{
		std::string errMsg = "Operation not implemented yet";
		throw std::runtime_error(errMsg);
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::DivideAndRound(const IntType &q) const
	{
		std::string errMsg = "Operation not implemented yet";
		throw std::runtime_error(errMsg);
		return *this;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const ILVectorArrayImpl<ModType,IntType,VecType,ParmType>& ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::operator*=(const IntType &element) {
		for (usint i = 0; i < this->m_vectors.size(); i++) {
			this->m_vectors.at(i) *= element.ConvertToInt(); //this->m_vectors.at(i) * (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
		}

		return *this;
	}

	/*OTHER FUNCTIONS*/
	
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::PrintValues() const{
		std::cout<<"---START PRINT DOUBLE CRT-- WITH SIZE" <<m_vectors.size() << std::endl;
		 for(usint i = 0; i < m_vectors.size();i++){
			std::cout<<"VECTOR " << i << std::endl;
			m_vectors[i].PrintValues();
		 }
		 std::cout<<"---END PRINT DOUBLE CRT--" << std::endl;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::AddILElementOne() {
		if(m_format != Format::EVALUATION)
			throw std::runtime_error("ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::AddILElementOne cannot be called on a ILVectorArrayImpl in COEFFICIENT format.");
		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].AddILElementOne();
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::MakeSparse(const uint32_t &wFactor){
		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].MakeSparse(wFactor);
		}
	}

	// This function modifies ILVectorArrayImpl to keep all the even indices in the tower. It reduces the ring dimension of the tower by half.
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Decompose() {
		
		if(m_format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArrayImpl not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		for(int i=0; i < m_vectors.size(); i++) {
			m_vectors[i].Decompose();
		}
		m_cyclotomicOrder = m_cyclotomicOrder / 2;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::IsEmpty() const{
		for(usint i=0;i<m_vectors.size();i++){
			if(!m_vectors.at(i).IsEmpty())
				return false;
		}
		return true;
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::DropLastElement(){
		if(m_vectors.size() == 0){
			throw std::out_of_range("Last element being removed from empty list");
		}
		m_modulus = m_modulus / ModType(m_vectors[m_vectors.size()-1].GetModulus().ConvertToInt());
		m_vectors.resize(m_vectors.size() - 1);
	}

	/**
	* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
	* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
	* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
	* 
	* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
	* ModReduce is written for ILVectorArrayImpl and it drops the last tower while updating the necessary parameters.
	* The steps taken here are as follows:
	* 1. compute a short d in R such that d = c mod q
	* 2. compute a short delta in R such that delta = (vq′−1)·d mod (pq′). E.g., all of delta’s integer coefficients can be in the range [−pq′/2, pq′/2).
	* 3. let d′ = c + delta mod q. By construction, d′ is divisible by q′.
	* 4. output (d′/q′) in R(q/q′).
	*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ModReduce(const IntType &plaintextModulus) {
	  bool dbg_flag = false;
		if(m_format != Format::EVALUATION) {
			throw std::logic_error("Mod Reduce function expects EVAL Formatted ILVectorArrayImpl. It was passed COEFF Formatted ILVectorArrayImpl.");
		}
		this->SwitchFormat();
		
		usint lastTowerIndex = m_vectors.size() - 1;

		ILVectorType towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
		ILVectorType d(towerT);

		//precomputations
		IntType qt(m_vectors[lastTowerIndex].GetModulus().ConvertToInt());
		DEBUG("qt: "<< qt.ToString());
		DEBUG("plaintextModulus: "<< plaintextModulus.ToString());
		IntType v(qt.ModInverse(plaintextModulus));
		DEBUG("v: "<< v.ToString());
		IntType a((v * qt).ModSub(IntType::ONE, plaintextModulus*qt));
		//std::cout<<"a:	"<<a<<std::endl;

		//Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
		d.SwitchModulus( (plaintextModulus*qt).ConvertToInt(), d.GetRootOfUnity().ConvertToInt());
			// FIXME NOT CHANGING ROOT OF UNITY-TODO: What to do with SwitchModulus and is it necessary to pass rootOfUnity
		//d.PrintValues();

		//Calculating delta, step 2
		ILVectorType delta(d.Times(a.ConvertToInt()));
		//delta.PrintValues();

		//Calculating d' = c + delta mod q (step 3)
		for(usint i=0; i<m_vectors.size(); i++) {
			ILVectorType temp(delta);
			temp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity());
			m_vectors[i] += temp;
		}

		//step 4
		DropLastElement();
		std::vector<IntType> qtInverseModQi(m_vectors.size());
		for(usint i=0; i<m_vectors.size(); i++) {
			IntType mod = IntType(m_vectors[i].GetModulus().ConvertToInt());
			qtInverseModQi[i] = qt.ModInverse(mod);
			m_vectors[i] = qtInverseModQi[i].ConvertToInt() * m_vectors[i];
		}
		
		SwitchFormat();
	}

	/*
	 * This method applies the Chinese Remainder Interpolation on an ILVectoArray2n and produces an ILVector2n
	* How the Algorithm works:
	* Consider the ILVectorArrayImpl as a 2-dimensional matrix M, with dimension ringDimension * Number of Towers.
	* For brevity , lets say this is r * t
	* Let qt denote the bigModulus (all the towers' moduli multiplied together) and qi denote the modulus of a particular tower. 
	* Let V be a BigBinaryVector of size tower (tower size). Each coefficient of V is calculated as follows:
	* for every r
	*   calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod qt
	*
	* Once we have the V values, we construct an ILVector2n from V, use qt as it's modulus, and calculate a root of unity
	* for parameter selection of the ILVector2n.
	*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVector2n ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::CRTInterpolate() const
	{
	  bool dbg_flag = true;

		usint ringDimension = m_cyclotomicOrder / 2;
		usint nTowers = m_vectors.size();

		DEBUG("in InterpolateIlArrayVector2n ring " << ringDimension << " towers " << nTowers);

		for( usint vi = 0; vi < nTowers; vi++ )
			DEBUG("tower " << vi << " is " << m_vectors[vi]);

		BigBinaryInteger bigModulus(m_modulus); // qT

		DEBUG("bigModulus " << bigModulus);

		// this is the resulting vector of coefficients
		BigBinaryVector coefficients(ringDimension, m_modulus);

		// this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt
		
		// first, precompute qt/qj factors
		vector<BigBinaryInteger> multiplier(nTowers);
		for( usint vi = 0 ; vi < nTowers; vi++ ) {
			BigBinaryInteger qj(m_vectors[vi].GetModulus().ConvertToInt());
			BigBinaryInteger divBy = bigModulus / qj;
			//BigBinaryInteger modInv = (divBy % qj).ModInverse(qj);
			BigBinaryInteger modInv = divBy.ModInverse(qj).Mod(qj);
			multiplier[vi] = divBy * modInv;

			DEBUG("multiplier " << vi << " " << qj << " " << multiplier[vi]);
		}

		// now, compute the values for the vector
		for( usint ri = 0; ri < ringDimension; ri++ ) {
			DEBUG( ri );
			coefficients[ri] = BigBinaryInteger::ZERO;
			for( usint vi = 0; vi < nTowers; vi++ ) {
				coefficients[ri] += (BigBinaryInteger(m_vectors[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
				DEBUG( coefficients[ri] << ":::" << BigBinaryInteger(m_vectors[vi].GetValues()[ri].ConvertToInt()) << ":::" << multiplier[vi] );
			}
			DEBUG( coefficients[ri] << ":::" << bigModulus );
			coefficients[ri] = coefficients[ri] % bigModulus;
			DEBUG( coefficients[ri] );
		}

		DEBUG("passed loops");
		DEBUG(coefficients);

		// Create an ILVector2n for this BigBinaryVector

		DEBUG("elementing after vectoring");
		DEBUG("m_cyclotomicOrder " << m_cyclotomicOrder);
		DEBUG("modulus "<< bigModulus);

		// Setting the root of unity to ONE as the calculation is expensive and not required.
		ILVector2n polynomialReconstructed( shared_ptr<ILParams>( new ILParams(m_cyclotomicOrder, bigModulus, BigBinaryInteger::ONE) ) );
		polynomialReconstructed.SetValues(coefficients,m_format);

		DEBUG("Z");

		return std::move( polynomialReconstructed );
	}

	/*Switch format calls IlVector2n's switchformat*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::SwitchFormat() {
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

#ifdef OUT
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::SwitchModulus(const IntType &modulus, const IntType &rootOfUnity) {
		m_modulus = ModType::ONE;
		for (usint i = 0; i < m_vectors.size(); ++i)
		{
			auto mod = modulus % ModType((*m_params)[i]->GetModulus().ConvertToInt());
			auto root = rootOfUnity % ModType((*m_params)[i]->GetModulus().ConvertToInt());
			m_vectors[i].SwitchModulus(mod.ConvertToInt(), root.ConvertToInt());
			m_modulus = m_modulus * mod;
		}
	}
#endif

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::SwitchModulusAtIndex(usint index, const IntType &modulus, const IntType &rootOfUnity) {
		if(index > m_vectors.size()-1) {
			std::string errMsg;
			errMsg = "ILVectorArrayImpl is of size = " + std::to_string(m_vectors.size()) + " but SwitchModulus for tower at index " + std::to_string(index) + "is called.";
			throw std::runtime_error(errMsg);
		}
		auto mod = modulus % ModType((*m_params)[index]->GetModulus().ConvertToInt());
		auto root = rootOfUnity % ModType((*m_params)[index]->GetModulus().ConvertToInt());

		m_modulus = m_modulus / ModType(m_vectors[index].GetModulus().ConvertToInt());
		m_modulus = m_modulus * ModType(modulus.ConvertToInt());
		m_vectors[index].SwitchModulus(mod.ConvertToInt(), root.ConvertToInt());
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::InverseExists() const
	{
		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}
		return true;
	}

	// JSON FACILITY - Serialize Operation
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
		obj.AddMember("Format", std::to_string(this->GetFormat()), serObj->GetAllocator());
		obj.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
		obj.AddMember("CyclotomicOrder", std::to_string(this->GetCyclotomicOrder()), serObj->GetAllocator());

		SerializeVector<ILVectorType>("Vectors", "ILVector2n", this->GetAllElements(), &obj);

		serObj->AddMember("ILVectorArrayImpl", obj, serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Deserialize(const Serialized& serObj) {
		SerialItem::ConstMemberIterator it = serObj.FindMember("ILVectorArrayImpl");

		if( it == serObj.MemberEnd() )
			return false;

		SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

		mIt = it->value.FindMember("Modulus");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_modulus = ModType( mIt->value.GetString() );

		mIt = it->value.FindMember("CyclotomicOrder");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_cyclotomicOrder = std::stoi(mIt->value.GetString());

		mIt = it->value.FindMember("Vectors");

		if( mIt == it->value.MemberEnd() ) {
			return false;
		}


		bool ret = DeserializeVector<ILVectorType>("Vectors", "ILVector2n", mIt, &this->m_vectors);

		return ret;
	}

} // namespace lbcrypto ends


