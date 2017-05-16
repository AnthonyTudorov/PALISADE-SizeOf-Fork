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

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	const std::string ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ElementName = "ILVectorArrayImpl";

	/*CONSTRUCTORS*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl() {
		m_format = EVALUATION;
		m_params.reset( new ParmType(0,1) );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const shared_ptr<ParmType> dcrtParams, Format format, bool initializeElementToZero)
	{
		m_format = format;
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
		m_params = element.m_params;
	}
	
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::fillVectorArrayFromBigVector(const ILVector2n &element, const shared_ptr<ParmType> params) {

		if( element.GetModulus() > params->GetModulus() ) {
			throw std::logic_error("Modulus of element passed to constructor is bigger that DCRT big modulus");
		}

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
			  
#if MATHBACKEND ==6
			  IntType tmp = element.GetValAtIndex(p) % bigmods[v];
			  m_vectors[v].SetValAtIndex(p, tmp.ConvertToInt());
#else
			  m_vectors[v].SetValAtIndex(p, ILVectorType::Integer((element.GetValAtIndex(p) % bigmods[v]).ConvertToInt()));
#endif
			}
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
		m_params = params;

		fillVectorArrayFromBigVector(element, params);

	}

	/* Construct using an tower of ILVectro2ns. The params and format for the ILVectorArrayImpl will be derived from the towers.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const std::vector<ILVectorType> &towers)
	{
		usint cyclotomicOrder = towers.at(0).GetCyclotomicOrder();
		std::vector<std::shared_ptr<native64::ILParams>> parms;
		for (usint i = 0; i < towers.size(); i++) {
			if ( towers[i].GetCyclotomicOrder() != cyclotomicOrder ) {
				throw std::logic_error(std::string("ILVectors provided to ILVectorArrayImpl must have the same ring dimension"));
			}
			parms.push_back( towers[i].GetParams() );
		}

		shared_ptr<ParmType> p( new ParmType(cyclotomicOrder, parms) );

		m_params = p;
		m_vectors = towers;
		m_format = m_vectors[0].GetFormat();
	}

	/*The dgg will be the seed to populate the towers of the ILVectorArrayImpl with random numbers. The algorithm to populate the towers can be seen below.*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const DggType& dgg, const shared_ptr<ParmType> dcrtParams, Format format)
	{
		m_format = format;
		m_params = dcrtParams;

		size_t vecSize = dcrtParams->GetParams().size();
		m_vectors.reserve(vecSize);

		//dgg generating random values
		std::shared_ptr<sint> dggValues = dgg.GenerateIntVector(dcrtParams->GetRingDimension());

		for(usint i = 0; i < vecSize; i++){
			
			native64::BigBinaryVector ilDggValues(dcrtParams->GetRingDimension(), dcrtParams->GetParams()[i]->GetModulus());

			for(usint j = 0; j < dcrtParams->GetRingDimension(); j++){
				uint64_t	entry;
				// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
				int64_t k = (dggValues.get())[j];
				if(k < 0){
					k *= (-1);
					entry = (uint64_t)dcrtParams->GetParams()[i]->GetModulus().ConvertToInt() - (uint64_t)k;
				}
				//if greater than or equal to zero, set it the value generated
				else {
					entry = k;
				}
				ilDggValues.SetValAtIndex(j,entry);
			}

			ILVectorType ilvector(dcrtParams->GetParams()[i]);
			ilvector.SetValues(ilDggValues, Format::COEFFICIENT); // the random values are set in coefficient format
			if(m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
				ilvector.SwitchFormat();
			}
			m_vectors.push_back(ilvector);
		}
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(DugType& dug, const shared_ptr<ParmType> dcrtParams, Format format) {

		m_format = format;
		m_params = dcrtParams;

		size_t numberOfTowers = dcrtParams->GetParams().size();
		m_vectors.reserve(numberOfTowers);

		for (usint i = 0; i < numberOfTowers; i++) {

			dug.SetModulus(dcrtParams->GetParams()[i]->GetModulus());
			native64::BigBinaryVector vals(dug.GenerateVector(dcrtParams->GetRingDimension()));
			ILVectorType ilvector(dcrtParams->GetParams()[i]);

			ilvector.SetValues(vals, Format::COEFFICIENT); // the random values are set in coefficient format
			if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
				ilvector.SwitchFormat();
			}
			m_vectors.push_back(ilvector);
		}
	}

	/*Move constructor*/
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::ILVectorArrayImpl(const ILVectorArrayImpl &&element){
		m_format = element.m_format;
		m_vectors = std::move(element.m_vectors);
		m_params = std::move(element.m_params);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::CloneParametersOnly() const{
		
		ILVectorArrayImpl res(this->m_params, this->m_format);
		return std::move(res);
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
	std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const {

		ILVector2n v( CRTInterpolate() );

		std::vector<ILVector2n> bdV = v.BaseDecompose(baseBits, false);

		std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> result;

		// populate the result by converting each of the big vectors into a VectorArray
		for( usint i=0; i<bdV.size(); i++ ) {
			ILVectorArrayImpl<ModType,IntType,VecType,ParmType> dv(bdV[i], this->GetParams());
			if( evalModeAnswer )
				dv.SwitchFormat();
			result.push_back( std::move(dv) );
		}

		return std::move(result);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::PowersOfBase(usint baseBits) const {

		std::vector<ILVectorArrayImpl<ModType,IntType,VecType,ParmType>> result;

		usint nBits = m_params->GetModulus().GetLengthForBase(2);

		usint nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;

		result.reserve(nWindows);
		
		// prepare for the calculations by gathering a big integer version of each of the little moduli
		std::vector<IntType> mods(m_params->GetParams().size());
		for( usint i = 0; i < m_params->GetParams().size(); i++ )
			mods[i] = IntType(m_params->GetParams()[i]->GetModulus().ConvertToInt());

		for( usint i = 0; i < nWindows; i++ ) {
			ILVectorArrayType x( m_params, m_format );

			IntType twoPow( IntType::TWO.Exp( i*baseBits ) );
			for( usint t = 0; t < m_params->GetParams().size(); t++ ) {
				IntType pI (twoPow % mods[t]);
				x.m_vectors[t] = m_vectors[t] * pI.ConvertToInt();
			}
			result.push_back( x );
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
		if( m_vectors.size() != element.m_vectors.size() ) {
			throw std::logic_error("tower size mismatch; cannot add");
		}
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
		if( m_vectors.size() != element.m_vectors.size() ) {
			throw std::logic_error("tower size mismatch; cannot subtract");
		}
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

		if( GetCyclotomicOrder() != rhs.GetCyclotomicOrder() )
			return false;

		if( GetModulus() != rhs.GetModulus() )
			return false;

		if (m_format != rhs.m_format) {
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
						this->m_vectors[i].SetValAtIndex(j,ILVectorType::Integer::ZERO);
					}
				}
			}
		}
		else{
			for(usint i=0;i<m_vectors.size();i++){
				native64::BigBinaryVector temp(m_params->GetRingDimension());
				temp.SetModulus(m_vectors.at(i).GetModulus());
				temp = rhs;
				m_vectors.at(i).SetValues(std::move(temp),m_format);
			}

		}
		return *this;
	}

	/*SCALAR OPERATIONS*/

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Plus(const IntType &element) const
	{
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element.ConvertToInt();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Minus(const IntType &element) const {
		ILVectorArrayImpl<ModType,IntType,VecType,ParmType> tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.ConvertToInt();
		}
		return std::move(tmp);
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	ILVectorArrayImpl<ModType,IntType,VecType,ParmType> ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Times(const ILVectorArrayImpl & element) const
	{
		if( m_vectors.size() != element.m_vectors.size() ) {
			throw std::logic_error("tower size mismatch; cannot multiply");
		}
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

	// This function modifies ILVectorArrayImpl to keep all the even indices in the tower.
	// It reduces the ring dimension of the tower by half.
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	void ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Decompose() {
		
		if(m_format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArrayImpl not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		for( size_t i = 0; i < m_vectors.size(); i++) {
			m_vectors[i].Decompose();
		}

		// the individual vectors parms have changed, so change the DCRT parms
		std::vector<std::shared_ptr<native64::ILParams>> vparms(m_vectors.size());
		for( size_t i = 0; i < m_vectors.size(); i++)
			vparms[i] = m_vectors[i].GetParams();
		m_params.reset( new ParmType(vparms[0]->GetCyclotomicOrder(), vparms) );
	}

	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::IsEmpty() const{
		for(size_t i=0;i<m_vectors.size();i++){
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

		m_vectors.resize(m_vectors.size() - 1);
		ParmType *newP = new ParmType( *m_params );
		newP->PopLastParam();
		m_params.reset(newP);
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

		DEBUG("ModReduce(" << plaintextModulus << ") on tower size " << m_vectors.size()<< " m=" << GetCyclotomicOrder());

		ILVectorType towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
		ILVectorType d(towerT);

		//precomputations
		typename ILVectorType::Integer ptm(plaintextModulus.ConvertToInt());
		typename ILVectorType::Integer qt(m_vectors[lastTowerIndex].GetModulus());
		DEBUG("qt: "<< qt);
		DEBUG("plaintextModulus: "<< ptm);
		typename ILVectorType::Integer v(qt.ModInverse(ptm));
		DEBUG("v: "<< v);
		typename ILVectorType::Integer a((v * qt).ModSub(ILVectorType::Integer::ONE, ptm*qt));
		DEBUG("a:	"<<a);

		// Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
		d.SwitchModulus( ptm*qt, d.GetRootOfUnity() );
			// FIXME NOT CHANGING ROOT OF UNITY-TODO: What to do with SwitchModulus and is it necessary to pass rootOfUnity

		// Calculating delta, step 2
		ILVectorType delta(d.Times(a));

		// Calculating d' = c + delta mod q (step 3)
		// no point in going to size() since the last tower's being dropped
		for(usint i=0; i<m_vectors.size(); i++) {
			ILVectorType temp(delta);
			temp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity());
			m_vectors[i] += temp;
		}

		//step 4
		DropLastElement();

		std::vector<ILVectorType::Integer> qtInverseModQi(m_vectors.size());
		for(usint i=0; i<m_vectors.size(); i++) {
			const ILVectorType::Integer& mod = m_vectors[i].GetModulus();
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
	  bool dbg_flag = false;

		usint ringDimension = GetRingDimension();
		usint nTowers = m_vectors.size();

		DEBUG("in InterpolateIlArrayVector2n ring " << ringDimension << " towers " << nTowers);

		for( usint vi = 0; vi < nTowers; vi++ )
			DEBUG("tower " << vi << " is " << m_vectors[vi]);

		BigBinaryInteger bigModulus(GetModulus()); // qT

		DEBUG("bigModulus " << bigModulus);

		// this is the resulting vector of coefficients
		BigBinaryVector coefficients(ringDimension, bigModulus);

		// this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt
		
		// first, precompute qt/qj factors
		vector<BigBinaryInteger> multiplier(nTowers);
		for( usint vi = 0 ; vi < nTowers; vi++ ) {
			BigBinaryInteger qj(m_vectors[vi].GetModulus().ConvertToInt());
			BigBinaryInteger divBy = bigModulus / qj;
			BigBinaryInteger modInv = divBy.ModInverse(qj).Mod(qj);
			multiplier[vi] = divBy * modInv;

			DEBUG("multiplier " << vi << " " << qj << " " << multiplier[vi]);
		}

		// if the vectors are not in COEFFICIENT form, they need to be, so we will need to make a copy
		// of them and switchformat on them... otherwise we can just use what we have
		const std::vector<ILVectorType> *vecs = &m_vectors;
		std::vector<ILVectorType> coeffVecs;
		if( m_format == EVALUATION ) {
			for( usint i=0; i<m_vectors.size(); i++ ) {
				ILVectorType vecCopy(m_vectors[i]);
				vecCopy.SetFormat(COEFFICIENT);
				coeffVecs.push_back( std::move(vecCopy) );
			}
			vecs = &coeffVecs;
		}

		for( usint vi = 0; vi < nTowers; vi++ )
			DEBUG("tower " << vi << " is " << (*vecs)[vi]);

		// now, compute the values for the vector
		for( usint ri = 0; ri < ringDimension; ri++ ) {
			coefficients[ri] = BigBinaryInteger::ZERO;
			for( usint vi = 0; vi < nTowers; vi++ ) {
				coefficients[ri] += (BigBinaryInteger((*vecs)[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
			}
			DEBUG( (*vecs)[0].GetValues()[ri] << " * " << multiplier[0] << " == " << coefficients[ri] );
			coefficients[ri] = coefficients[ri] % bigModulus;
		}

		DEBUG("passed loops");
		DEBUG(coefficients);

		// Create an ILVector2n for this BigBinaryVector

		DEBUG("elementing after vectoring");
		DEBUG("m_cyclotomicOrder " << GetCyclotomicOrder());
		DEBUG("modulus "<< bigModulus);

		// Setting the root of unity to ONE as the calculation is expensive and not required.
		ILVector2n polynomialReconstructed( shared_ptr<ILParams>( new ILParams(GetCyclotomicOrder(), bigModulus, BigBinaryInteger::ONE) ) );
		polynomialReconstructed.SetValues(coefficients,COEFFICIENT);

		DEBUG("answer: " << polynomialReconstructed);

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

		m_vectors[index].SwitchModulus(ILVectorType::Integer(modulus.ConvertToInt()), ILVectorType::Integer(rootOfUnity.ConvertToInt()));
		m_params->RecalculateModulus();
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
		if (!m_params->Serialize(&obj))
			return false;


		obj.AddMember("Format", std::to_string(this->GetFormat()), serObj->GetAllocator());

		SerializeVector<ILVectorType>("Vectors", "ILVectorImpl", this->GetAllElements(), &obj);

		serObj->AddMember("ILVectorArrayImpl", obj, serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	template<typename ModType, typename IntType, typename VecType, typename ParmType>
	bool ILVectorArrayImpl<ModType,IntType,VecType,ParmType>::Deserialize(const Serialized& serObj) {
		SerialItem::ConstMemberIterator it = serObj.FindMember("ILVectorArrayImpl");

		if( it == serObj.MemberEnd() )
			return false;

		SerialItem::ConstMemberIterator pIt = it->value.FindMember("ILDCRTParams");
		if (pIt == it->value.MemberEnd()) return false;

		Serialized parm(rapidjson::kObjectType);
		parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

		shared_ptr<ParmType> json_ilParams(new ParmType());
		if (!json_ilParams->Deserialize(parm))
			return false;
		m_params = json_ilParams;

		SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

		mIt = it->value.FindMember("Vectors");

		if( mIt == it->value.MemberEnd() ) {
			return false;
		}

		bool ret = DeserializeVector<ILVectorType>("Vectors", "ILVectorImpl", mIt, &this->m_vectors);

		return ret;
	}

} // namespace lbcrypto ends


