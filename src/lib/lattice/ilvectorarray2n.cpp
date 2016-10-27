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
#include "../utils/serializablehelper.h"

namespace lbcrypto {

	/*CONSTRUCTORS*/

	ILVectorArray2n::ILVectorArray2n() : m_format(EVALUATION), m_cyclotomicOrder(0), m_modulus(1){
	}

	ILVectorArray2n::ILVectorArray2n(const shared_ptr<ElemParams> params, Format format, bool initializeElementToZero)
	{
		const shared_ptr<ILDCRTParams> dcrtParams = std::dynamic_pointer_cast<ILDCRTParams>(params);

		if( dcrtParams == 0 )
			throw std::logic_error("ILVectorArray2n must be constructed with an ILDCRTParams");

		m_cyclotomicOrder = params->GetCyclotomicOrder();
		m_format = format;
		m_modulus = params->GetModulus();

		size_t vecSize = dcrtParams->GetModuli().size();
		m_vectors.reserve(vecSize);
		
		for (usint i = 0; i < vecSize; i++) {
			BigBinaryInteger modulus(dcrtParams->GetModuli()[i]);
			BigBinaryInteger rootOfUnity(dcrtParams->GetRootsOfUnity()[i]);
			shared_ptr<ILParams> ip( new ILParams(m_cyclotomicOrder, modulus, rootOfUnity) );
			m_vectors.push_back(std::move(ILVector2n(ip,format,initializeElementToZero)));
		}
	}

	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &element)  {
		m_format = element.m_format;
		m_vectors = element.m_vectors;
		m_modulus = element.m_modulus;
		m_cyclotomicOrder = element.m_cyclotomicOrder;
	}
	
	/* Construct using a single ILVector2n. The format is derived from the passed in ILVector2n.*/
	ILVectorArray2n::ILVectorArray2n(const ILVector2n &element, const shared_ptr<ILDCRTParams> params)
	{
		Format format;
		try{
			format = element.GetFormat();
		}
		catch (const std::exception& e) {
			throw std::logic_error("There is an issue with the format of ILVectors passed to the constructor of ILVectorArray2n");
		}

		m_format = format;
		m_modulus = params->GetModulus();
		m_cyclotomicOrder = params->GetCyclotomicOrder();

		size_t vecSize = params->GetModuli().size();
		m_vectors.reserve(vecSize);

		ILVector2n ilvector2n(element);

		for (usint i = 0; i < vecSize; i++) {
			ILVector2n ilvector2nSwitchModulus(ilvector2n);
			ilvector2nSwitchModulus.SwitchModulus(params->GetModuli()[i], params->GetRootsOfUnity()[i]);
			m_vectors.push_back(std::move(ilvector2nSwitchModulus));
		}
	}

	/* Construct using an tower of ILVectro2ns. The params and format for the ILVectorArray2n will be derived from the towers.*/
	ILVectorArray2n::ILVectorArray2n(const std::vector<ILVector2n> &towers)
	{
		usint ringDimension = towers.at(0).GetCyclotomicOrder() / 2;
		for (usint i = 1; i < towers.size(); i++) {
			if (!(towers.at(i).GetCyclotomicOrder() / 2 == ringDimension)) {
				throw std::logic_error(std::string("ILVectors provided to ILVectorArray2n must have the same parameters"));
			}
		}

		m_vectors = towers; // once all the params are correct, set ILVectorArray2n's towers to the passed value
		m_format = m_vectors[0].GetFormat();
		m_cyclotomicOrder = m_vectors[0].GetCyclotomicOrder();
		m_modulus = 1;

		for (usint i = 0; i<towers.size(); i++)
			m_modulus = m_modulus*m_vectors.at(i).GetModulus();
	}

	/*The dgg will be the seed to populate the towers of the ILVectorArray2n with random numbers. The algorithm to populate the towers can be seen below.*/
	ILVectorArray2n::ILVectorArray2n(const DiscreteGaussianGenerator & dgg, const shared_ptr<ElemParams> params, Format format)
	{
		const shared_ptr<ILDCRTParams> dcrtParams = std::dynamic_pointer_cast<ILDCRTParams>(params);

		if( dcrtParams == 0 )
			throw std::logic_error("ILVectorArray2n must be constructed with an ILDCRTParams");

		m_modulus = dcrtParams->GetModulus();
		m_cyclotomicOrder= dcrtParams->GetCyclotomicOrder();
		m_format = format;

		size_t vecSize = dcrtParams->GetModuli().size();
		m_vectors.reserve(vecSize);

		//dgg generating random values
		
		sint* dggValues = dgg.GenerateIntVector(params->GetCyclotomicOrder()/2);

		BigBinaryInteger modulus;
		BigBinaryInteger rootOfUnity;
		BigBinaryInteger temp;

		for(usint i = 0; i < vecSize; i++){
			
			modulus = dcrtParams->GetModuli()[i];
			rootOfUnity = dcrtParams->GetRootsOfUnity()[i];

			shared_ptr<ILParams> ilVectorDggValuesParams( new ILParams(params->GetCyclotomicOrder(), modulus, rootOfUnity) );
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(params->GetCyclotomicOrder()/2,modulus);

			for(usint j = 0; j < params->GetCyclotomicOrder()/2; j++){
				// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
				if((int)dggValues[j] < 0){
					int k = (int)dggValues[j];
					k = k * (-1);
					temp = k;
					temp = dcrtParams->GetModuli()[i] - temp;
					ilDggValues.SetValAtIndex(j,temp);
				}
				//if greater than or equal to zero, set it the value generated
				else{				
					int k = (int)dggValues[j];
					temp = k;
					ilDggValues.SetValAtIndex(j,temp);
				}
			}

			ilvector.SetValues(ilDggValues, Format::COEFFICIENT); // the random values are set in coefficient format
			if(m_format == Format::EVALUATION){  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
				ilvector.SwitchFormat();
			}
			m_vectors.push_back(ilvector);
		}
	}

	ILVectorArray2n::ILVectorArray2n(const DiscreteUniformGenerator &dug, const shared_ptr<ElemParams> params, Format format) {

		const shared_ptr<ILDCRTParams> dcrtParams = std::dynamic_pointer_cast<ILDCRTParams>(params);
		m_modulus = dcrtParams->GetModulus();
		m_cyclotomicOrder = dcrtParams->GetCyclotomicOrder();
		m_format = format;

		size_t numberOfTowers = dcrtParams->GetModuli().size();
		m_vectors.reserve(numberOfTowers);

		//dgg generating random values
		BigBinaryVector vals(dug.GenerateVector(m_cyclotomicOrder / 2));

		BigBinaryInteger modulus;
		BigBinaryInteger rootOfUnity;
		BigBinaryInteger temp;

		for (usint i = 0; i < numberOfTowers; i++) {

			modulus = dcrtParams->GetModuli()[i];
			rootOfUnity = dcrtParams->GetRootsOfUnity()[i];

			shared_ptr<ILParams> ilParams(new ILParams(dcrtParams->GetCyclotomicOrder(), modulus, rootOfUnity));
			ILVector2n ilvector(ilParams);

			//BigBinaryVector ilDggValues(params.GetCyclotomicOrder() / 2, modulus);
			vals.SwitchModulus(modulus);
			
			ilvector.SetValues(vals , Format::COEFFICIENT); // the random values are set in coefficient format
			if (m_format == Format::EVALUATION) {  // if the input format is evaluation, then once random values are set in coefficient format, switch the format to achieve what the caller asked for.
				ilvector.SwitchFormat();
			}
			m_vectors.push_back(ilvector);

		}


	}

	/*Move constructor*/
	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &&element){
		m_format = element.m_format;
		m_modulus = std::move(element.m_modulus);
		m_cyclotomicOrder = element.m_cyclotomicOrder;
		m_vectors = std::move(element.m_vectors);
	}

	ILVectorArray2n ILVectorArray2n::CloneWithParams() const{
		
		std::vector<ILVector2n> result;
		result.reserve(m_vectors.size());
		
		for(usint i=0;i<m_vectors.size();i++){
			result.push_back(std::move(m_vectors.at(i).CloneWithParams()));
		}

		ILVectorArray2n res(result);

		return std::move(res);
	}

	ILVectorArray2n ILVectorArray2n::CloneWithNoise(const DiscreteGaussianGenerator &dgg, Format format) const{
		std::vector<ILVector2n> result;
		result.reserve(m_vectors.size());
		
		for(usint i=0;i<m_vectors.size();i++){
			result.push_back(std::move(m_vectors.at(i).CloneWithNoise(dgg, format)));
		}

		ILVectorArray2n res(result);
		return std::move(res);
	}

	usint ILVectorArray2n::GetCyclotomicOrder() const {
		return m_cyclotomicOrder;
	}

	const BigBinaryInteger &ILVectorArray2n::GetModulus() const {
		return m_modulus;
	}

	// DESTRUCTORS

	ILVectorArray2n::~ILVectorArray2n() {}

	// GET ACCESSORS
	const ILVector2n& ILVectorArray2n::GetElementAtIndex (usint i) const
	{
		if(m_vectors.empty())
			throw std::logic_error("ILVectorArray2n's towers are not initialized. Throwing error now.");
		if(i > m_vectors.size()-1)
			throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
		return m_vectors[i];
	}

	usint ILVectorArray2n::GetNumOfElements() const {
		return m_vectors.size();
	}

	const std::vector<ILVector2n>& ILVectorArray2n::GetAllElements() const
	{
		return m_vectors;
	}

	Format ILVectorArray2n::GetFormat() const
	{
		return m_format;
	}

	ILVectorArray2n ILVectorArray2n::GetDigitAtIndexForBase(usint index, usint base) const{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].GetDigitAtIndexForBase(index,base);
		}
		return tmp;
	}

	std::vector<ILVectorArray2n> ILVectorArray2n::BaseDecompose(usint baseBits) const {
		
		std::vector< std::vector<ILVector2n> > baseDecomposeElementWise;

		std::vector<ILVectorArray2n> result;

		ILVectorArray2n zero(this->CloneWithParams());
		zero = { 0,0 };
				
		for (usint i= 0 ; i <  this->m_vectors.size(); i++) {
			baseDecomposeElementWise.push_back(std::move(this->m_vectors.at(i).BaseDecompose(baseBits)));
		}

		usint maxTowerVectorSize = baseDecomposeElementWise.back().size();

		for (usint i = 0; i < maxTowerVectorSize; i++) {
			ILVectorArray2n temp;
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

	std::vector<ILVectorArray2n> ILVectorArray2n::PowersOfBase(usint baseBits) const {

		std::vector<ILVectorArray2n> result;

		std::vector< std::vector<ILVector2n> > towerVals;

		ILVectorArray2n zero(this->CloneWithParams());
		zero = {0,0};
		

		for (usint i = 0; i < this->m_vectors.size(); i++) {
			towerVals.insert(towerVals.begin()+i,std::move(this->m_vectors[i].PowersOfBase(baseBits)) );
		}

		usint maxTowerVectorSize = towerVals.back().size();

		for (usint i = 0; i < maxTowerVectorSize; i++) {
			ILVectorArray2n temp;
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

	ILVectorArray2n ILVectorArray2n::MultiplicativeInverse() const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
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

	ILVectorArray2n ILVectorArray2n::SignedMod(const BigBinaryInteger & modulus) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].SignedMod(modulus);
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Plus(const ILVectorArray2n &element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element.GetElementAtIndex (i);
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Negate() const {
		ILVectorArray2n tmp(this->CloneWithParams());
		tmp.m_vectors.clear();

		for (usint i = 0; i < this->m_vectors.size(); i++) {
			tmp.m_vectors.push_back(std::move(this->m_vectors.at(i).Negate()));
		}

		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Minus(const ILVectorArray2n &element) const {
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.GetElementAtIndex (i);
		}
		return tmp;
	}

	const ILVectorArray2n& ILVectorArray2n::operator+=(const ILVectorArray2n &rhs)
	{
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			this->m_vectors.at(i) += rhs.GetElementAtIndex(i);
		}
		return *this;

	}

	const ILVectorArray2n& ILVectorArray2n::operator-=(const ILVectorArray2n &rhs) {
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			this->m_vectors.at(i) -= rhs.GetElementAtIndex(i);
		}
		return *this;

	}

	const ILVectorArray2n& ILVectorArray2n::operator*=(const ILVectorArray2n &element) {
		for (usint i = 0; i < this->m_vectors.size(); i++) {
			this->m_vectors.at(i) *= element.m_vectors.at(i);
		}

		return *this;

	}

	bool ILVectorArray2n::operator!=(const ILVectorArray2n &rhs) const {
        return !(*this == rhs); 
    }
	
	bool ILVectorArray2n::operator==(const ILVectorArray2n &rhs) const {
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

	const ILVectorArray2n & ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
	{
		if (this != &rhs) {
			m_vectors = rhs.m_vectors;			
			m_format = rhs.m_format;	
			m_modulus = rhs.m_modulus;
			m_cyclotomicOrder = rhs.m_cyclotomicOrder;
		}
		return *this;
	}

	ILVectorArray2n& ILVectorArray2n::operator=(std::initializer_list<sint> rhs){
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
				BigBinaryVector temp(m_cyclotomicOrder/2);
				temp.SetModulus(m_vectors.at(i).GetModulus());
				temp = rhs;
				m_vectors.at(i).SetValues(std::move(temp),m_format);
			}
			
		}
		return *this;
	}

	/*SCALAR OPERATIONS*/

	ILVectorArray2n ILVectorArray2n::Plus(const BigBinaryInteger &element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element;
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Minus(const BigBinaryInteger &element) const {
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element;
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Times(const ILVectorArray2n & element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			//ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
			tmp.m_vectors[i].SetValues(((m_vectors[i].GetValues()).ModMul(element.m_vectors[i].GetValues())), m_format);
			
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Times(const BigBinaryInteger &element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = (element*tmp.m_vectors[i]);
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::MultiplyAndRound(const BigBinaryInteger &p, const BigBinaryInteger &q) const
	{
		std::string errMsg = "Operation not implemented yet";
		throw std::runtime_error(errMsg);
		return *this;
	}

	ILVectorArray2n ILVectorArray2n::DivideAndRound(const BigBinaryInteger &q) const
	{
		std::string errMsg = "Operation not implemented yet";
		throw std::runtime_error(errMsg);
		return *this;
	}

	const ILVectorArray2n& ILVectorArray2n::operator+=(const BigBinaryInteger &rhs){
         return this->Plus(rhs); //TODO-OPTIMIZE
	}
	
	const ILVectorArray2n& ILVectorArray2n::operator-=(const BigBinaryInteger &rhs){
          return this->Minus(rhs); //TODO-OPTIMIZE
	}


	const ILVectorArray2n& ILVectorArray2n::operator*=(const BigBinaryInteger &element) {
		for (usint i = 0; i < this->m_vectors.size(); i++) {
			this->m_vectors.at(i) *= element;
		}

		return *this;
	}

	/*OTHER FUNCTIONS*/
	
	void ILVectorArray2n::PrintValues() const{
		std::cout<<"---START PRINT DOUBLE CRT-- WITH SIZE" <<m_vectors.size() << std::endl;
		 for(usint i = 0; i < m_vectors.size();i++){
			std::cout<<"VECTOR " << i << std::endl;
			m_vectors[i].PrintValues();
		 }
		 std::cout<<"---END PRINT DOUBLE CRT--" << std::endl;
	}

	void ILVectorArray2n::AddILElementOne() {
		if(m_format != Format::EVALUATION)
			throw std::runtime_error("ILVectorArray2n::AddILElementOne cannot be called on a ILVectorArray2n in COEFFICIENT format.");
		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].AddILElementOne();
		}
	}

	void ILVectorArray2n::MakeSparse(const BigBinaryInteger &wFactor){
		for(usint i = 0; i < m_vectors.size(); i++){
			m_vectors[i].MakeSparse(wFactor);
		}
	}

	// This function modifies ILVectorArray2n to keep all the even indices in the tower. It reduces the ring dimension of the tower by half.
	void ILVectorArray2n::Decompose() {
		
		if(m_format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArray2n not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		for(int i=0; i < m_vectors.size(); i++) {
			m_vectors[i].Decompose();
		}
		m_cyclotomicOrder = m_cyclotomicOrder / 2;
	}

	bool ILVectorArray2n::IsEmpty() const{
		for(usint i=0;i<m_vectors.size();i++){
			if(!m_vectors.at(i).IsEmpty())
				return false;
		}
		return true;
	}

	void ILVectorArray2n::DropElementAtIndex(usint index){
		if(index >= m_vectors.size()){
			throw std::out_of_range("Index of tower being removed is larger than ILVectorArray2n tower\n");
		}
		m_modulus = m_modulus /(m_vectors[index].GetModulus());
		m_vectors.erase(m_vectors.begin() + index);
	}

	/**
	* This function performs ModReduce on ciphertext element and private key element. The algorithm can be found from this paper:
	* D.Cousins, K. Rohloff, A Scalabale Implementation of Fully Homomorphic Encyrption Built on NTRU, October 2014, Financial Cryptography and Data Security
	* http://link.springer.com/chapter/10.1007/978-3-662-44774-1_18
	* 
	* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus q/qi. The qi is generally the largest. In the code below,
	* ModReduce is written for ILVectorArray2n and it drops the last tower while updating the necessary parameters. 
	* The steps taken here are as follows:
	* 1. compute a short d in R such that d = c mod q
	* 2. compute a short delta in R such that delta = (vq′−1)·d mod (pq′). E.g., all of delta’s integer coefficients can be in the range [−pq′/2, pq′/2).
	* 3. let d′ = c + delta mod q. By construction, d′ is divisible by q′.
	* 4. output (d′/q′) in R(q/q′).
	*/
	void ILVectorArray2n::ModReduce(const BigBinaryInteger &plaintextModulus) {
	  bool dbg_flag = false;
		if(m_format != Format::EVALUATION) {
			throw std::logic_error("Mod Reduce function expects EVAL Formatted ILVectorArray2n. It was passed COEFF Formatted ILVectorArray2n.");
		}
		this->SwitchFormat();
		
		usint lastTowerIndex = m_vectors.size() - 1;

		ILVector2n towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
		ILVector2n d(towerT); 

		//precomputations
		BigBinaryInteger qt(m_vectors[lastTowerIndex].GetModulus());
		DEBUG("qt: "<< qt.ToString());
		DEBUG("plaintextModulus: "<< plaintextModulus.ToString());
		BigBinaryInteger v(qt.ModInverse(plaintextModulus));
		DEBUG("v: "<< v.ToString());
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, plaintextModulus*qt));
		//std::cout<<"a:	"<<a<<std::endl;

		//Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
		d.SwitchModulus(plaintextModulus*qt, d.GetRootOfUnity()); // NOT CHANGING ROOT OF UNITY-TODO: What to do with SwitchModulus and is it necessary to pass rootOfUnity		
		//d.PrintValues();

		//Calculating delta, step 2
		ILVector2n delta(d.Times(a)); 
		//delta.PrintValues();

		//Calculating d' = c + delta mod q (step 3)
		for(usint i=0; i<m_vectors.size(); i++) {
			ILVector2n temp(delta);
			temp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity());
			m_vectors[i] += temp;
		}

		//step 4
		DropElementAtIndex(lastTowerIndex);
		std::vector<BigBinaryInteger> qtInverseModQi(m_vectors.size());
		for(usint i=0; i<m_vectors.size(); i++) {
			qtInverseModQi[i] = qt.ModInverse(m_vectors[i].GetModulus());
			m_vectors[i] = qtInverseModQi[i] * m_vectors[i];
		}
		
		SwitchFormat();
	}

	/*This method applies the Chinese Remainder Interpolation on an ILVectoArray2n and produces an ILVector2n embedded into ILVectorArray2n. 
	* The ILVector2n is the ILVectorArray2n's represantation
	* with one single coefficient vector.
	* How the Algorithm works:
	* Consider the ILVectorArray2n as a 2-dimensional matrix, denoted as M, with dimension ringDimension * Number of Towers. For breviety , lets say this is r * t
	* Let qt denote the bigModulus (all the towers' moduli multiplied together) and qi denote the modulus of a particular tower. 
	* Let V be a BigBinaryVector of size tower (tower size). Each coefficient of V is calculated as follows:
	* for every r
	*   calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}modqt 
	*
	* Once we have the V values, we construct an ILVector2n from V, use qt as it's modulus and calculate a root of unity for parameter selection of the ILVector2n.
	*/
	ILVectorArray2n ILVectorArray2n::CRTInterpolate() const
	{
	  bool dbg_flag = false;
	  DEBUG("in InterpolateIlArrayVector2n");
		if(m_vectors.size() == 1) return *this;

		/*initializing variables for effciency*/
		usint ringDimension = m_cyclotomicOrder / 2;

		BigBinaryInteger qj; //qj

		BigBinaryInteger bigModulus(m_modulus); //qt

		BigBinaryInteger divideBigModulusByIndexModulus; //qt/qj

		BigBinaryInteger modularInverse; // (qt/qj)^(-1) mod qj

		BigBinaryInteger chineseRemainderMultiplier; // qt/qj * [(qt/qj)(-1) mod qj]

		BigBinaryInteger multiplyValue;// M (r, i) * qt/qj * [(qt/qj)(-1) mod qj]

		BigBinaryVector coefficients(ringDimension,m_modulus); // V vector

		BigBinaryInteger interpolateValue("0"); // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt 

		/*This loop calculates every coefficient of the interpolated valued.*/
		for (usint i = 0; i < ringDimension; i++) {
		/*This for loops to calculate V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod qt, the loop is basically the sigma.
		Mod qt is done outside the loop*/
			for (usint j = 0; j < m_vectors.size(); j++) {

				qj = m_vectors[j].GetModulus(); //qj

				divideBigModulusByIndexModulus = bigModulus.DividedBy(qj); //qt/qj

				modularInverse = divideBigModulusByIndexModulus.Mod(qj).ModInverse(qj); // (qt/qj)^(-1) mod qj

				chineseRemainderMultiplier = divideBigModulusByIndexModulus.Times(modularInverse); // qt/qj * [(qt/qj)(-1) mod qj]

				multiplyValue = (m_vectors[j].GetValAtIndex(i)).Times(chineseRemainderMultiplier); // M (r, i) * qt/qj * [(qt/qj)(-1) mod qj]

				interpolateValue += multiplyValue;

			}

			interpolateValue = interpolateValue.Mod(m_modulus);
			coefficients.SetValAtIndex(i, interpolateValue); // This Calculates V[j]
			interpolateValue = BigBinaryInteger::ZERO;
		}
		DEBUG("passed loops");

		/*Intializing and setting the params of the resulting ILVector2n*/
		usint m = m_cyclotomicOrder;
		BigBinaryInteger modulus;
		modulus = m_modulus;
		BigBinaryInteger rootOfUnity;
		DEBUG("X");
		DEBUG("m_cyclotomicOrder "<<m_cyclotomicOrder);
		DEBUG("modulus "<< modulus.ToString());
		ILParams ilParams(m_cyclotomicOrder, modulus, BigBinaryInteger::ONE);
		DEBUG("Y");

		ILVector2n polynomialReconstructed( shared_ptr<ILParams>( new ILParams(m_cyclotomicOrder, modulus) ) );
		polynomialReconstructed.SetValues(coefficients,m_format);
		DEBUG("Z");

		ILVectorArray2n interpolatedIL2n;
		interpolatedIL2n.m_format = this->m_format;
		interpolatedIL2n.m_cyclotomicOrder = this->m_cyclotomicOrder;
		interpolatedIL2n.m_modulus = modulus;
		interpolatedIL2n.m_vectors.push_back(polynomialReconstructed);

		return interpolatedIL2n;

	}

	/*Switch format calls IlVector2n's switchformat*/
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

	void ILVectorArray2n::SwitchModulus(const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity) {
		m_modulus = BigBinaryInteger::ONE;
		for (usint i = 0; i < m_vectors.size(); ++i)
		{
			m_vectors[i].SwitchModulus(modulus, rootOfUnity);
			m_modulus = m_modulus * modulus;
		}
	}

	void ILVectorArray2n::SwitchModulusAtIndex(usint index, const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity) {
		if(index > m_vectors.size()-1) {
			std::string errMsg;
			errMsg = "ILVectorArray2n is of size = " + std::to_string(m_vectors.size()) + " but SwitchModulus for tower at index " + std::to_string(index) + "is called.";
			throw std::runtime_error(errMsg);
		}
		m_modulus = m_modulus/(m_vectors[index].GetModulus());
		m_modulus = m_modulus * modulus;
		m_vectors[index].SwitchModulus(modulus, rootOfUnity);
	}

	bool ILVectorArray2n::InverseExists() const
	{
		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}
		return true;
	}
	//JSON FACILITY

	// JSON FACILITY - Serialize Operation
	bool ILVectorArray2n::Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
		obj.AddMember("Format", std::to_string(this->GetFormat()), serObj->GetAllocator());
		obj.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
		obj.AddMember("CyclotomicOrder", std::to_string(this->GetCyclotomicOrder()), serObj->GetAllocator());

		SerializeVector<ILVector2n>("Vectors", "ILVector2n", this->GetAllElements(), &obj);

		serObj->AddMember("ILVectorArray2n", obj, serObj->GetAllocator());

		return true;
	}

	// JSON FACILITY - Deserialize Operation
	bool ILVectorArray2n::Deserialize(const Serialized& serObj) {
		SerialItem::ConstMemberIterator it = serObj.FindMember("ILVectorArray2n");

		if( it == serObj.MemberEnd() )
			return false;

		SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

		mIt = it->value.FindMember("Modulus");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_modulus = BigBinaryInteger( mIt->value.GetString() );

		mIt = it->value.FindMember("CyclotomicOrder");
		if( mIt == it->value.MemberEnd() ) return false;
		this->m_cyclotomicOrder = std::stoi(mIt->value.GetString());

		mIt = it->value.FindMember("Vectors");

		if( mIt == it->value.MemberEnd() ) {
			return false;
		}


		bool ret = DeserializeVector<ILVector2n>("Vectors", "ILVector2n", mIt, &this->m_vectors);

		return ret;
	}

} // namespace lbcrypto ends


