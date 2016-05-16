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

namespace lbcrypto {

	/*CONSTRUCTORS*/

	ILVectorArray2n::ILVectorArray2n() : m_vectors(NULL), m_format(EVALUATION),m_params()
	{
	}

	ILVectorArray2n::ILVectorArray2n(const ElemParams &params) : m_params(static_cast<const ILDCRTParams&>(params)), m_format(EVALUATION)
	{
		usint sizeOfVector = m_params.GetModuli().size(); 
		m_vectors.reserve(sizeOfVector); 

		ILParams ilParams0;
		ILVector2n ilvector2n;

		for (usint i = 0; i < sizeOfVector; i++) { 
			usint m = m_params.GetCyclotomicOrder();
			BigBinaryInteger modulus(m_params.GetModuli()[i]);
			BigBinaryInteger rootOfUnity(m_params.GetRootsOfUnity()[i]);

			ilParams0.SetCyclotomicOrder(m);
			ilParams0.SetModulus(modulus);
			ilParams0.SetRootOfUnity(rootOfUnity);
					
			ilvector2n.SetParams(ilParams0);
			BigBinaryVector tmp(m_params.GetCyclotomicOrder() / 2, m_params.GetModuli()[i]);
			ilvector2n.SetValues(tmp, m_format);
			m_vectors.push_back(ilvector2n);

		}
	}

	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &element)  {
		this->m_params = element.m_params;
		this->m_format = element.m_format;
		this->m_vectors = element.m_vectors;
	}
	/* Construct using an tower of ILVectro2ns. The params and format for the ILVectorArray2n will be derived from the towers.*/
	ILVectorArray2n::ILVectorArray2n(const std::vector<ILVector2n> &towers)
	{
		this->SetParamsFromTowers(towers);
		m_vectors = towers; // once all the params are correct, set ILVectorArray2n's towers to the passed value
	}
	/* Construct using a single ILVector2n. The format is derived from the passed in ILVector2n.*/
	ILVectorArray2n::ILVectorArray2n(const ILVector2n &element, const ElemParams &params)
	{
		Format format;
		try{
			format = element.GetFormat();
		}
		catch(_exception e){
			throw std::logic_error("There is an issue with the format of ILVectors passed to the constructor of ILVectorArray2n");
		}
		m_format = format;
		const ILDCRTParams &castedParams = static_cast<const ILDCRTParams&>(params);

		m_params = castedParams;

		usint i = 0;

		usint size = castedParams.GetModuli().size();
		m_vectors.reserve(size);

		ILParams ilParams;
		ILVector2n ilvector2n(element);

		usint cyclotomic_order = castedParams.GetCyclotomicOrder();

		for (i = 0; i < size; i++) {
			ilParams.SetCyclotomicOrder(cyclotomic_order);
			ilParams.SetModulus(m_params.GetModuli()[i]);
			ilParams.SetRootOfUnity(m_params.GetRootsOfUnity()[i]);
	
			ilvector2n.SetParams(ilParams);
			ilvector2n.SetModulus(m_params.GetModuli()[i]);
			m_vectors.push_back(ilvector2n);	
		}
	}

	ILVectorArray2n::ILVectorArray2n(const DiscreteGaussianGenerator & dgg, const ElemParams & params, Format format) :m_params(static_cast<const ILDCRTParams&>(params))
	{
		const ILDCRTParams &m_params = static_cast<const ILDCRTParams&>(params);

		m_vectors.reserve(m_params.GetModuli().size());

		m_format = format;
		//dgg generating random values
		sint* dggValues = dgg.GenerateCharVector(m_params.GetCyclotomicOrder()/2);
	

		BigBinaryInteger modulus;
		BigBinaryInteger rootOfUnity;
		BigBinaryInteger temp;

		for(usint i = 0; i < m_params.GetModuli().size();i++){
			
			modulus = m_params.GetModuli()[i];
			rootOfUnity = m_params.GetRootsOfUnity()[i];

			ILParams ilVectorDggValuesParams(m_params.GetCyclotomicOrder(), modulus, rootOfUnity);	
			ILVector2n ilvector(ilVectorDggValuesParams);

			BigBinaryVector ilDggValues(m_params.GetCyclotomicOrder()/2,modulus);

			for(usint j = 0; j < m_params.GetCyclotomicOrder()/2; j++){
				// if the random generated value is less than zero, then multiply it by (-1) and subtract the modulus of the current tower to set the coefficient
				if((int)dggValues[j] < 0){
					int k = (int)dggValues[j];
					k = k * (-1);
					temp = k;
					temp = m_params.GetModuli()[i] - temp;
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

	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &&element){
		
		this->m_format = element.m_format;
		this->m_params = element.m_params;
		this->m_vectors = std::move(element.m_vectors);
	}


	// DESTRUCTORS

	ILVectorArray2n::~ILVectorArray2n()
	{
	}

	// GET ACCESSORS
	const ILVector2n& ILVectorArray2n::GetValues(usint i) const
	{
		return m_vectors[i];
	}

	usint ILVectorArray2n::GetLength() const {
		return m_vectors.size();
	}

	const std::vector<ILVector2n>& ILVectorArray2n::GetValues() const
	{
		return m_vectors;
	}

	const ElemParams & ILVectorArray2n::GetParams() const
	{
		return m_params;
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

	ElemParams& ILVectorArray2n::AccessParams(){
		return this->m_params;
	}

	/*SETTERS*/

	void ILVectorArray2n::SetValues(const std::vector<ILVector2n> &towers)
	{
		SetParamsFromTowers(towers);
		m_vectors = towers;
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

	// Private Function
	void ILVectorArray2n:: SetParamsFromTowers(const std::vector<ILVector2n> &towers){
		ILParams tempParams;
		Format formatChecker; //This will be assigned the first towers format. Will check if formats are consistent.
		usint cyclotomicOrder; 
		try{
			formatChecker = towers.at(0).GetFormat();
		}

		catch(_exception e){
			throw std::logic_error("There is an issue with the format of ILVectors");
		}
		/*obtaining the chain of moduli and roots of unity*/
		std::vector<BigBinaryInteger> moduli;
		moduli.reserve(towers.size());

		std::vector<BigBinaryInteger> rootsOfUnity;
		rootsOfUnity.reserve(towers.size());
		
		try{
			 cyclotomicOrder = towers.at(0).GetParams().GetCyclotomicOrder();
		}
		catch(_exception e){
			throw std::logic_error("There is an issue with params of ILVectors passed");
		}
		
		for(usint i=0;i < towers.size();i++){
			try{
				tempParams = towers.at(i).GetParams();
				if(towers.at(i).GetFormat() != formatChecker){
				     throw std::logic_error("The format of the ILVector2ns' are not consistent");
				}
				moduli.push_back(tempParams.GetModulus());
				rootsOfUnity.push_back(tempParams.GetRootOfUnity());
			}
			catch(_exception e){
					throw std::logic_error("There is an issue with params of ILVectors");
			}
		}
	
		m_params.SetModuli(moduli);
		m_params.SetRootsOfUnity(rootsOfUnity);
		m_params.SetCyclotomicOrder(cyclotomicOrder);
		m_format = formatChecker;
	}

	/*VECTOR OPERATIONS*/

	ILVectorArray2n ILVectorArray2n::MultiplicativeInverse() const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = tmp.m_vectors[i].MultiplicativeInverse();
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

	ILVectorArray2n ILVectorArray2n::Plus(const ILVectorArray2n &element) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] += element.GetValues(i);
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Minus(const ILVectorArray2n &element) const {
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.GetValues(i);
		}
		return tmp;
	}

	const ILVectorArray2n & ILVectorArray2n::operator+=(const ILVectorArray2n &rhs)
	{
		  ILVectorArray2n result = this->Plus(rhs);
            *this = result;
            return *this;
	}

	const ILVectorArray2n& ILVectorArray2n::operator-=(const lbcrypto::ILVectorArray2n &rhs) {
            ILVectorArray2n result = this->Minus(rhs);
            *this = result;
            return *this;
        }

	bool ILVectorArray2n::operator!=(const lbcrypto::ILVectorArray2n &rhs) const {
            return !(*this == rhs);
        }
	
	bool ILVectorArray2n::operator==(const lbcrypto::ILVectorArray2n &rhs) const {
            if (this->GetFormat() != rhs.GetFormat()) {
                return false;
            }
            if (m_vectors != rhs.GetValues()) {
                return false;
            }

		    const ILDCRTParams &castedObj = dynamic_cast<const ILDCRTParams&>(rhs.GetParams());

			if(const_cast<ILDCRTParams&>(m_params) != castedObj) { //why is it seeing m_params as const???!!
				return false;
			}
            return true;
        }

	ILVectorArray2n & ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
	{
		if (this != &rhs) {
			m_vectors.resize(rhs.m_params.GetModuli().size());
				this->m_vectors = rhs.m_vectors;			
			    this->m_params = rhs.m_params;
			    this->m_format = rhs.m_format;	
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
		tmp.m_params= this->m_params;
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Mod(const BigBinaryInteger &modulus) const
	{
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = m_vectors[i].Mod(modulus);
		}
		return tmp;
	}

	const ILVectorArray2n& ILVectorArray2n::operator+=(const BigBinaryInteger &rhs){
		 ILVectorArray2n result = this->Plus(rhs);
            *this = result;
            return *this;
	}
	
	const ILVectorArray2n& ILVectorArray2n::operator-=(const BigBinaryInteger &rhs){
		 ILVectorArray2n result = this->Minus(rhs);
            *this = result;
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

	void ILVectorArray2n::AddILElementOne(){
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
		Format format(this->GetFormat());
		
		if(format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArray2n not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		usint cyclotomicOrder = this->m_params.GetCyclotomicOrder();

		// To keep consistent roots of unity between the towers and ILVectorArray2n, we keep track of the roots of unity. As seen below, Decompose of ILVector2n is called
		// and decompose of ILVector2n creates new roots of unity, because the cyclotomic order of the ILVector2n changes. 
		std::vector<BigBinaryInteger> rootsOfUnity; 
		rootsOfUnity.reserve(m_vectors.size());

		for(int i=0; i < m_vectors.size(); i++) {
			ILParams ilvectorParams(cyclotomicOrder, this->m_params.GetModuli().at(i), this->m_params.GetRootsOfUnity().at(i));
			m_vectors[i].Decompose();
			rootsOfUnity.push_back(m_vectors[i].GetParams().GetRootOfUnity());
		}

		m_params.SetRootsOfUnity(rootsOfUnity);
		m_params.SetCyclotomicOrder(cyclotomicOrder/2);

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
	void ILVectorArray2n::ModReduce() {
		if(this->GetFormat() != Format::EVALUATION) {
			throw std::logic_error("Mod Reduce function expects EVAL Formatted ILVectorArray2n. It was passed COEFF Formatted ILVectorArray2n.");
		}
		this->SwitchFormat();

		usint length = this->GetLength();
		usint lastTowerIndex = length - 1;
		const std::vector<BigBinaryInteger> &moduli = m_params.GetModuli();

		ILVector2n towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
		ILVector2n d(towerT); 

		//TODO: Get the Plain text modulus properly!
		BigBinaryInteger p(BigBinaryInteger::TWO);
		//precomputations
		BigBinaryInteger qt(m_params.GetModuli()[lastTowerIndex]);
		BigBinaryInteger v(qt.ModInverse(p));
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, p*qt));
		//Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
		d.SwitchModulus(p*qt); 		

		//Calculating delta, step 2
		ILVector2n delta(d.Times(a)); 

		//Calculating d' = c + delta mod q (step 3)
		for(usint i=0; i<length; i++) {
			ILVector2n temp(delta);
			temp.SwitchModulus(moduli[i]);
			m_vectors[i] += temp;
		}

		//step 4
		this->DropTower(lastTowerIndex);

		std::vector<BigBinaryInteger> qtInverseModQi(length-1);
		for(usint i=0; i<length-1; i++) {
			qtInverseModQi[i] =  qt > moduli[i] ? qt.Mod(moduli[i]).ModInverse(moduli[i]) : qt.ModInverse(moduli[i]);
			m_vectors[i] = qtInverseModQi[i] * m_vectors[i];
		}
		this->SwitchFormat();
	}

	/*This method applies the Chinese Remainder Interpolation on an ILVectoArray2n and produces an ILVector2n. The ILVector2n is the ILVectorArray2n's represantation
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
	ILVector2n ILVectorArray2n::InterpolateIlArrayVector2n() const
	{
		/*initializing variables for effciency*/
		usint ringDimension = m_params.GetCyclotomicOrder() / 2;

		BigBinaryInteger qi; //qi

		BigBinaryInteger bigModulus(m_params.GetModulus()); //qt

		BigBinaryInteger divideBigModulusByIndexModulus; //qt/qi

		BigBinaryInteger modularInverse; // (qt/qi)^(-1) mod qi

		BigBinaryInteger chineseRemainderMultiplier; // qt/qi * [(qt/qi)(-1) mod qi]

		BigBinaryInteger multiplyValue;// M (r, i) * qt/qi * [(qt/qi)(-1) mod qi]

		BigBinaryVector coefficients(ringDimension,m_params.GetModulus()); // V vector

		BigBinaryInteger interpolateValue("0"); // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}modqt 

		/*This loop calculates every coefficient of the interpolated valued.*/
		for (usint i = 0; i < ringDimension; i++) {
		/*This for loops to calculate V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod qt, the loop is basically the sigma.
		Mod qt is done outside the loop*/
			for (usint j = 0; j < m_vectors.size(); j++) {

				qi = m_params.GetModuli()[j]; //qi

				divideBigModulusByIndexModulus = bigModulus.DividedBy(qi); //qt/qi

				modularInverse = divideBigModulusByIndexModulus.Mod(qi).ModInverse(qi); // (qt/qi)^(-1) mod qi

				chineseRemainderMultiplier = divideBigModulusByIndexModulus.Times(modularInverse); // qt/qi * [(qt/qi)(-1) mod qi]

				/*m_vectors[i].GetValAtIndex(index) is M (r, i) with r = index amd r = j. The helper method CalculateChineseRemainderInterpolationCoefficient 
				calculates qt/qi *[ (qt/qi)^(-1) mod qi ] where the input parameter j is the row that the operation is performed on.*/
				multiplyValue = (m_vectors[j].GetValAtIndex(i)).Times(chineseRemainderMultiplier); // M (r, i) * qt/qi * [(qt/qi)(-1) mod qi]
				interpolateValue += multiplyValue;
			}

			interpolateValue = interpolateValue.Mod(m_params.GetModulus());
			coefficients.SetValAtIndex(i, interpolateValue); // This Calculates V[j]
			interpolateValue = BigBinaryInteger::ZERO;
		}
		/*Intializing and setting the params of the resulting ILVector2n*/
		usint m = m_params.GetCyclotomicOrder();
		BigBinaryInteger modulus;
		modulus = m_params.GetModulus();
		BigBinaryInteger rootOfUnity;

		ILParams ilParams(m_params.GetCyclotomicOrder(), modulus);

		ILVector2n polynomialReconstructed(ilParams);
		polynomialReconstructed.SetValues(coefficients,m_format);

		return polynomialReconstructed;
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

	bool ILVectorArray2n::InverseExists() const
	{
		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}
		return true;
	}
	//JSON FACILITY

	// JSON FACILITY - SetIdFlag Operation
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ILVectorArray2n::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {
		return serializationMap;
	}

	// JSON FACILITY - Serialize Operation
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ILVectorArray2n::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {
		return serializationMap;
	}

	// JSON FACILITY - Deserialize Operation
	void ILVectorArray2n::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {}

} // namespace lbcrypto ends


