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

	ILVectorArray2n::ILVectorArray2n() : m_format(EVALUATION),m_params(){}

	ILVectorArray2n::ILVectorArray2n(const std::vector<ILParams> &ilparams) : m_format(EVALUATION)
	{
		
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
	ILVectorArray2n::ILVectorArray2n(const ILVector2n &element, const std::vector<ILParams> &ilparams)
	{
		
	}

	/*The dgg will be the seed to populate the towers of the ILVectorArray2n with random numbers. The algorithm to populate the towers can be seen below.*/
	ILVectorArray2n::ILVectorArray2n(const DiscreteGaussianGenerator & dgg, const std::vector<ILParams> &ilparams, Format format = EVALUATION)
	{
		
	}

	/*Move constructor*/
	ILVectorArray2n::ILVectorArray2n(const ILVectorArray2n &&element){
		
		this->m_format = element.m_format;
		this->m_vectors = std::move(element.m_vectors);
	}

	ILVectorArray2n ILVectorArray2n::CloneWithParams() {
		return *this;
	}

	ILVectorArray2n ILVectorArray2n::CloneWithNoise(const DiscreteGaussianGenerator &dgg) {
		return *this;
	}

	// DESTRUCTORS

	ILVectorArray2n::~ILVectorArray2n()
	{
	}

	// GET ACCESSORS
	const ILVector2n& ILVectorArray2n::GetTowerAtIndex (usint i) const
	{
		return m_vectors[i];
	}

	usint ILVectorArray2n::GetTowerLength() const {
		return m_vectors.size();
	}

	const std::vector<ILVector2n>& ILVectorArray2n::GetAllTowers() const
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
			tmp.m_vectors[i] += element.GetTowerAtIndex (i);
		}
		return tmp;
	}

	ILVectorArray2n ILVectorArray2n::Minus(const ILVectorArray2n &element) const {
		ILVectorArray2n tmp(*this);

		for (usint i = 0; i < tmp.m_vectors.size(); i++) {
			tmp.m_vectors[i] -= element.GetTowerAtIndex (i);
		}
		return tmp;
	}

	const ILVectorArray2n & ILVectorArray2n::operator+=(const ILVectorArray2n &rhs)
	{
            return this->Plus(rhs);
	}

	const ILVectorArray2n& ILVectorArray2n::operator-=(const ILVectorArray2n &rhs) {
		return this->Minus(rhs);
    }

	bool ILVectorArray2n::operator!=(const ILVectorArray2n &rhs) const {
            return !(*this == rhs);
        }
	
	bool ILVectorArray2n::operator==(const ILVectorArray2n &rhs) const {
		//check if the format's are the same
         if (this->GetFormat() != rhs.GetFormat()) {
                return false;
          }

		const ILDCRTParams &castedObj = static_cast<const ILDCRTParams&>(rhs.GetParams());
		//check if the params (m_params) are the same
		if(const_cast<ILDCRTParams&>(m_params) != castedObj) { 
			return false;
		}
		//check if the towers are the same
        if (m_vectors != rhs.GetAllTowers()) {
           return false;
        }
		
		return true;
       
	}

	const ILVectorArray2n & ILVectorArray2n::operator=(const ILVectorArray2n & rhs)
	{
		if (this != &rhs) {
			this->m_vectors = rhs.m_vectors;			
			this->m_params = rhs.m_params;
			this->m_format = rhs.m_format;	
		}
		return *this;
	}

	ILVectorArray2n& ILVectorArray2n::operator=(std::initializer_list<sint> rhs){
		usint len = rhs.size();
		usint vectorLength = this->m_vectors[0].GetLength();
		for(usint i=0;i<this->GetTowerLength();i++){ // this loops over each tower
			for(usint j=0; j<vectorLength; j++) { // loops within a tower
				if(j<len) {
					this->m_vectors[i].SetValAtIndex(j, *(rhs.begin()+j));
				} else {
					this->m_vectors[i].SetValAtIndex(j,0);
				}
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
		// tmp.m_params= this->m_params;
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
         return this->Plus(rhs);
	}
	
	const ILVectorArray2n& ILVectorArray2n::operator-=(const BigBinaryInteger &rhs){
          return this->Minus(rhs);
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

		for(int i=0; i < m_numberOfTowers; i++) {
			m_vectors[i].Decompose();
		}
	}

	void ILVectorArray2n::DropTower(usint index){
		if(index >= m_numberOfTowers){
			throw std::out_of_range("Index of tower being removed is larger than ILVectorArray2n tower\n");
		}
		m_modulus = m_modulus /(m_vectors[index].GetModulus());
		m_vectors.erase(m_vectors.begin() + index);
		m_numberOfTowers -= 1;
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
		if(this->GetFormat() != Format::EVALUATION) {
			throw std::logic_error("Mod Reduce function expects EVAL Formatted ILVectorArray2n. It was passed COEFF Formatted ILVectorArray2n.");
		}
		this->SwitchFormat();

		usint length = this->GetTowerLength();
		usint lastTowerIndex = length - 1;
		const std::vector<BigBinaryInteger> &moduli = m_params.GetModuli();

		ILVector2n towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
		ILVector2n d(towerT); 

		//precomputations
		BigBinaryInteger qt(m_params.GetModuli()[lastTowerIndex]);
		BigBinaryInteger v(qt.ModInverse(plaintextModulus));
		BigBinaryInteger a((v * qt).ModSub(BigBinaryInteger::ONE, plaintextModulus*qt));
		//Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
		d.SwitchModulus(plaintextModulus*qt); 		

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

	// JSON FACILITY - Serialize Operation
	bool ILVectorArray2n::Serialize(Serialized* serObj, const std::string fileFlag) const {
		return false;
	}

	// JSON FACILITY - Deserialize Operation
	bool ILVectorArray2n::Deserialize(const Serialized& serObj) {
		return false;
	}

} // namespace lbcrypto ends


