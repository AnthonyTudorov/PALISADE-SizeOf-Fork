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
			m_vectors[i].SetValues(tmp, m_format);

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

	ILVectorArray2n::~ILVectorArray2n()
	{
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

	void ILVectorArray2n::SetValues(const std::vector<ILVector2n> &levels, Format format)
	{
		m_vectors = levels;
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
		}
		return tmp;
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

		for (usint i = 0; i < m_vectors.size(); i++) {
			tmp.m_vectors[i] = ((element*tmp.m_vectors[i]).Mod(m_params.GetModuli()[i]));
		}
		tmp.m_params= this->m_params;
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

	void ILVectorArray2n::PrintValues() const{
		std::cout<<"---START PRINT DOUBLE CRT-- WITH SIZE" <<m_vectors.size() << std::endl;
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

	/*This method applies the Chinese Remainder Interpolation on an ILVectoArray2n and produces an ILVector2n. The ILVector2n is the ILVectorArray2n's represantation
	* with one single coefficient vector.
	* How the Algorithm works:
	* Consider the ILVectorArray2n as a 2-dimensional matrix, denoted as M, with dimension ringDimension * Number of Towers. For breviety , lets say this is r * t
	* Let qt denote the bigModulus (all the towers' moduli multiplied together) and qi denote the modulus of a particular tower. 
	* Let V be a BigBinaryVector of size tower (tower size). Each coefficient of V is calculated as follows:
	* for every r
	*   calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}modqt 
	*
	* Once we have the V[j] values, we construct an ILVector2n from V[j], use qt as it's modulus and calculate a root of unity for parameter selection of the ILVector2n.
	*/
	ILVector2n ILVectorArray2n::InterpolateIlArrayVector2n() const
	{
		usint ringDimension = m_params.GetCyclotomicOrder() / 2;

		BigBinaryVector coefficients(ringDimension,m_params.GetModulus());

		for (usint i = 0; i < ringDimension; i++) {

			coefficients.SetValAtIndex(i, CalculateInterpolationSum(i)); // This Calculates V[j]
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
	/*See comments within the function. Please refer to comments of InterpolateILArracyVector2n to udnerstand what the parameters in the comments are*/
	BigBinaryInteger ILVectorArray2n::CalculateInterpolationSum(usint index) const
	{
		BigBinaryInteger results("0");
		/*This for loops to calculate V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod qt, the loop is basically the sigma.
		Mod qt is done outside the loop*/
		for (usint j = 0; j < m_vectors.size(); j++) {

			BigBinaryInteger multiplyValue;
			
			/*m_vectors[i].GetValAtIndex(index) is M (r, i) with r = index amd r = j. The helper method CalculateChineseRemainderInterpolationCoefficient 
			calculates qt/qi *[ (qt/qi)^(-1) mod qi ] where the input parameter j is the row that the operation is performed on.*/
			multiplyValue = (m_vectors[j].GetValAtIndex(index)).Times(CalculateChineseRemainderInterpolationCoefficient(j)); 
			results = (results.Plus((multiplyValue)));
		}

		results = results.Mod(m_params.GetModulus());

		return results;
	}
	/*This function calculates qt/qi *[ (qt/qi)^(-1) mod qi] , please refer to the comments in InterpolateIlArrayVector2n to understand
	what these values are.*/
    BigBinaryInteger ILVectorArray2n::CalculateChineseRemainderInterpolationCoefficient(usint i) const
	{
		BigBinaryInteger qi(m_params.GetModuli()[i]); //qi

		BigBinaryInteger bigModulus(m_params.GetModulus()); //qt

		BigBinaryInteger divideBigModulusByIndexModulus;

		divideBigModulusByIndexModulus = bigModulus.DividedBy(qi); //qt/qi

		BigBinaryInteger modularInverse;

		modularInverse = divideBigModulusByIndexModulus.Mod(qi).ModInverse(qi); // (qt/qi)^(-1) mod qi

		BigBinaryInteger results;

		results = divideBigModulusByIndexModulus.Times(modularInverse); // qt/qi * [(qt/qi)(-1) mod qi]

		return results;
	}

	void ILVectorArray2n::Decompose() {
		Format format(this->GetFormat());
		
		if(format != Format::COEFFICIENT) {
			std::string errMsg = "ILVectorArray2n not in COEFFICIENT format to perform Decompose.";
			throw std::runtime_error(errMsg);
		}
		
		usint cyclotomicOrder = this->m_params.GetCyclotomicOrder();
		std::vector<BigBinaryInteger> moduli = this->m_params.GetModuli();
		moduli.reserve(this->GetLength());
		std::vector<BigBinaryInteger> rootsOfUnity = this->m_params.GetRootsOfUnity(); 

		for(int i=0; i < m_vectors.size(); i++) {
			ILParams ilvectorParams(cyclotomicOrder, moduli[i], rootsOfUnity[i]);
			 m_vectors[i].Decompose();
			 rootsOfUnity[i] = m_vectors[i].GetParams().GetRootOfUnity();
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

	bool ILVectorArray2n::InverseExists() const
	{
		for (usint i = 0; i < m_vectors.size(); i++) {
			if (!m_vectors[i].InverseExists()) return false;
		}
		return true;
	}

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


