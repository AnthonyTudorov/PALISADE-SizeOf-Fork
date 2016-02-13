/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	6/14/2015 5:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:
	This code provides the core somewhat homomorphic encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include "lweconjunctionobfuscate.h"

namespace lbcrypto {

	//Function for re-encypting ciphertext using the array generated by ProxyGen


template <class Element>
ClearLWEConjunctionPattern<Element>::ClearLWEConjunctionPattern(const std::string patternString) {
	m_patternString += patternString;
};

template <class Element>
std::string ClearLWEConjunctionPattern<Element>::GetPatternString() const {
	return m_patternString;
};

template <class Element>
char ClearLWEConjunctionPattern<Element>::GetIndex(usint loc) const {
	return (char)m_patternString[loc];
};

template <class Element>
usint ClearLWEConjunctionPattern<Element>::GetLength() const {
	return m_patternString.length();
};
/*
template <class Element>
ObfuscatedLWEConjunctionPattern<Element>::ObfuscatedLWEConjunctionPattern(usint length) {

	this->m_length=length;

	// Create 2D array of pointers:
	ringArray = new Element**[this->m_length];
	for (usint i = 0; i < 2*this->m_length; ++i) {
		ringArray[i] = new Element*[2];
		}

	// Null out the pointers contained in the array:
	for (usint i = 0; i < this->m_length; ++i) {
		for (usint j = 0; j < 2; ++j) {
			ringArray[i][j] = NULL;
			}
		}
};
*/

template <class Element>
void ObfuscatedLWEConjunctionPattern<Element>::SetLength(usint length) {
	m_length = length;
};

template <class Element>
const BigBinaryInteger ObfuscatedLWEConjunctionPattern<Element>::GetModulus() const{
	BigBinaryInteger q(m_cryptoParameters->GetModulus());
	return q;
};

template <class Element>
usint ObfuscatedLWEConjunctionPattern<Element>::GetRingDimension() const{
	return (this->m_cryptoParameters->GetCyclotomicOrder())/2;
};

template <class Element>
usint ObfuscatedLWEConjunctionPattern<Element>::GetLogModulus() const{
	double val = this->m_cryptoParameters->GetModulus().ConvertToDouble();
	//std::cout << "val : " << val << std::endl;
	double logTwo = log(val-1.0)/log(2)+1.0;
	//std::cout << "logTwo : " << logTwo << std::endl;
	usint logModulus = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
	return logModulus;
};

template <class Element>
void ObfuscatedLWEConjunctionPattern<Element>::SetModulus(BigBinaryInteger &modulus) {
	this->m_cryptoParameters.SetModulus(modulus);
};

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::KeyGen(DiscreteGaussianGenerator &dgg,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern) const {

	usint n = obfuscatedPattern->GetRingDimension();
	usint k = obfuscatedPattern->GetLogModulus();
	usint l = obfuscatedPattern->GetLength();
	ILParams params = *(obfuscatedPattern->GetParameters());
	usint stddev = dgg.GetStd(); 
	//double s = 1000;
	//double s = 600;

	// Initialize the Pk and Ek matrices.
	std::vector<ILMat<Element>> *Pk_vector = new std::vector<ILMat<Element>>();
	std::vector<TrapdoorPair>   *Ek_vector = new std::vector<TrapdoorPair>();
	std::vector<ILMat<LargeFloat>> *sigma = new std::vector<ILMat<LargeFloat>>();

	for(usint i=0; i<=l+1; i++) {
		pair<RingMat, TrapdoorPair> trapPair = TrapdoorSample(params, stddev); //TODO remove stddev

		ILMat<LargeFloat> sigmaSqrt([](){ return make_unique<LargeFloat>(); }, n*(k+2), n*(k+2));
		PerturbationMatrixGen(n, k, trapPair.first, trapPair.second, S, &sigmaSqrt);

		Pk_vector->push_back(trapPair.first);
		Ek_vector->push_back(trapPair.second);

		sigma->push_back(sigmaSqrt);
	}

	obfuscatedPattern->SetKeys(Pk_vector,Ek_vector,sigma);

}


template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				DiscreteGaussianGenerator &dgg,
				BinaryUniformGenerator &dbg,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern) const {

	
	obfuscatedPattern->SetLength(clearPattern.GetLength());
	usint l = clearPattern.GetLength();
	usint n = obfuscatedPattern->GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern->GetModulus());
	usint m = obfuscatedPattern->GetLogModulus() + 2;
	ILParams params = *(obfuscatedPattern->GetParameters());
	//usint stddev = dgg.GetStd(); 

	const std::vector<ILMat<Element>> &Pk_vector = obfuscatedPattern->GetPublicKeys();
	const std::vector<TrapdoorPair>   &Ek_vector = obfuscatedPattern->GetEncodingKeys();
	const std::vector<ILMat<LargeFloat>>   &Sigma = obfuscatedPattern->GetSigmaKeys();

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits + 2 \t m : " << m << std::endl;

	char val=0;

	// Initialize the s and r matrices.
	std::vector<Element> s_small_0;
	std::vector<Element> s_small_1;

	std::vector<Element> r_small_0;
	std::vector<Element> r_small_1;

	Element s_prod;

	for(usint i=0; i<=l-1; i++) {
		//Set the elements s and r to a discrete uniform generated vector.
		Element elems0(dbg,params,EVALUATION);
		s_small_0.push_back(elems0);
		//std::cout << elems0 << std::endl;

		Element	elemr0(dbg,params,EVALUATION);
		r_small_0.push_back(elemr0);
		//std::cout << elemr0 << std::endl;

		//Determine wildcard or not.  If wildcard, copy s and r.  Else, don't copy.
		bool wildCard = ((char)clearPattern.GetIndex(i) == '?');
		if (wildCard) {
			val = 1;
			s_small_1.push_back(s_small_0.back());
			r_small_1.push_back(r_small_0.back());
		} else {
			//Element elems1(dug,params,EVALUATION);
			Element elems1(dbg,params,EVALUATION);
			s_small_1.push_back(elems1);

			//Element	elemr1(dug,params,EVALUATION);
			Element	elemr1(dbg,params,EVALUATION);
			r_small_1.push_back(elemr1);
		}
		
		const Element *vi = NULL;
		if ((char)clearPattern.GetIndex(i) == '1')
		{
			std::cout << "index is 1" << std::endl;
			vi = &s_small_1.back();
		}
		else
			vi = &s_small_0.back();
		
		if (i==0) {
			s_prod = *vi;
		} else {
			s_prod = (*vi) * s_prod;
		}

	}

	std::cout << "Obfuscate: Generated random uniform ring elements" << std::endl;

	std::vector<ILMat<Element>> *S0_vec = new std::vector<ILMat<Element>>();
	std::vector<ILMat<Element>> *S1_vec = new std::vector<ILMat<Element>>();

	std::vector<ILMat<Element>> *R0_vec = new std::vector<ILMat<Element>>();
	std::vector<ILMat<Element>> *R1_vec = new std::vector<ILMat<Element>>();

	for(usint i=1; i<=l; i++) {

		ILMat<Element> *S0_i = new ILMat<ILVector2n>(zero_alloc, m, m);

		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],s_small_0[i-1]*r_small_0[i-1],dgg,S0_i);
		S0_vec->push_back(*S0_i);

		//std::cout << "encode ran S0" << std::endl;

		ILMat<Element> *S1_i = new ILMat<ILVector2n>(zero_alloc, m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],s_small_1[i-1]*r_small_1[i-1],dgg,S1_i);
		S1_vec->push_back(*S1_i);

		//std::cout << "encode ran S1" << std::endl;

		ILMat<Element> *R0_i = new ILMat<ILVector2n>(zero_alloc, m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],r_small_0[i-1],dgg,R0_i);
		R0_vec->push_back(*R0_i);

		//std::cout << "encode ran R0" << std::endl;

		ILMat<Element> *R1_i = new ILMat<ILVector2n>(zero_alloc, m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],r_small_1[i-1],dgg,R1_i);
		R1_vec->push_back(*R1_i);

		//std::cout << "encode ran R1" << std::endl;

		std::cout << "encode round " << i << " completed" << std::endl;
	}

	//std::cout << "encode started for L" << std::endl;

	//Element	elemrl1(dug,params,EVALUATION);
	Element	elemrl1(dbg,params,EVALUATION);

	ILMat<Element> *Sl = new ILMat<ILVector2n>(zero_alloc, m, m);
	this->Encode(Pk_vector[l],Pk_vector[l+1],Ek_vector[l],Sigma[l],elemrl1*s_prod,dgg,Sl);

	//std::cout << "encode 1 for L ran" << std::endl;
	//std::cout << elemrl1.GetValues() << std::endl;

	ILMat<Element> *Rl = new ILMat<ILVector2n>(zero_alloc, m, m);
	this->Encode(Pk_vector[l],Pk_vector[l+1],Ek_vector[l],Sigma[l],elemrl1,dgg,Rl);

	//std::cout << "encode 2 for L ran" << std::endl;

	//Sl.PrintValues();
	//Rl.PrintValues();
	obfuscatedPattern->SetMatrices(S0_vec,S1_vec,R0_vec,R1_vec,Sl,Rl);

	//obfuscatedPattern->GetSl();

};

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::Encode(
				const ILMat<Element> &Ai,
				const ILMat<Element> &Aj,
				const TrapdoorPair &Ti,
				const ILMat<LargeFloat> &sigma,
				const Element &elemS,
				DiscreteGaussianGenerator &dgg,
				ILMat<Element> *encodedElem) const {

	size_t m = Ai.GetCols();
	size_t k = m - 2;
	size_t n = elemS.GetParams().GetCyclotomicOrder()/2;
	const BigBinaryInteger &modulus = elemS.GetParams().GetModulus();
	const ILParams &params = elemS.GetParams();
	auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	//generate a row vector of discrete Gaussian ring elements
	//YSP this can be done using discrete Gaussian allocator later - after the dgg allocator is updated to use the same dgg instance
	ILMat<Element> ej(zero_alloc, 1, m); 
	for(size_t i=0; i<m; i++) {
		ej(0,i).SetValues(dgg.GenerateVector(n,modulus),COEFFICIENT);
		ej(0,i).SwitchFormat();
	}

	ILMat<Element> bj = Aj.ScalarMult(elemS) + ej;

	//std::cout << "Encode: Computed bj, next will do GaussSamp" << std::endl; 

	for(size_t i=0; i<m; i++) {
		ILMat<Element> gaussj = GaussSamp(n,k,Ai,Ti,sigma,bj(0,i),dgg.GetStd(), dgg);
		for(size_t j=0; j<m; j++)
			(*encodedElem)(j,i) = gaussj(j,0);
	}

	//encodedElem->SwitchFormat();
	//std::cout<<"norm = "<<encodedElem->Norm() <<std::endl;
	//encodedElem->SwitchFormat();

	//Test to make sure Ai*gaussj = bj(0,1)
	//ILMat<Element> test(zero_alloc, m, 1); 
	//for(size_t j=0; j<m; j++)
	//	test(j,0) = (*encodedElem)(j,2);
	//ILVector2n bEst = (Ai * test)(0,0);
	//std::cout << "bj(0,2) = " << bj(0,2) << std::endl;
	//std::cout << "Ai*z = " << bEst << std::endl;

};

template <class Element>
bool LWEConjunctionObfuscationAlgorithm<Element>::Evaluate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				const std::string &testString) const {
	bool retVal = true;
	usint loc = 0;
	char loc1;
	char loc2;

	while ((loc < clearPattern.GetLength())&retVal)
	{
		loc1 = (char)testString[loc];
		loc2 = (char)clearPattern.GetIndex(loc);
		//std::cout << " Index: " << loc << std::endl;
		//std::cout << " \t Input: \t" << loc1 << std::endl;
		//std::cout << " \t Pattern: \t" << loc2 << std::endl;
		if ((loc1!=loc2)&(loc2!='?'))
		{
			retVal = false;
		}
		//std::cout << " \t Matches: \t" << retVal << std::endl;
		loc++;
	}


	return retVal;
};

template <class Element>
bool LWEConjunctionObfuscationAlgorithm<Element>::Evaluate(
				const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				const std::string &testString) const {

	usint l = obfuscatedPattern.GetLength();
	usint n = obfuscatedPattern.GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern.GetModulus());
	usint m = obfuscatedPattern.GetLogModulus() + 2;
	double constraint = obfuscatedPattern.GetConstraint();

	const std::vector<ILMat<Element>> &Pk_vector = obfuscatedPattern.GetPublicKeys();

	const ILParams *params = obfuscatedPattern.GetParameters();

	auto zero_alloc = ILVector2n::MakeAllocator(*params, EVALUATION);

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits \t m : " << m << std::endl;
	std::cout << "Constraint \t : " << constraint << std::endl;

	bool retVal = true;
	char testVal;

	double norm = constraint;

	ILMat<Element> S_prod = ILMat<Element>(zero_alloc, m, m).Identity();
	ILMat<Element> R_prod = ILMat<Element>(zero_alloc, m, m).Identity();

	//S_prod.PrintValues();
	//R_prod.PrintValues();

	ILMat<Element> *S_ib;// = ILMat<Element>(secureIL2nAlloc(), m, m);
	ILMat<Element> *R_ib;// = ILMat<Element>(secureIL2nAlloc(), m, m);

	for (usint i=0; i<l; i++)
	{
		testVal = (char)testString[i];
		std::cout << " Index: " << i << std::endl;
		std::cout << " \t Input: \t" << testVal << std::endl;
		
		S_ib = obfuscatedPattern.GetS(i,testVal);
		R_ib = obfuscatedPattern.GetR(i,testVal);

		//S_ib->PrintValues();
		//R_ib->PrintValues();
		
		S_prod = S_prod * (*S_ib);
		R_prod = R_prod * (*R_ib);

		//if (i==0)
		//	std::cout << "does identity work correctly" << (S_prod == *S_ib) << std::endl;
		
	}
	std::cout << " S_prod: " << std::endl;
	//S_prod.PrintValues();
	std::cout << " R_prod: " << std::endl;
	//R_prod.PrintValues();

	ILMat<Element>* Sl = obfuscatedPattern.GetSl();
	ILMat<Element>* Rl = obfuscatedPattern.GetRl();
	
	std::cout << " Sl: " << std::endl;
	//Sl->PrintValues();
	std::cout << " Rl: " << std::endl;
	//Rl->PrintValues();

	std::cout << " Cross Product: " << std::endl;
	ILMat<Element> CrossProd = Pk_vector[0]*((S_prod * (*Rl)) - (R_prod * (*Sl)));
	//CrossProd.PrintValues();

	//for(size_t i=0; i<m; i++)
	//		CrossProd(0,i).SwitchFormat();

	//the norm can be estimated after all elements are converted to coefficient representation
	CrossProd.SwitchFormat();

	//CrossProd.PrintValues();

	//std::cout << "cross product dimensions: " <<  CrossProd.GetRows() << ", " << CrossProd.GetCols() << std::endl;
	//std::cout <<  CrossProd << std::endl;

	norm = CrossProd.Norm();
	std::cout << " Norm: " << norm << std::endl;

	return (norm <= constraint);

};

template class ClearLWEConjunctionPattern<ILVector2n>;
template class LWEConjunctionObfuscationAlgorithm<ILVector2n>;
}
