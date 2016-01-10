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
	double logTwo = log2(val-1.0)+1.0;
	//std::cout << "logTwo : " << logTwo << std::endl;
	usint logModulus = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
	return logModulus;
};

template <class Element>
void ObfuscatedLWEConjunctionPattern<Element>::SetModulus(BigBinaryInteger &modulus) {
	this->m_cryptoParameters.SetModulus(modulus);
};

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				DiscreteGaussianGenerator &dgg,
				DiscreteUniformGenerator &dug,
				ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern) const {

	obfuscatedPattern.SetLength(clearPattern.GetLength());

	usint l = clearPattern.GetLength();
	usint n = obfuscatedPattern.GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern.GetModulus());
	usint m = obfuscatedPattern.GetLogModulus();
	ILParams params = *(obfuscatedPattern.GetParameters());
	usint stddev = 6;  // TODO remove this.

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits \t m : " << m << std::endl;

	char val=0;

	//ILMat<Element> z(secureIL2nAlloc(), m,m);
	std::cout << "One " << m << "x" << m << std::endl;
	const ILMat<Element> one = ILMat<Element>(secureIL2nAlloc(), m, m).Ones();
	one.PrintValues();

	std::cout << "Eye " << m << "x" << m << std::endl;
	const ILMat<Element> eye = ILMat<Element>(secureIL2nAlloc(), m, m).Identity();
	eye.PrintValues();

	// Initialize the Pk and Ek matrices.
	std::vector<ILMat<Element>> Pk_vector;
	std::vector<TrapdoorPair>   Ek_vector;

	for(usint i=0; i<=l+1; i++) {
		std::cout << " Index A: " << i << std::endl;
		pair<RingMat, TrapdoorPair> trapPair = TrapdoorSample(params, stddev); //TODO remove stddev
		Pk_vector.push_back(trapPair.first);
		Ek_vector.push_back(trapPair.second);
	} 

	// Initialize the s and r matrices.
	std::vector<Element> s_small_0;
	std::vector<Element> s_small_1;

	std::vector<Element> r_small_0;
	std::vector<Element> r_small_1;

	Element s_prod;

	for(usint i=0; i<=l-1; i++) {
		std::cout << " Index B: " << i << std::endl;
		//Set the elements s and r to a discrete uniform generated vector.
		Element elems0(params,EVALUATION);
		elems0.SetValues(dug.GenerateVector(n),EVALUATION);
		s_small_0.push_back(elems0);

		Element	elemr0(params,EVALUATION);
		elemr0.SetValues(dug.GenerateVector(n),EVALUATION);
		r_small_0.push_back(elemr0);

		//Determine wildcard or not.  If wildcard, copy s and r.  Else, don't copy.
		bool wildCard = ((char)clearPattern.GetIndex(i) == '?');
		if (wildCard) {
			std::cout << " Following if A: " << i << std::endl;
			val = 1;
			s_small_1.push_back(s_small_0.back());
			r_small_1.push_back(r_small_0.back());
		} else {
			std::cout << " Following else A: " << i << std::endl;
			Element elems1(params,EVALUATION);
			elems1.SetValues(dug.GenerateVector(n),EVALUATION);
			s_small_1.push_back(elems1);

			Element	elemr1(params,EVALUATION);
			elemr1.SetValues(dug.GenerateVector(n),EVALUATION);
			r_small_1.push_back(elemr1);
		}
		if (i==0) {
			std::cout << " Following if B: " << i << std::endl;
			s_prod = s_small_0.back();
			s_prod.PrintValues();
		} else {
			std::cout << " Following else B: " << i << std::endl;
			Element s_prod_prime = s_small_0.back();
			s_prod_prime.PrintValues();
			std::cout << " Middle else B: " << i << std::endl;
			s_prod_prime.PrintValues();
			s_prod.PrintValues();
			s_prod = s_prod_prime * s_prod;			//TODO There is an odd error here.
			std::cout << " Ending else B: " << i << std::endl;
		}
		std::cout << " End Index B: " << i << std::endl;
	}

	Element r_l1(params,EVALUATION);
	r_l1.SetValues(dug.GenerateVector(n),EVALUATION);


	std::vector<ILMat<Element>> S0_vec;
	std::vector<ILMat<Element>> S1_vec;

	std::vector<ILMat<Element>> R0_vec;
	std::vector<ILMat<Element>> R1_vec;

	for(usint i=1; i<=l+1; i++) {
		std::cout << " Index C: " << i << std::endl;

		ILMat<Element> S0_i = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],s_small_0[i-1]*r_small_0[i-1],S0_i);
		S0_vec.push_back(S0_i);

		ILMat<Element> S1_i = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],s_small_1[i-1]*r_small_1[i-1],S1_i);
		S1_vec.push_back(S1_i);

		ILMat<Element> R0_i = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],r_small_0[i-1],R0_i);
		R0_vec.push_back(R0_i);

		ILMat<Element> R1_i = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
		this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],r_small_1[i-1],R1_i);
		R1_vec.push_back(R1_i);
	}

	std::cout << " After looping. " << std::endl;

//	ILMat<Element> Sl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m).Identity();
//	ILMat<Element> Rl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m).Identity();

	Element	elemrl1(params,EVALUATION);
	elemrl1.SetValues(dug.GenerateVector(n),EVALUATION);

	ILMat<Element> Sl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
	this->Encode(Pk_vector[l],Pk_vector[l+1],Ek_vector[l],r_small_0[l+1]*s_prod,Sl);


	ILMat<Element> Rl = ILMat<ILVector2n>(secureIL2nAlloc(), m, m);
	this->Encode(Pk_vector[l],Pk_vector[l+1],Ek_vector[l],elemrl1,Rl);

	obfuscatedPattern.SetMatrices(S0_vec,S1_vec,R0_vec,R1_vec,Sl,Rl);

};

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::Encode(
				const ILMat<Element> &Ai,
				const ILMat<Element> &Aj,
				const TrapdoorPair &Ti,
				const Element &elem,
				ILMat<Element> &encodedElem) const {
	
	encodedElem.Identity();

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
	usint m = obfuscatedPattern.GetLogModulus();
	double constraint = obfuscatedPattern.GetConstraint();

	bool retVal = true;
	char testVal;

/*

	ILMat<Element> S_prod = ILMat<Element>(secureIL2nAlloc(), m, m).Identity();
	ILMat<Element> R_prod = ILMat<Element>(secureIL2nAlloc(), m, m).Identity();

	for (usint i=0; i<l; i++)
	{
		testVal = (char)testString[i];
		std::cout << " Index: " << i << std::endl;
		std::cout << " \t Input: \t" << testVal << std::endl;
		
		ILMat<Element> S_ib = ILMat<Element>(secureIL2nAlloc(), m, m);
		ILMat<Element> R_ib = ILMat<Element>(secureIL2nAlloc(), m, m);

		obfuscatedPattern.GetS(i,testVal,&S_ib);
		obfuscatedPattern.GetR(i,testVal,&R_ib);

		S_prod = S_prod * S_ib;
		R_prod = R_prod * R_ib;
	}

	ILMat<Element> S_l = obfuscatedPattern.GetSl();
	ILMat<Element> R_l = obfuscatedPattern.GetRl();

	ILMat<Element> CrossProd = ((S_prod * R_l) - (R_prod * S_l));
	double norm = CrossProd.Norm();

	return (norm <= constraint);
*/
	return false;

	//ILMat<ILMat<Element>> S(l,1);
	//ILMat<ILMat<Element>> R(l,1);
/*
	ILMat<Element> Sprod(m,m);
	ILMat<Element> Rprod(m,m);

	ILMat<Element> CrossDiff;

	usint input = ((char)testString[0] == '0');
	if (input) {
		Sprod = obfuscatedPattern.GetS(0,0);
		Rprod = obfuscatedPattern.GetR(0,0);
	} else {
		Sprod = obfuscatedPattern.GetS(0,1);
		Rprod = obfuscatedPattern.GetR(0,1);
	}

	for(usint i=1; i<=l-1; i++) {
		input  = ((char)testString[i] == '0');
		if (input) {
			Sprod = Sprod*obfuscatedPattern.GetS(i,0);
			Rprod = Rprod*obfuscatedPattern.GetR(i,0);
		} else {
			Sprod = Sprod*obfuscatedPattern.GetS(i,1);
			Rprod = Sprod*obfuscatedPattern.GetR(i,1);
		}
	}

	CrossDiff = (Sprod*obfuscatedPattern.getRl()) - (Rprod*obfuscatedPattern.getSl());
	float norm = CrossDiff.InfinityNorm();

	return norm<constraint;
*/
	return false;
};

template class ClearLWEConjunctionPattern<ILVector2n>;
template class LWEConjunctionObfuscationAlgorithm<ILVector2n>;
}
