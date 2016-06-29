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
Description:
	This code provides the core entropic ring lwe obfuscation capability for conjunctions.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include "lweconjunctionobfuscatev2.h"

#include "../utils/memory.h"
#include "../utils/debug.h"

namespace lbcrypto {

template <class Element>
ObfuscatedLWEConjunctionPatternV2<Element>::ObfuscatedLWEConjunctionPatternV2() {

	this->m_elemParams = NULL;
	this->m_length = 0;
	this->m_chunkSize = 1;
	this->m_S_vec = NULL;

	this->m_R_vec = NULL;

	this->m_Sl = NULL;
	this->m_Rl = NULL;

	this->m_pk = NULL;
	this->m_ek = NULL;
	this->m_Sigma = NULL;

}

template <class Element>
ObfuscatedLWEConjunctionPatternV2<Element>::~ObfuscatedLWEConjunctionPatternV2() {
	if (this->m_S_vec != NULL){
		delete this->m_S_vec;
		delete this->m_R_vec;
	
		delete this->m_Sl;
		delete this->m_Rl;
	}

	if (this->m_pk != NULL) {
		delete this->m_pk;
		delete this->m_ek;
		delete this->m_Sigma;
	}
}

template <class Element>
ObfuscatedLWEConjunctionPatternV2<Element>::ObfuscatedLWEConjunctionPatternV2(ElemParams &elemParams, usint chunkSize) {

	this->m_elemParams = &elemParams;

	this->m_length = 0;
	this->m_chunkSize = chunkSize;

	this->m_S_vec = NULL;

	this->m_R_vec = NULL;

	this->m_Sl = NULL;
	this->m_Rl = NULL;

	this->m_pk = NULL;
	this->m_ek = NULL;
	this->m_Sigma = NULL;
}

template <class Element>
ObfuscatedLWEConjunctionPatternV2<Element>::ObfuscatedLWEConjunctionPatternV2(ElemParams &elemParams) : 
	ObfuscatedLWEConjunctionPatternV2(elemParams,1) {};

template <class Element>
void ObfuscatedLWEConjunctionPatternV2<Element>::SetLength(usint length) {
	m_length = length;
};

template <class Element>
const BigBinaryInteger ObfuscatedLWEConjunctionPatternV2<Element>::GetModulus() const{
	BigBinaryInteger q(m_elemParams->GetModulus());
	return q;
};

template <class Element>
usint ObfuscatedLWEConjunctionPatternV2<Element>::GetRingDimension() const{
	return (this->m_elemParams->GetCyclotomicOrder())/2;
};

// Gets the log of the modulus
template <class Element>
usint ObfuscatedLWEConjunctionPatternV2<Element>::GetLogModulus() const{
	double val = this->m_elemParams->GetModulus().ConvertToDouble();
	//std::cout << "val : " << val << std::endl;
	double logTwo = log(val-1.0)/log(2)+1.0;
	//std::cout << "logTwo : " << logTwo << std::endl;
	usint logModulus = (usint) floor(logTwo);// = this->m_elemParams.GetModulus();
	return logModulus;
};

template <class Element>
void ObfuscatedLWEConjunctionPatternV2<Element>::SetModulus(BigBinaryInteger &modulus) {
	this->m_elemParams.SetModulus(modulus);
};

// Sets the matrices that define the obfuscated pattern.
template <class Element>
void ObfuscatedLWEConjunctionPatternV2<Element>::SetMatrices(vector<vector<Matrix<Element>>> *S_vec,
		vector<vector<Matrix<Element>>> * R_vec, Matrix<Element> * Sl, Matrix<Element> * Rl) {

	this->m_S_vec = S_vec;
	this->m_R_vec = R_vec;
	this->m_Sl = Sl;
	this->m_Rl = Rl;

}

template <class Element>
Matrix<Element>*  ObfuscatedLWEConjunctionPatternV2<Element>::GetR(usint i, const std::string &testVal) const {

	Matrix<Element> *R_ib;

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	R_ib = &(this->m_R_vec->at(i).at(value));

	return R_ib;
}


template <class Element>
Matrix<Element>*  ObfuscatedLWEConjunctionPatternV2<Element>::GetS(usint i, const std::string &testVal) const {

	Matrix<Element> *S_ib;

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	vector<Matrix<Element>> temp =  this->m_R_vec->at(i);

	S_ib = &(this->m_S_vec->at(i).at(value));

	return S_ib;
}

template <class Element>
void LWEConjunctionObfuscationAlgorithmV2<Element>::KeyGen(DiscreteGaussianGenerator &dgg,
				ObfuscatedLWEConjunctionPatternV2<Element> *obfuscatedPattern) const {
	TimeVar t1,t2; // for TIC TOC
	bool dbg_flag = 0;
	TIC(t1);

	usint n = obfuscatedPattern->GetRingDimension();
	usint k = obfuscatedPattern->GetLogModulus();
	std::cout << "BitLength in KeyGen: " << k << std::endl;

	usint l = obfuscatedPattern->GetLength();
	const ElemParams *params = obfuscatedPattern->GetParameters();
	usint chunkSize = obfuscatedPattern->GetChunkSize();
	usint adjustedLength = l/chunkSize;
	usint stddev = dgg.GetStd(); 
	//double s = 1000;
	//double s = 600;
	double s = 40*std::sqrt(n*(k+2));
	std::cout << "parameter s = " << s << std::endl;

#if 0 //original code
	// Initialize the Pk and Ek matrices.
	std::vector<Matrix<Element>> *Pk_vector = new std::vector<Matrix<Element>>();
	std::vector<RLWETrapdoorPair>   *Ek_vector = new std::vector<RLWETrapdoorPair>();
	std::vector<Matrix<LargeFloat>> *sigma = new std::vector<Matrix<LargeFloat>>();

	DEBUG("keygen1: "<<TOC(t1) <<" ms");
	DEBUG("l = "<<l);

	TIC(t2);
	for(usint i=0; i<=adjustedLength+1; i++) {

		TIC(t1);
		pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev); //TODO remove stddev
		DEBUG("keygen2.0:#"<< i << ": "<<TOC(t1) <<" ms");

		TIC(t1);
		Matrix<LargeFloat> sigmaSqrt([](){ return make_unique<LargeFloat>(); }, n*(k+2), n*(k+2));
		DEBUG("keygen2.1:#"<< i << ": "<<TOC(t1) <<" ms");

		TIC(t1);
		//the following takes all the time
		PerturbationMatrixGen(n, k, trapPair.first, trapPair.second, s, &sigmaSqrt);
		DEBUG("keygen2.2:#"<< i << ": "<<TOC(t1) <<" ms");

		TIC(t1);
		Pk_vector->push_back(trapPair.first);
		Ek_vector->push_back(trapPair.second);

		sigma->push_back(sigmaSqrt);
		DEBUG("keygen2.3:#" << i << ": "<<TOC(t1) <<" ms");
	}
	DEBUG("keygen3: "<< TOC(t2) <<" ms");
	TIC(t1);
	obfuscatedPattern->SetKeys(Pk_vector,Ek_vector,sigma);
	DEBUG("keygen4: "<< TOC(t1) <<" ms");
#else //parallelized method
	// Initialize the Pk and Ek matrices.
	std::vector<Matrix<Element>> *Pk_vector = new std::vector<Matrix<Element>>();
	std::vector<RLWETrapdoorPair>   *Ek_vector = new std::vector<RLWETrapdoorPair>();
	std::vector<Matrix<LargeFloat>> *sigma = new std::vector<Matrix<LargeFloat>>();

	DEBUG("keygen1: "<<TOC(t1) <<" ms");
	DEBUG("l = "<<l);

	TIC(t1);
#pragma omp parallel // this is executed in parallel
	{
		TimeVar tp; // for TIC TOC
		//private copies of our vectors
		std::vector<Matrix<Element>> *Pk_vector_pvt = new std::vector<Matrix<Element>>();
		std::vector<RLWETrapdoorPair>   *Ek_vector_pvt = new std::vector<RLWETrapdoorPair>();
		std::vector<Matrix<LargeFloat>> *sigma_pvt = new std::vector<Matrix<LargeFloat>>();
#pragma omp for nowait schedule(static)
		for(int32_t i=0; i<=adjustedLength+1; i++) {
			//build private copies in parallel
			TIC(tp);
			std::pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev); //TODO remove stddev
			DEBUG("keygen2.0:#"<< i << ": "<<TOC(tp) <<" ms");

			TIC(tp);
			Matrix<LargeFloat> sigmaSqrt([](){ return make_unique<LargeFloat>(); }, n*(k+2), n*(k+2));
			DEBUG("keygen2.1:#"<< i << ": "<<TOC(tp) <<" ms");

			TIC(tp);
			//the following takes all the time
			RLWETrapdoorUtility::PerturbationMatrixGen(n, k, trapPair.first, trapPair.second, s, &sigmaSqrt);
			DEBUG("keygen2.2:#"<< i << ": "<<TOC(tp) <<" ms");

			TIC(tp);
			Pk_vector_pvt->push_back(trapPair.first);
			Ek_vector_pvt->push_back(trapPair.second);

			sigma_pvt->push_back(sigmaSqrt);

		}
        #pragma omp for schedule(static) ordered
		// now stitch them back together sequentially to preserve order of i
		for (int i=0; i<omp_get_num_threads(); i++) {
			#pragma omp ordered
			 Pk_vector->insert(Pk_vector->end(), Pk_vector_pvt->begin(), Pk_vector_pvt->end());
			 Ek_vector->insert(Ek_vector->end(), Ek_vector_pvt->begin(), Ek_vector_pvt->end());
			 sigma->insert(sigma->end(), sigma_pvt->begin(), sigma_pvt->end());

		}

	}
	DEBUG("keygen3: " <<TOC(t1) <<" ms");
	TIC(t1);
	obfuscatedPattern->SetKeys(Pk_vector,Ek_vector,sigma);
	DEBUG("keygen4: "<< TOC(t1) <<" ms");
#endif
}

template <class Element>
void LWEConjunctionObfuscationAlgorithmV2<Element>::Encode(
				const Matrix<Element> &Ai,
				const Matrix<Element> &Aj,
				const RLWETrapdoorPair &Ti,
				const Matrix<LargeFloat> &sigma,
				const Element &elemS,
				DiscreteGaussianGenerator &dgg,
				Matrix<Element> *encodedElem) const {

        TimeVar t1,t_total; // for TIC TOC
	bool dbg_flag = 0;//set to 0 for no debug statements

	TIC(t_total);	      // time the  overall Encode function with a timer;

	size_t m = Ai.GetCols();
	size_t k = m - 2;
	size_t n = elemS.GetParams().GetCyclotomicOrder()/2;
	const BigBinaryInteger &modulus = elemS.GetParams().GetModulus();
	const ElemParams &params = elemS.GetParams();
	auto zero_alloc = Element::MakeAllocator(&params, COEFFICIENT);

	//generate a row vector of discrete Gaussian ring elements
	//YSP this can be done using discrete Gaussian allocator later - after the dgg allocator is updated to use the same dgg instance
	//DBC all the following have insignificant timing
	Matrix<Element> ej(zero_alloc, 1, m); 

	for(size_t i=0; i<m; i++) {
		ej(0,i).SetValues(dgg.GenerateVector(n,modulus),COEFFICIENT);
		ej(0,i).SwitchFormat();
	}

	Matrix<Element> bj = Aj.ScalarMult(elemS) + ej;

	//std::cout << "Encode: Computed bj, next will do GaussSamp" << std::endl; 
	TIC(t1);	

	//DBC: this loop takes all the time in encode
	//TODO (dcousins): move gaussj generation out of the loop to enable parallelisation
	#pragma omp parallel for
	for(int32_t i=0; i<m; i++) {

	  // the following takes approx 250 msec
		Matrix<Element> gaussj = RLWETrapdoorUtility::GaussSamp(n,k,Ai,Ti,sigma,bj(0,i),dgg.GetStd(), dgg);
		// the following takes no time
		for(int32_t j=0; j<m; j++) {
			(*encodedElem)(j,i) = gaussj(j,0);

		}

	}

	DEBUG("Enc: " << " "  << TOC(t1) << " ms");

	// encodedElem->SwitchFormat();
	// std::cout<<"norm = "<<encodedElem->Norm() <<std::endl;
	// encodedElem->SwitchFormat();

	// //Test to make sure Ai*gaussj = bj(0,1)
	// Matrix<Element> test(zero_alloc, m, 1); 
	// for(size_t j=0; j<m; j++)
	// 	test(j,0) = (*encodedElem)(j,2);
	// ILVector2n bEst = (Ai * test)(0,0);
	// std::cout << "bj(0,2) = " << bj(0,2) << std::endl;
	// std::cout << "Ai*z = " << bEst << std::endl;
	DEBUG("EncTot: " << " "  << TOC(t_total) << " ms");

};

template <class Element>
void LWEConjunctionObfuscationAlgorithmV2<Element>::Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				DiscreteGaussianGenerator &dgg,
				BinaryUniformGenerator &dbg,
				ObfuscatedLWEConjunctionPatternV2<Element> *obfuscatedPattern) const {

	TimeVar t1; // for TIC TOC
	bool dbg_flag = 0;

	obfuscatedPattern->SetLength(clearPattern.GetLength());
	usint l = clearPattern.GetLength();
	usint n = obfuscatedPattern->GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern->GetModulus());
	usint m = obfuscatedPattern->GetLogModulus() + 2;
	usint chunkSize = obfuscatedPattern->GetChunkSize();
	usint adjustedLength = l/chunkSize;
	usint chunkExponent = 1 << chunkSize;
	const ElemParams *params = obfuscatedPattern->GetParameters();

	const std::string patternString = clearPattern.GetPatternString();

	//usint stddev = dgg.GetStd(); 

	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern->GetPublicKeys();
	const std::vector<RLWETrapdoorPair>   &Ek_vector = obfuscatedPattern->GetEncodingKeys();
	const std::vector<Matrix<LargeFloat>>   &Sigma = obfuscatedPattern->GetSigmaKeys();

	auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits + 2 \t m : " << m << std::endl;

	char val=0;

	// Initialize the s and r matrices.
	vector<vector<Element>> s_small;
	vector<vector<Element>> r_small;

	std::string wildcardChunk = std::string(chunkSize,'?');

	Element s_prod;
	//DBC: above setup has insignificant timing.

	//DBC: this loop has insignificant timing.
	for(usint i=0; i<=adjustedLength-1; i++) {

		//current chunk of cleartext pattern
		std::string chunk = patternString.substr(i*chunkSize,chunkSize);

		//Set the elements s and r to a discrete uniform generated vector.
		vector<Element> sVector;
		Element elems0(dbg,*params,EVALUATION);
		sVector.push_back(elems0);

		vector<Element> rVector;
		Element	elemr0(dbg,*params,EVALUATION);
		rVector.push_back(elemr0);

		//Determine wildcard or not.  If wildcard, copy s and r.  Else, don't copy.
		bool wildCard = (chunk == wildcardChunk);
		if (wildCard) {
			val = 1;
			for (usint k=0; k < chunkExponent; k++) {

				sVector.push_back(elems0);
				rVector.push_back(elemr0);

			}
		} else {
			for (usint k=0; k < chunkExponent; k++) {

				//Element elems1(dug,params,EVALUATION);
				Element elems1(dbg,*params,EVALUATION);
				sVector.push_back(elems1);

				//Element	elemr1(dug,params,EVALUATION);
				Element	elemr1(dbg,*params,EVALUATION);
				rVector.push_back(elemr1);

			}
		}
		
		const Element *vi = NULL;


		if (chunk != wildcardChunk) {
			int value = std::stoi(chunk,nullptr,2);
			std::cout << "chunk is " << chunk << std::endl;
			std::cout << "index is " << value << std::endl;
			vi = &sVector[value];
		}
		else
			vi = &sVector[0];
		
		if (i==0) {
			s_prod = *vi;
		} else {
			s_prod = (*vi) * s_prod;
		}

		s_small.push_back(sVector);
		r_small.push_back(rVector);

	}

	//DBC this setup has insignificant timing
	std::cout << "Obfuscate: Generated random uniform ring elements" << std::endl;

	std::vector<std::vector<Matrix<Element>>> *S_vec = new std::vector<std::vector<Matrix<Element>>>();
	std::vector<std::vector<Matrix<Element>>> *R_vec = new std::vector<std::vector<Matrix<Element>>>();

	//DBC: this loop takes all the time, so we time it with TIC TOC
	for(usint i=1; i<=adjustedLength; i++) {

		TIC(t1);

		std::vector<Matrix<Element>> SVector;
		std::vector<Matrix<Element>> RVector;

		for(usint k=0; k<chunkExponent; k++) {

			Matrix<Element> *S_i = new Matrix<Element>(zero_alloc, m, m);
			this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],s_small[i-1][k]*r_small[i-1][k],dgg,S_i);
			SVector.push_back(*S_i);

			Matrix<Element> *R_i = new Matrix<Element>(zero_alloc, m, m);
			this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],Sigma[i-1],r_small[i-1][k],dgg,R_i);
			RVector.push_back(*R_i);

		}

		S_vec->push_back(SVector);
		R_vec->push_back(RVector);

		std::cout << "encode round " << i << " completed" << std::endl;
		DEBUG("Obf1:#"<< i << ": "<<TOC(t1) <<" ms");
	}
	//the remainder of the code in this function also takes some time so time it
	TIC(t1);

	//std::cout << "encode started for L" << std::endl;

	Element	elemrl1(dbg,*params,EVALUATION);

	Matrix<Element> *Sl = new Matrix<Element>(zero_alloc, m, m);
	this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],Sigma[adjustedLength],elemrl1*s_prod,dgg,Sl);

	//std::cout << "encode 1 for L ran" << std::endl;
	//std::cout << elemrl1.GetValues() << std::endl;

	Matrix<Element> *Rl = new Matrix<Element>(zero_alloc, m, m);
	this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],Sigma[adjustedLength],elemrl1,dgg,Rl);

	//std::cout << "encode 2 for L ran" << std::endl;

	//Sl.PrintValues();
	//Rl.PrintValues();
	obfuscatedPattern->SetMatrices(S_vec,R_vec,Sl,Rl);

	//obfuscatedPattern->GetSl();
	DEBUG("Obf2: "<<TOC(t1) <<" ms");
};


template <class Element>
bool LWEConjunctionObfuscationAlgorithmV2<Element>::Evaluate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				const std::string &testString) const {
	//Evaluation of Clear Conjunction Pattern
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
bool LWEConjunctionObfuscationAlgorithmV2<Element>::Evaluate(
				const ObfuscatedLWEConjunctionPatternV2<Element> &obfuscatedPattern,
				const std::string &testString) const {
	//Evaluation of Obfuscated Conjunction Pattern
	TimeVar t1; // for TIC TOC
	bool dbg_flag = 0;
	TIC(t1);

	usint l = obfuscatedPattern.GetLength();
	usint n = obfuscatedPattern.GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern.GetModulus());
	usint m = obfuscatedPattern.GetLogModulus() + 2;
	usint chunkSize = obfuscatedPattern.GetChunkSize();
	usint adjustedLength = l/chunkSize;
	double constraint = obfuscatedPattern.GetConstraint();

	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern.GetPublicKeys();

	const ElemParams *params = obfuscatedPattern.GetParameters();

	auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits \t m : " << m << std::endl;
	std::cout << "Constraint \t : " << constraint << std::endl;

	bool retVal = true;
	std::string testVal;

	double norm = constraint;

	Matrix<Element> S_prod = Matrix<Element>(zero_alloc, m, m).Identity();
	Matrix<Element> R_prod = Matrix<Element>(zero_alloc, m, m).Identity();

	//S_prod.PrintValues();
	//R_prod.PrintValues();

	Matrix<Element> *S_ib;
	Matrix<Element> *R_ib;

	DEBUG("Eval1: "<<TOC(t1) <<" ms");

	for (usint i=0; i<adjustedLength; i++) 	{
		TIC(t1);

		//pragma omp parallel sections
		{
			{
				testVal = testString.substr(i*chunkSize,chunkSize);
				std::cout << " Index: " << i << std::endl;
				std::cout << " \t Input: \t" << testVal << std::endl;
			}
			S_ib = obfuscatedPattern.GetS(i,testVal);
			R_ib = obfuscatedPattern.GetR(i,testVal);

			//S_ib->PrintValues();
			//R_ib->PrintValues();

			S_prod = S_prod * (*S_ib);
			R_prod = R_prod * (*R_ib);
			//if (i==0)
			//	std::cout << "does identity work correctly" << (S_prod == *S_ib) << std::endl;
		}
		DEBUG("Eval2:#"<< i << ": " <<TOC(t1) <<" ms");
	}
	TIC(t1);	
	std::cout << " S_prod: " << std::endl;
	//S_prod.PrintValues();
	std::cout << " R_prod: " << std::endl;
	//R_prod.PrintValues();

	Matrix<Element>* Sl = obfuscatedPattern.GetSl();
	Matrix<Element>* Rl = obfuscatedPattern.GetRl();
	
	std::cout << " Sl: " << std::endl;
	//Sl->PrintValues();
	std::cout << " Rl: " << std::endl;
	//Rl->PrintValues();

	std::cout << " Cross Product: " << std::endl;
	Matrix<Element> CrossProd = Pk_vector[0]*((S_prod * (*Rl)) - (R_prod * (*Sl)));
	//CrossProd.PrintValues();


	DEBUG("Eval3: " <<TOC(t1) <<" ms");
	TIC(t1);	
	//for(size_t i=0; i<m; i++)
	//		CrossProd(0,i).SwitchFormat();

	//the norm can be estimated after all elements are converted to coefficient representation
	CrossProd.SwitchFormat();
	DEBUG("Eval4: " <<TOC(t1) <<" ms");
	TIC(t1);	
	//CrossProd.PrintValues();

	//std::cout << "cross product dimensions: " <<  CrossProd.GetRows() << ", " << CrossProd.GetCols() << std::endl;
	//std::cout <<  CrossProd << std::endl;

	norm = CrossProd.Norm();
	DEBUG("Eval5: " <<TOC(t1) <<" ms");

	std::cout << " Norm: " << norm << std::endl;

	return (norm <= constraint);

};

}
