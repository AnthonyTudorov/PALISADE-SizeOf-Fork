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
#include "lweconjunctionobfuscatev3.h"

#include "utils/memory.h"
#include "utils/debug.h"

namespace lbcrypto {

template <class Element>
ObfuscatedLWEConjunctionPatternV3<Element>::ObfuscatedLWEConjunctionPatternV3() {

	this->m_length = 0;
	this->m_chunkSize = 1;
	this->m_S_vec = NULL;

	this->m_R_vec = NULL;

	this->m_Sl = NULL;
	this->m_Rl = NULL;

	this->m_pk = NULL;
	this->m_ek = NULL;

}

template <class Element>
ObfuscatedLWEConjunctionPatternV3<Element>::~ObfuscatedLWEConjunctionPatternV3() {}

template <class Element>
ObfuscatedLWEConjunctionPatternV3<Element>::ObfuscatedLWEConjunctionPatternV3(shared_ptr<ElemParams> elemParams, usint chunkSize) {

	this->m_elemParams = elemParams;

	this->m_length = 0;
	this->m_chunkSize = chunkSize;

	this->m_S_vec = NULL;

	this->m_R_vec = NULL;

	this->m_Sl = NULL;
	this->m_Rl = NULL;

	this->m_pk = NULL;
	this->m_ek = NULL;
}

template <class Element>
ObfuscatedLWEConjunctionPatternV3<Element>::ObfuscatedLWEConjunctionPatternV3(shared_ptr<ElemParams> elemParams) :
	ObfuscatedLWEConjunctionPatternV3(elemParams,1) {};

template <class Element>
void ObfuscatedLWEConjunctionPatternV3<Element>::SetLength(usint length) {
	m_length = length;
};

template <class Element>
const BigBinaryInteger ObfuscatedLWEConjunctionPatternV3<Element>::GetModulus() const{
	BigBinaryInteger q(m_elemParams->GetModulus());
	return q;
};

template <class Element>
usint ObfuscatedLWEConjunctionPatternV3<Element>::GetRingDimension() const{
	return (this->m_elemParams->GetCyclotomicOrder())/2;
};

// Gets the log of the modulus
template <class Element>
usint ObfuscatedLWEConjunctionPatternV3<Element>::GetLogModulus() const{
	double val = this->m_elemParams->GetModulus().ConvertToDouble();
	//std::cout << "val : " << val << std::endl;
	double logTwo = log(val-1.0)/log(2)+1.0;
	//std::cout << "logTwo : " << logTwo << std::endl;
	usint logModulus = (usint) floor(logTwo);// = this->m_elemParams.GetModulus();
	return logModulus;
};

template <class Element>
void ObfuscatedLWEConjunctionPatternV3<Element>::SetModulus(BigBinaryInteger &modulus) {
	this->m_elemParams.SetModulus(modulus);
};

// Sets the matrices that define the obfuscated pattern.
template <class Element>
void ObfuscatedLWEConjunctionPatternV3<Element>::SetMatrices(shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> S_vec,
	shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> R_vec, shared_ptr<Matrix<Element>> Sl, shared_ptr<Matrix<Element>> Rl) {

	this->m_S_vec = S_vec;
	this->m_R_vec = R_vec;
	this->m_Sl = Sl;
	this->m_Rl = Rl;

}

template <class Element>
shared_ptr<Matrix<Element>>  ObfuscatedLWEConjunctionPatternV3<Element>::GetR(usint i, const std::string &testVal) const {

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	return this->m_R_vec->at(i).at(value);

}


template <class Element>
shared_ptr<Matrix<Element>>  ObfuscatedLWEConjunctionPatternV3<Element>::GetS(usint i, const std::string &testVal) const {

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	return this->m_S_vec->at(i).at(value);
}

template <class Element>
void LWEConjunctionObfuscationAlgorithmV3<Element>::ParamsGen(DiscreteGaussianGenerator &dgg,
	ObfuscatedLWEConjunctionPatternV3<Element> *obfuscatedPattern, uint32_t n) const {

	//smoothing parameter - also standard deviation for noise polynomials
	double sigma = SIGMA;
	
	//assurance measure
	double alpha = 9.0;

	//empirical parameter
	double beta = 6.0;

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//security parameter
	double hermiteFactor = obfuscatedPattern->GetRootHermiteFactor();

	uint32_t length = obfuscatedPattern->GetLength() / obfuscatedPattern->GetChunkSize();

	//Computes the root Hermite factor for given values of q and n
	auto delta = [&](uint32_t n, double q) { return pow(2,log2(q/sigma)/(4*n));  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//Correctness constraint
	auto qCorrectness = [&](uint32_t n, uint32_t m) -> double { return  32*Berr*pow(sqrt(m*n)*beta*SPECTRAL_BOUND(n,m-2),length);  };

	double qPrev = 1e6;
	double q = 0;

	//If ring dimension was provided as input
	if ( n > 0 )
	{ 
		//initial value
		q = qCorrectness(n, floor(log2(qPrev)+1)+2);

		//get a more accurate value of q
		while (std::abs(q - qPrev) > 0.001*q) {
			qPrev = q;
			q = qCorrectness(n, floor(log2(qPrev) + 1) + 2);
		}
	}
	//compute ring dimension and modulus based on the root Hermite factor
	else
	{
		//initial values
		n = 512;
		q = qCorrectness(n, floor(log2(qPrev) + 1) + 2);

		//needed if the more accurate value of q bumps up the ring dimension requirement
		//entered at most twice
		while (nRLWE(q) > n) {

			//get good estimates of n and q
			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qCorrectness(n, floor(log2(qPrev) + 1) + 2);
				qPrev = q;
			}

			//find a more accurate value of q for this value of n
			q = qCorrectness(n, floor(log2(qPrev) + 1) + 2);
			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qCorrectness(n, floor(log2(qPrev) + 1) + 2);
			}

		}
	}

	BigBinaryInteger qPrime = FindPrimeModulus(2 * n, floor(log2(q) + 1) + 1);
	BigBinaryInteger rootOfUnity = RootOfUnity(2 * n, qPrime);

	//Prepare for parameters.
	shared_ptr<ILParams> ilParams(new ILParams(2*n, qPrime, rootOfUnity));

	obfuscatedPattern->SetParameters(ilParams);

	//Sets, update the root Hermite factor
	obfuscatedPattern->SetRootHermiteFactor(delta(n, qPrime.ConvertToDouble()));

}

template <class Element>
void LWEConjunctionObfuscationAlgorithmV3<Element>::KeyGen(DiscreteGaussianGenerator &dgg,
				ObfuscatedLWEConjunctionPatternV3<Element> *obfuscatedPattern) const {
	TimeVar t1,t2; // for TIC TOC
	bool dbg_flag = false;
	TIC(t1);

	usint n = obfuscatedPattern->GetRingDimension();
	usint k = obfuscatedPattern->GetLogModulus();

	DEBUG("BitLength in KeyGen: " << k);

	//std::cout << "BitLength in KeyGen: " << k << std::endl;

	usint l = obfuscatedPattern->GetLength();
	const shared_ptr<ElemParams> params = obfuscatedPattern->GetParameters();
	usint chunkSize = obfuscatedPattern->GetChunkSize();
	usint adjustedLength = l/chunkSize;
	usint stddev = dgg.GetStd(); 

	 //parallelized method
	// Initialize the Pk and Ek matrices.
	shared_ptr<std::vector<Matrix<Element>>> Pk_vector (new std::vector<Matrix<Element>>());
	shared_ptr<std::vector<RLWETrapdoorPair<ILVector2n>>>   Ek_vector (new std::vector<RLWETrapdoorPair<ILVector2n>>());

	DEBUG("keygen1: "<<TOC(t1) <<" ms");
	DEBUG("l = "<<l);

	TIC(t1);
#pragma omp parallel // this is executed in parallel
	{
		TimeVar tp; // for TIC TOC
		//private copies of our vectors
		shared_ptr<std::vector<Matrix<Element>>> Pk_vector_pvt (new std::vector<Matrix<Element>>());
		shared_ptr<std::vector<RLWETrapdoorPair<ILVector2n>>>   Ek_vector_pvt (new std::vector<RLWETrapdoorPair<ILVector2n>>());
#pragma omp for nowait schedule(static)
		for(int32_t i=0; i<=adjustedLength+1; i++) {
			//build private copies in parallel
			TIC(tp);
			std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev); //TODO remove stddev
			DEBUG("keygen2.0:#"<< i << ": "<<TOC(tp) <<" ms");

			TIC(tp);
			Pk_vector_pvt->push_back(trapPair.first);
			Ek_vector_pvt->push_back(trapPair.second);

		}
        #pragma omp for schedule(static) ordered
		// now stitch them back together sequentially to preserve order of i
		for (int i=0; i<omp_get_num_threads(); i++) {
			#pragma omp ordered
			 Pk_vector->insert(Pk_vector->end(), Pk_vector_pvt->begin(), Pk_vector_pvt->end());
			 Ek_vector->insert(Ek_vector->end(), Ek_vector_pvt->begin(), Ek_vector_pvt->end());
		}

	}
	DEBUG("keygen3: " <<TOC(t1) <<" ms");
	TIC(t1);
	obfuscatedPattern->SetKeys(Pk_vector,Ek_vector);
	DEBUG("keygen4: "<< TOC(t1) <<" ms");

}

template <class Element>
shared_ptr<Matrix<Element>> LWEConjunctionObfuscationAlgorithmV3<Element>::Encode(
				const Matrix<Element> &Ai,
				const Matrix<Element> &Aj,
				const RLWETrapdoorPair<ILVector2n> &Ti,
				const Element &elemS,
				DiscreteGaussianGenerator &dgg,
				DiscreteGaussianGenerator &dggLargeSigma) const {

    TimeVar t1,t_total; // for TIC TOC
	bool dbg_flag = 0;//set to 0 for no debug statements

	TIC(t_total);	      // time the  overall Encode function with a timer;

	size_t m = Ai.GetCols();
	size_t k = m - 2;
	size_t n = elemS.GetParams()->GetCyclotomicOrder()/2;
	const BigBinaryInteger &modulus = elemS.GetParams()->GetModulus();
	auto zero_alloc = Element::MakeAllocator(elemS.GetParams(), COEFFICIENT);

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

	shared_ptr<Matrix<Element>> result(new Matrix<Element>(zero_alloc, m, m));

	//DBC: this loop takes all the time in encode
	//TODO (dcousins): move gaussj generation out of the loop to enable parallelisation
	#pragma omp parallel for
	for(int32_t i=0; i<m; i++) {

	  // the following takes approx 250 msec
		Matrix<Element> gaussj = RLWETrapdoorUtility::GaussSampV3(n,k,Ai,Ti,bj(0,i),dgg.GetStd(), dgg, dggLargeSigma);
//		gaussj(0, 0).PrintValues();
//		gaussj(1, 0).PrintValues();
		// the following takes no time
		for(int32_t j=0; j<m; j++) {
//			gaussj(j, 0).PrintValues();
			(*result)(j,i) = gaussj(j,0);
		}

	}

	DEBUG("Enc: " << " "  << TOC(t1) << " ms");
	DEBUG("EncTot: " << " "  << TOC(t_total) << " ms");

	return result;

};

template <class Element>
void LWEConjunctionObfuscationAlgorithmV3<Element>::Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				DiscreteGaussianGenerator &dgg,
				TernaryUniformGenerator &tug,
				ObfuscatedLWEConjunctionPatternV3<Element> *obfuscatedPattern) const {

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
	const shared_ptr<ElemParams> params = obfuscatedPattern->GetParameters();

	double c = 2 * SIGMA;
	double s = SPECTRAL_BOUND(n, m - 2);

	DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));

	const std::string patternString = clearPattern.GetPatternString();

	//usint stddev = dgg.GetStd(); 

	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern->GetPublicKeys();
	const std::vector<RLWETrapdoorPair<ILVector2n>>   &Ek_vector = obfuscatedPattern->GetEncodingKeys();

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

	Element s_prod;
	//DBC: above setup has insignificant timing.

	//DBC: this loop has insignificant timing.
	for(usint i=0; i<=adjustedLength-1; i++) {

		// current chunk of cleartext pattern
		std::string chunk = patternString.substr(i*chunkSize,chunkSize);

		// build a chunk mask that maps "10??" to "0011" - ones correspond to wildcard character 
		std::string chunkTemp = replaceChar(chunk,'1','0');
		chunkTemp = replaceChar(chunkTemp,'?','1');

		// store the mask as integer for bitwise operations
		int chunkMask = std::stoi(chunkTemp,nullptr,2);

		//std::cout << "mask = " << chunkMask << endl;

		// build a an inverse chunk mask that maps "10??" to "1100" - ones correspond to wildcard character 
		chunkTemp = replaceChar(chunk,'0','1');
		chunkTemp = replaceChar(chunkTemp,'?','0');
		// store the mask as integer for bitwise operations
		int inverseChunkMask = std::stoi(chunkTemp,nullptr,2);

		//std::cout << "inverse mask = " << inverseChunkMask << endl;

		vector<Element> sVector;
		vector<Element> rVector;

		//cout << "before entering the loop " << endl;

		for (usint k=0; k < chunkExponent; k++) {

			//cout << "entered the loop " << endl;

			//cout << "k: " << k << "flag : " << (k & chunkMask) << endl;

			// if all wildcard bits are set to 0, then a new random element "s" needs to be created
			// otherwise use an existing one that has already been created
			if ((k & chunkMask)==0) {
				//cout << "entered the non-mask condition " << endl;
				Element elems1(tug,params,COEFFICIENT);
				//Convert to Evaluation representation
				elems1.SwitchFormat();
				sVector.push_back(elems1);
			}
			else
			{
				//cout << "entered the mask condition " << endl;
				Element elems1 = sVector[k & inverseChunkMask];
				sVector.push_back(elems1);
			}
			
			Element elemr1(tug,params,COEFFICIENT);
			//Convert to Evaluation representation
			elemr1.SwitchFormat();
			rVector.push_back(elemr1);

		}

		//cout << "done with the loop " << endl;
		
		const Element *vi = NULL;

		// get current value for s vector replacing each "?" with 0
		chunkTemp = replaceChar(chunk,'?','0');
		// store the mask as integer for bitwise operations
		int chunkValue = std::stoi(chunkTemp,nullptr,2);

		//std::cout << "value = " << chunkValue << endl;

		vi = &sVector[chunkValue];
		
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

	shared_ptr<std::vector<std::vector<shared_ptr<Matrix<Element>>>>> S_vec (new std::vector<std::vector<shared_ptr<Matrix<Element>>>>());
	shared_ptr<std::vector<std::vector<shared_ptr<Matrix<Element>>>>> R_vec (new std::vector<std::vector<shared_ptr<Matrix<Element>>>>());

	//DBC: this loop takes all the time, so we time it with TIC TOC
	for(usint i=1; i<=adjustedLength; i++) {

		TIC(t1);

		std::vector<shared_ptr<Matrix<Element>>> SVector;
		std::vector<shared_ptr<Matrix<Element>>> RVector;

		for(usint k=0; k<chunkExponent; k++) {

			shared_ptr<Matrix<Element>> S_i = this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],s_small[i-1][k]*r_small[i-1][k],dgg, dggLargeSigma);
			SVector.push_back(S_i);

			shared_ptr<Matrix<Element>> R_i = this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],r_small[i-1][k],dgg, dggLargeSigma);
			RVector.push_back(R_i);

		}

		S_vec->push_back(SVector);
		R_vec->push_back(RVector);

		std::cout << "encode round " << i << " completed" << std::endl;
		DEBUG("Obf1:#"<< i << ": "<<TOC(t1) <<" ms");
	}
	//the remainder of the code in this function also takes some time so time it
	TIC(t1);

	//std::cout << "encode started for L" << std::endl;

	Element	elemrl1(tug,params,COEFFICIENT);
	//Convert to Evaluation representation
	elemrl1.SwitchFormat();

	shared_ptr<Matrix<Element>> Sl = 
		this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],elemrl1*s_prod,dgg, dggLargeSigma);

	//std::cout << "encode 1 for L ran" << std::endl;
	//std::cout << elemrl1.GetValues() << std::endl;

	shared_ptr<Matrix<Element>> Rl = 
		this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],elemrl1,dgg, dggLargeSigma);

	//std::cout << "encode 2 for L ran" << std::endl;

	//Sl.PrintValues();
	//Rl.PrintValues();
	obfuscatedPattern->SetMatrices(S_vec,R_vec,Sl,Rl);

	DEBUG("Obf2: "<<TOC(t1) <<" ms");
};


template <class Element>
bool LWEConjunctionObfuscationAlgorithmV3<Element>::Evaluate(
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
bool LWEConjunctionObfuscationAlgorithmV3<Element>::Evaluate(
				const ObfuscatedLWEConjunctionPatternV3<Element> &obfuscatedPattern,
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

	const shared_ptr<ElemParams> params = obfuscatedPattern.GetParameters();

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

	shared_ptr<Matrix<Element>> S_ib;
	shared_ptr<Matrix<Element>> R_ib;

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
	//std::cout << " S_prod: " << std::endl;
	//S_prod.PrintValues();
	//std::cout << " R_prod: " << std::endl;
	//R_prod.PrintValues();

	shared_ptr<Matrix<Element>> Sl = obfuscatedPattern.GetSl();
	shared_ptr<Matrix<Element>> Rl = obfuscatedPattern.GetRl();
	
	//std::cout << " Sl: " << std::endl;
	//Sl->PrintValues();
	//std::cout << " Rl: " << std::endl;
	//Rl->PrintValues();

	//std::cout << " Cross Product: " << std::endl;
	Matrix<Element> CrossProd = Pk_vector[0]*((S_prod * (*Rl)) - (R_prod * (*Sl)));
	//CrossProd.PrintValues();


	DEBUG("Eval3: " <<TOC(t1) <<" ms");
	TIC(t1);

	//the norm can be estimated after all elements are converted to coefficient representation
	CrossProd.SwitchFormat();
	//DEBUG("Eval4: " <<TOC(t1) <<" ms");
	//TIC(t1);
	//CrossProd.PrintValues();

	//std::cout << "cross product dimensions: " <<  CrossProd.GetRows() << ", " << CrossProd.GetCols() << std::endl;
	//std::cout <<  CrossProd << std::endl;

	norm = CrossProd.Norm();
	DEBUG("Eval: " <<TOC(t1) <<" ms");

	std::cout << " Original Norm: " << norm << std::endl;

	return (norm <= constraint);

};


template <class Element>
bool LWEConjunctionObfuscationAlgorithmV3<Element>::EvaluateACS(
				const ObfuscatedLWEConjunctionPatternV3<Element> &obfuscatedPattern,
				const std::string &testString, const int useRandomVector) const {
	//Evaluation of Obfuscated Conjunction Pattern
	TimeVar t1; // for TIC TOC
	bool dbg_flag = 1;
	TIC(t1);

	usint l = obfuscatedPattern.GetLength();
	usint n = obfuscatedPattern.GetRingDimension();
	BigBinaryInteger q(obfuscatedPattern.GetModulus());
	usint m = obfuscatedPattern.GetLogModulus() + 2;
	usint chunkSize = obfuscatedPattern.GetChunkSize();
	usint adjustedLength = l/chunkSize;
	double constraint = obfuscatedPattern.GetConstraint();


	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern.GetPublicKeys();

	const shared_ptr<ElemParams> params = obfuscatedPattern.GetParameters();

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



	shared_ptr<Matrix<Element>> S_ib;
	shared_ptr<Matrix<Element>> R_ib;
	Matrix<Element> CrossSR = Matrix<Element>(zero_alloc, m, 1);
	Matrix<Element> CrossRS = Matrix<Element>(zero_alloc, m, 1);

	shared_ptr<Matrix<Element>> Sl = obfuscatedPattern.GetSl();
	shared_ptr<Matrix<Element>> Rl = obfuscatedPattern.GetRl();
	std::cout << "Sl dimensions: " <<  Sl->GetRows() << ", " << Sl->GetCols() << std::endl;
	std::cout << "Rl dimensions: " <<  Rl->GetRows() << ", " << Rl->GetCols() << std::endl;
	if (useRandomVector == 1) {
		std::vector<int> randvec;
		randvec.reserve(Rl->GetCols());
		for (int i = 0; i < Rl->GetCols(); i++) {
			randvec.push_back(rand() % 2);
		}
		std::cout<<"About to set CrossSR and CrossRS from randvec"<<std::endl;
		CrossSR = Rl->MultByRandomVector(randvec);
		CrossRS = Sl->MultByRandomVector(randvec);
	} else {
		std::cout<<"About to set CrossSR and CrossRS from unity vec"<<std::endl;
		CrossSR = Rl->MultByUnityVector();
		CrossRS = Sl->MultByUnityVector();
	}
	std::cout << "CrossSR dimensions: " <<  CrossSR.GetRows() << ", " << CrossSR.GetCols() << std::endl;
	std::cout << "CrossRS dimensions: " <<  CrossRS.GetRows() << ", " << CrossRS.GetCols() << std::endl;
	//DEBUG("EvalACS1: "<<TOC(t1) <<" ms");

	for (int i=adjustedLength-1; i>=0; i--) 	{
		//TIC(t1);

		//pragma omp parallel sections
		{
			{
				testVal = testString.substr(i*chunkSize,chunkSize);
				//std::cout << " Index: " << i << std::endl;
				//std::cout << " \t Input: \t" << testVal << std::endl;
			}
			S_ib = obfuscatedPattern.GetS(i,testVal);
			R_ib = obfuscatedPattern.GetR(i,testVal);
			//std::cout << "S_ib dimensions: " <<  S_ib->GetRows() << ", " << S_ib->GetCols() << std::endl;
			//std::cout << "R_ib dimensions: " <<  R_ib->GetRows() << ", " << R_ib->GetCols() << std::endl;
			//S_ib->PrintValues();
			//R_ib->PrintValues();

			CrossSR = (*S_ib) * (CrossSR);

			CrossRS = (*R_ib) * (CrossRS);


		}
		//DEBUG("EvalACS2:#"<< i << ": " <<TOC(t1) <<" ms");
	}
	//TIC(t1);

	//std::cout << "Final CrossSR dimensions: " <<  CrossSR.GetRows() << ", " << CrossSR.GetCols() << std::endl;
	//std::cout << "Final CrossRS dimensions: " <<  CrossRS.GetRows() << ", " << CrossRS.GetCols() << std::endl;

	//std::cout << "Pk_vector[0] dimensions: " <<  Pk_vector[0].GetRows() << ", " << Pk_vector[0].GetCols() << std::endl;
	Matrix<Element> CrossProd = Pk_vector[0]*(CrossSR - CrossRS);



	//DEBUG("EvalACS3: " <<TOC(t1) <<" ms");
	//TIC(t1);

	//the norm can be estimated after all elements are converted to coefficient representation
	CrossProd.SwitchFormat();
	//DEBUG("EvalACS4: " <<TOC(t1) <<" ms");
	//TIC(t1);


	//std::cout << "cross product dimensions: " <<  CrossProd.GetRows() << ", " << CrossProd.GetCols() << std::endl;
	//std::cout <<  CrossProd << std::endl;

	norm = CrossProd.Norm();
	std::cout <<"EvalACS: " <<TOC(t1) <<" ms"<< std::endl;

	std::cout << "ACS Norm: " << norm << std::endl;

	return (norm <= constraint);

};


template <class Element>
bool LWEConjunctionObfuscationAlgorithmV3<Element>::EvaluateFast(
				const ObfuscatedLWEConjunctionPatternV3<Element> &obfuscatedPattern,
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

	const shared_ptr<ElemParams> params = obfuscatedPattern.GetParameters();

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

	Matrix<Element> S_prod = Matrix<Element>(zero_alloc,1,m);
	Matrix<Element> R_prod = Matrix<Element>(zero_alloc,1,m);
	S_prod = Pk_vector[0];
	R_prod = Pk_vector[0];

	//S_prod.PrintValues();
	//R_prod.PrintValues();

	shared_ptr<Matrix<Element>> S_ib;
	shared_ptr<Matrix<Element>> R_ib;

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

	shared_ptr<Matrix<Element>> Sl = obfuscatedPattern.GetSl();
	shared_ptr<Matrix<Element>> Rl = obfuscatedPattern.GetRl();

	std::cout << " Sl: " << std::endl;
	//Sl->PrintValues();
	std::cout << " Rl: " << std::endl;
	//Rl->PrintValues();

	std::cout << " Cross Product: " << std::endl;
	Matrix<Element> CrossProd = (S_prod * (*Rl)) - (R_prod * (*Sl));
	//CrossProd.PrintValues();


	DEBUG("Eval3: " <<TOC(t1) <<" ms");
	TIC(t1);

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
