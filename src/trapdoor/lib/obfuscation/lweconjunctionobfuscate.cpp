/**
 * @file lweconjunctionobfuscate.cpp Implementation of conjunction obfuscator as described in https://eprint.iacr.org/2017/844.pdf
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATEV3_CPP
#define LBCRYPTO_OBFUSCATE_LWECONJUNCTIONOBFUSCATEV3_CPP

#include "lweconjunctionobfuscate.h"

#include "utils/memory.h"
#include "utils/debug.h"
 
namespace lbcrypto {

template <class Element>
ClearLWEConjunctionPattern<Element>::ClearLWEConjunctionPattern(const std::string patternString) {
	m_patternString = patternString;
};

template <class Element>
std::string ClearLWEConjunctionPattern<Element>::GetPatternString() const {
	return m_patternString;
};

template <class Element>
void ClearLWEConjunctionPattern<Element>::SetPatternString(const std::string patternString) {
  this->m_patternString = patternString;
};

// Gets the character in the pattern  at a specific index
template <class Element>
char ClearLWEConjunctionPattern<Element>::GetIndex(usint loc) const {
	return (char)m_patternString[loc];
};

template <class Element>
usint ClearLWEConjunctionPattern<Element>::GetLength() const {
	return m_patternString.length();
};

// Serialize Operation
template<class Element>
bool ClearLWEConjunctionPattern<Element>::Serialize(Serialized* serObj) const {
  bool dbg_flag = true;
  if( !serObj->IsObject() ){
    DEBUG("ClearLWEConjunctionPattern::Serialize is obj failed");
    return false;
  }
  Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());

  obj.AddMember("PatternString", m_patternString, obj.GetAllocator());

  serObj->AddMember("ClearLWEConjunctionPattern", obj.Move(), serObj->GetAllocator());

  return true;
};


// Deserialize Operation
template<class  Element>
bool ClearLWEConjunctionPattern<Element>::Deserialize(const Serialized& serObj){
    bool dbg_flag= true;
    Serialized::ConstMemberIterator iMap = serObj.FindMember("ClearLWEConjunctionPattern");
    if (iMap == serObj.MemberEnd()) {
      DEBUG("clearLWEConjunctionPattern::Deserialize could not find ClearLWEConjunctionPattern<Element>");
      return false;
    }
    
    SerialItem::ConstMemberIterator pIt = iMap->value.FindMember("PatternString");
   
    
    if (pIt == iMap->value.MemberEnd()) {
      DEBUG("ClearLWEConjunctionPattern::Deserialize could not find PatternString");
      return false;
    }


    
    this->m_patternString= pIt->value.GetString();

    DEBUGEXP(this->m_patternString);
    return true;
};

























  
template <class Element>
ObfuscatedLWEConjunctionPattern<Element>::ObfuscatedLWEConjunctionPattern() {

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
ObfuscatedLWEConjunctionPattern<Element>::~ObfuscatedLWEConjunctionPattern() {}

template <class Element>
ObfuscatedLWEConjunctionPattern<Element>::ObfuscatedLWEConjunctionPattern(shared_ptr<typename Element::Params> elemParams, usint chunkSize) {

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
ObfuscatedLWEConjunctionPattern<Element>::ObfuscatedLWEConjunctionPattern(shared_ptr<typename Element::Params> elemParams) :
	ObfuscatedLWEConjunctionPattern(elemParams,1) {};

template <class Element>
void ObfuscatedLWEConjunctionPattern<Element>::SetLength(usint length) {
	m_length = length;
};

template <class Element>
const typename Element::Integer ObfuscatedLWEConjunctionPattern<Element>::GetModulus() const{
	typename Element::Integer q(m_elemParams->GetModulus());
	return q;
};

template <class Element>
usint ObfuscatedLWEConjunctionPattern<Element>::GetRingDimension() const{
	return (this->m_elemParams->GetRingDimension());
};

// Gets the log of the modulus
template <class Element>
usint ObfuscatedLWEConjunctionPattern<Element>::GetLogModulus() const{
	double val = this->m_elemParams->GetModulus().ConvertToDouble();
	//std::cout << "val : " << val << std::endl;
	usint logModulus = floor(log2(val-1.0)+1.0);// = this->m_elemParams.GetModulus();
	return logModulus;
};

// Sets the matrices that define the obfuscated pattern.
template <class Element>
void ObfuscatedLWEConjunctionPattern<Element>::SetMatrices(shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> S_vec,
	shared_ptr<vector<vector<shared_ptr<Matrix<Element>>>>> R_vec, shared_ptr<Matrix<Element>> Sl, shared_ptr<Matrix<Element>> Rl) {

	this->m_S_vec = S_vec;
	this->m_R_vec = R_vec;
	this->m_Sl = Sl;
	this->m_Rl = Rl;

}

template <class Element>
shared_ptr<Matrix<Element>>  ObfuscatedLWEConjunctionPattern<Element>::GetR(usint i, const std::string &testVal) const {

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	return this->m_R_vec->at(i).at(value);

}


template <class Element>
shared_ptr<Matrix<Element>>  ObfuscatedLWEConjunctionPattern<Element>::GetS(usint i, const std::string &testVal) const {

	//extract the string corresponding to chunk size
	int value = std::stoi(testVal,nullptr,2);

	return this->m_S_vec->at(i).at(value);
}


template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::ParamsGen(typename Element::DggType &dgg,
	ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern, uint32_t n) const {

	//smoothing parameter - also standard deviation for noise Elementnomials
	double sigma = SIGMA;
	
	//assurance measure
	double alpha = 36;

	//empirical parameter
	double beta = 2;

	//Bound of the Gaussian error Elementnomial
	double Berr = sigma*sqrt(alpha);

	//security parameter
	double hermiteFactor = obfuscatedPattern->GetRootHermiteFactor();

	uint32_t length = obfuscatedPattern->GetLength() / obfuscatedPattern->GetChunkSize();
	uint32_t base = obfuscatedPattern->GetBase();

	//Computes the root Hermite factor for given values of q and n
	auto delta = [&](uint32_t n, double q) { return pow(2,log2(q/sigma)/(4*n));  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//Correctness constraint
	auto qCorrectness = [&](uint32_t n, uint32_t m, uint32_t k) -> double { return  32*Berr*k*sqrt(n)*pow(sqrt(m*n)*beta*SPECTRAL_BOUND(n,m-2,base),length);  };

	double qPrev = 1e6;
	double q = 0;
	usint k = 0;
	usint m = 0;

	//If ring dimension was provided as input
	if ( n > 0 )
	{ 
		//initial value
		k = floor(log2(qPrev-1.0)+1.0);
		m = ceil(k / log2(base)) + 2;
		q = qCorrectness(n, m, k);

		//get a more accurate value of q
		while (std::abs(q - qPrev) > 0.001*q) {
			qPrev = q;
			k = floor(log2(qPrev - 1.0) + 1.0);
			m = ceil(k / log2(base)) + 2;
			q = qCorrectness(n, m, k);
		}
	}
	//compute ring dimension and modulus based on the root Hermite factor
	else
	{
		//initial values
		n = 512;
		k = floor(log2(qPrev - 1.0) + 1.0);
		m = ceil(k / log2(base)) + 2;
		q = qCorrectness(n, m, k);

		//needed if the more accurate value of q bumps up the ring dimension requirement
		//entered at most twice
		while (nRLWE(q) > n) {

			//get good estimates of n and q
			while (nRLWE(q) > n) {
				n = 2 * n;
				k = floor(log2(qPrev - 1.0) + 1.0);
				m = ceil(k / log2(base)) + 2;
				q = qCorrectness(n, m, k);
				qPrev = q;
			}

			//find a more accurate value of q for this value of n
			k = floor(log2(qPrev - 1.0) + 1.0);
			m = ceil(k / log2(base)) + 2;
			q = qCorrectness(n, m, k);
			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				k = floor(log2(qPrev - 1.0) + 1.0);
				m = ceil(k / log2(base)) + 2;
				q = qCorrectness(n, m, k);
			}

		}
	}

	//Prepare for parameters.
	auto params = GenerateElemParams(q, n);

	obfuscatedPattern->SetParameters(params);

	//Sets, update the root Hermite factor
	obfuscatedPattern->SetRootHermiteFactor(delta(n, q));

}

// Method to generate keys as described in Algorithm 5 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::KeyGen(typename Element::DggType &dgg,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern) const {
	TimeVar t1,t2; // for TIC TOC
	bool dbg_flag = false;
	TIC(t1);

	usint k = obfuscatedPattern->GetLogModulus();

	DEBUG("BitLength in KeyGen: " << k);

	//std::cout << "BitLength in KeyGen: " << k << std::endl;

	usint l = obfuscatedPattern->GetLength();
	const shared_ptr<typename Element::Params> params = obfuscatedPattern->GetParameters();
	usint chunkSize = obfuscatedPattern->GetChunkSize();
	usint base = obfuscatedPattern->GetBase();
	usint adjustedLength = l/chunkSize;
	usint stddev = dgg.GetStd(); 

	 //parallelized method
	// Initialize the Pk and Ek matrices.
	shared_ptr<std::vector<Matrix<Element>>> Pk_vector (new std::vector<Matrix<Element>>());
	shared_ptr<std::vector<RLWETrapdoorPair<Element>>>   Ek_vector (new std::vector<RLWETrapdoorPair<Element>>());

	DEBUG("keygen1: "<<TOC(t1) <<" ms");
	DEBUG("l = "<<l);

	TIC(t1);
//#pragma omp parallel // this is executed in parallel
	{
		TimeVar tp; // for TIC TOC
		//private copies of our vectors
		shared_ptr<std::vector<Matrix<Element>>> Pk_vector_pvt (new std::vector<Matrix<Element>>());
		shared_ptr<std::vector<RLWETrapdoorPair<Element>>>   Ek_vector_pvt (new std::vector<RLWETrapdoorPair<Element>>());
#pragma omp for nowait schedule(static)
		for(size_t i=0; i<=adjustedLength+1; i++) {
			//build private copies in parallel
			TIC(tp);
			std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> trapPair = RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base); //TODO remove stddev
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

// Directed encoding method as described in Algorithm 6 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
shared_ptr<Matrix<Element>> LWEConjunctionObfuscationAlgorithm<Element>::Encode(
				const Matrix<Element> &Ai,
				const Matrix<Element> &Aj,
				const RLWETrapdoorPair<Element> &Ti,
				const Element &elemS,
				typename Element::DggType &dgg,
				typename Element::DggType &dggLargeSigma,
				typename Element::DggType &dggEncoding,
				uint32_t base) const {

        TimeVar t1,t2, t3, t_total; // for TIC TOC
	bool dbg_flag = false;//set to 0 for no debug statements

	TIC(t_total);	      // time the  overall Encode function with a timer;
        TIC(t2);
	size_t m = Ai.GetCols();
	size_t k = m - 2;
	size_t n = elemS.GetRingDimension();
	//const typename Element::Integer &modulus = elemS.GetParams()->GetModulus();
	auto zero_alloc = Element::MakeAllocator(elemS.GetParams(), EVALUATION);

	//generate a row vector of discrete Gaussian ring elements
	//YSP this can be done using discrete Gaussian allocator later - after the dgg allocator is updated to use the same dgg instance
	//DBC all the following have insignificant timing
	Matrix<Element> ej(zero_alloc, 1, m); 

	#pragma omp parallel for
	for(size_t i=0; i<m; i++) {
		ej(0,i) = Element(dggEncoding, elemS.GetParams(), COEFFICIENT);
		//ej(0,i).SetValues(dggEncoding.GenerateVector(n,modulus),COEFFICIENT);
		ej(0,i).SwitchFormat();
	}

	const Matrix<Element> &bj = Aj.ScalarMult(elemS) + ej;

	//std::cout << "Encode: Computed bj, next will do GaussSamp" << std::endl;
	DEBUG("Enc2: " << " "  << TOC(t2) << " ms");
	TIC(t1);	

	shared_ptr<Matrix<Element>> result(new Matrix<Element>(zero_alloc, m, m));

	//DBC: this loop takes all the time in encode
	//TODO (dcousins): move gaussj generation out of the loop to enable parallelisation
	DEBUG("calling "<<m<<" gaussj");
	#pragma omp parallel for schedule(dynamic)
	for(size_t i=0; i<m; i++) {

	  // the following takes approx 250 msec
		const Matrix<Element> &gaussj = RLWETrapdoorUtility<Element>::GaussSamp(n,k,Ai,Ti,bj(0,i), dgg, dggLargeSigma, base);
		//std::cout << gaussj(0, 0) <<std::endl;
		//std::cout << gaussj(1, 0) <<std::endl;

		// the following takes no time
		for(size_t j=0; j<m; j++) {
		        //std::cout << gaussj(j, 0) <<std::endl;
			(*result)(j,i) = gaussj(j,0);
		}

	}

	DEBUG("Enc1: " << " "  << TOC(t1) << " ms");

	DEBUG("EncTot: " << " "  << TOC(t_total) << " ms");

	return result;

};

// Method to obfuscate the cleartext pattern into an obfuscated pattern.
// As described in Algorithm 7 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
void LWEConjunctionObfuscationAlgorithm<Element>::Obfuscate(
				const ClearLWEConjunctionPattern<Element> &clearPattern,
				typename Element::DggType &dgg,
				typename Element::TugType &tug,
				ObfuscatedLWEConjunctionPattern<Element> *obfuscatedPattern,
				bool optimized) const {

	TimeVar t1; // for TIC TOC
	bool dbg_flag = false;

	//obfuscatedPattern->SetLength(clearPattern.GetLength());
	usint l = obfuscatedPattern->GetLength();
	usint n = obfuscatedPattern->GetRingDimension();
	typename Element::Integer q(obfuscatedPattern->GetModulus());
	usint k = obfuscatedPattern->GetLogModulus();
	usint base = obfuscatedPattern->GetBase();
	usint m = ceil(k/log2(base)) + 2;
	usint chunkSize = obfuscatedPattern->GetChunkSize();
	usint adjustedLength = l/chunkSize;
	usint chunkExponent = 1 << chunkSize;
	const shared_ptr<typename Element::Params> params = obfuscatedPattern->GetParameters();

	double c = (base + 1) * SIGMA;
	double s = SPECTRAL_BOUND(n, m - 2, base);

	typename Element::DggType dggLargeSigma;

	if (sqrt(s * s - c * c) <= 3e5)
		dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
	else
		dggLargeSigma = dgg;

	typename Element::DggType dggEncoding;
	if (optimized)	
		dggEncoding = typename Element::DggType(k*sqrt(n)*SIGMA);
	else
		dggEncoding = typename Element::DggType(k*SIGMA*6*sqrt(n)*SIGMA);

	const std::string patternString = clearPattern.GetPatternString();

	//usint stddev = dgg.GetStd(); 

	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern->GetPublicKeys();
	const std::vector<RLWETrapdoorPair<Element>>   &Ek_vector = obfuscatedPattern->GetEncodingKeys();

	auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

	std::cout << "" << std::endl;
	std::cout << "Pattern length \t l : " << l << std::endl;
	std::cout << "Ring dimension \t n : " << n << std::endl;
	std::cout << "Modulus \t q : " << q << std::endl;
	std::cout << "Num bits \t k : " << k << std::endl;
	std::cout << "Num digits + 2 \t m : " << m << std::endl;

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

		// build a an inverse chunk mask that maps "10??" to "1100" - ones correspond to non-wildcard character 
		chunkTemp = replaceChar(chunk,'0','1');
		chunkTemp = replaceChar(chunkTemp,'?','0');
		// store the mask as integer for bitwise operations
		int inverseChunkMask = std::stoi(chunkTemp,nullptr,2);

		//std::cout << "inverse mask = " << inverseChunkMask << endl;

		vector<Element> sVector;
		vector<Element> rVector;

		Element elems1, elemr1;

		//cout << "before entering the loop " << endl;

		for (usint k=0; k < chunkExponent; k++) {

			//cout << "entered the loop " << endl;

			//cout << "k: " << k << "flag : " << (k & chunkMask) << endl;

			// if all wildcard bits are set to 0, then a new random element "s" needs to be created
			// otherwise use an existing one that has already been created
			if ((k & chunkMask)==0) {
				//cout << "entered the non-mask condition " << endl;
				if (optimized)
					elems1 = Element(tug,params,COEFFICIENT);
				else
					elems1 = Element(dgg,params,COEFFICIENT);
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
			
			if (optimized)
				elemr1 = Element(tug,params,COEFFICIENT);
			else
				elemr1 = Element(dgg,params,COEFFICIENT);
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

		std::vector<shared_ptr<Matrix<Element>>> SVector(chunkExponent);
		std::vector<shared_ptr<Matrix<Element>>> RVector(chunkExponent);

		for(usint k=0; k<chunkExponent; k++) {

			shared_ptr<Matrix<Element>> S_i = this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],s_small[i-1][k]*r_small[i-1][k],dgg, dggLargeSigma, dggEncoding, base);
			SVector[k] = S_i;

			shared_ptr<Matrix<Element>> R_i = this->Encode(Pk_vector[i-1],Pk_vector[i],Ek_vector[i-1],r_small[i-1][k],dgg, dggLargeSigma,dgg, base);
			RVector[k] = R_i;

		}

		S_vec->push_back(SVector);
		R_vec->push_back(RVector);

		std::cout << "encode round " << i << " completed" << std::endl;
		DEBUG("Obf1:#"<< i << ": "<<TOC(t1) <<" ms");
	}
	//the remainder of the code in this function also takes some time so time it
	TIC(t1);

	//std::cout << "encode started for L" << std::endl;

	Element elemrl1;

	if (optimized)
		elemrl1 = Element(tug,params,COEFFICIENT);
	else
		elemrl1 = Element(dgg,params,COEFFICIENT);
	//Convert to Evaluation representation
	elemrl1.SwitchFormat();

	shared_ptr<Matrix<Element>> Sl = 
		this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],elemrl1*s_prod,dgg, dggLargeSigma, dgg, base);

	//std::cout << "encode 1 for L ran" << std::endl;
	//std::cout << elemrl1.GetValues() << std::endl;

	shared_ptr<Matrix<Element>> Rl = 
		this->Encode(Pk_vector[adjustedLength],Pk_vector[adjustedLength+1],Ek_vector[adjustedLength],elemrl1,dgg, dggLargeSigma, dggEncoding, base);

	//std::cout << "encode 2 for L ran" << std::endl;

	//std::cout << Sl << std::endl;
	//std::cout << Rl << std::endl;
	obfuscatedPattern->SetMatrices(S_vec,R_vec,Sl,Rl);

	DEBUG("Obf2: "<<TOC(t1) <<" ms");
};

// Method for evaluating the pattern in cleartext

template <class Element>
bool LWEConjunctionObfuscationAlgorithm<Element>::Evaluate(
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

// Method for evaluating the pattern as described in Algorithm 8 of https://eprint.iacr.org/2017/844.pdf

template <class Element>
bool LWEConjunctionObfuscationAlgorithm<Element>::Evaluate(
				const ObfuscatedLWEConjunctionPattern<Element> &obfuscatedPattern,
				const std::string &testString) const {

	//Evaluation of Obfuscated Conjunction Pattern
	TimeVar t1; // for TIC TOC
	bool dbg_flag = false;
	TIC(t1);

	usint l = obfuscatedPattern.GetLength();
	//usint n = obfuscatedPattern.GetRingDimension();
	//typename Element::Integer q(obfuscatedPattern.GetModulus());
	usint k = obfuscatedPattern.GetLogModulus();
	usint base = obfuscatedPattern.GetBase();
	usint m = ceil(k/log2(base)) + 2;
	usint chunkSize = obfuscatedPattern.GetChunkSize();
	usint adjustedLength = l/chunkSize;
	double constraint = obfuscatedPattern.GetConstraint();

	const std::vector<Matrix<Element>> &Pk_vector = obfuscatedPattern.GetPublicKeys();

	const shared_ptr<typename Element::Params> params = obfuscatedPattern.GetParameters();

	auto zero_alloc = Element::MakeAllocator(params, EVALUATION);

	//std::cout << "" << std::endl;
	//std::cout << "Pattern length \t l : " << l << std::endl;
	//std::cout << "Ring dimension \t n : " << n << std::endl;
	//std::cout << "Modulus \t q : " << q << std::endl;
	//std::cout << "Num digits \t m : " << m << std::endl;
	//std::cout << "Constraint \t : " << constraint << std::endl;

	std::string testVal;

	double norm = constraint;

	Matrix<Element> S_prod = Matrix<Element>(zero_alloc,1,m);
	Matrix<Element> R_prod = Matrix<Element>(zero_alloc,1,m);
	S_prod = Pk_vector[0];
	R_prod = Pk_vector[0];

	//std::cout << S_prod << std::endl;
	//std::cout << R_prod << std::endl;

	shared_ptr<Matrix<Element>> S_ib;
	shared_ptr<Matrix<Element>> R_ib;

	DEBUG("Eval1: "<<TOC(t1) <<" ms");

	for (usint i=0; i<adjustedLength; i++) 	{
		TIC(t1);

		//pragma omp parallel sections
		{
			{
				testVal = testString.substr(i*chunkSize,chunkSize);
				//std::cout << " Index: " << i << std::endl;
				//std::cout << " \t Input: \t" << testVal << std::endl;
			}
			S_ib = obfuscatedPattern.GetS(i,testVal);
			R_ib = obfuscatedPattern.GetR(i,testVal);

			//std::cout << *S_ib << std::endl;
			//std::cout << *R_ib << std::endl;

			S_prod = S_prod * (*S_ib);
			R_prod = R_prod * (*R_ib);
			//if (i==0)
			//	std::cout << "does identity work correctly" << (S_prod == *S_ib) << std::endl;
		}
		DEBUG("Eval2:#"<< i << ": " <<TOC(t1) <<" ms");
	}
	TIC(t1);
	//std::cout << " S_prod: " << S_prod << std::endl;
	//std::cout << " R_prod: " << R_prod << std::endl;

	shared_ptr<Matrix<Element>> Sl = obfuscatedPattern.GetSl();
	shared_ptr<Matrix<Element>> Rl = obfuscatedPattern.GetRl();

	//std::cout << " Sl: " << *Sl << std::endl;
	//std::cout << " Rl: " << *Rl << std::endl;

	//std::cout << " Cross Product: " << std::endl;
	Matrix<Element> CrossProd = (S_prod * (*Rl)) - (R_prod * (*Sl));
	//std::cout << CrossProd << std::endl;

	DEBUG("Eval3: " <<TOC(t1) <<" ms");
	TIC(t1);

	//the norm can be estimated after all elements are converted to coefficient representation
	CrossProd.SwitchFormat();
	DEBUG("Eval4: " <<TOC(t1) <<" ms");
	TIC(t1);
	//std::cout << CrossProd << std::endl;

	//std::cout << "cross product dimensions: " <<  CrossProd.GetRows() << ", " << CrossProd.GetCols() << std::endl;
	//std::cout <<  CrossProd << std::endl;

	norm = CrossProd.Norm();
	DEBUG("Eval5: " <<TOC(t1) <<" ms");

	//std::cout << " Norm: " << norm << std::endl;

	return (norm <= constraint);

};

}
#endif
