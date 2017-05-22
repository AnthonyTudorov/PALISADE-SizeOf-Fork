/*
  PRE SCHEME PROJECT, Crypto Lab, NJIT
  Version:
  v00.01
  Last Edited:
  11/15/2015
  List of Authors:
  TPOC:
  Dr. Kurt Rohloff, rohloff@njit.edu
  Programmers:
  Dr. Yuriy Polyakov, polyakov@njit.edu
  Gyana Sahu, grs22@njit.edu
  Nishanth Pasham, np386@njit.edu
  Dr. David Bruce Cousins, dcousins@bbn.com
  Description:
  This code exercises the math libraries of the PALISADE lattice encryption library.

  License Information:

  Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
  All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "sampling/trapdoor.h"
//#include "../../../src/lib/lattice/trapdoor.cpp"
#include "obfuscation/lweconjunctionobfuscatev3.h"
#include "obfuscation/lweconjunctionobfuscatev3.cpp"

//using namespace std;
using namespace lbcrypto;


class UnitTestTrapdoor : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF TRAPDOOR CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

#if 0 //TODO DBC FUNCTION IS UNUSED
static function<unique_ptr<ILVector2n>()> fastIL2nAlloc() {
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
    return ILVector2n::MakeAllocator(
        ILParams(
        m, modulus, rootOfUnity),
        EVALUATION
        );
}
#endif

TEST(UTTrapdoor,randomized_round){
    //  It compiles! ...
    //RandomizeRound(0, 4.3, 1024);
}



TEST(UTTrapdoor,sizes){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> fastParams( new ILParams(m, modulus, rootOfUnity) );
	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(fastParams, stddev);

	EXPECT_EQ(1,trapPair.first.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k+2,trapPair.first.GetCols())
		<< "Failure testing number of colums";

	EXPECT_EQ(1,trapPair.second.m_r.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapPair.second.m_r.GetCols())
		<< "Failure testing number of colums";

	EXPECT_EQ(1,trapPair.second.m_e.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapPair.second.m_e.GetCols())
		<< "Failure testing number of colums";


}

TEST(UTTrapdoor,TrapDoorPairTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
    RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.VStack(rHat);
	//stackedTrap2.PrintValues();

	EXPECT_EQ(2,stackedTrap1.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,stackedTrap1.GetCols())
		<< "Failure testing number of colums";

	RingMat stackedTrap2 = stackedTrap1.VStack(eyeKK);

	EXPECT_EQ(k+2,stackedTrap2.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,stackedTrap2.GetCols())
		<< "Failure testing number of colums";

        //RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();
}

TEST(UTTrapdoor,GadgetTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

        RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

	EXPECT_EQ(1,g.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,g.GetCols())
		<< "Failure testing number of colums";
}


TEST(UTTrapdoor,TrapDoorMultTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
    RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.VStack(rHat);
	RingMat stackedTrap2 = stackedTrap1.VStack(eyeKK);

	RingMat trapMult = (trapPair.first)*(stackedTrap2);
	EXPECT_EQ(1,trapMult.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapMult.GetCols())
		<< "Failure testing number of colums";

    RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();
    EXPECT_EQ(g, trapMult);
}

TEST(UTTrapdoor,TrapDoorGaussGqSampTest) {
	usint m = 16;
    usint n = m/2;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	//BigBinaryInteger modulus("134218081");
	//BigBinaryInteger rootOfUnity("19091337");
	//BigBinaryInteger modulus("1048609");
	//BigBinaryInteger rootOfUnity("389832");
	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
	double sigma = SIGMA;

	ILVector2n::DggType dgg(sigma);
	ILVector2n::DugType dug = ILVector2n::DugType();
	dug.SetModulus(modulus);

	ILVector2n u(dug,params,COEFFICIENT);

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	//YSP check logTwo computation
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);

	Matrix<int32_t> zHatBBI([](){ return make_unique<int32_t>(); },  k, m/2);

	LatticeGaussSampUtility::GaussSampGq(u,sigma,k,modulus, 2,dgg,&zHatBBI);

	EXPECT_EQ(k,zHatBBI.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(u.GetLength(),zHatBBI.GetCols())
		<< "Failure testing number of colums";
    Matrix<ILVector2n> z = SplitInt32AltIntoILVector2nElements(zHatBBI, n, params);
	z.SwitchFormat();

	ILVector2n uEst;
	uEst = (Matrix<ILVector2n>(zero_alloc, 1,  k).GadgetVector()*z)(0,0);
	uEst.SwitchFormat();

    EXPECT_EQ(u, uEst);

}

// Test of Gaussian Sampling using the UCSD integer perturbation sampling algorithm
TEST(UTTrapdoor, TrapDoorGaussSampTest) {

	usint m = 16;
	usint n = m / 2;

	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	double sigma = SIGMA;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	usint k = (usint)floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));
	//auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, sigma);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
	//auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, EVALUATION);

	ILVector2n::DggType dgg(sigma);
	ILVector2n::DugType dug = ILVector2n::DugType();
	dug.SetModulus(modulus);

	double c = 2 * SIGMA;
	double s = SPECTRAL_BOUND(n, k);
	ILVector2n::DggType dggLargeSigma(sqrt(s * s - c * c));

	ILVector2n u(dug, params, COEFFICIENT);
	u.SwitchFormat();

	RingMat z = RLWETrapdoorUtility::GaussSamp(m / 2, k, trapPair.first, trapPair.second, u, sigma, dgg, dggLargeSigma);

	//Matrix<ILVector2n> uEst = trapPair.first * z;

	EXPECT_EQ(trapPair.first.GetCols(), z.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(m / 2, z(0, 0).GetLength())
		<< "Failure testing ring dimension for the first ring element";

	ILVector2n uEst = (trapPair.first * z)(0, 0);
	uEst.SwitchFormat();
	u.SwitchFormat();

	EXPECT_EQ(u, uEst);

	//std::cout << z << std::endl;

}

// Test  UCSD integer perturbation sampling algorithm
// So far the test simply runs 100 instances of ZSampleSigmaP
// and makes sure no exceptions are encountered - this validates that
// covariance matrices at all steps are positive definite 
TEST(UTTrapdoor, TrapDoorPerturbationSamplingTest) {

	//usint m = 2048;
	usint m = 16;
	//usint m = 8192;
	usint n = m / 2;

	//for m = 16
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");

	//for m = 2048
	//BigBinaryInteger modulus("134246401");
	//BigBinaryInteger rootOfUnity("34044212");

	//for m = 2^13
	//BigBinaryInteger modulus("268460033");
	//BigBinaryInteger rootOfUnity("154905983");

	//BigBinaryInteger modulus("1237940039285380274899136513");
	//BigBinaryInteger rootOfUnity("977145384161930579732228319");

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	usint k = (usint)floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	//smoothing parameter
	//double c(2 * sqrt(log(2 * n*(1 + 1 / DG_ERROR)) / M_PI));
	double c = 2 * SIGMA;

	//spectral bound s
	double s = SPECTRAL_BOUND(n, k);

	//std::cout << "sigma = " << SIGMA << std::endl;
	//std::cout << "s = " << s << std::endl;

	//Generate the trapdoor pair
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	double sigma = SIGMA;

	//std::cout << 50 / (c*sigma) << std::endl;

	std::pair<RingMat, RLWETrapdoorPair<ILVector2n>> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, sigma);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;

	ILVector2n::DggType dgg(sigma);
	ILVector2n::DugType dug = ILVector2n::DugType();
	dug.SetModulus(modulus);

	ILVector2n::DggType dggLargeSigma(sqrt(s * s - c * c));

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	auto singleAlloc = [=]() { return make_unique<BigBinaryVector>(1, modulus); };

	//Do perturbation sampling
	RingMat pHat(zero_alloc, k + 2, 1);

	Matrix<int32_t> p([]() { return make_unique<int32_t>(); }, (2 + k)*n, 1);

	Matrix<int32_t> pCovarianceMatrix([]()  { return make_unique<int32_t>(); }, 2*n, 2*n);;

	//std::vector<Matrix<int32_t>> pTrapdoors;

	Matrix<int32_t> pTrapdoor([]() { return make_unique<int32_t>(); }, 2 * n, 1);

	Matrix<BigBinaryInteger> bbiTrapdoor(BigBinaryInteger::Allocator, 2*n, 1);

	Matrix<int32_t> pTrapdoorAverage([]() { return make_unique<int32_t>(); }, 2 * n, 1);

	size_t count = 100;

	for (size_t i = 0; i < count; i++) {
		RLWETrapdoorUtility::ZSampleSigmaP(n, s, c, trapPair.second, dgg, dggLargeSigma, &pHat);

		//convert to coefficient representation
		pHat.SwitchFormat();

		for (size_t j = 0; j < n; j++) {
			bbiTrapdoor(j, 0) = pHat(0, 0).GetValues().GetValAtIndex(j);
			bbiTrapdoor(j+n, 0) = pHat(1, 0).GetValues().GetValAtIndex(j);
		}

		pTrapdoor = ConvertToInt32(bbiTrapdoor, modulus);

		for (size_t j = 0; j < 2 * n; j++) {
			pTrapdoorAverage(j, 0) = pTrapdoorAverage(j, 0) + pTrapdoor(j, 0);
		}
		//pTrapdoors.push_back(pTrapdoor);
		
		pCovarianceMatrix = pCovarianceMatrix + pTrapdoor*pTrapdoor.Transpose();
	}

	Matrix<ILVector2n> Tprime0 = eHat;
	Matrix<ILVector2n> Tprime1 = rHat;

	// all three polynomials are initialized with "0" coefficients
	ILVector2n va(params, EVALUATION, 1);
	ILVector2n vb(params, EVALUATION, 1);
	ILVector2n vd(params, EVALUATION, 1);

	for (size_t i = 0; i < k; i++) {
		va = va + Tprime0(0, i)*Tprime0(0, i).Transpose();
		vb = vb + Tprime1(0, i)*Tprime0(0, i).Transpose();
		vd = vd + Tprime1(0, i)*Tprime1(0, i).Transpose();
	}

	//Switch the ring elements (polynomials) to coefficient representation
	va.SwitchFormat();
	vb.SwitchFormat();
	vd.SwitchFormat();

	//Create field elements from ring elements
	Field2n a(va), b(vb), d(vd);

	double scalarFactor = -s * s * c * c / (s * s - c * c);

	a = a.ScalarMult(scalarFactor);
	b = b.ScalarMult(scalarFactor);
	d = d.ScalarMult(scalarFactor);

	a = a + s*s;
	d = d + s*s;

	//for (size_t j = 0; j < 2 * n; j++) {
	//	pTrapdoorAverage(j, 0) = pTrapdoorAverage(j, 0) / count;
	//}

	//std::cout << a << std::endl;

	Matrix<int32_t> meanMatrix = pTrapdoorAverage*pTrapdoorAverage.Transpose();

	//std::cout << (double(pCovarianceMatrix(0, 0)) - meanMatrix(0, 0))/ count << std::endl;
	//std::cout << (double(pCovarianceMatrix(1, 0)) - meanMatrix(1, 0)) / count << std::endl;
	//std::cout << (double(pCovarianceMatrix(2, 0)) - meanMatrix(2, 0)) / count << std::endl;
	//std::cout << (double(pCovarianceMatrix(3, 0)) - meanMatrix(3, 0)) / count << std::endl;

}


//TEST(UTTrapdoor,EncodeTest_dgg_yes) {
//	bool dbg_flag = false;
//
//	usint m_cyclo = 16;
//	usint n = m_cyclo/2;
//
//	BigBinaryInteger modulus("67108913");
//	BigBinaryInteger rootOfUnity("61564");
//	float stddev = 4;
//	usint chunkSize = 1;
//
//	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
//	double logTwo = log(val-1.0)/log(2)+1.0;
//	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
//
//	double norm = 0;
//
//	shared_ptr<ILParams> params( new ILParams(m_cyclo, modulus, rootOfUnity) );
//    	//auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);
//
//	DiscreteGaussianGenerator dgg(4);
//
//	// Precomputations for DGG
//	ILVector2n::PreComputeDggSamples(dgg, params);
//
//	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(params,chunkSize);
//	obfuscatedPattern.SetLength(1);
//
//	usint m = obfuscatedPattern.GetLogModulus() + 2;
//
//	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigBinaryInteger(m));
//
//	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;
//
//	algorithm.KeyGen(dgg,&obfuscatedPattern);
//
//	const std::vector<Matrix<ILVector2n>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
//	const std::vector<RLWETrapdoorPair<ILVector2n>>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
//
//	double constraint = obfuscatedPattern.GetConstraint();
//
//	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
//
//	ILVector2n	s1(dgg,params,EVALUATION);
//
//	Matrix<ILVector2n> *encoded1 = new Matrix<ILVector2n>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);
//
//	Matrix<ILVector2n> *encoded2 = new Matrix<ILVector2n>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded2);	
//
//	Matrix<ILVector2n> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);
//
//	CrossProd.SwitchFormat();
//
//	norm = CrossProd.Norm();
//	DEBUG(" Constraint: " << constraint);
//	DEBUG(" Norm 1: " << norm);
//
//
//	//bool result1 = (norm <= constraint);
//
//	EXPECT_LE(norm,constraint);
//
//	delete encoded1;
//	delete encoded2;
//
//	//cleans up precomputed samples
//	//ILVector2n::DestroyPreComputedSamples();
//
//	
//}
//TEST(UTTrapdoor,EncodeTest_dgg_no) {
//	bool dbg_flag = false;
//
//	usint m_cyclo = 16;
//	usint n = m_cyclo/2;
//
//	BigBinaryInteger modulus("67108913");
//	BigBinaryInteger rootOfUnity("61564");
//	float stddev = 4;
//	usint chunkSize = 1;
//
//	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
//	double logTwo = log(val-1.0)/log(2)+1.0;
//	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
//
//	double norm = 0;
//
//	shared_ptr<ILParams> params( new ILParams(m_cyclo, modulus, rootOfUnity) );
//    //auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);
//
//	ObfuscatedLWEConjunctionPatternV2<ILVector2n> obfuscatedPattern(params,chunkSize);
//	obfuscatedPattern.SetLength(1);
//
//	usint m = obfuscatedPattern.GetLogModulus() + 2;
//
//	LWEConjunctionObfuscationAlgorithmV2<ILVector2n> algorithm;
//
//	DiscreteGaussianGenerator dgg(4);
//	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigBinaryInteger(m));
//
//	algorithm.KeyGen(dgg,&obfuscatedPattern);
//
//	const std::vector<Matrix<ILVector2n>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
//	const std::vector<RLWETrapdoorPair<ILVector2n>>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
//	const std::vector<Matrix<LargeFloat>>   &Sigma = obfuscatedPattern.GetSigmaKeys();
//
//	double constraint = obfuscatedPattern.GetConstraint();
//
//	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
//
//	ILVector2n	s1(dgg,params,EVALUATION);
//	ILVector2n	s2(dgg,params,EVALUATION);
//
//	Matrix<ILVector2n> *encoded1 = new Matrix<ILVector2n>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);
//
//	Matrix<ILVector2n> *encoded2 = new Matrix<ILVector2n>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s2,dgg,encoded2);	
//
//	Matrix<ILVector2n> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);
//
//	CrossProd.SwitchFormat();
//
//	norm = CrossProd.Norm();
//	DEBUG( " Constraint: " << constraint );
//	DEBUG( " Norm 1: " << norm );
//
//	//bool result1 = (norm <= constraint);
//
//	delete encoded1;
//	delete encoded2;
//
//	EXPECT_GT(norm, constraint);
//
//}
/*
int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();

}
*/
