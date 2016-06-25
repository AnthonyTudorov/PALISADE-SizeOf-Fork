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


#include "../../include/gtest/gtest.h"
#include <iostream>

#include "../../../src/lib/math/backend.h"
#include "../../../src/lib/math/nbtheory.h"
#include "../../../src/lib/math/distrgen.h"
#include "../../../src/lib/lattice/ilvector2n.h"
#include "../../../src/lib/crypto/lwecrypt.h"
#include "../../../src/lib/crypto/lwepre.h"
#include "../../../src/lib/utils/inttypes.h"
#include "../../../src/lib/utils/utilities.h"

#include "../../../src/lib/obfmath/randomizedround.h"
#include "../../../src/lib/obfmath/trapdoor.h"
#include "../../../src/lib/obfuscate/lweconjunctionobfuscate.h"
#include "../../../src/lib/obfuscate/lweconjunctionobfuscate.cpp"

using namespace std;
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

	ILParams fastParams( m, modulus, rootOfUnity);
	pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(fastParams, stddev);

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

	ILParams params( m, modulus, rootOfUnity);
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);

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
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams params( m, modulus, rootOfUnity);
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

	ILParams params( m, modulus, rootOfUnity);
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);

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
	ILParams params( m, modulus, rootOfUnity);
    auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
	float sigma = 4;

	DiscreteGaussianGenerator dgg(sigma);
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);

	ILVector2n u(dug,params,COEFFICIENT);

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);

	Matrix<int32_t> zHatBBI([](){ return make_unique<int32_t>(); },  k, m/2);

	GaussSampGq(u,sigma,k,modulus, dgg,&zHatBBI);
	//GaussSampG(u,sigma,k,dgg,&zHatBBI);

	EXPECT_EQ(k,zHatBBI.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(u.GetLength(),zHatBBI.GetCols())
		<< "Failure testing number of colums";
    Matrix<ILVector2n> z = SplitInt32AltIntoILVector2nElements(zHatBBI, n, params);
	z.SwitchFormat();
	ILVector2n uEst(params,COEFFICIENT);
	uEst = (Matrix<ILVector2n>(zero_alloc, 1,  k).GadgetVector()*z)(0,0);
	uEst.SwitchFormat();

    EXPECT_EQ(u, uEst);

}

TEST(UTTrapdoor,TrapDoorGaussSampTest) {

	usint m = 16;
	usint n = m/2;
	double s = 600;

	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams params( m, modulus, rootOfUnity);
    //auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	pair<RingMat, RLWETrapdoorPair> trapPair = RLWETrapdoorUtility::TrapdoorGen(params, stddev);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
    //auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, EVALUATION);

	DiscreteGaussianGenerator dgg(4);
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);

	ILVector2n u(dug,params,COEFFICIENT);
	u.SwitchFormat();

	Matrix<LargeFloat> sigmaSqrt([](){ return make_unique<LargeFloat>(); }, n*(k+2), n*(k+2));
	RLWETrapdoorUtility::PerturbationMatrixGen(n, k, trapPair.first, trapPair.second, s, &sigmaSqrt);

    //  600 is a very rough estimate for s, refer to Durmstradt 4.2 for
    //      estimation
	RingMat z = RLWETrapdoorUtility::GaussSamp(m/2, k, trapPair.first, trapPair.second, sigmaSqrt, u, stddev, dgg);

	//Matrix<ILVector2n> uEst = trapPair.first * z;

	EXPECT_EQ(trapPair.first.GetCols(),z.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(m/2,z(0,0).GetLength())
		<< "Failure testing ring dimension for the first ring element";
	
	ILVector2n uEst = (trapPair.first * z)(0,0);
	uEst.SwitchFormat();
	u.SwitchFormat();

    EXPECT_EQ(u, uEst);

	//std::cout << z << std::endl;

}
TEST(UTTrapdoor,EncodeTest_dgg_yes) {

	usint m_cyclo = 16;
	usint n = m_cyclo/2;

	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;


	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	double norm = 0;

	ILParams params(m_cyclo, modulus, rootOfUnity);
    	//auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	DiscreteGaussianGenerator dgg(4);

	// Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(params);
	obfuscatedPattern.SetLength(1);

	usint m = obfuscatedPattern.GetLogModulus() + 2;

	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigBinaryInteger(m));

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	algorithm.KeyGen(dgg,&obfuscatedPattern);

	const std::vector<Matrix<ILVector2n>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
	const std::vector<RLWETrapdoorPair>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
	const std::vector<Matrix<LargeFloat>>   &Sigma = obfuscatedPattern.GetSigmaKeys();

	double constraint = obfuscatedPattern.GetConstraint();

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	ILVector2n	s1(dgg,params,EVALUATION);

	Matrix<ILVector2n> *encoded1 = new Matrix<ILVector2n>(zero_alloc, m, m);
	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);

	Matrix<ILVector2n> *encoded2 = new Matrix<ILVector2n>(zero_alloc, m, m);
	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded2);	

	Matrix<ILVector2n> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);

	CrossProd.SwitchFormat();

	norm = CrossProd.Norm();
	std::cout << " Constraint: " << constraint << std::endl;
	std::cout << " Norm 1: " << norm << std::endl;


	//bool result1 = (norm <= constraint);

	EXPECT_LE(norm,constraint);

	delete encoded1;
	delete encoded2;

	//cleans up precomputed samples
	//ILVector2n::DestroyPreComputedSamples();

	
}
TEST(UTTrapdoor,EncodeTest_dgg_no) {

	usint m_cyclo = 16;
	usint n = m_cyclo/2;

	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	double norm = 0;

	ILParams params( m_cyclo, modulus, rootOfUnity);
    //auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(params);
	obfuscatedPattern.SetLength(1);

	usint m = obfuscatedPattern.GetLogModulus() + 2;

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	DiscreteGaussianGenerator dgg(4);
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigBinaryInteger(m));

	algorithm.KeyGen(dgg,&obfuscatedPattern);

	const std::vector<Matrix<ILVector2n>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
	const std::vector<RLWETrapdoorPair>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
	const std::vector<Matrix<LargeFloat>>   &Sigma = obfuscatedPattern.GetSigmaKeys();

	double constraint = obfuscatedPattern.GetConstraint();

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	ILVector2n	s1(dgg,params,EVALUATION);
	ILVector2n	s2(dgg,params,EVALUATION);

	Matrix<ILVector2n> *encoded1 = new Matrix<ILVector2n>(zero_alloc, m, m);
	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);

	Matrix<ILVector2n> *encoded2 = new Matrix<ILVector2n>(zero_alloc, m, m);
	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s2,dgg,encoded2);	

	Matrix<ILVector2n> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);

	CrossProd.SwitchFormat();

	norm = CrossProd.Norm();
	std::cout << " Constraint: " << constraint << std::endl;
	std::cout << " Norm 1: " << norm << std::endl;

	//bool result1 = (norm <= constraint);

	delete encoded1;
	delete encoded2;

	EXPECT_GT(norm, constraint);

}
