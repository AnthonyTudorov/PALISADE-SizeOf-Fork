/*
 * @file 
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


#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "sampling/trapdoor.h"
//#include "../../../src/lib/lattice/trapdoor.cpp"
#include "obfuscation/lweconjunctionobfuscate.h"
#include "obfuscation/lweconjunctionobfuscate.cpp"

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

TEST(UTTrapdoor,randomized_round){
    //  It compiles! ...
    //RandomizeRound(0, 4.3, 1024);
}



TEST(UTTrapdoor,sizes){
	usint m = 16;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> fastParams( new ILParams(m, modulus, rootOfUnity) );
	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(fastParams, stddev);

	EXPECT_EQ(1U,trapPair.first.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k+2,trapPair.first.GetCols())
		<< "Failure testing number of colums";

	EXPECT_EQ(1U,trapPair.second.m_r.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapPair.second.m_r.GetCols())
		<< "Failure testing number of colums";

	EXPECT_EQ(1U,trapPair.second.m_e.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapPair.second.m_e.GetCols())
		<< "Failure testing number of colums";


}

TEST(UTTrapdoor,TrapDoorPairTest){
	usint m = 16;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, stddev);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
    RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.VStack(rHat);
	//stackedTrap2.PrintValues();

	EXPECT_EQ(2U,stackedTrap1.GetRows())
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
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
        auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

        RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

	EXPECT_EQ(1U,g.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,g.GetCols())
		<< "Failure testing number of colums";
}


TEST(UTTrapdoor,TrapDoorMultTest){
	usint m = 16;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, stddev);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
    RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.VStack(rHat);
	RingMat stackedTrap2 = stackedTrap1.VStack(eyeKK);

	RingMat trapMult = (trapPair.first)*(stackedTrap2);
	EXPECT_EQ(1U,trapMult.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapMult.GetCols())
		<< "Failure testing number of colums";

    RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();
    EXPECT_EQ(g, trapMult);
}

TEST(UTTrapdoor,TrapDoorGaussGqSampTest) {
  bool dbg_flag = false;
  DEBUG("start tests");
	usint m = 16;
    usint n = m/2;
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	//BigInteger modulus("134218081");
	//BigInteger rootOfUnity("19091337");
	//BigInteger modulus("1048609");
	//BigInteger rootOfUnity("389832");
	shared_ptr<ILParams> params( new ILParams( m, modulus, rootOfUnity) );
    auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

	uint32_t base = 2;
	double sigma = (base+1)*SIGMA;

	Poly::DggType dgg(sigma);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(modulus);


  DEBUG("1");
	Poly u(dug,params,COEFFICIENT);
  DEBUG("2");
	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	//YSP check logTwo computation
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);

	Matrix<int32_t> zHatBBI([](){ return make_unique<int32_t>(); },  k, m/2);

  DEBUG("3");
  DEBUG("u "<<u);
  DEBUG("sigma "<<sigma);
  DEBUG("k "<<k);
  DEBUG("modulus "<<modulus);
  
	LatticeGaussSampUtility<Poly>::GaussSampGq(u,sigma,k,modulus, base,dgg,&zHatBBI);

	EXPECT_EQ(k,zHatBBI.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(u.GetLength(),zHatBBI.GetCols())
		<< "Failure testing number of colums";
  DEBUG("4");
    Matrix<Poly> z = SplitInt32AltIntoElements<Poly>(zHatBBI, n, params);
	z.SwitchFormat();

	Poly uEst;
	uEst = (Matrix<Poly>(zero_alloc, 1,  k).GadgetVector()*z)(0,0);
	uEst.SwitchFormat();

    EXPECT_EQ(u, uEst);
  DEBUG("end tests");
}

TEST(UTTrapdoor, TrapDoorGaussGqSampTestBase1024) {
	bool dbg_flag = false;
	DEBUG("start tests");
	
	usint m = 1024;
	usint n = m / 2;
	BigInteger modulus("8399873");
	BigInteger rootOfUnity("824894");
	//BigInteger modulus("134218081");
	//BigInteger rootOfUnity("19091337");
	//BigInteger modulus("1048609");
	//BigInteger rootOfUnity("389832");
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));
	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

	uint32_t base = 1<<10;
	double sigma = (base + 1)*SIGMA;

	Poly::DggType dgg(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(modulus);


	DEBUG("1");
	Poly u(dug, params, COEFFICIENT);
	DEBUG("2");
	//double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
											//YSP check logTwo computation
	
	usint nBits = floor(log2(modulus.ConvertToDouble() - 1.0) + 1.0);
	usint k = ceil(nBits / log2(base));
	
	//double logTwo = log(val - 1.0) / log(2) + 1.0;
	//usint k = (usint)floor(logTwo);

	Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, m / 2);

	DEBUG("3");
	DEBUG("u " << u);
	DEBUG("sigma " << sigma);
	DEBUG("k " << k);
	DEBUG("modulus " << modulus);
	DEBUG("base = " << base);

	LatticeGaussSampUtility<Poly>::GaussSampGq(u, sigma, k, modulus, base, dgg, &zHatBBI);

	EXPECT_EQ(k, zHatBBI.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(u.GetLength(), zHatBBI.GetCols())
		<< "Failure testing number of colums";
	DEBUG("4");

	//int32_t maxValue = 0;

	//for (size_t i = 0; i < zHatBBI.GetRows(); i++)
	//	for (size_t j = 0; j < zHatBBI.GetCols(); j++)
	//		if (std::abs(zHatBBI(i, j)) > maxValue)
	//			maxValue = std::abs(zHatBBI(i, j));
	//
	//std::cout << maxValue << std::endl;

	Matrix<Poly> z = SplitInt32AltIntoElements<Poly>(zHatBBI, n, params);
	z.SwitchFormat();

	Poly uEst;
	uEst = (Matrix<Poly>(zero_alloc, 1, k).GadgetVector(base)*z)(0, 0);
	uEst.SwitchFormat();

	//std::cout << u - uEst << std::endl;

	EXPECT_EQ(u, uEst);
	DEBUG("end tests");
}

// Test of Gaussian Sampling using the UCSD integer perturbation sampling algorithm
TEST(UTTrapdoor, TrapDoorGaussSampTest) {
        bool dbg_flag = false;
	DEBUG("in test");
	usint m = 16;
	usint n = m / 2;

	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");
	double sigma = SIGMA;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	usint k = (usint)floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	DEBUG("k = "<<k);
	DEBUG("sigma = "<<sigma);
	DEBUG("m = "<<m);
	DEBUG("modulus = "<<modulus);
	DEBUG("root = "<<rootOfUnity);

	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));
	//auto zero_alloc = Poly::MakeAllocator(params, COEFFICIENT);

	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, sigma);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
	//auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, EVALUATION);

	Poly::DggType dgg(sigma);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(modulus);

	uint32_t base = 2;
	double c = (base + 1) * SIGMA;
	double s = SPECTRAL_BOUND(n, k, base);
	Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

	Poly u(dug, params, COEFFICIENT);

	DEBUG("u "<<u);
	u.SwitchFormat();
	DEBUG("u "<<u);

	RingMat z = RLWETrapdoorUtility<Poly>::GaussSamp(m / 2, k, trapPair.first, trapPair.second, u, dgg, dggLargeSigma);

	//Matrix<Poly> uEst = trapPair.first * z;

	EXPECT_EQ(trapPair.first.GetCols(), z.GetRows())
		<< "Failure testing number of rows";
	EXPECT_EQ(m / 2, z(0, 0).GetLength())
		<< "Failure testing ring dimension for the first ring element";

	Poly uEst = (trapPair.first * z)(0, 0);

	DEBUG("uEst "<<uEst);
	DEBUG("u "<<u);

	
	DEBUG("uEst.GetModulus() "<<uEst.GetModulus());
	DEBUG("u.GetModulus() "<<u.GetModulus());


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
	BigInteger modulus("67108913");
	BigInteger rootOfUnity("61564");

	//for m = 2048
	//BigInteger modulus("134246401");
	//BigInteger rootOfUnity("34044212");

	//for m = 2^13
	//BigInteger modulus("268460033");
	//BigInteger rootOfUnity("154905983");

	//BigInteger modulus("1237940039285380274899136513");
	//BigInteger rootOfUnity("977145384161930579732228319");

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	usint k = (usint)floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	//smoothing parameter
	//double c(2 * sqrt(log(2 * n*(1 + 1 / DG_ERROR)) / M_PI));
	uint32_t base = 2;
	double c = (base + 1) * SIGMA;

	//spectral bound s
	double s = SPECTRAL_BOUND(n, k, base);

	//std::cout << "sigma = " << SIGMA << std::endl;
	//std::cout << "s = " << s << std::endl;

	//Generate the trapdoor pair
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	double sigma = SIGMA;

	//std::cout << 50 / (c*sigma) << std::endl;

	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapPair = RLWETrapdoorUtility<Poly>::TrapdoorGen(params, sigma);

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;

	Poly::DggType dgg(sigma);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(modulus);

	Poly::DggType dggLargeSigma(sqrt(s * s - c * c));

	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);

	//Do perturbation sampling
	shared_ptr<RingMat> pHat(new RingMat(zero_alloc, k + 2, 1));

	Matrix<int32_t> p([]() { return make_unique<int32_t>(); }, (2 + k)*n, 1);

	Matrix<int32_t> pCovarianceMatrix([]()  { return make_unique<int32_t>(); }, 2*n, 2*n);;

	//std::vector<Matrix<int32_t>> pTrapdoors;

	Matrix<int32_t> pTrapdoor([]() { return make_unique<int32_t>(); }, 2 * n, 1);

	Matrix<BigInteger> bbiTrapdoor(BigInteger::Allocator, 2*n, 1);

	Matrix<int32_t> pTrapdoorAverage([]() { return make_unique<int32_t>(); }, 2 * n, 1);

	size_t count = 100;

	for (size_t i = 0; i < count; i++) {
		RLWETrapdoorUtility<Poly>::ZSampleSigmaP(n, s, c, trapPair.second, dgg, dggLargeSigma, pHat);

		//convert to coefficient representation
		pHat->SwitchFormat();

		for (size_t j = 0; j < n; j++) {
			bbiTrapdoor(j, 0) = (*pHat)(0, 0).GetValues().at(j);
			bbiTrapdoor(j+n, 0) = (*pHat)(1, 0).GetValues().at(j);
		}

		pTrapdoor = ConvertToInt32(bbiTrapdoor, modulus);

		for (size_t j = 0; j < 2 * n; j++) {
			pTrapdoorAverage(j, 0) = pTrapdoorAverage(j, 0) + pTrapdoor(j, 0);
		}
		//pTrapdoors.push_back(pTrapdoor);
		
		pCovarianceMatrix = pCovarianceMatrix + pTrapdoor*pTrapdoor.Transpose();
	}

	Matrix<Poly> Tprime0 = eHat;
	Matrix<Poly> Tprime1 = rHat;

	// all three polynomials are initialized with "0" coefficients
	Poly va(params, EVALUATION, 1);
	Poly vb(params, EVALUATION, 1);
	Poly vd(params, EVALUATION, 1);

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
//	BigInteger modulus("67108913");
//	BigInteger rootOfUnity("61564");
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
//    	//auto zero_alloc = Poly::MakeAllocator(params, COEFFICIENT);
//
//	DiscreteGaussianGenerator dgg(4);
//
//	ObfuscatedLWEConjunctionPattern<Poly> obfuscatedPattern(params,chunkSize);
//	obfuscatedPattern.SetLength(1);
//
//	usint m = obfuscatedPattern.GetLogModulus() + 2;
//
//	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigInteger(m));
//
//	LWEConjunctionObfuscationAlgorithm<Poly> algorithm;
//
//	algorithm.KeyGen(dgg,&obfuscatedPattern);
//
//	const std::vector<Matrix<Poly>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
//	const std::vector<RLWETrapdoorPair<Poly>>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
//
//	double constraint = obfuscatedPattern.GetConstraint();
//
//	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);
//
//	Poly	s1(dgg,params,EVALUATION);
//
//	Matrix<Poly> *encoded1 = new Matrix<Poly>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);
//
//	Matrix<Poly> *encoded2 = new Matrix<Poly>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded2);	
//
//	Matrix<Poly> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);
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
//	//Poly::DestroyPreComputedSamples();
//
//	
//}
//TEST(UTTrapdoor,EncodeTest_dgg_no) {
//	bool dbg_flag = false;
//
//	usint m_cyclo = 16;
//	usint n = m_cyclo/2;
//
//	BigInteger modulus("67108913");
//	BigInteger rootOfUnity("61564");
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
//    //auto zero_alloc = Poly::MakeAllocator(params, COEFFICIENT);
//
//	ObfuscatedLWEConjunctionPatternV2<Poly> obfuscatedPattern(params,chunkSize);
//	obfuscatedPattern.SetLength(1);
//
//	usint m = obfuscatedPattern.GetLogModulus() + 2;
//
//	LWEConjunctionObfuscationAlgorithmV2<Poly> algorithm;
//
//	DiscreteGaussianGenerator dgg(4);
//	DiscreteUniformGenerator dug = DiscreteUniformGenerator(BigInteger(m));
//
//	algorithm.KeyGen(dgg,&obfuscatedPattern);
//
//	const std::vector<Matrix<Poly>> &Pk_vector = obfuscatedPattern.GetPublicKeys();
//	const std::vector<RLWETrapdoorPair<Poly>>   &Ek_vector = obfuscatedPattern.GetEncodingKeys();
//	const std::vector<Matrix<LargeFloat>>   &Sigma = obfuscatedPattern.GetSigmaKeys();
//
//	double constraint = obfuscatedPattern.GetConstraint();
//
//	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);
//
//	Poly	s1(dgg,params,EVALUATION);
//	Poly	s2(dgg,params,EVALUATION);
//
//	Matrix<Poly> *encoded1 = new Matrix<Poly>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s1,dgg,encoded1);
//
//	Matrix<Poly> *encoded2 = new Matrix<Poly>(zero_alloc, m, m);
//	algorithm.Encode(Pk_vector[0],Pk_vector[1],Ek_vector[0],Sigma[0],s2,dgg,encoded2);	
//
//	Matrix<Poly> CrossProd = Pk_vector[0]*(*encoded1 - *encoded2);
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
