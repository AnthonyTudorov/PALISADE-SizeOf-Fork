/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
12/22/2015 2:37PM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Nishanth Pasham, np386@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

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
#include <vector>
#include <algorithm>
#include <random>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestEvalLinearRegression : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

struct rationalInt {
	usint m_numerator;
	usint m_denominator;
	rationalInt():m_numerator(0),m_denominator(0){}
	rationalInt(usint n,usint d) :m_numerator(n), m_denominator(d) {}
};

rationalInt ArbBVLinearRegressionPackedArray();

rationalInt ArbFVLinearRegressionPackedArray();

TEST(UTEvalLR, Test_BV_EvalLR) {
	
	rationalInt result = ArbBVLinearRegressionPackedArray();

	rationalInt expectedResult(300,270);

	EXPECT_EQ(result.m_numerator, expectedResult.m_numerator);
	EXPECT_EQ(result.m_denominator, expectedResult.m_denominator);
	
}

TEST(UTEvalLR, Test_FV_EvalLR) {
	
	rationalInt result = ArbFVLinearRegressionPackedArray();

	rationalInt expectedResult(300, 270);

	EXPECT_EQ(result.m_numerator, expectedResult.m_numerator);
	EXPECT_EQ(result.m_denominator, expectedResult.m_denominator);
}

rationalInt ArbBVLinearRegressionPackedArray() {

	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;
	usint p = 2333;
	BigBinaryInteger modulusP(p);
	BigBinaryInteger modulusQ("1267650600228229401496703214121");
	BigBinaryInteger squareRootOfRoot("498618454049802547396506932253");

	BigBinaryInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigBinaryInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");
	
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	shared_ptr<CryptoContext<ILVector2n>> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, encodingParams, 8, stdDev, OPTIMIZED);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, 2);

	xP(0, 0) = { 0, 2, 1, 3,  2,  2, 1, 2 };
	xP(0, 1) = { 1 , 1 , 2 , 1 , 1 , 1, 3 , 2 };

	Matrix<PackedIntPlaintextEncoding> yP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = { 0, 1, 2, 6, 1, 2, 3, 4 };
	
	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<PackedIntPlaintextEncoding> numerator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<PackedIntPlaintextEncoding> denominator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	rationalInt output(numerator(0, 0)[0], denominator(0, 0)[0]);

	return output;

}


rationalInt ArbFVLinearRegressionPackedArray() {

	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().Destroy();

	usint m = 22;

	usint p = 2333; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusQ("1152921504606847009");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("1147559132892757400");

	BigBinaryInteger bigmodulus("42535295865117307932921825928971026753");
	BigBinaryInteger bigroot("13201431150704581233041184864526870950");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("42535295865117307932921825928971026753");
	BigBinaryInteger bigEvalMultRootOfUnity("22649103892665819561201725524201801241");
	BigBinaryInteger bigEvalMultModulusAlt("115792089237316195423570985008687907853269984665640564039457584007913129642241");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("37861550304274465568523443986246841530644847113781666728121717722285667862085");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	shared_ptr<CryptoContext<ILVector2n>> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc->KeyGen();

	// Compute evaluation keys
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, 2);

	xP(0, 0) = { 0, 2, 1, 3,  2,  2, 1, 2 };
	xP(0, 1) = { 1 , 1 , 2 , 1 , 1 , 1, 3 , 2 };

	Matrix<PackedIntPlaintextEncoding> yP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = { 0, 1, 2, 6, 1, 2, 3, 4 };

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc->EncryptMatrix(kp.publicKey, xP);

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc->EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc->EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<PackedIntPlaintextEncoding> numerator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<PackedIntPlaintextEncoding> denominator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc->DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	rationalInt output(numerator(0, 0)[0], denominator(0, 0)[0]);

	return output;
}
