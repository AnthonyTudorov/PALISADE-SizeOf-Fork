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
#include <vector>

#include "../lib/cryptocontext.h"

#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UTLTVBATCHING : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

class UTFVBATCHING : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

class UTBVBATCHING : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

/*Simple Encrypt-Decrypt check for DCRTPoly. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*tower size is set to 3*/
TEST_F(UTLTVBATCHING, Poly_Encrypt_Decrypt) {

	float stdDev = 4;

	usint m = 8;
	BigInteger modulus("2199023288321");
	BigInteger rootOfUnity;

	modulus = NextPrime(modulus, m);
	rootOfUnity = RootOfUnity(m, modulus);

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };

	shared_ptr<Poly::Params> ep( new Poly::Params(m, modulus, rootOfUnity) );
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(ep, 17, 8, stdDev);

	cc->Enable(ENCRYPTION);

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<Poly> kp = cc->KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	shared_ptr<Ciphertext<Poly>> ciphertext;

	ciphertext = cc->Encrypt(kp.publicKey, intArray1);


	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Plaintext> intArrayNew;

	DecryptResult result = cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew);

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfInts1);
}


TEST_F(UTLTVBATCHING, Poly_EVALADD) {

	float stdDev = 4;

	usint m = 8;
	BigInteger modulus("2199023288321");
	BigInteger rootOfUnity;

	modulus = NextPrime(modulus, m);
	rootOfUnity = RootOfUnity(m, modulus);

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };


	std::vector<usint> vectorOfInts2 = { 4,3,2,1 };


	std::vector<usint> vectorOfIntsExpected = { 5,5,5,5 };

	shared_ptr<Poly::Params> ep( new Poly::Params(m, modulus, rootOfUnity) );
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(ep, 17, 8, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<Poly> kp = cc->KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	shared_ptr<Ciphertext<Poly>> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

	shared_ptr<Ciphertext<Poly>> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);


	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////
	shared_ptr<Ciphertext<Poly>> ciphertextResult = cc->EvalAdd(ciphertext1, ciphertext2);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	shared_ptr<Plaintext> intArrayNew;

	DecryptResult result = cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew);

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfIntsExpected);
}

TEST_F(UTLTVBATCHING, Poly_EVALMULT) {

	usint ptMod = 17;

	usint m = 8;
	usint relin = 1;
	float stdDev = 4;

	BigInteger q("2199023288321");

	q = NextPrime(q, m);
	BigInteger rootOfUnity(RootOfUnity(m, q));

	shared_ptr<Poly::Params> parms( new Poly::Params(m, q, rootOfUnity) );

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(parms, ptMod,
		relin, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };
	std::vector<usint> vectorOfInts2 = { 4,3,2,1 };

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 4,6,6,4 };


	kp = cc->KeyGen();

	shared_ptr<Ciphertext<Poly>> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	shared_ptr<Ciphertext<Poly>> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	cc->EvalMultKeyGen(kp.secretKey);

	shared_ptr<Ciphertext<Poly>> ciphertextResults = cc->EvalMult(ciphertext1, ciphertext2);
	
	shared_ptr<Plaintext> results;

	cc->Decrypt(kp.secretKey, ciphertextResults, &results);

	
	EXPECT_EQ(results->GetPackedValue(), vectorOfIntsExpected);
}


/*Simple Encrypt-Decrypt check for Poly. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set to 22
*tower size is set to 3*/
TEST_F(UTLTVBATCHING, Poly_Encrypt_Decrypt_Arb) {
	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("800053");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("59094");
	BigInteger bigmodulus("1019642968797569");
	BigInteger bigroot("116200103432701");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, p, 8, stdDev);
	cc->Enable(ENCRYPTION);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<usint> vectorOfInts = { 1,1,1,5,1,4,1,6,1,7 };
	shared_ptr<Plaintext> intArray = cc->MakePackedPlaintext(vectorOfInts);

	shared_ptr<Ciphertext<Poly>> ciphertext = cc->Encrypt(kp.publicKey, intArray);

	shared_ptr<Plaintext> intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertext, &intArrayNew);

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfInts);
}

TEST_F(UTLTVBATCHING, Poly_EVALADD_Arb) {
	PackedIntPlaintextEncoding::Destroy();
	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("800053");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("59094");
	BigInteger bigmodulus("1019642968797569");
	BigInteger bigroot("116200103432701");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	std::vector<usint> vectorOfInts2 = { 10,9,8,7,6,5,4,3,2,1 };

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::vector<usint> vectorOfIntsAdd;
	std::transform(vectorOfInts1.begin(), vectorOfInts1.end(), vectorOfInts2.begin(), std::back_inserter(vectorOfIntsAdd), std::plus<usint>());

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
	shared_ptr<Plaintext> intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextAdd, &intArrayNew);

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfIntsAdd);
}

TEST_F(UTBVBATCHING, Poly_EVALMULT_Arb) {
	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("72385066601");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("69414828251");
	BigInteger bigmodulus("77302754575416994210914689");
	BigInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextBV(params, p, 1, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	std::vector<usint> vectorOfInts2 = { 10,9,8,7,6,5,4,3,2,1 };

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::vector<usint> vectorOfIntsMult;
	std::transform(vectorOfInts1.begin(), vectorOfInts1.end(), vectorOfInts2.begin(), std::back_inserter(vectorOfIntsMult), std::multiplies<usint>());

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext2);
	shared_ptr<Plaintext> intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextMult, &intArrayNew);

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfIntsMult);
}

TEST_F(UTFVBATCHING, Poly_EVALMULT_Arb) {
	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusQ("72385066601");
	BigInteger modulusP(p);
	BigInteger rootOfUnity("69414828251");
	BigInteger bigmodulus("77302754575416994210914689");
	BigInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigInteger, BigVector>::PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigInteger bigEvalMultModulus("37778931862957161710549");
	BigInteger bigEvalMultRootOfUnity("7161758688665914206613");
	BigInteger bigEvalMultModulusAlt("1461501637330902918203684832716283019655932547329");
	BigInteger bigEvalMultRootOfUnityAlt("570268124029534407621996591794583635795426001824");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigVector, BigInteger>(m, bigEvalMultModulus);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextFV(params, encodingParams, 1, stdDev,delta.ToString(),OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(),1,9,1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());
	
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	std::vector<usint> vectorOfInts2 = { 10,9,8,7,6,5,4,3,2,1 };

	shared_ptr<Plaintext> intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::vector<usint> vectorOfIntsMult;
	std::transform(vectorOfInts1.begin(), vectorOfInts1.end(), vectorOfInts2.begin(), std::back_inserter(vectorOfIntsMult), std::multiplies<usint>());

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext2);
	shared_ptr<Plaintext> intArrayNew;

	cc->Decrypt(kp.secretKey, ciphertextMult, &intArrayNew);

	EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfIntsMult);
}

