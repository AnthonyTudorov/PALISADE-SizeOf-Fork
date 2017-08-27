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

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"
#include "utils/parmfactory.h"
#include "lattice/elemparamfactory.h"

#include <cmath>


using namespace std;
using namespace lbcrypto;

// A new one of these is created for each test
class UTSHEAdvanced : public testing::Test
{
public:
	UTSHEAdvanced() {}

	void SetUp()
	{
	}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

const usint dcrtBits = 40;

#if !defined(_MSC_VER)

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {

	usint m = 16;
	usint relin = 1;
	float stdDev = 4;

	shared_ptr<Poly::Params> parms = ElemParamFactory::GenElemParams<Poly::Params,Poly::Integer>(m, 50);

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(parms, 5 + 4, relin, stdDev);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<Poly> kp;

	std::vector<usint> vectorOfInts1 = { 2 };
	shared_ptr<Plaintext> intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3 };
	shared_ptr<Plaintext> intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	shared_ptr<Ciphertext<Poly>> cResult =
		cc->EvalMult(ciphertext1, ciphertext2);

	LPKeyPair<Poly> newKp = cc->KeyGen();

	shared_ptr<LPEvalKey<Poly>> keySwitchHint2 = cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult = cc->KeySwitch(keySwitchHint2, cResult);

	shared_ptr<Plaintext> results;

	cc->Decrypt(newKp.secretKey, cResult, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 6U);
}


TEST_F(UTSHEAdvanced, test_eval_mult_double_crt) {

	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	usint plaintextModulus = 9;

	vector<native_int::BigInteger> init_moduli(init_size);

	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, init_m);
	native_int::BigInteger temp;
	BigInteger modulus("1");

	for (usint i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigInteger(init_moduli[i].ConvertToInt());
		q = NextPrime(q, init_m);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity));

	usint relWindow = 1;

	// Fixme use the ParameterSelection version of genCryptoContext
	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<DCRTPoly> kp;

	//Generating new cryptoparameters for when modulus reduction is done. - not used?
	std::vector<usint> vectorOfInts1 = { 2, 4 };
	shared_ptr<Plaintext> intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3, 3 };
	shared_ptr<Plaintext> intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);

	shared_ptr<Ciphertext<DCRTPoly>> ciphertext1;
	shared_ptr<Ciphertext<DCRTPoly>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	std::shared_ptr<Ciphertext<DCRTPoly>> cResult = cc->EvalMult(ciphertext1, ciphertext2);

	LPKeyPair<DCRTPoly> newKp = cc->KeyGen();

	shared_ptr<LPEvalKey<DCRTPoly>> keySwitchHint2 = cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult = cc->KeySwitch(keySwitchHint2, cResult);

	shared_ptr<Plaintext> results;

	cc->Decrypt(newKp.secretKey, cResult, &results);

	EXPECT_EQ(6U, results->GetCoefPackedValue().at(0));
	EXPECT_EQ(0U, results->GetCoefPackedValue().at(1));
	EXPECT_EQ(3U, results->GetCoefPackedValue().at(2));
}


TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
	bool dbg_flag = false;
	usint m = 16;

	float stdDev = 4;

	shared_ptr<Poly::Params> parms = ElemParamFactory::GenElemParams<Poly::Params,Poly::Integer>(m);

	shared_ptr<CryptoContext<Poly>> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(parms, 8, 1, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<Poly> kp;

	DEBUG("Filling 1");
	std::vector<usint> vectorOfInts1 = { 2, 3, 1, 4 };
	shared_ptr<Plaintext> intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	DEBUG("Filling 2");
	std::vector<usint> vectorOfInts2 = { 3, 6, 3, 1 };
	shared_ptr<Plaintext> intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	DEBUG("getting pairs");
	kp = cc->KeyGen();

	DEBUG("got pairs");
	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	DEBUG("after crypt 1");
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
	DEBUG("after crypt 2");

	shared_ptr<Ciphertext<Poly>> cResult;
	DEBUG("before EA");
	cResult = cc->EvalAdd(ciphertext1, ciphertext2);
	DEBUG("after");

	shared_ptr<Ciphertext<Poly>> ciphertextResults({ cResult });
	shared_ptr<Plaintext> results;

	cc->Decrypt(kp.secretKey, ciphertextResults, &results);

	EXPECT_EQ(5U, results->GetCoefPackedValue().at(0));
	EXPECT_EQ(1U, results->GetCoefPackedValue().at(1));
	EXPECT_EQ(4U, results->GetCoefPackedValue().at(2));
	EXPECT_EQ(5U, results->GetCoefPackedValue().at(3));
}


TEST_F(UTSHEAdvanced, test_eval_add_double_crt) {
	bool dbg_flag = false;
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;
	usint plaintextModulus = 9;

	vector<native_int::BigInteger> init_moduli(init_size);

	vector<native_int::BigInteger> init_rootsOfUnity(init_size);

	native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, init_m);
	native_int::BigInteger temp;
	BigInteger modulus(1);
	DEBUG("1");

	for (size_t i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigInteger(init_moduli[i].ConvertToInt());
		q = NextPrime(q, init_m);
	}
	DEBUG("2");
	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity));

	DEBUG("5");

	usint relWindow = 1;

	// Fixme use the ParameterSelection version of genCryptoContext
	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	std::vector<usint> vectorOfInts1 = { 2, 4, 8, 5 };
	shared_ptr<Plaintext> intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3, 3, 4, 1 };
	shared_ptr<Plaintext> intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	shared_ptr<Ciphertext<DCRTPoly>> ciphertext1;
	shared_ptr<Ciphertext<DCRTPoly>> ciphertext2;

	ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	shared_ptr<Ciphertext<DCRTPoly>> cResult;

	cResult = cc->EvalAdd(ciphertext1, ciphertext2);


	shared_ptr<Ciphertext<DCRTPoly>> ciphertextResults({ cResult });
	shared_ptr<Plaintext> results;

	cc->Decrypt(kp.secretKey, ciphertextResults, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 5U);
	EXPECT_EQ(results->GetCoefPackedValue().at(1), 7U);
	EXPECT_EQ(results->GetCoefPackedValue().at(2), 3U);
	EXPECT_EQ(results->GetCoefPackedValue().at(3), 6U);
	DEBUG("13");
}


TEST_F(UTSHEAdvanced, test_composed_eval_mult_two_towers) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 5;

	usint ptm = 9;

	shared_ptr<ILDCRTParams<BigInteger>> params = GenerateDCRTParams( init_m, ptm, init_size, dcrtBits );

	shared_ptr<ILDCRTParams<BigInteger>> paramsSmall( new ILDCRTParams<BigInteger>( *params ) );
	paramsSmall->PopLastParam();

	usint relWindow = 4;

	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(params, 5+4, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc->Enable(SHE);
	cc->Enable(ENCRYPTION);
	cc->Enable(LEVELEDSHE);

	shared_ptr<CryptoContext<DCRTPoly>> ccSmall = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(paramsSmall, ptm, relWindow, init_stdDev, init_size - 1);
	ccSmall->Enable(SHE);
	ccSmall->Enable(ENCRYPTION);
	ccSmall->Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	//Generating Quadratic KeySwitchHint from sk^2 to skNew
	cc->EvalMultKeyGen(kp.secretKey);

	std::vector<usint> firstElement = { 8, 5, 4 };
	shared_ptr<Plaintext> firstElementEncoding = cc->MakeCoefPackedPlaintext(firstElement);

	std::vector<usint> secondElement = { 7, 4, 2 };
	shared_ptr<Plaintext> secondElementEncoding = cc->MakeCoefPackedPlaintext(secondElement);

	shared_ptr<Ciphertext<DCRTPoly>> ciphertextElementOne;
	shared_ptr<Ciphertext<DCRTPoly>> ciphertextElementTwo;

	ciphertextElementOne = cc->Encrypt(kp.publicKey, firstElementEncoding);
	ciphertextElementTwo = cc->Encrypt(kp.publicKey, secondElementEncoding);

	shared_ptr<Ciphertext<DCRTPoly>> cResult = cc->ComposedEvalMult(ciphertextElementOne, ciphertextElementTwo);

	// ok let's try making the secret keys both have one less tower
	// because ComposedEvalMult performs a ModReduce

	DCRTPoly tempPrivateElement(kp.secretKey->GetPrivateElement());
	tempPrivateElement.DropLastElement();
	kp.secretKey->SetPrivateElement(tempPrivateElement);

	shared_ptr<LPPrivateKey<DCRTPoly>> kpSecretSmall( new LPPrivateKey<DCRTPoly>(ccSmall) );
	kpSecretSmall->SetPrivateElement(tempPrivateElement);
	LPKeyPair<DCRTPoly> kp1 = ccSmall->KeyGen();

	shared_ptr<LPEvalKey<DCRTPoly>> KeySwitchHint = ccSmall->KeySwitchGen(kpSecretSmall, kp1.secretKey);

	// have to perform the operation in the new context
	shared_ptr<Ciphertext<DCRTPoly>> cResultSmall( new Ciphertext<DCRTPoly>(ccSmall) );
	cResultSmall->SetElements( cResult->GetElements() );

	cResult = ccSmall->KeySwitch(KeySwitchHint, cResultSmall);

	shared_ptr<Plaintext> results;

	ccSmall->Decrypt(kp1.secretKey, cResult, &results);

	EXPECT_EQ(results->GetCoefPackedValue().at(0), 2U);
	EXPECT_EQ(results->GetCoefPackedValue().at(1), 4U);
	EXPECT_EQ(results->GetCoefPackedValue().at(2), 1U);
	EXPECT_EQ(results->GetCoefPackedValue().at(3), 8U);
	EXPECT_EQ(results->GetCoefPackedValue().at(4), 8U);
}
#endif
