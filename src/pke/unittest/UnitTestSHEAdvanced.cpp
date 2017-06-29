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

#include <cmath>


using namespace std;
using namespace lbcrypto;

// A new one of these is created for each test
class UTSHEAdvanced : public testing::Test
{
public:
	UTSHEAdvanced() {}

	virtual void SetUp()
	{
	}

	virtual void TearDown()
	{
	}
};

const usint dcrtBits = 40;

#if !defined(_MSC_VER)
///*Testing Parameter selection. The test will check if generated parameters are greater than the following thresholds:
//* The first modulus generated needs to be greater than q1 > 4pr sqrt(n) w. Where
//* p is the plaintext modulus
//* r is Gaussian Parameter
//* w is the assurance measure
//* n is the ring dimension
//*/
//TEST_F(UTSHEAdvanced, ParameterSelection) {
//
//
//	usint m = 16; // initial cycltomic order
//
//	float stdDev = 4;
//
//	usint size = 11; // tower size, equal to depth of operation + 1
//
//	vector<native_int::BinaryInteger> moduli(size);
//
//	vector<native_int::BinaryInteger> rootsOfUnity(size);
//
//	native_int::BinaryInteger q = FindPrimeModulus<native_int::BinaryInteger>(m, dcrtBits);
//	native_int::BinaryInteger temp;
//	BigBinaryInteger modulus("1");
//
//	for (size_t i = 0; i < size; i++) {
//		lbcrypto::NextQ(q, native_int::BinaryInteger(2), m, native_int::BinaryInteger(4), native_int::BinaryInteger(4));
//		moduli[i] = q;
//		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
//		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
//
//	}
//
//	//intializing cryptoparameters alongside variables
//	shared_ptr<ILDCRTParams<BigBinaryInteger>> params(new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity));
//	LPCryptoParametersLTV<ILDCRT2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(2);
//	cryptoParams.SetDistributionParameter(stdDev);
//	cryptoParams.SetRelinWindow(1);
//	cryptoParams.SetElementParams(params);
//	cryptoParams.SetAssuranceMeasure(6);
//	cryptoParams.SetDepth(size - 1);
//	cryptoParams.SetSecurityLevel(1.006);
//
//	//New CryptoParameters placeholder
//	LPCryptoParametersLTV<ILDCRT2n> cryptoParams2;
//	//calling ParameterSelection. cryptoParams2 will have the new Moduli and ring dimension (cyclotomicorder/2)
//	cryptoParams.ParameterSelection(&cryptoParams2);
//
//	shared_ptr<ILDCRTParams<BigBinaryInteger>> dcrtParams = std::dynamic_pointer_cast<ILDCRTParams<BigBinaryInteger>>(cryptoParams2.GetElementParams());
//	std::vector<shared_ptr<native_int::ILParams>> finalParams = dcrtParams->GetParams();
//	//threshold for the first modulus
//	double q1Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetElementParams()->GetCyclotomicOrder() / 2, 0.5) * cryptoParams2.GetAssuranceMeasure();
//	//test for the first modulus
//	EXPECT_LT(q1Threshold, finalParams[0]->GetModulus().ConvertToDouble());
//	//threshold for all but the first modulus
//	double q2Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetDistributionParameter(), 5) * pow(cryptoParams2.GetElementParams()->GetCyclotomicOrder() / 2, 1.5) * pow(cryptoParams2.GetAssuranceMeasure(), 5);
//
//	//test for all but the first modulus
//	for (usint i = 1; i < finalParams.size(); i++) {
//		EXPECT_LT(q2Threshold, finalParams[i]->GetModulus().ConvertToDouble());
//	}
//}

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {

	usint m = 16;
	usint relin = 1;
	float stdDev = 4;

	shared_ptr<ILVector2n::Params> parms = GenerateTestParams<ILVector2n::Params, ILVector2n::Integer>(m, dcrtBits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(parms, 5 + 4, relin, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<usint> vectorOfInts1(8);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 0;
	vectorOfInts1.at(2) = 0;
	vectorOfInts1.at(3) = 0;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(8);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 0;
	vectorOfInts2.at(2) = 0;
	vectorOfInts2.at(3) = 0;
	IntPlaintextEncoding intArray2(vectorOfInts2);
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);

	kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<Ciphertext<ILVector2n>> cResult =
		cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0));

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint2 = cc.KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult = cc.KeySwitch(keySwitchHint2, cResult);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	cc.Decrypt(newKp.secretKey, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 6U);
}


TEST_F(UTSHEAdvanced, test_eval_mult_double_crt) {
	bool dbg_flag = false;

//	FAIL() << ("this fails because it uses LTV ParamsGen, which is broken");

	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	usint plaintextModulus = 9;

	vector<native_int::BinaryInteger> init_moduli(init_size);

	vector<native_int::BinaryInteger> init_rootsOfUnity(init_size);

	native_int::BinaryInteger q = FirstPrime<native_int::BinaryInteger>(dcrtBits, init_m);
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (usint i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigBinaryInteger(init_moduli[i].ConvertToInt());
		q = NextPrime(q, init_m);
	}

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params(new ILDCRTParams<BigBinaryInteger>(init_m, init_moduli, init_rootsOfUnity));

//	LPCryptoParametersLTV<ILDCRT2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
//	cryptoParams.SetDistributionParameter(init_stdDev);
//	cryptoParams.SetRelinWindow(1);
//	cryptoParams.SetElementParams(params);
//	cryptoParams.SetAssuranceMeasure(6);
//	cryptoParams.SetDepth(init_size - 1);
//	cryptoParams.SetSecurityLevel(1.006);

	usint relWindow = 1;

//	LPCryptoParametersLTV<ILDCRT2n> finalParams;
//
//	cryptoParams.ParameterSelection(&finalParams);
//
//	DEBUG("old parms " << cryptoParams);
//	DEBUG("new parms" << finalParams);

	// Fixme use the ParameterSelection version of genCryptoContext
	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILDCRT2n> kp;

	//Generating new cryptoparameters for when modulus reduction is done. - not used?
	std::vector<usint> vectorOfInts1(2048);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 4;
	vectorOfInts1.at(2) = 0;
	vectorOfInts1.at(3) = 0;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(2048);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 3;
	vectorOfInts2.at(2) = 0;
	vectorOfInts2.at(3) = 0;
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);
	IntPlaintextEncoding intArray2(vectorOfInts2);

	kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	std::vector<shared_ptr<Ciphertext<ILDCRT2n>>> cResult;
	cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)));

	DEBUG("1 " << ciphertext1.at(0)->GetElement().GetLength());
	DEBUG("2 " << ciphertext2.at(0)->GetElement().GetLength());
	DEBUG("out " << cResult.at(0)->GetElement().GetLength());

	LPKeyPair<ILDCRT2n> newKp = cc.KeyGen();

	shared_ptr<LPEvalKey<ILDCRT2n>> keySwitchHint2 = cc.KeySwitchGen(kp.secretKey, newKp.secretKey);

	cResult.at(0) = cc.KeySwitch(keySwitchHint2, cResult.at(0));

	IntPlaintextEncoding results;

	cc.Decrypt(newKp.secretKey, cResult, &results, false);

	EXPECT_EQ(6U, results.at(0));
	EXPECT_EQ(0U, results.at(1));
	EXPECT_EQ(3U, results.at(2));

}


TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
	bool dbg_flag = false;
	usint m = 16;

	float stdDev = 4;

	shared_ptr<ILVector2n::Params> parms = GenerateTestParams<ILVector2n::Params, ILVector2n::Integer>(m, dcrtBits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(parms, 8, 1, stdDev);
	// plaintextmodulus // 5 + 3,
	// ringdim // m,
	// modulus // q.ToString(),
	//rootOfUnity.ToString(),
	// relinWindow // 1,
	//stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	DEBUG("Filling 1");
	std::vector<usint> vectorOfInts1(8);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 3;
	vectorOfInts1.at(2) = 1;
	vectorOfInts1.at(3) = 4;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	DEBUG("Filling 2");
	std::vector<usint> vectorOfInts2(8);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 6;
	vectorOfInts2.at(2) = 3;
	vectorOfInts2.at(3) = 1;
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);
	IntPlaintextEncoding intArray2(vectorOfInts2);

	DEBUG("getting pairs");
	kp = cc.KeyGen();

	DEBUG("got pairs");
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	DEBUG("after crypt 1");
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);
	DEBUG("after crypt 2");

	shared_ptr<Ciphertext<ILVector2n>> cResult;
	DEBUG("before EA");
	cResult = cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0));
	DEBUG("after");

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResults({ cResult });
	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, ciphertextResults, &results, false);

	EXPECT_EQ(5U, results.at(0));
	EXPECT_EQ(1U, results.at(1));
	EXPECT_EQ(4U, results.at(2));
	EXPECT_EQ(5U, results.at(3));
}


TEST_F(UTSHEAdvanced, test_eval_add_double_crt) {
	bool dbg_flag = false;
	usint init_m = 16;

//	FAIL() << ("this fails because it uses LTV ParamsGen, which is broken");

	float init_stdDev = 4;

	usint init_size = 2;
	usint plaintextModulus = 9;

	vector<native_int::BinaryInteger> init_moduli(init_size);

	vector<native_int::BinaryInteger> init_rootsOfUnity(init_size);

	native_int::BinaryInteger q = FirstPrime<native_int::BinaryInteger>(dcrtBits, init_m);
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus(1);
	DEBUG("1");

	for (size_t i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * BigBinaryInteger(init_moduli[i].ConvertToInt());
		q = NextPrime(q, init_m);
	}
	DEBUG("2");
	shared_ptr<ILDCRTParams<BigBinaryInteger>> params(new ILDCRTParams<BigBinaryInteger>(init_m, init_moduli, init_rootsOfUnity));

//	LPCryptoParametersLTV<ILDCRT2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
//	cryptoParams.SetDistributionParameter(init_stdDev);
//	cryptoParams.SetRelinWindow(1);
//	cryptoParams.SetElementParams(params);
//	cryptoParams.SetAssuranceMeasure(6);
//	cryptoParams.SetDepth(init_size - 1);
//	cryptoParams.SetSecurityLevel(1.006);
	DEBUG("5");

	usint relWindow = 1;

//	LPCryptoParametersLTV<ILDCRT2n> finalParams;
//
//	cryptoParams.ParameterSelection(&finalParams);
//
//	const shared_ptr<ILDCRTParams<BigBinaryInteger>> dcrtParams = std::dynamic_pointer_cast<ILDCRTParams<BigBinaryInteger>>(finalParams.GetElementParams());

	// Fixme use the ParameterSelection version of genCryptoContext
	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, plaintextModulus, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	std::vector<usint> vectorOfInts1(2048);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 4;
	vectorOfInts1.at(2) = 8;
	vectorOfInts1.at(3) = 5;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(2048);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 3;
	vectorOfInts2.at(2) = 4;
	vectorOfInts2.at(3) = 1;
	IntPlaintextEncoding intArray2(vectorOfInts2);
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<Ciphertext<ILDCRT2n>> cResult;

	cResult = cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0));


	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertextResults({ cResult });
	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 5U);
	EXPECT_EQ(results.at(1), 7U);
	EXPECT_EQ(results.at(2), 3U);
	EXPECT_EQ(results.at(3), 6U);
	DEBUG("13");
}


TEST_F(UTSHEAdvanced, test_composed_eval_mult_two_towers) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	usint ptm = 9;

	vector<native_int::BinaryInteger> init_moduli(init_size);

	vector<native_int::BinaryInteger> init_rootsOfUnity(init_size);

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params = GenerateDCRTParams( init_m, ptm, init_size, dcrtBits );

	shared_ptr<ILDCRTParams<BigBinaryInteger>> paramsSmall( new ILDCRTParams<BigBinaryInteger>( *params ) );
	paramsSmall->PopLastParam();

	usint relWindow = 1;

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, 5+4, relWindow, init_stdDev, init_size - 1, 6, 1.006);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	CryptoContext<ILDCRT2n> ccSmall = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(paramsSmall, ptm, relWindow, init_stdDev, init_size - 1);
	ccSmall.Enable(SHE);
	ccSmall.Enable(ENCRYPTION);
	ccSmall.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext
	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	//Generating Quadratic KeySwitchHint from sk^2 to skNew
	cc.EvalMultKeyGen(kp.secretKey);

	std::vector<usint> firstElement(8,0);
	firstElement[0] = 8;
	firstElement[1] = 5;
	firstElement[2] = 4;

	IntPlaintextEncoding firstElementEncoding(firstElement);

	std::vector<usint> secondElement(8,0);
	secondElement[0] = 7;
	secondElement[1] = 4;
	secondElement[2] = 2;

	IntPlaintextEncoding secondElementEncoding(secondElement);

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertextElementOne;
	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertextElementTwo;

	ciphertextElementOne = cc.Encrypt(kp.publicKey, firstElementEncoding, false);
	ciphertextElementTwo = cc.Encrypt(kp.publicKey, secondElementEncoding, false);

	shared_ptr<Ciphertext<ILDCRT2n>> cResult = cc.ComposedEvalMult(ciphertextElementOne[0], ciphertextElementTwo[0]);

	// ok let's try making the secret keys both have one less tower
	// because ComposedEvalMult performs a ModReduce

	ILDCRT2n tempPrivateElement(kp.secretKey->GetPrivateElement());
	tempPrivateElement.DropLastElement();
	kp.secretKey->SetPrivateElement(tempPrivateElement);

	shared_ptr<LPPrivateKey<ILDCRT2n>> kpSecretSmall( new LPPrivateKey<ILDCRT2n>(ccSmall) );
	kpSecretSmall->SetPrivateElement(tempPrivateElement);
	LPKeyPair<ILDCRT2n> kp1 = ccSmall.KeyGen();

	shared_ptr<LPEvalKey<ILDCRT2n>> KeySwitchHint = ccSmall.KeySwitchGen(kpSecretSmall, kp1.secretKey);

	// have to perform the operation in the new context
	shared_ptr<Ciphertext<ILDCRT2n>> cResultSmall( new Ciphertext<ILDCRT2n>(ccSmall) );
	cResultSmall->SetElements( cResult->GetElements() );

	cResult = ccSmall.KeySwitch(KeySwitchHint, cResultSmall);

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> tempvec2( { cResult } );
	IntPlaintextEncoding results;

	ccSmall.Decrypt(kp1.secretKey, tempvec2, &results, false);

	EXPECT_EQ(results.at(0), 2U);
	EXPECT_EQ(results.at(1), 4U);
	EXPECT_EQ(results.at(2), 1U);
	EXPECT_EQ(results.at(3), 8U);
	EXPECT_EQ(results.at(4), 8U);
}
#endif
