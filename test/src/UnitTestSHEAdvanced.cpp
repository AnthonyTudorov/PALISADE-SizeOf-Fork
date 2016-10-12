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
Hadi Sajjadpour, ss2959@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This file tests the following
EvalAdd
EvalMult
ComposedEvalMult
LevelReduction

ModReduce, RingReduce and KeySwitch Hint will be in UnitTestSHE.cpp

*/

#include "../include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"


#include "../../src/lib/crypto/cryptocontext.h"
#include "../../src/lib/utils/cryptocontexthelper.h"
#include "../../src/lib/crypto/cryptocontext.cpp"
#include "../../src/lib/utils/cryptocontexthelper.cpp"
#include "../../src/lib/crypto/ciphertext.h"
#include "../../src/lib/crypto/ciphertext.cpp"


#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"

#include "../../src/lib/utils/cryptoutility.h"

#include "../../src/lib/utils/debug.h"
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

/*Testing Parameter selection. The test will check if generated parameters are greater than the following thresholds:
* The first modulus generated needs to be greater than q1 > 4pr sqrt(n) w. Where
* p is the plaintext modulus
* r is Gaussian Parameter
* w is the assurance measure
* n is the ring dimension
*/
TEST_F(UTSHEAdvanced, ParameterSelection) {


	usint m = 16; // initial cycltomic order

	float stdDev = 4;

	usint size = 11; // tower size, equal to depth of operation + 1

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus* moduli[i];

	}

	//intializing cryptoparameters alongside variables
	DiscreteGaussianGenerator dgg(stdDev);
	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	//New CryptoParameters placeholder
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
	//calling ParameterSelection. cryptoParams2 will have the new Moduli and ring dimension (cyclotomicorder/2)
	cryptoParams.ParameterSelection(&cryptoParams2);

	shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>(cryptoParams2.GetElementParams());
	std::vector<BigBinaryInteger> finalModuli = dcrtParams->GetModuli();
	//threshold for the first modulus
	double q1Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetElementParams()->GetCyclotomicOrder() / 2, 0.5) * cryptoParams2.GetAssuranceMeasure();
	//test for the first modulus
	EXPECT_LT(q1Threshold, finalModuli[0].ConvertToDouble());
	//threshold for all but the first modulus
	double q2Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetDistributionParameter(), 5) * pow(cryptoParams2.GetElementParams()->GetCyclotomicOrder() / 2, 1.5) * pow(cryptoParams2.GetAssuranceMeasure(), 5);

	//test for all but the first modulus
	for (usint i = 1; i < finalModuli.size(); i++) {
		EXPECT_LT(q2Threshold, finalModuli[i].ConvertToDouble());
	}
}

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {

	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4000"), BigBinaryInteger("40000"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(/*plaintextmodulus*/ 5 + 4,
			/*ringdim*/ m, /*modulus*/ q.ToString(), rootOfUnity.ToString(),
			/*relinWindow*/ 1, /*stDev*/ stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

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

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<Ciphertext<ILVector2n>> cResult =
			cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0));

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();

	cc.GetEncryptionAlgorithm().QuadraticEvalMultKeyGen(kp.secretKey, skNew, &keySwitchHint);

	cResult = cc.GetEncryptionAlgorithm().KeySwitch(keySwitchHint, cResult);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	cc.Decrypt(newKp.secretKey, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 6);

	ILVector2n::DestroyPreComputedSamples();
}

TEST_F(UTSHEAdvanced, test_eval_mult_double_crt) {

	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	LPCryptoParametersLTV<ILVectorArray2n> finalParams;

	cryptoParams.ParameterSelection(&finalParams);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParams.GetElementParams());

	usint m = dcrtParams.GetCyclotomicOrder();
	usint size = finalParams.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParams.GetPlaintextModulus();
	//scheme initialization: LTV Scheme
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPPublicKey<ILVectorArray2n> pk(finalParams);
	LPPrivateKey<ILVectorArray2n> sk(finalParams);
	algorithm.KeyGen(&pk, &sk);

	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsOneTower(finalParams);
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
	IntPlaintextEncoding intArray2(vectorOfInts2);
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);

	algorithm.KeyGen(&pk, &sk);


	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), &cResult);

	LPEvalKeyNTRU<ILVectorArray2n> keySwitchHint(cryptoParams);

	LPPublicKey<ILVectorArray2n> pkNew(finalParams);
	LPPrivateKey<ILVectorArray2n> skNew(finalParams);

	algorithm.KeyGen(&pkNew, &skNew);

	algorithm.QuadraticEvalMultKeyGen(sk, skNew, &keySwitchHint);

	cResult = algorithm.KeySwitch(keySwitchHint, cResult);

	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, skNew, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 6);
	EXPECT_EQ(results.at(1), 0);
	EXPECT_EQ(results.at(2), 3);

}

TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::THREE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1(8);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 3;
	vectorOfInts1.at(2) = 1;
	vectorOfInts1.at(3) = 4;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(8);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 6;
	vectorOfInts2.at(2) = 3;
	vectorOfInts2.at(3) = 1;
	IntPlaintextEncoding intArray2(vectorOfInts2);
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext1;
	vector<Ciphertext<ILVector2n>> ciphertext2;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	Ciphertext<ILVector2n> cResult(ciphertext1.at(0));

	algorithm.EvalAdd(ciphertext1.at(0), ciphertext2.at(0), &cResult);

	vector<Ciphertext<ILVector2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 5);
	EXPECT_EQ(results.at(1), 1);
	EXPECT_EQ(results.at(2), 4);
	EXPECT_EQ(results.at(3), 5);

	ILVector2n::DestroyPreComputedSamples();
}

TEST_F(UTSHEAdvanced, test_eval_add_double_crt) {
        bool dbg_flag = false;
	usint init_m = 16;


	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");
	DEBUG("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}
	DEBUG("2");
	DiscreteGaussianGenerator dgg(init_stdDev);
	DEBUG("3");
	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);
	DEBUG("4");
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);
	DEBUG("5");
	usint n = 16;

	LPCryptoParametersLTV<ILVectorArray2n> finalParams;

	cryptoParams.ParameterSelection(&finalParams);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParams.GetElementParams());

	usint m = dcrtParams.GetCyclotomicOrder();
	usint size = finalParams.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParams.GetPlaintextModulus();
	DEBUG("6");
	//scheme initialization: LTV Scheme
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPPublicKey<ILVectorArray2n> pk(finalParams);
	LPPrivateKey<ILVectorArray2n> sk(finalParams);
	algorithm.KeyGen(&pk, &sk);
	DEBUG("7");
	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsOneTower(finalParams);
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


	DEBUG("8");

	algorithm.KeyGen(&pk, &sk);
	DEBUG("9");
	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);
	DEBUG("10");
	Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	algorithm.EvalAdd(ciphertext1.at(0), ciphertext2.at(0), &cResult);


	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;
	DEBUG("11");
	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);
	DEBUG("12");
	EXPECT_EQ(results.at(0), 5);
	EXPECT_EQ(results.at(1), 7);
	EXPECT_EQ(results.at(2), 3);
	EXPECT_EQ(results.at(3), 6);
	DEBUG("13");
}

TEST_F(UTSHEAdvanced, test_composed_eval_mult_two_towers) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	LPCryptoParametersLTV<ILVectorArray2n> finalParamsTwoTowers;

	cryptoParams.ParameterSelection(&finalParamsTwoTowers);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParamsTwoTowers.GetElementParams());

	usint m = dcrtParams.GetCyclotomicOrder();
	usint size = finalParamsTwoTowers.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParamsTwoTowers.GetPlaintextModulus();
	//scheme initialization: LTV Scheme
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPPublicKey<ILVectorArray2n> pk(finalParamsTwoTowers);
	LPPrivateKey<ILVectorArray2n> sk(finalParamsTwoTowers);
	algorithm.KeyGen(&pk, &sk);

	//Generate the keys for level 1, same number of towers
	LPPublicKey<ILVectorArray2n> pk1(finalParamsTwoTowers);
	LPPrivateKey<ILVectorArray2n> sk1(finalParamsTwoTowers);
	algorithm.KeyGen(&pk1, &sk1);

	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsOneTower(finalParamsTwoTowers);

	const ILDCRTParams &dcrtParamsWithOneTowers = dynamic_cast<const ILDCRTParams&>(finalParamsTwoTowers.GetElementParams());
	ILDCRTParams dcrtParamsWith1Tower(dcrtParamsWithOneTowers);
	dcrtParamsWith1Tower.PopLastParam();
	finalParamsOneTower.SetElementParams(dcrtParamsWith1Tower);

	//Generating Quaraditic KeySwitchHint from sk^2 to skNew
	LPEvalKeyNTRU<ILVectorArray2n> quadraticKeySwitchHint(finalParamsTwoTowers);
	algorithm.QuadraticEvalMultKeyGen(sk, sk1, &quadraticKeySwitchHint);

	//Dropping the last tower of skNew, because ComposedEvalMult performs a ModReduce
	LPPrivateKey<ILVectorArray2n> sk2(finalParamsOneTower);
	ILVectorArray2n skNewOldElement(sk1.GetPrivateElement());
	skNewOldElement.DropElementAtIndex(skNewOldElement.GetNumOfElements() - 1);
	sk2.SetPrivateElement(skNewOldElement);

	std::vector<usint> firstElement(2048);
	firstElement.at(0) = 8;
	firstElement.at(1) = 5;
	firstElement.at(2) = 4;

	std::fill(firstElement.begin() + 3, firstElement.end(), 0);

	IntPlaintextEncoding firstElementEncoding(firstElement);

	std::vector<usint> secondElement(2048);
	secondElement.at(0) = 7;
	secondElement.at(1) = 4;
	secondElement.at(2) = 2;


	std::fill(secondElement.begin() + 3, secondElement.end(), 0);
	IntPlaintextEncoding secondElementEncoding(secondElement);

	vector<Ciphertext<ILVectorArray2n>> ciphertextElementOne;
	vector<Ciphertext<ILVectorArray2n>> ciphertextElementTwo;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, firstElementEncoding, &ciphertextElementOne, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, secondElementEncoding, &ciphertextElementTwo, false);

	vector<Ciphertext<ILVectorArray2n>> cResult(ciphertextElementOne);

	CryptoUtility<ILVectorArray2n>::ComposedEvalMult(algorithm, ciphertextElementOne, ciphertextElementTwo, quadraticKeySwitchHint, &cResult);

	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk2, cResult, &results, false);

	EXPECT_EQ(results.at(0), 2);
	EXPECT_EQ(results.at(1), 4);
	EXPECT_EQ(results.at(2), 1);
	EXPECT_EQ(results.at(3), 8);
	EXPECT_EQ(results.at(4), 8);
}
