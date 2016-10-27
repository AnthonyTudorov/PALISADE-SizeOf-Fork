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

	keySwitchHint = cc.QuadraticEvalMultKeyGen(kp.secretKey, newKp.secretKey);

	cResult = cc.KeySwitch(keySwitchHint, cResult);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	cc.Decrypt(newKp.secretKey, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 6);

	ILVector2n::DestroyPreComputedSamples();
}

TEST_F(UTSHEAdvanced, test_eval_mult_double_crt) {
    bool dbg_flag = true;

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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

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

	DEBUG("old parms " << cryptoParams);
	DEBUG("new parms" << finalParams);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParams);
	//scheme initialization: LTV Scheme
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp;

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

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<Ciphertext<ILVectorArray2n>> cResult = cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0));

	DEBUG("1 " << ciphertext1.at(0)->GetElement().GetLength());
	DEBUG("2 " << ciphertext2.at(0)->GetElement().GetLength());
	DEBUG("out " << cResult->GetElement().GetLength());

	shared_ptr<LPEvalKeyNTRU<ILVectorArray2n>> keySwitchHint;

	LPKeyPair<ILVectorArray2n> newKp = cc.KeyGen();

	keySwitchHint = cc.QuadraticEvalMultKeyGen(kp.secretKey, newKp.secretKey);

	shared_ptr<Ciphertext<ILVectorArray2n>> swResult = cc.KeySwitch(keySwitchHint, cResult);
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> sResult( {swResult} );

	IntPlaintextEncoding results;

	cc.Decrypt(newKp.secretKey, sResult, &results, false);

	EXPECT_EQ(6, results.at(0));
	EXPECT_EQ(0, results.at(1));
	EXPECT_EQ(3, results.at(2));

}

TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
    bool dbg_flag = false;
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	//shared_ptr<ILParams> params( new ILParams(m, q, RootOfUnity(m, q)) );

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(
			/* plaintextmodulus */ 5 + 3,
			/* ringdim */ m,
			/* modulus */ q.ToString(),
			rootOfUnity.ToString(),
			/* relinWindow */ 1,
			stdDev);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

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

	EXPECT_EQ(5, results.at(0));
	EXPECT_EQ(1, results.at(1));
	EXPECT_EQ(4, results.at(2));
	EXPECT_EQ(5, results.at(3));

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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

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

	const shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>(finalParams.GetElementParams());

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParams);

	usint m = dcrtParams->GetCyclotomicOrder();
	usint size = finalParams.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParams.GetPlaintextModulus();

	//scheme initialization: LTV Scheme
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

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

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<Ciphertext<ILVectorArray2n>> cResult;

	cResult = cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0));


	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertextResults({ cResult });
	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, ciphertextResults, &results, false);

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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

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

	const shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>(finalParamsTwoTowers.GetElementParams());

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParamsTwoTowers);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	usint m = dcrtParams->GetCyclotomicOrder();
	usint size = finalParamsTwoTowers.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParamsTwoTowers.GetPlaintextModulus();

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//Generate the keys for level 1, same number of towers
	LPKeyPair<ILVectorArray2n> kp1 = cc.KeyGen();

	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsOneTower(finalParamsTwoTowers);

	const shared_ptr<ILDCRTParams> dcrtParamsWithOneTowers = std::static_pointer_cast<ILDCRTParams>(finalParamsTwoTowers.GetElementParams());
	shared_ptr<ILDCRTParams> dcrtParamsWith1Tower( new ILDCRTParams(*dcrtParamsWithOneTowers) );
	dcrtParamsWith1Tower->PopLastParam();
	finalParamsOneTower.SetElementParams(dcrtParamsWith1Tower);

	//Generating Quaraditic KeySwitchHint from sk^2 to skNew
	shared_ptr<LPEvalKeyNTRU<ILVectorArray2n>> quadraticKeySwitchHint = cc.QuadraticEvalMultKeyGen(kp.secretKey, kp1.secretKey);

	//Dropping the last tower of skNew, because ComposedEvalMult performs a ModReduce
	shared_ptr<LPPrivateKey<ILVectorArray2n>> sk2( new LPPrivateKey<ILVectorArray2n>( kp1.secretKey->GetCryptoContext() ) );
	ILVectorArray2n skNewOldElement(kp1.secretKey->GetPrivateElement());
	skNewOldElement.DropElementAtIndex(skNewOldElement.GetNumOfElements() - 1);
	sk2->SetPrivateElement(skNewOldElement);

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

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertextElementOne;
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertextElementTwo;

	ciphertextElementOne = cc.Encrypt(kp.publicKey, firstElementEncoding, false);
	ciphertextElementTwo = cc.Encrypt(kp.publicKey, secondElementEncoding, false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cResult =
			cc.ComposedEvalMult(ciphertextElementOne, ciphertextElementTwo, quadraticKeySwitchHint);

	IntPlaintextEncoding results;

	cc.Decrypt(sk2, cResult, &results, false);

	EXPECT_EQ(results.at(0), 2);
	EXPECT_EQ(results.at(1), 4);
	EXPECT_EQ(results.at(2), 1);
	EXPECT_EQ(results.at(3), 8);
	EXPECT_EQ(results.at(4), 8);
}
