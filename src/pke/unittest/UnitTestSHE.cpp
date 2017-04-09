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

Test cases in this file make the following assumptions:
1. All functionatliy of plaintext (both BytePlainTextEncoding and IntPlainTextEncoding) work.
2. Encrypt/Decrypt work
3. Math layer operations such as functions in nbtheory
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;



template <class T>
class UTSHE : public ::testing::Test {

public:
	const usint m = 16;

protected:
	UTSHE() {}

	virtual void SetUp() {
	}

	virtual void TearDown() {

	}

	virtual ~UTSHE() {  }

};

TEST(UTSHE, keyswitch_sparse_key_SingleCRT_byteplaintext) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m,
			q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, plaintext);

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext.push_back(newCt);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);
}

TEST(UTSHE, keyswitch_sparse_key_SingleCRT_intArray) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m,
			q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);
	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	intArrayNew.resize(intArray.size());

	EXPECT_EQ(intArray, intArrayNew);
}

TEST(UTSHE, keyswitch_SingleCRT) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m,
			q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);
	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.KeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);
}

TEST(UTSHE, sparsekeygen_single_crt_encrypt_decrypt) {

	//ILVector2n::DestroyPreComputedSamples();

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m,
			q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.SparseKeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	ILVector2n privateElement(kp.secretKey->GetPrivateElement());
	privateElement.SwitchFormat();

	for (usint i = 1; i < privateElement.GetLength(); i += 2) {
		EXPECT_EQ(BigBinaryInteger::ZERO, privateElement.GetValAtIndex(i));
	}
}

TEST(UTSHE, keyswitch_ModReduce_DCRT) {

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;
	usint size = 4;

	vector<native64::BigBinaryInteger> moduli(size);
	moduli.reserve(4);
	vector<native64::BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity.reserve(4);

	native64::BigBinaryInteger q("1");
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("40"), native64::BigBinaryInteger("4"));

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("4"), native64::BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext(1);

	LPKeyPair<ILVectorArray2n> kp2 = cc.KeyGen();

	shared_ptr<LPEvalKey<ILVectorArray2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVectorArray2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	BytePlaintextEncoding plaintextNewKeySwitch;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNewKeySwitch);

	EXPECT_EQ(plaintext, plaintextNewKeySwitch);

	/**************************KEYSWITCH TEST END******************************/
	/**************************MODREDUCE TEST BEGIN******************************/

	cc.ModReduce(newCiphertext);
	ILVectorArray2n sk2PrivateElement(kp2.secretKey->GetPrivateElement());
	sk2PrivateElement.DropLastElement();
	kp2.secretKey->SetPrivateElement(sk2PrivateElement);

	BytePlaintextEncoding plaintextNewModReduce;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNewModReduce);
	
	EXPECT_EQ(plaintext, plaintextNewModReduce);
}

TEST(UTSHE, ringreduce_single_crt) {
	//ILVector2n::DestroyPreComputedSamples();
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m,
			q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	ciphertext = cc.RingReduce(ciphertext, keySwitchHint);

	ILVector2n skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	cc.Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR, false);

	IntPlaintextEncoding intArrayExpected = {1,1,1,1};

	EXPECT_EQ(intArrayNewRR, intArrayExpected);
}

TEST(UTSHE, ringreduce_double_crt) {

	usint m = 16;
	float stdDev = 4;
	usint size = 3;

	vector<native64::BigBinaryInteger> moduli(size);
	moduli.reserve(4);
	vector<native64::BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity.reserve(4);

	native64::BigBinaryInteger q("1");
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("40"), native64::BigBinaryInteger("4"));

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("4"), native64::BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVectorArray2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVectorArray2n>> keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	newCiphertext[0] = cc.KeySwitch(keySwitchHint, ciphertext[0]);

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	ciphertext = cc.RingReduce(ciphertext, keySwitchHint);

	ILVectorArray2n skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	cc.Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR, false);

	IntPlaintextEncoding intArrayExpected({ 1,1,1,1 });

	EXPECT_EQ(intArrayNewRR, intArrayExpected);

	ILVector2n::DestroyPreComputedSamples();

}

TEST(UTSHE, canringreduce) {
	BigBinaryInteger m1("17729");
	BigBinaryInteger m2("17761");
	std::vector<BigBinaryInteger> moduli;
	moduli.reserve(2);
	moduli.push_back(m1);
	moduli.push_back(m2);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(SHE);

	EXPECT_TRUE(algorithm.CanRingReduce(4096, moduli, 1.006));
	EXPECT_TRUE(algorithm.CanRingReduce(2048, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(1024, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(512, moduli, 1.006));

}

TEST(UTSHE, decomposeMult) {
	usint m1 = 16;

	BigBinaryInteger modulus("1");
	NextQ(modulus, BigBinaryInteger("2"), m1, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
	shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );

	ILVector2n x1(params, Format::COEFFICIENT);
	x1 = { 0,0,0,0,0,0,1,0 };

	ILVector2n x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	ILVector2n resultsEval(params2, Format::EVALUATION);

	x1.SwitchFormat();
	x2.SwitchFormat();

	resultsEval = x1*x2;

	resultsEval.SwitchFormat();

	ILVector2n x3(x1.CloneParametersOnly());
	x3.SetFormat(Format::COEFFICIENT);
	x3 = { 0,0,0,1 };

	ILVector2n x4(x1.CloneParametersOnly());
	x4.SetFormat(Format::COEFFICIENT);
	x4 = { 0,0,0,1 };

	x3.SwitchFormat();
	x4.SwitchFormat();

	ILVector2n resultsTest(x4.CloneParametersOnly());

	resultsTest = x3 * x4;

	resultsTest.SwitchFormat();
}
