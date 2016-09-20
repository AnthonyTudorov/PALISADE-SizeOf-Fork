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

#include "../include/gtest/gtest.h"
#include <iostream>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/math/nbtheory.h"
#include "../../src/lib/lattice/elemparams.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/lattice/ilelement.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/crypto/lwepre.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"
#include "../../src/lib/utils/utilities.h"

#include "../../src/lib/crypto/lwecrypt.cpp"
#include "../../src/lib/crypto/ciphertext.cpp"
#include "../../src/lib/utils/cryptoutility.h"

#include "../../src/lib/utils/debug.h"
#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"



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

	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;

	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);
	vector<Ciphertext<ILVector2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());

	LPPublicKey<ILVector2n> pk2(cryptoParams);
	LPPrivateKey<ILVector2n> sk2(cryptoParams);

	algorithm.SparseKeyGen(&pk2, &sk2);

	LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);
	algorithm.EvalMultKeyGen(sk, sk2, &keySwitchHint);


	CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	BytePlaintextEncoding plaintextNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk2, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);

	ILVector2n::DestroyPreComputedSamples();
}

TEST(UTSHE, keyswitch_sparse_key_SingleCRT_intArray) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;

	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray, &ciphertext);
	vector<Ciphertext<ILVector2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());

	LPPublicKey<ILVector2n> pk2(cryptoParams);
	LPPrivateKey<ILVector2n> sk2(cryptoParams);

	algorithm.SparseKeyGen(&pk2, &sk2);

	LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);
	algorithm.EvalMultKeyGen(sk, sk2, &keySwitchHint);

	CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	IntPlaintextEncoding intArrayNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk2, newCiphertext, &intArrayNew);

	EXPECT_EQ(intArray, intArrayNew);

	ILVector2n::DestroyPreComputedSamples();

}

TEST(UTSHE, keyswitch_SingleCRT) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	 //Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk); 

	vector<Ciphertext<ILVector2n>> ciphertext;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);
	vector<Ciphertext<ILVector2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());
		  
	   LPPublicKey<ILVector2n> pk2(cryptoParams);
	   LPPrivateKey<ILVector2n> sk2(cryptoParams);

	   algorithm.KeyGen(&pk2, &sk2);


    LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);
    algorithm.EvalMultKeyGen(sk, sk2, &keySwitchHint);


	CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	BytePlaintextEncoding plaintextNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk2, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);
	 
    ILVector2n::DestroyPreComputedSamples();
	 
}

TEST(UTSHE, sparsekeygen_single_crt_encrypt_decrypt) {

	//ILVector2n::DestroyPreComputedSamples();

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;

	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(ENCRYPTION);

	algorithm.SparseKeyGen(&pk, &sk);
	vector<Ciphertext<ILVector2n>> ciphertext;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);

	BytePlaintextEncoding plaintextNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	ILVector2n privateElement(sk.GetPrivateElement());
	privateElement.SwitchFormat();

	for (usint i = 1; i < privateElement.GetLength(); i += 2) {
		EXPECT_EQ(BigBinaryInteger::ZERO, privateElement.GetValAtIndex(i));
	}
	ILVector2n::DestroyPreComputedSamples();
}

TEST(UTSHE, keyswitch_ModReduce_DCRT) {

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;
	usint size = 4;

	vector<BigBinaryInteger> moduli(size);
	moduli.reserve(4);
	vector<BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity.reserve(4);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus* moduli[i];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	ILDCRTParams params(m, moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);


	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;

	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk); 

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);
	vector<Ciphertext<ILVectorArray2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());

	LPPublicKey<ILVectorArray2n> pk2(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk2(cryptoParams);

	algorithm.KeyGen(&pk2, &sk2);

	LPEvalKeyNTRU<ILVectorArray2n> keySwitchHint(cryptoParams);
	algorithm.EvalMultKeyGen(sk, sk2, &keySwitchHint);
	


	CryptoUtility<ILVectorArray2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	BytePlaintextEncoding plaintextNewKeySwitch;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk2, newCiphertext, &plaintextNewKeySwitch);

	EXPECT_EQ(plaintext, plaintextNewKeySwitch);

	/**************************KEYSWITCH TEST END******************************/
	/**************************MODREDUCE TEST BEGIN******************************/

	CryptoUtility<ILVectorArray2n>::ModReduce(algorithm, &newCiphertext);
	ILVectorArray2n sk2PrivateElement(sk2.GetPrivateElement());
	sk2PrivateElement.DropElementAtIndex(sk2PrivateElement.GetNumOfElements() - 1);
	sk2.SetPrivateElement(sk2PrivateElement);

	BytePlaintextEncoding plaintextNewModReduce;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk2, newCiphertext, &plaintextNewModReduce);
	
	EXPECT_EQ(plaintext, plaintextNewModReduce);

}

TEST(UTSHE, ringreduce_single_crt) {
	//ILVector2n::DestroyPreComputedSamples();
	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;

	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(SHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray, &ciphertext, false);
	vector<Ciphertext<ILVector2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());

	LPPublicKey<ILVector2n> pk2(cryptoParams);
	LPPrivateKey<ILVector2n> skSparse(cryptoParams);

	algorithm.SparseKeyGen(&pk2, &skSparse);

	LPEvalKeyNTRU<ILVector2n> keySwitchHint(cryptoParams);

	algorithm.EvalMultKeyGen(sk, skSparse, &keySwitchHint);

	CryptoUtility<ILVector2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	IntPlaintextEncoding intArrayNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, skSparse, newCiphertext, &intArrayNew, false);

	CryptoUtility<ILVector2n>::RingReduce(algorithm, &ciphertext, keySwitchHint);

	ILVector2n skSparseElement(skSparse.GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	skSparse.SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	LPCryptoParametersLTV<ILVector2n> cryptoParamsRR;
	ILParams ilparams2(ciphertext[0].GetElement().GetParams().GetCyclotomicOrder() / 2, ciphertext[0].GetElement().GetParams().GetModulus(), ciphertext[0].GetElement().GetParams().GetRootOfUnity());
	cryptoParamsRR.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParamsRR.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParamsRR.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParamsRR.SetElementParams(ilparams2);                // Set the initialization parameters.
	cryptoParamsRR.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

//	for (int i = 0; i < ciphertext.size(); i++) {
//		ciphertext.at(i).SetCryptoParameters(&cryptoParamsRR);
//	}

//	skSparse.SetCryptoParameters(&cryptoParamsRR);

	CryptoUtility<ILVector2n>::Decrypt(algorithm, skSparse, ciphertext, &intArrayNewRR, false);

	std::vector<usint> vectorOfExpectedResults = { 1,1,1,1 };
	IntPlaintextEncoding intArrayExpected(vectorOfExpectedResults);

	EXPECT_EQ(intArrayNewRR, intArrayExpected);

	ILVector2n::DestroyPreComputedSamples();
}

TEST(UTSHE, ringreduce_double_crt) {

	usint m = 16;
	float stdDev = 4;
	usint size = 3;

	vector<BigBinaryInteger> moduli(size);
	moduli.reserve(4);
	vector<BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity.reserve(4);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus* moduli[i];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	ILDCRTParams params(m, moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

	//Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;

	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(SHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray, &ciphertext, false);
	vector<Ciphertext<ILVectorArray2n>> newCiphertext;
	newCiphertext.reserve(ciphertext.size());

	LPPublicKey<ILVectorArray2n> pk2(cryptoParams);
	LPPrivateKey<ILVectorArray2n> skSparse(cryptoParams);

	algorithm.SparseKeyGen(&pk2, &skSparse);

	LPEvalKeyNTRU<ILVectorArray2n> keySwitchHint(cryptoParams);
	algorithm.EvalMultKeyGen(sk, skSparse, &keySwitchHint);

	CryptoUtility<ILVectorArray2n>::KeySwitch(algorithm, keySwitchHint, ciphertext, &newCiphertext);

	IntPlaintextEncoding intArrayNew;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, skSparse, newCiphertext, &intArrayNew, false);

	CryptoUtility<ILVectorArray2n>::RingReduce(algorithm, &ciphertext, keySwitchHint);

	ILVectorArray2n skSparseElement(skSparse.GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	skSparse.SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParamsRR;
	cryptoParamsRR.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParamsRR.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParamsRR.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParamsRR.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

//	for (int i = 0; i < ciphertext.size(); i++) {
//		ciphertext.at(i).SetCryptoParameters(&cryptoParamsRR);
//	}

	LPPrivateKey<ILVectorArray2n> skSparseRR(cryptoParamsRR);

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, skSparse, ciphertext, &intArrayNewRR, false);

	std::vector<usint> vectorOfExpectedResults = { 1,1,1,1 };
	IntPlaintextEncoding intArrayExpected(vectorOfExpectedResults);

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
	ILParams params(m1, modulus, rootOfUnity);
	ILParams params2(m1 / 2, modulus, rootOfUnity);

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

	ILVector2n x3(x1.CloneWithParams());
	x3.SetFormat(Format::COEFFICIENT);
	x3 = { 0,0,0,1 };

	ILVector2n x4(x1.CloneWithParams());
	x4.SetFormat(Format::COEFFICIENT);
	x4 = { 0,0,0,1 };

	x3.SwitchFormat();
	x4.SwitchFormat();

	ILVector2n resultsTest(x4.CloneWithParams());

	resultsTest = x3 * x4;

	resultsTest.SwitchFormat();
}
