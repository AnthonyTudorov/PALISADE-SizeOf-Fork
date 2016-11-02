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

#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/utils/cryptoutility.h"
#include "../../src/lib/encoding/intplaintextencoding.h"


#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

/**Simple Encrypt-Decrypt check for BV scheme.
* This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*/
TEST(UTBVDCRT, ILVector2n_bv_Encrypt_Decrypt_DCRT) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);

	bool successKeyGen = false;

	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext, false);	// This is the core encryption operation.


	IntPlaintextEncoding intArrayNew;



	DecryptResult result = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertext, &intArrayNew, false);  // This is the core decryption operation.



	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}
	
	EXPECT_EQ(intArray1, intArrayNew);
}


TEST(UTBVDCRT, ILVector2n_bv_PRE_DCRT) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	bool successKeyGen = false;

	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext, false);	// This is the core encryption operation.


	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPPublicKey<ILVectorArray2n> newPK(cryptoParams);
	LPPrivateKey<ILVectorArray2n> newSK(cryptoParams);



	successKeyGen = CryptoUtility<ILVectorArray2n>::KeyGen(algorithm, &newPK, &newSK);	// This is the same core key generation operation.

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	LPEvalKeyRelin<ILVectorArray2n> evalKey(cryptoParams);

	algorithm.ReKeyGen(newSK, sk, &evalKey);  // FIXME this can't use CryptoUtility because the calling sequence is wrong (2 private keys)


	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<Ciphertext<ILVectorArray2n>> newCiphertext;

	CryptoUtility<ILVectorArray2n>::ReEncrypt(algorithm, evalKey, ciphertext, &newCiphertext);  // This is the core re-encryption operation.																				

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding intArrayNew;


	DecryptResult result1 = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, newSK, newCiphertext, &intArrayNew, false);  // This is the core decryption operation.

	if (!result1.isValid) {
		exit(1);
	}

	EXPECT_EQ(intArray1, intArrayNew);
}

TEST(UTBVDCRT, ILVector2n_bv_EVALADD_DCRT) {

	usint m = 8;

	usint numOfTower = 2;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BytePlaintextEncoding ctxtd;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger(13));  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(1);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	//Precomputations for DGG
	//ILVector2n::PreComputeDggSamples(dgg, params);


	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1(4);
	vectorOfInts1 = { 2,3,1,4 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(4);
	vectorOfInts2 = { 3,6,3,1 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected(4);
	vectorOfInts2 = { 5,9,4,5 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);

	bool successKeyGen = false;

	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.


	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	algorithm.EvalAdd(ciphertext1.at(0), ciphertext2.at(0), &cResult);

	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

	EXPECT_EQ(intArrayExpected, results);
}


TEST(UTBVDCRT, ILVector2n_bv_EVALMULT) {

	usint m = 8;

	float stdDev = 4;

	BigBinaryInteger q("500000");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4000"), BigBinaryInteger("40000"));
	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(8);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

															//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3,0,0,0 };

	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 2,0,0,0 };

	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	LPPublicKeyEncryptionSchemeBV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext1;
	vector<Ciphertext<ILVector2n>> ciphertext2;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);


	Ciphertext<ILVector2n> cResult(ciphertext1.at(0));

	LPEvalKeyRelin<ILVector2n> keySwitchHint(cryptoParams);

	algorithm.QuadraticEvalMultKeyGen(sk, sk, &keySwitchHint);

	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint, &cResult);

	vector<Ciphertext<ILVector2n>> ciphertextResults(1);

	ciphertextResults.at(0) = cResult;

	IntPlaintextEncoding results;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

	EXPECT_EQ(intArrayExpected, results);

}

TEST(UTBVDCRT, ILVector2n_bv_EVALMULT_DCRT) {

	usint init_m = 8;

	float init_stdDev = 4;

	usint init_size = 3;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("2199023288321");
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


	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG

	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(init_stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	//Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 2,0,0,0 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 3,0,0,0 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);



	Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	LPEvalKeyRelin<ILVectorArray2n> keySwitchHint(cryptoParams);

	algorithm.QuadraticEvalMultKeyGen(sk, sk, &keySwitchHint);

	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint, &cResult);

	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);

	ciphertextResults.at(0) = cResult;

	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

	EXPECT_EQ(intArrayExpected, results);

}

TEST(UTBVDCRT, ILVector2n_bv_DCRT_MODREDUCE) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
		std::cout << "modulus is: " << moduli[j] << std::endl;
		std::cout << "rootsOfUnity is: " << rootsOfUnity[j] << std::endl;
	}


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	//Precomputations for DGG
	//ILVector2n::PreComputeDggSamples(dgg, params);


	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::vector<usint> vectorOfInts1 = { 4,1,2,3 };

	IntPlaintextEncoding intArray1(vectorOfInts1);


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);


	bool successKeyGen = false;

	std::cout << "\n" << "Running key generation..." << std::endl;


	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	//cout<<"\n"<<"original plaintext: "<< intArray1 <<"\n"<<endl;

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext, false);	// This is the core encryption operation.


	IntPlaintextEncoding intArrayNew;

	CryptoUtility<ILVectorArray2n>::ModReduce(algorithm, &ciphertext);

	//drop a tower from the secret key

	auto skEl(sk.GetPrivateElement());
	skEl.DropElementAtIndex(skEl.GetNumOfElements() - 1);
	sk.SetPrivateElement(skEl);

	DecryptResult result = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertext, &intArrayNew, false);  // This is the core decryption operation.



	if (!result.isValid) {
		exit(1);
	}

	EXPECT_EQ(intArray1, intArrayNew);

}


TEST(UTBVDCRT, ILVector2n_bv_DCRT_MULT_MODREDUCE) {//TO ADD MODREDUCE

	usint init_m = 8;

	float init_stdDev = 4;

	usint init_size = 3;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("2199023288321");
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


	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG

	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(init_stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	//Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 2,0,0,0 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 3,0,0,0 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;
	vector<Ciphertext<ILVectorArray2n>> ciphertextResult(1);

	ciphertextResult.at(0).SetCryptoParameters(&cryptoParams);


	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	//Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	LPEvalKeyRelin<ILVectorArray2n> keySwitchHint(cryptoParams);

	algorithm.QuadraticEvalMultKeyGen(sk, sk, &keySwitchHint);


	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint, &ciphertextResult.at(0));

	//CryptoUtility<ILVectorArray2n>::ModReduce(algorithm,&ciphertextResult);


	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResult, &results, false);

	EXPECT_EQ(intArrayExpected, results);

}






