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
This code test FV scheme operations.

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
#include <fstream>

#include "../../src/lib/crypto/cryptocontext.h"
#include "../../src/lib/utils/cryptocontexthelper.h"
#include "../../src/lib/crypto/cryptocontext.cpp"
#include "../../src/lib/utils/cryptocontexthelper.cpp"

#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"
#include "../../src/lib/utils/cryptoutility.h"

#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

/**Simple Encrypt-Decrypt check for FV scheme.
* This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*/
TEST(UTFV, ILVector2n_FV_Encrypt_Decrypt) {

	usint m = 2048;
	BigBinaryInteger modulus("268441601");
	BigBinaryInteger rootOfUnity("16947867");
	usint relWindow = 1;

	//BigBinaryInteger modulus2("1237940039285380274899136513");
	//BigBinaryInteger rootOfUnity2("1067388930511360414468370668");

	//BigBinaryInteger modulus2("1152921504606877697");
	//BigBinaryInteger rootOfUnity2("418639631973566421");

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	
	float stdDev = 4;

	//Prepare for parameters.
	ILParams ilParams(m, modulus, rootOfUnity);

	BigBinaryInteger plaintextModulus(BigBinaryInteger::TWO);

	//Set crypto parametes
	LPCryptoParametersFV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plaintextModulus);  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(1);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	BigBinaryInteger delta(modulus.DividedBy(plaintextModulus));
	cryptoParams.SetDelta(delta);

	DiscreteGaussianGenerator dgg(stdDev);				// Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	const ILParams &cpILParams = static_cast<const ILParams&>(cryptoParams.GetElementParams());

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	// Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	//Regular FV encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPPublicKeyEncryptionSchemeFV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);

	bool successKeyGen = false;

	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<ILVector2n>> ciphertext;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext, false);	// This is the core encryption operation.

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew, false);  // This is the core decryption operation.

	EXPECT_EQ(plaintextNew, plaintext);

}

TEST(UTFV, ILVector2n_FV_Eval_Operations) {

	usint m = 2048;
	//BigBinaryInteger modulus("1152921504606877697");
	//BigBinaryInteger rootOfUnity("418639631973566421");

	BigBinaryInteger modulus("1099511678977");
	BigBinaryInteger rootOfUnity("928976858506");

	BigBinaryInteger bigModulus("1237940039285380274899136513");
	BigBinaryInteger bigRootOfUnity("1067388930511360414468370668");

	//BigBinaryInteger modulus("1267650600228229401496703385601");
	//BigBinaryInteger rootOfUnity("540976213121087081496420385771");

	usint relWindow = 1;

	BigBinaryInteger plaintextModulus(BigBinaryInteger("64"));

	float stdDev = 4;

	//Prepare for parameters.
	ILParams ilParams(m, modulus, rootOfUnity);

	//Set crypto parametes
	LPCryptoParametersFV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plaintextModulus);  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(1);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	BigBinaryInteger delta(modulus.DividedBy(plaintextModulus));
	cryptoParams.SetDelta(delta);
	cryptoParams.SetMode(RLWE);
	cryptoParams.SetBigModulus(bigModulus);
	cryptoParams.SetBigRootOfUnity(bigRootOfUnity);

	DiscreteGaussianGenerator dgg(stdDev);				// Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	const ILParams &cpILParams = static_cast<const ILParams&>(cryptoParams.GetElementParams());

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	// Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPPublicKeyEncryptionSchemeFV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);

	algorithm.ParamsGen(&cryptoParams);

	bool successKeyGen = false;

	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<ILVector2n>> ciphertext1;
	vector<Ciphertext<ILVector2n>> ciphertext2;
	vector<Ciphertext<ILVector2n>> ciphertextAdd;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext1, &ciphertext1, true);	
	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext2, &ciphertext2, true);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	//YSP this is a workaround for now - I think we need to change EvalAdd to do this automatically
	Ciphertext<ILVector2n> ciphertextTemp(ciphertext1[0]);

	//YSP this needs to be switched to the CryptoUtility operation
	algorithm.EvalAdd(ciphertext1[0], ciphertext2[0], &ciphertextTemp);

	ciphertextAdd.push_back(ciphertextTemp);

	IntPlaintextEncoding plaintextNew;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertextAdd, &plaintextNew, true);  // This is the core decryption operation.

	//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	plaintextNew.resize(plaintextAdd.size());

	EXPECT_EQ(plaintextAdd, plaintextNew) << "FV.EvalAdd gives incorrect results.\n";

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	LPEvalKeyRelin<ILVector2n> evalKey(cryptoParams);

	//generate the evaluate key
	algorithm.RelinKeyGen(sk, &evalKey);

	vector<Ciphertext<ILVector2n>> ciphertextMult;

	//YSP this is a workaround for now - I think we need to change EvalAdd to do this automatically
	Ciphertext<ILVector2n> ciphertextTempMult(ciphertext1[0]);

	//YSP this needs to be switched to the CryptoUtility operation
	algorithm.EvalMult(ciphertext1[0], ciphertext2[0], evalKey, &ciphertextTempMult);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	result = CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertextMult, &plaintextNewMult, true);  // This is the core decryption operation.	
																														//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FV.EvalMult gives incorrect results.\n";

}
