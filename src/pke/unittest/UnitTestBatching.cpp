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

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBatching : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};


/*Simple Encrypt-Decrypt check for ILVectorArray2n. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*tower size is set to 3*/
TEST(UTLTVBATCHING, ILVector2n_Encrypt_Decrypt) {	

	float stdDev = 4;

	usint m = 8;
	BigBinaryInteger modulus("2199023288321");
	BigBinaryInteger rootOfUnity;
	usint relWindow = 1;

	lbcrypto::NextQ(modulus, BigBinaryInteger(17), m, BigBinaryInteger("4000"), BigBinaryInteger("4000"));
	rootOfUnity = RootOfUnity(m, modulus);

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(17,
			m, modulus.ToString(), rootOfUnity.ToString(), 8, stdDev);

	cc.Enable(ENCRYPTION);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> kp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	ciphertext = cc.Encrypt(kp.publicKey, intArray1, false);


	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	PackedIntPlaintextEncoding intArrayNew;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew, vectorOfInts1);
}


TEST(UTLTVBATCHING, ILVector2n_EVALADD) {

	float stdDev = 4;

	usint m = 8;
	BigBinaryInteger modulus("2199023288321");
	BigBinaryInteger rootOfUnity;
	usint relWindow = 1;

	lbcrypto::NextQ(modulus, BigBinaryInteger(17), m, BigBinaryInteger("4000"), BigBinaryInteger("4000"));
	rootOfUnity = RootOfUnity(m, modulus);

//	//Prepare for parameters.
//	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));
//
//	//Set crypto parametes
//	LPCryptoParametersBV<ILVector2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(BigBinaryInteger("17"));  	// Set plaintext modulus.
//	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
//	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
//	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 4,3,2,1 };

	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 5,5,5,5 };

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(17,
			m, modulus.ToString(), rootOfUnity.ToString(), 8, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> kp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);


	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	ciphertextResult.insert(ciphertextResult.begin(), cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0)) );

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	PackedIntPlaintextEncoding intArrayNew;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew, vectorOfIntsExpected);
}

TEST(UTLTVBATCHING, ILVector2n_EVALMULT) {

	usint ptMod = 17;

	usint m = 8;
	usint relin = 1;
	float stdDev = 4;

	BigBinaryInteger q("2199023288321");

	lbcrypto::NextQ(q, BigBinaryInteger(ptMod), m, BigBinaryInteger("4000"), BigBinaryInteger("40000"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));

	shared_ptr<ILVector2n::Params> parms( new ILVector2n::Params(m, q, rootOfUnity) );

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(parms, ptMod,
		relin, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 4,3,2,1 };

	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 4,6,6,4 };


	kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResults;

	cc.EvalMultKeyGen(kp.secretKey);

	ciphertextResults.insert(ciphertextResults.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)));
	
	PackedIntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, ciphertextResults, &results, false);

	
	EXPECT_EQ(results, vectorOfIntsExpected);
}
