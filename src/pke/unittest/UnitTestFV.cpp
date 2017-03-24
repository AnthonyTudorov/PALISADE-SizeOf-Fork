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

#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

#include "cryptolayertests.h"

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

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	
	float stdDev = 4;

	BigBinaryInteger plaintextModulus(BigBinaryInteger::TWO);
	BigBinaryInteger delta(modulus.DividedBy(plaintextModulus));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			2, m, modulus.ToString(), rootOfUnity.ToString(),
			relWindow, stdDev, delta.ToString());
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	UnitTestEncryption<ILVector2n>(cc);
}

//Tests EvalAdd, EvalSub, and EvalMul operations for FV in the RLWE mode
TEST(UTFV, ILVector2n_FV_Eval_Operations) {

	usint m = 2048;

	BigBinaryInteger modulus("1099511678977");
	BigBinaryInteger rootOfUnity("928976858506");

	BigBinaryInteger bigModulus("1237940039285380274899136513");
	BigBinaryInteger bigRootOfUnity("1067388930511360414468370668");

	BigBinaryInteger plaintextModulus("64");

	float stdDev = 4;

	//Set crypto parametes
	BigBinaryInteger delta(modulus.DividedBy(plaintextModulus));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			64, m, modulus.ToString(), rootOfUnity.ToString(),
			1, stdDev, delta.ToString(), RLWE, bigModulus.ToString(),
			bigRootOfUnity.ToString(), 0, 9, 1.006);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, true);
	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, true);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAdd;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTemp = cc.EvalAdd(ciphertext1[0], ciphertext2[0]);

	ciphertextAdd.push_back(ciphertextTemp);

	IntPlaintextEncoding plaintextNew;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextAdd, &plaintextNew, true);

	//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	plaintextNew.resize(plaintextAdd.size());

	EXPECT_EQ(plaintextAdd, plaintextNew) << "FV.EvalAdd gives incorrect results.\n";

	////////////////////////////////////////////////////////////
	//EvalSub Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextSub;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempSub = cc.EvalSub(ciphertext1[0], ciphertext2[0]);

	ciphertextSub.push_back(ciphertextTempSub);

	IntPlaintextEncoding plaintextNewSub;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	result = cc.Decrypt(kp.secretKey, ciphertextSub, &plaintextNewSub, true);

	plaintextNewSub.resize(plaintextSub.size());

	EXPECT_EQ(plaintextSub, plaintextNewSub) << "FV.EvalSub gives incorrect results.\n";


	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	result = cc.Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FV.EvalMult gives incorrect results.\n";

}

// Generates parameters for FV in the RWLE mode to support a single EvalMult and then validates that single EvalMult works correctly
TEST(UTFV, ILVector2n_FV_ParamsGen_EvalMul) {

	usint relWindow = 1;
	BigBinaryInteger plaintextModulus(BigBinaryInteger("4"));
	float stdDev = 4;

	//Set crypto parametes
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(plaintextModulus, 1.006, 0, 1, 0);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, false);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FV.EvalMult gives incorrect results when parameters are generated on the fly by ParamsGen.\n";

}

//Tests ParamsGen, EvalAdd, EvalSub, and EvalMul operations for FV in the OPTIMIZED mode
TEST(UTFV, ILVector2n_FV_Optimized_Eval_Operations) {

	usint relWindow = 1;
	BigBinaryInteger plaintextModulus(BigBinaryInteger("64"));
	float stdDev = 4;

	//Set crypto parametes
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			64, 0, "0", "0",
			relWindow, stdDev, "0",
			OPTIMIZED, "0", "0", 0, 9, 1.006);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	cc.GetEncryptionAlgorithm()->ParamsGen(cc.GetCryptoParameters(), 0, 1);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, false);

	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAdd;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTemp;

	//YSP this needs to be switched to the CryptoUtility operation
	ciphertextTemp = cc.EvalAdd(ciphertext1[0], ciphertext2[0]);

	ciphertextAdd.push_back(ciphertextTemp);

	IntPlaintextEncoding plaintextNew;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertextAdd, &plaintextNew, true);

	plaintextNew.resize(plaintextAdd.size());

	EXPECT_EQ(plaintextAdd, plaintextNew) << "FVOptimized.EvalAdd gives incorrect results.\n";

	////////////////////////////////////////////////////////////
	//EvalSub Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextSub;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempSub;

	ciphertextTempSub = cc.EvalSub(ciphertext1[0], ciphertext2[0]);

	ciphertextSub.push_back(ciphertextTempSub);

	IntPlaintextEncoding plaintextNewSub;

	////////////////////////////////////////////////////////////
	//Decryption after EvalAdd Operation
	////////////////////////////////////////////////////////////

	result = cc.Decrypt(kp.secretKey, ciphertextSub, &plaintextNewSub, true);

	plaintextNewSub.resize(plaintextSub.size());

	EXPECT_EQ(plaintextSub, plaintextNewSub) << "FVOptimized.EvalSub gives incorrect results.\n";


	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult;

	ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0]);

	ciphertextMult.push_back(ciphertextTempMult);

	IntPlaintextEncoding plaintextNewMult;

	////////////////////////////////////////////////////////////
	//Decryption after EvalMult Operation
	////////////////////////////////////////////////////////////

	result = cc.Decrypt(kp.secretKey, ciphertextMult, &plaintextNewMult, true);

	plaintextNewMult.resize(plaintextMult.size());

	EXPECT_EQ(plaintextMult, plaintextNewMult) << "FVOptimized.EvalMult gives incorrect results.\n";

}