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
#include <fstream>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

#include "cryptolayertests.h"

using namespace std;
using namespace lbcrypto;

class UnitTestFV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

//Tests EvalMult w/o keyswitching and EvalMultMany for FV in the RLWE mode
TEST(UTFVEVALMM, Poly_FV_Eval_Mult_Many_Operations) {

	int relWindow = 1;
	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.03;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0, OPTIMIZED, 4);

	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<Poly> keyPair;
	keyPair = cryptoContext->KeyGen();

	if (!keyPair.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//Create evaluation key vector to be used in keyswitching
	shared_ptr<vector<shared_ptr<LPEvalKey<Poly>>>> evalKeys = cryptoContext->GetEncryptionAlgorithm()->EvalMultKeysGen(keyPair.secretKey);

	////////////////////////////////////////////////////////////
	//Plaintext
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	std::vector<uint32_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {3,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts4 = {4,0,0,0,0,0,0,0,0,0,0,0};

	std::vector<uint32_t> vectorOfInts5 = {10,8,6,4,2,0,10,8,6,4,2,0};
	std::vector<uint32_t> vectorOfInts6 = {30,24,18,12,6,0,30,24,18,12,6,0};
	std::vector<uint32_t> vectorOfInts7 = {120,96,72,48,24,0,120,96,72,48,24,0};

	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);
	IntPlaintextEncoding plaintext4(vectorOfInts4);

	IntPlaintextEncoding plaintextResult1(vectorOfInts5);
	IntPlaintextEncoding plaintextResult2(vectorOfInts6);
	IntPlaintextEncoding plaintextResult3(vectorOfInts7);


	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext4;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1, true);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2, true);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3, true);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4, true);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12;
	shared_ptr<Ciphertext<Poly>> ciphertextMul123;
	shared_ptr<Ciphertext<Poly>> ciphertextMul1234;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect3;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect4;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect5;

	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextMul12     = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertext1[0],ciphertext2[0]);
	ciphertextMul123    = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertextMul12, ciphertext3[0]);
	ciphertextMul1234   = cryptoContext->GetEncryptionAlgorithm()->EvalMultAndRelinearize(ciphertextMul123, ciphertext4[0], evalKeys);

	ciphertextMulVect1.push_back(ciphertextMul12);
	ciphertextMulVect2.push_back(ciphertextMul123);
	ciphertextMulVect3.push_back(ciphertextMul1234);

	////////////////////////////////////////////////////////////
	//Decryption of multiplicative results with and without keyswtiching (depends on the level)
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextMul1;
	IntPlaintextEncoding plaintextMul2;
	IntPlaintextEncoding plaintextMul3;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect1, &plaintextMul1, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect2, &plaintextMul2, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect3, &plaintextMul3, true);

	plaintextMul1.resize(plaintext1.size());
	plaintextMul2.resize(plaintext1.size());
	plaintextMul3.resize(plaintext1.size());

	////////////////////////////////////////////////////////////
	//Prepare EvalMultMany
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12345;
	shared_ptr<vector<shared_ptr<Ciphertext<Poly>>>> cipherTextList(new vector<shared_ptr<Ciphertext<Poly>>>);

	cipherTextList->push_back(ciphertext1[0]);
	cipherTextList->push_back(ciphertext2[0]);
	cipherTextList->push_back(ciphertext3[0]);
	cipherTextList->push_back(ciphertext4[0]);

	////////////////////////////////////////////////////////////
	//Compute EvalMultMany
	////////////////////////////////////////////////////////////

	ciphertextMul12345 = cryptoContext->GetEncryptionAlgorithm()->EvalMultMany(cipherTextList, evalKeys);

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVectMany;
	ciphertextMulVectMany.push_back(ciphertextMul12345);

	////////////////////////////////////////////////////////////
	//Decrypt EvalMultMany
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextMulMany;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVectMany, &plaintextMulMany, true);
	plaintextMulMany.resize(plaintext1.size());


	EXPECT_EQ(plaintextMul1, plaintextResult1) << "FV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(plaintextMul2, plaintextResult2) << "FV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(plaintextMul3, plaintextResult3) << "FV.EvalMultAndRelinearize gives incorrect results.\n";
	EXPECT_EQ(plaintextMulMany, plaintextResult3) << "FV.EvalMultMany gives incorrect results.\n";

}

