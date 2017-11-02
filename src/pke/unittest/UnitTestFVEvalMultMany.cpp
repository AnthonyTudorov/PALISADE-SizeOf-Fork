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

#include "encoding/encodings.h"

#include "utils/debug.h"

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

	shared_ptr<Plaintext> plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	shared_ptr<Plaintext> plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
	shared_ptr<Plaintext> plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
	shared_ptr<Plaintext> plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

	shared_ptr<Plaintext> plaintextResult1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
	shared_ptr<Plaintext> plaintextResult2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
	shared_ptr<Plaintext> plaintextResult3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

	shared_ptr<Ciphertext<Poly>> ciphertext1;
	shared_ptr<Ciphertext<Poly>> ciphertext2;
	shared_ptr<Ciphertext<Poly>> ciphertext3;
	shared_ptr<Ciphertext<Poly>> ciphertext4;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12;
	shared_ptr<Ciphertext<Poly>> ciphertextMul123;
	shared_ptr<Ciphertext<Poly>> ciphertextMul1234;

	shared_ptr<Ciphertext<Poly>> ciphertextMulVect3;
	shared_ptr<Ciphertext<Poly>> ciphertextMulVect4;
	shared_ptr<Ciphertext<Poly>> ciphertextMulVect5;

	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextMul12     = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertext1,ciphertext2);
	ciphertextMul123    = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertextMul12, ciphertext3);
	ciphertextMul1234   = cryptoContext->GetEncryptionAlgorithm()->EvalMultAndRelinearize(ciphertextMul123, ciphertext4, evalKeys);

	////////////////////////////////////////////////////////////
	//Decryption of multiplicative results with and without keyswtiching (depends on the level)
	////////////////////////////////////////////////////////////

	shared_ptr<Plaintext> plaintextMul1;
	shared_ptr<Plaintext> plaintextMul2;
	shared_ptr<Plaintext> plaintextMul3;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

	////////////////////////////////////////////////////////////
	//Prepare EvalMultMany
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12345;
	vector<shared_ptr<Ciphertext<Poly>>> cipherTextList;

	cipherTextList.push_back(ciphertext1);
	cipherTextList.push_back(ciphertext2);
	cipherTextList.push_back(ciphertext3);
	cipherTextList.push_back(ciphertext4);

	////////////////////////////////////////////////////////////
	//Compute EvalMultMany
	////////////////////////////////////////////////////////////

	ciphertextMul12345 = cryptoContext->GetEncryptionAlgorithm()->EvalMultMany(cipherTextList, evalKeys);

	////////////////////////////////////////////////////////////
	//Decrypt EvalMultMany
	////////////////////////////////////////////////////////////

	shared_ptr<Plaintext> plaintextMulMany;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345, &plaintextMulMany);

	EXPECT_EQ(*plaintextMul1, *plaintextResult1) << "FV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(plaintextMul2, plaintextResult2) << "FV.EvalMult gives incorrect results.\n";
	EXPECT_EQ(plaintextMul3, plaintextResult3) << "FV.EvalMultAndRelinearize gives incorrect results.\n";
	EXPECT_EQ(plaintextMulMany, plaintextResult3) << "FV.EvalMultMany gives incorrect results.\n";

}

