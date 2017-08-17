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
#include <vector>

#include "palisade.h"
#include "cryptolayertests.h"
#include "cryptocontextparametersets.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

// This file unit tests the ENCRYPTION capabilities for all schemes, using both known elements

class UTENCRYPT : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

template <typename Element>
void
UnitTestNewEncryptionScalar(const shared_ptr<CryptoContext<Element>> cc) {
	uint32_t		value = 29;
	shared_ptr<Plaintext> plaintext = cc->MakeScalarPlaintext(value);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Element>> ciphertext = cc->NEWEncrypt(kp.publicKey, plaintext);
	shared_ptr<Plaintext> plaintextNew;
	cc->NEWDecrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew) << "unsigned";

	shared_ptr<Plaintext> plaintext2 = cc->MakeScalarPlaintext(-value, true);
	ciphertext = cc->NEWEncrypt(kp.publicKey, plaintext2);
	cc->NEWDecrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext2, *plaintextNew) << "signed";
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(8, 64);
	UnitTestNewEncryptionScalar<Poly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(8, 64);
	UnitTestNewEncryptionScalar<Poly>(cc);
}
TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(8, 64);
	UnitTestNewEncryptionScalar<Poly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(8, 64);
	UnitTestNewEncryptionScalar<Poly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(8, 64);
	UnitTestNewEncryptionScalar<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRT_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(8, 3, 64);
	UnitTestNewEncryptionScalar<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_DCRT_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(8, 3, 64);
	UnitTestNewEncryptionScalar<DCRTPoly>(cc);
}
TEST(UTENCRYPT, StSt_DCRT_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(8, 3, 64);
	UnitTestNewEncryptionScalar<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_DCRT_Encrypt_Decrypt_Scalar) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(8, 3, 64);
	UnitTestNewEncryptionScalar<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_DCRT_Encrypt_Decrypt_Scalar) {
	cout << "DCRT not supported for FV" << endl;
	SUCCEED();
	return;
	if( 0 ) {
		shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(8, 3, 64);
		UnitTestNewEncryptionScalar<DCRTPoly>(cc);
	}
}

template <typename Element>
void
UnitTestNewEncryptionInteger(const shared_ptr<CryptoContext<Element>> cc) {
	uint64_t		value = 256*256*256;
	shared_ptr<Plaintext> plaintext = cc->MakeIntegerPlaintext(value);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Element>> ciphertext = cc->NEWEncrypt(kp.publicKey, plaintext);
	shared_ptr<Plaintext> plaintextNew;
	cc->NEWDecrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew);
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(2048, 64);
	UnitTestNewEncryptionInteger<Poly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(128, 64);
	UnitTestNewEncryptionInteger<Poly>(cc);
}
TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(4096, 64);
	UnitTestNewEncryptionInteger<Poly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(128, 64);
	UnitTestNewEncryptionInteger<Poly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(128, 64);
	UnitTestNewEncryptionInteger<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRT_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(128, 3, 64);
	UnitTestNewEncryptionInteger<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_DCRT_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(128, 3, 64);
	UnitTestNewEncryptionInteger<DCRTPoly>(cc);
}
TEST(UTENCRYPT, StSt_DCRT_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(128, 3, 64);
	UnitTestNewEncryptionInteger<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_DCRT_Encrypt_Decrypt_Integer) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(128, 3, 64);
	UnitTestNewEncryptionInteger<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_DCRT_Encrypt_Decrypt_Integer) {
	cout << "DCRT not supported for FV" << endl;
	SUCCEED();
	return;
	if( 0 ) {
		shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(128, 3, 64);
		UnitTestNewEncryptionInteger<DCRTPoly>(cc);
	}
}

template <typename Element>
void
UnitTestNewEncryptionString(const shared_ptr<CryptoContext<Element>> cc) {
	string		value = "You keep using that word. I do not think it means what you think it means";
	shared_ptr<Plaintext> plaintext = cc->MakeStringPlaintext(value);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Element>> ciphertext = cc->NEWEncrypt(kp.publicKey, plaintext);
	shared_ptr<Plaintext> plaintextNew;
	cc->NEWDecrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew);
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(2048, 256);
	UnitTestNewEncryptionString<Poly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(512, 256);
	UnitTestNewEncryptionString<Poly>(cc);
}
TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(4096, 256);
	UnitTestNewEncryptionString<Poly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(2048, 256);
	UnitTestNewEncryptionString<Poly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(512, 256);
	UnitTestNewEncryptionString<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRT_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(512, 3, 256);
	UnitTestNewEncryptionString<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_DCRT_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(512, 3, 256);
	UnitTestNewEncryptionString<DCRTPoly>(cc);
}
TEST(UTENCRYPT, StSt_DCRT_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(512, 3, 256);
	UnitTestNewEncryptionString<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_DCRT_Encrypt_Decrypt_String) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(512, 3, 256);
	UnitTestNewEncryptionString<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_DCRT_Encrypt_Decrypt_String) {
	cout << "DCRT not supported for FV" << endl;
	SUCCEED();
	return;
	if( 0 ) {
		shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(512, 3, 256);
		UnitTestNewEncryptionString<DCRTPoly>(cc);
	}
}

template <typename Element>
void
UnitTestNewEncryptionCoefPacked(const shared_ptr<CryptoContext<Element>> cc) {

	size_t intSize = cc->GetRingDimension();
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	shared_ptr<Plaintext> plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

	vector<int32_t> sintvec;
	for( size_t ii=0; ii<intSize; ii++) {
		int rnum = rand() % ptm;
		if( rnum > (int)ptm/2 ) rnum = ptm - rnum;
		sintvec.push_back( rnum );
	}
	shared_ptr<Plaintext> plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt short, with padding, full, and long
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Element>> ciphertext4 = cc->NEWEncrypt(kp.publicKey, plaintextInt);
	shared_ptr<Plaintext> plaintextIntNew;
	cc->NEWDecrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
	EXPECT_EQ(*plaintextIntNew, *plaintextInt) << "Encrypt integer plaintext";

	shared_ptr<Ciphertext<Element>> ciphertext5 = cc->NEWEncrypt(kp.publicKey, plaintextSInt);
	shared_ptr<Plaintext> plaintextSIntNew;
	cc->NEWDecrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
	EXPECT_EQ(*plaintextSIntNew, *plaintextSInt) << "Encrypt signed integer plaintext";
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(2048, 256);
	UnitTestNewEncryptionCoefPacked<Poly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(512, 256);
	UnitTestNewEncryptionCoefPacked<Poly>(cc);
}
TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(4096, 256);
	UnitTestNewEncryptionCoefPacked<Poly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(2048, 256);
	UnitTestNewEncryptionCoefPacked<Poly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(512, 256);
	UnitTestNewEncryptionCoefPacked<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRT_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(512, 3, 256);
	UnitTestNewEncryptionCoefPacked<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_DCRT_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(512, 3, 256);
	UnitTestNewEncryptionCoefPacked<DCRTPoly>(cc);
}
TEST(UTENCRYPT, StSt_DCRT_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(512, 3, 256);
	UnitTestNewEncryptionCoefPacked<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_DCRT_Encrypt_Decrypt_CoefPacked) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(512, 3, 256);
	UnitTestNewEncryptionCoefPacked<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_DCRT_Encrypt_Decrypt_CoefPacked) {
	cout << "DCRT not supported for FV" << endl;
	SUCCEED();
	return;
	if( 0 ) {
		shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(512, 3, 256);
		UnitTestNewEncryptionCoefPacked<DCRTPoly>(cc);
	}
}

// FIXME below is probably obsolete
template <typename Element>
void
UnitTestEncryption(const shared_ptr<CryptoContext<Element>> cc) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	GenerateTestPlaintext(cc->GetCyclotomicOrder(),
			cc->GetCryptoParameters()->GetPlaintextModulus(),
			plaintextShort, plaintextFull, plaintextLong);

	size_t intSize = cc->GetRingDimension();
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	IntPlaintextEncoding plaintextInt(intvec);

	vector<int32_t> sintvec;
	for( size_t ii=0; ii<intSize; ii++) {
		int rnum = rand() % ptm;
		if( rnum > (int)ptm/2 ) rnum = ptm - rnum;
		sintvec.push_back( rnum );
	}
	SignedIntPlaintextEncoding plaintextSInt(sintvec);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc->KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encrypt and decrypt short, with padding, full, and long
	////////////////////////////////////////////////////////////

	if( plaintextShort.size() == 0 ) {
		std::cout << "This set of test parameters generated zero-length test strings, skipping string cases" << std::endl;
	} else {
		vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort, true);
		BytePlaintextEncoding plaintextShortNew;
		cc->Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
		EXPECT_EQ(plaintextShortNew, plaintextShort) << "Encrypt short plaintext with padding";

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull, false);
		BytePlaintextEncoding plaintextFullNew;
		cc->Decrypt(kp.secretKey, ciphertext2, &plaintextFullNew, false);
		EXPECT_EQ(plaintextFullNew, plaintextFull) << "Encrypt regular plaintext";

		vector<shared_ptr<Ciphertext<Element>>> ciphertext3 = cc->Encrypt(kp.publicKey, plaintextLong, false);
		BytePlaintextEncoding plaintextLongNew;
		cc->Decrypt(kp.secretKey, ciphertext3, &plaintextLongNew, false);
		EXPECT_EQ(plaintextLongNew, plaintextLong) << "Encrypt long plaintext";
	}

	vector<shared_ptr<Ciphertext<Element>>> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt, false);
	IntPlaintextEncoding plaintextIntNew;
	cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew, false);
	EXPECT_EQ(plaintextIntNew, plaintextInt) << "Encrypt integer plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt, false);
	SignedIntPlaintextEncoding plaintextSIntNew;
	cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew, false);
	EXPECT_EQ(plaintextSIntNew, plaintextSInt) << "Encrypt signed integer plaintext";
}

TEST(UTENCRYPT, LTV_Poly_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementLTV(2048, 256);
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, Null_Poly_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementNull(512, 256);
	UnitTestEncryption<Poly>(cc);
}
TEST(UTENCRYPT, StSt_Poly_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementStSt(4096, 256);
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, BV_Poly_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementBV(2048, 256);
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, FV_Poly_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<Poly>> cc = GenCryptoContextElementFV(512, 256);
	UnitTestEncryption<Poly>(cc);
}

TEST(UTENCRYPT, LTV_DCRT_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayLTV(128, 3, 256);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, Null_DCRT_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayNull(128, 3, 256);
	UnitTestEncryption<DCRTPoly>(cc);
}
TEST(UTENCRYPT, StSt_DCRT_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayStSt(128, 3, 256);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, BV_DCRT_Encrypt_Decrypt_Byte) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayBV(128, 3, 256);
	UnitTestEncryption<DCRTPoly>(cc);
}

TEST(UTENCRYPT, FV_DCRT_Encrypt_Decrypt_Byte) {
	cout << "DCRT not supported for FV" << endl;
	SUCCEED();
	return;
	if( 0 ) {
		shared_ptr<CryptoContext<DCRTPoly>> cc = GenCryptoContextElementArrayFV(128, 3, 256);
		UnitTestEncryption<DCRTPoly>(cc);
	}
}
