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
	Plaintext plaintext = cc->MakeScalarPlaintext(value);

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

	shared_ptr<Ciphertext<Element>> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew) << "unsigned";

	Plaintext plaintext2 = cc->MakeScalarPlaintext(-value, true);
	ciphertext = cc->Encrypt(kp.publicKey, plaintext2);
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
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
	Plaintext plaintext = cc->MakeIntegerPlaintext(value);

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

	shared_ptr<Ciphertext<Element>> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
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
	Plaintext plaintext = cc->MakeStringPlaintext(value);

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

	shared_ptr<Ciphertext<Element>> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
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
	Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

	vector<int32_t> sintvec;
	for( size_t ii=0; ii<intSize; ii++) {
		int rnum = rand() % ptm;
		if( rnum > (int)ptm/2 ) rnum = ptm - rnum;
		sintvec.push_back( rnum );
	}
	Plaintext plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

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

	shared_ptr<Ciphertext<Element>> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
	Plaintext plaintextIntNew;
	cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
	EXPECT_EQ(*plaintextIntNew, *plaintextInt) << "Encrypt integer plaintext";

	shared_ptr<Ciphertext<Element>> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt);
	Plaintext plaintextSIntNew;
	cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
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
	size_t vecSize = cc->GetRingDimension();

	auto randchar = []() -> char {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
	};

	string shortStr(vecSize/2,0);
	std::generate_n(shortStr.begin(), vecSize/2, randchar);
	Plaintext plaintextShort( new StringEncoding(cc->GetElementParams(), cc->GetEncodingParams(), shortStr) );

	string fullStr(vecSize,0);
	std::generate_n(fullStr.begin(), vecSize, randchar);
	Plaintext plaintextFull( new StringEncoding(cc->GetElementParams(), cc->GetEncodingParams(), fullStr) );

	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<vecSize; ii++)
		intvec.push_back( rand() % ptm );
	Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

	vector<int32_t> sintvec;
	for( size_t ii=0; ii<vecSize; ii++) {
		int rnum = rand() % ptm;
		if( rnum > (int)ptm/2 ) rnum = ptm - rnum;
		sintvec.push_back( rnum );
	}
	Plaintext plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

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

	if( plaintextShort->GetLength() == 0 ) {
		std::cout << "This set of test parameters generated zero-length test strings, skipping string cases" << std::endl;
	} else {
		shared_ptr<Ciphertext<Element>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
		Plaintext plaintextShortNew;
		cc->Decrypt(kp.secretKey, ciphertext, &plaintextShortNew);
		EXPECT_EQ(plaintextShortNew->GetStringValue(), plaintextShort->GetStringValue()) << "Encrypt short plaintext with padding";

		shared_ptr<Ciphertext<Element>> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull);
		Plaintext plaintextFullNew;
		cc->Decrypt(kp.secretKey, ciphertext2, &plaintextFullNew);
		EXPECT_EQ(plaintextFullNew->GetStringValue(), plaintextFull->GetStringValue()) << "Encrypt regular plaintext";

	}

	shared_ptr<Ciphertext<Element>> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
	Plaintext plaintextIntNew;
	cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
	EXPECT_EQ(plaintextIntNew->GetCoefPackedValue(), plaintextInt->GetCoefPackedValue()) << "Encrypt integer plaintext";

	shared_ptr<Ciphertext<Element>> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt);
	Plaintext plaintextSIntNew;
	cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
	EXPECT_EQ(plaintextSIntNew->GetCoefPackedSignedValue(), plaintextSInt->GetCoefPackedSignedValue()) << "Encrypt signed integer plaintext";
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
