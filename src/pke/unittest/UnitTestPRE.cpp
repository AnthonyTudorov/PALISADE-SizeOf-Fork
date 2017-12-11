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
#include <list>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

class UTPRE : public ::testing::Test {
protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}

public:
};

// This file unit tests the PRE capabilities for all schemes, using all known elements

template <typename Element>
class ReEncrypt : public ::testing::Test {
public:
	virtual ~ReEncrypt() {}
	typedef std::list<Element> List;
	static Element shared_;
	Element value_;

protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<NativePoly>::ReleaseAllContexts();
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

// FIXME StSt AND skip DCRTPoly for FV please
static vector<string> AllSchemes( {"Null", "LTV", /*"StSt",*/ "BV", /*"FV",*/ "BFVrns"} );
typedef ::testing::Types<Poly, DCRTPoly, NativePoly> EncryptElementTypes;
TYPED_TEST_CASE(ReEncrypt, EncryptElementTypes);

static const usint ORDER = 4096;
static const usint PTM = 256;

template<typename Element>
static void ReEncryption(const CryptoContext<Element> cc, const string& failmsg) {
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

	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();

	vector<uint32_t> intvec;
	for( size_t ii=0; ii<vecSize; ii++)
		intvec.push_back( rand() % ptm );
	Plaintext plaintextInt( new CoefPackedEncoding(cc->GetElementParams(), cc->GetEncodingParams(), intvec) );

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

	LPKeyPair<Element> newKp = cc->KeyGen();
	EXPECT_EQ(newKp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

	// This generates the keys which are used to perform the key switching.
	LPEvalKey<Element> evalKey;
	if( failmsg == "BV" || failmsg == "FV" ) {
		evalKey = cc->ReKeyGen(newKp.secretKey, kp.secretKey);
	} else {
		evalKey = cc->ReKeyGen(newKp.publicKey, kp.secretKey);
	}

	Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
	Plaintext plaintextShortNew;
	Ciphertext<Element> reCiphertext = cc->ReEncrypt(evalKey, ciphertext);
	DecryptResult result = cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextShortNew);
	EXPECT_EQ(plaintextShortNew->GetStringValue(), plaintextShort->GetStringValue()) << failmsg << " ReEncrypt short string plaintext with padding";

	Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull);
	Plaintext plaintextFullNew;
	Ciphertext<Element> reCiphertext2 = cc->ReEncrypt(evalKey, ciphertext2);
	result = cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextFullNew);
	EXPECT_EQ(plaintextFullNew->GetStringValue(), plaintextFull->GetStringValue()) << failmsg << " ReEncrypt full string plaintext";

	Ciphertext<Element> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
	Plaintext plaintextIntNew;
	Ciphertext<Element> reCiphertext4 = cc->ReEncrypt(evalKey, ciphertext4);
	result = cc->Decrypt(newKp.secretKey, reCiphertext4, &plaintextIntNew);
	EXPECT_EQ(plaintextIntNew->GetCoefPackedValue(), plaintextInt->GetCoefPackedValue()) << failmsg << " ReEncrypt integer plaintext";
}

TYPED_TEST(ReEncrypt, PRE) {
	CryptoContext<TypeParam> cc;

	for( size_t i=0; i<AllSchemes.size(); i++ ) {
		try {
			cc = GenTestCryptoContext<TypeParam>(AllSchemes[i], ORDER, PTM);
		} catch( ... ) {
			continue;
		}

		ReEncryption<TypeParam>(cc, AllSchemes[i]);
	}
}

//TEST_F(UTPRE, LTV_Poly_ReEncrypt_pub) {
//	CryptoContext<Poly> cc = GenCryptoContextElementLTV(4096, PTM);
//	UnitTestReEncrypt<Poly>(cc, true);
//}
//
////TEST_F(UTPRE, LTV_DCRTPoly_ReEncrypt_pub) {
////	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
////	UnitTestReEncrypt<DCRTPoly>(cc, true);
////}
//
////TEST_F(UTPRE, StSt_Poly_ReEncrypt_pub) {
////	CryptoContext<Poly> cc = GenCryptoContextElementStSt(ORDER, PTM);
////	UnitTestReEncrypt<Poly>(cc, true);
////}
////
////TEST_F(UTPRE, StSt_DCRTPoly_ReEncrypt_pub) {
////	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
////	UnitTestReEncrypt<DCRTPoly>(cc, true);
////}
//
//TEST_F(UTPRE, Null_Poly_ReEncrypt_pub) {
//	CryptoContext<Poly> cc = GenCryptoContextElementNull(ORDER, PTM);
//	UnitTestReEncrypt<Poly>(cc, true);
//}
//
//TEST_F(UTPRE, Null_DCRTPoly_ReEncrypt_pub) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
//	UnitTestReEncrypt<DCRTPoly>(cc, true);
//}
//
//TEST_F(UTPRE, BV_Poly_ReEncrypt_pri) {
//	CryptoContext<Poly> cc = GenCryptoContextElementBV(ORDER, PTM);
//	UnitTestReEncrypt<Poly>(cc, false);
//}
//
//#if !defined(_MSC_VER)
//TEST_F(UTPRE, BV_DCRTPoly_ReEncrypt_pri) {
//	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<DCRTPoly>(cc, false);
//}
//#endif
//
//TEST_F(UTPRE, FV_Poly_ReEncrypt_pri) {
//	CryptoContext<Poly> cc = GenCryptoContextElementFV(ORDER, PTM);
//	UnitTestReEncrypt<Poly>(cc, false);
//}
//
////TEST_F(UTPRE, FV_DCRTPoly_ReEncrypt_pri) {
////	CryptoContext<DCRTPoly> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
////	UnitTestReEncrypt<DCRTPoly>(cc, false);
////}
