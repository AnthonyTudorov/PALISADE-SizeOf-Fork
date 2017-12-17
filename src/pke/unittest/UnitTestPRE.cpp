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
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

// This file unit tests the PRE capabilities for all schemes, using all known elements

class ReEncrypt : public ::testing::Test {
public:
	virtual ~ReEncrypt() {}

protected:
	void SetUp() {}

	void TearDown() {
		CryptoContextFactory<NativePoly>::ReleaseAllContexts();
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

// FIXME StSt will not work with NativePoly because the bits for q are too big for a NativeInteger
//GENERATE_PKE_TEST_CASE_BITS(x, y, NativePoly, StSt, ORD, PTM, 80)

#define GENERATE_TEST_CASES_FUNC(x,y,ORD,PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE_BITS(x, y, Poly, StSt, ORD, PTM, 80) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, FV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, FV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, FV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, FV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, StSt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)

static const usint ORDER = 4096;
static const usint PTMOD = 256;

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

	vector<uint64_t> intvec;
	for( size_t ii=0; ii<vecSize; ii++)
		intvec.push_back( rand() % ptm );
	Plaintext plaintextInt( new CoefPackedEncoding(cc->GetElementParams(), cc->GetEncodingParams(), intvec) );

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

	LPKeyPair<Element> newKp = cc->KeyGen();
	EXPECT_EQ(newKp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

	// This generates the keys which are used to perform the key switching.
	LPEvalKey<Element> evalKey;
	if( failmsg.substr(0,2) == "BGV" || failmsg.substr(0,2) == "FV" || failmsg.substr(0,6) == "BFVrns" ) {
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

GENERATE_TEST_CASES_FUNC(ReEncrypt, ReEncryption, ORDER, PTMOD)
