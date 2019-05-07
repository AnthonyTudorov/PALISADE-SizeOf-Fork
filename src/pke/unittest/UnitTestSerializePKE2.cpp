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

#include "palisade.h"
#include "cryptocontext.h"
#include "math/nbtheory.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "utils/serial.h"

#include "bfv-ser.h"
#include "bfvrns-ser.h"
#include "bfvrnsB-ser.h"
#include "nullscheme-ser.h"
#include "stst-ser.h"

using namespace std;
using namespace lbcrypto;

// TODO: temporary fix until Windows serialization is fixed
#if not defined(_WIN32) and not defined(_WIN64)

class UTPKESer : public ::testing::Test {
protected:
	void SetUp() {
	}

	void TearDown() {
		CryptoContextImpl<Poly>::ClearEvalMultKeys();
		CryptoContextImpl<Poly>::ClearEvalMultKeys();
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
		CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
	}
};

static CryptoContext<Poly> GenerateTestCryptoContext(const string& parmsetName) {
	PlaintextModulus modulusP(256);
	CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(parmsetName,
			EncodingParams(new EncodingParamsImpl(modulusP,8)));
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

static CryptoContext<DCRTPoly> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	CryptoContext<DCRTPoly> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

template<typename T>
void UnitTestContextWithSertype(CryptoContext<T> cc, SerType sertype, string msg) {

	LPKeyPair<T> kp = cc->KeyGen();
	try {
		cc->EvalMultKeyGen(kp.secretKey);
	} catch(...) {}
	try {
		cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
	} catch(...) {}

	stringstream s;
	Serial::Serialize(cc, s, sertype);

	CryptoContext<T> newcc;
	Serial::Deserialize(newcc, s, sertype);

	ASSERT_TRUE( newcc.get() != 0 ) << msg << " Deserialize failed";

	EXPECT_EQ( *cc, *newcc ) << msg << " Mismatched context";

	EXPECT_EQ( *cc->GetEncryptionAlgorithm(), *newcc->GetEncryptionAlgorithm() ) << msg << " Scheme mismatch after ser/deser";
	EXPECT_EQ( *cc->GetCryptoParameters(), *newcc->GetCryptoParameters() ) << msg << " Crypto parms mismatch after ser/deser";
	EXPECT_EQ( *cc->GetEncodingParams(), *newcc->GetEncodingParams() ) << msg << " Encoding parms mismatch after ser/deser";
	EXPECT_EQ( cc->GetEncryptionAlgorithm()->GetEnabled(), newcc->GetEncryptionAlgorithm()->GetEnabled() ) << msg << " Enabled features mismatch after ser/deser";

	s.str("");
	s.clear();
	Serial::Serialize(kp.publicKey, s, sertype);

	LPPublicKey<T> newPub;
	Serial::Deserialize(newPub, s, sertype);
	ASSERT_TRUE( newPub.get() != 0 ) << msg << " Key deserialize failed";

	EXPECT_EQ( *kp.publicKey, *newPub ) << msg << " Key mismatch";

	CryptoContext<T> newccFromkey = newPub->GetCryptoContext();
	EXPECT_EQ( *cc, *newccFromkey ) << msg << " Key deser has wrong context";
}

template<typename T>
void UnitTestContext(CryptoContext<T> cc) {
	UnitTestContextWithSertype(cc, SerType::JSON, "json");
	UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
}

TEST_F(UTPKESer, LTV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("LTV5");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, LTV_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("LTV5", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, StSt_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("StSt6");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, StSt_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, Null_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("Null");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, Null_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, BFV_Poly_Serial) {
	CryptoContext<Poly> cc = GenerateTestCryptoContext("BFV2");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, BFVrns_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BFVrns2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, BFVrnsB_DCRTPoly_Serial) {
	CryptoContext<DCRTPoly> cc = GenerateTestDCRTCryptoContext("BFVrnsB2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

#endif
