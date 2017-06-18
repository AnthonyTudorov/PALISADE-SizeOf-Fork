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
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


class UnitTestPkeSerialize : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

static CryptoContext<ILVector2n> GenerateTestCryptoContext(const string& parmsetName) {
	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(parmsetName);
	cc.Enable(ENCRYPTION);
	return cc;
}

static CryptoContext<ILDCRT2n> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	CryptoContext<ILDCRT2n> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc.Enable(ENCRYPTION);
	return cc;
}

template<typename T>
void UnitTestContext(const CryptoContext<T>& cc) {

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( cc.Serialize(&ser) ) << "Serialization failed";

	CryptoContext<T> newcc;
	ASSERT_TRUE( newcc.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *cc.GetCryptoParameters(), *newcc.GetCryptoParameters() ) << "Mismatch after ser/deser";
}

TEST(UTPKESer, LTV_ILVector2n_Serial) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("LTV5");
	UnitTestContext<ILVector2n>(cc);
}

TEST(UTPKESer, LTV_ILVectorArray2n_Serial) {
	CryptoContext<ILDCRT2n> cc = GenerateTestDCRTCryptoContext("LTV5", 3, 20);
	UnitTestContext<ILDCRT2n>(cc);
}

TEST(UTPKESer, StSt_ILVector2n_Serial) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("StSt6");
	UnitTestContext<ILVector2n>(cc);
}

TEST(UTPKESer, StSt_ILVectorArray2n_Serial) {
	CryptoContext<ILDCRT2n> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestContext<ILDCRT2n>(cc);
}

TEST(UTPKESer, BV_ILVector2n_Serial) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("BV2");
	UnitTestContext<ILVector2n>(cc);
}

TEST(UTPKESer, BV_ILVectorArray2n_Serial) {
	CryptoContext<ILDCRT2n> cc = GenerateTestDCRTCryptoContext("BV2", 3, 20);
	UnitTestContext<ILDCRT2n>(cc);
}

TEST(UTPKESer, Null_ILVector2n_Serial) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("Null");
	UnitTestContext<ILVector2n>(cc);
}

TEST(UTPKESer, Null_ILVectorArray2n_Serial) {
	CryptoContext<ILDCRT2n> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestContext<ILDCRT2n>(cc);
}

TEST(UTPKESer, FV_ILVector2n_Serial) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("FV2");
	UnitTestContext<ILVector2n>(cc);
}

//TEST(UTPKESer, FV_ILVectorArray2n_Serial) {
//	CryptoContext<ILDCRT2n> cc = GenerateTestDCRTCryptoContext("FV2", 3, 20);
//	UnitTestContext<ILDCRT2n>(cc);
//}

// REMAINDER OF THE TESTS USE LTV AS A REPRESENTITIVE CONTEXT
TEST(UTPKESer, LTV_keys_and_ciphertext) {
	CryptoContext<ILVector2n> cc = GenerateTestCryptoContext("LTV5");
	LPKeyPair<ILVector2n> kp = cc.KeyGen();
	LPKeyPair<ILVector2n> kpnew;

	{
		Serialized ser;
		ser.SetObject();
		ASSERT_TRUE( kp.publicKey->Serialize(&ser) ) << "Public Key serialization failed";

		ASSERT_TRUE( (kpnew.publicKey = cc.deserializePublicKey(ser)) ) << "Public key deserialization failed";

		EXPECT_EQ( *kp.publicKey, *kpnew.publicKey ) << "Public key mismatch after ser/deser";
	}

	{
		Serialized ser;
		ser.SetObject();
		ASSERT_TRUE( kp.secretKey->Serialize(&ser) ) << "Secret Key serialization failed";

		ASSERT_TRUE( (kpnew.secretKey = cc.deserializeSecretKey(ser)) ) << "Secret key deserialization failed";

		EXPECT_EQ( *kp.secretKey, *kpnew.secretKey ) << "Secret key mismatch after ser/deser";
	}

	BytePlaintextEncoding plaintextShort("This is just a little test");
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, plaintextShort, true);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( ciphertext[0]->Serialize(&ser) ) << "Ciphertext serialize failed";
	shared_ptr<Ciphertext<ILVector2n>> newC;
	ASSERT_TRUE( (newC = cc.deserializeCiphertext(ser)) ) << "Ciphertext deserialization failed";

	EXPECT_EQ( *ciphertext[0], *newC ) << "Ciphertext mismatch";

	ciphertext[0] = newC;
	BytePlaintextEncoding plaintextShortNew;
	cc.Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "Decrypted deserialize failed";
}
