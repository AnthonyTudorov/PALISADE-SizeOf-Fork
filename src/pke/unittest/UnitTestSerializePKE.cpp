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


class UTPKESer : public ::testing::Test {
protected:
	void SetUp() {
	}

	void TearDown() {
		CryptoContextFactory<Poly>::ReleaseAllContexts();
		CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
		CryptoContext<Poly>::ClearEvalMultKeys();
		CryptoContext<DCRTPoly>::ClearEvalMultKeys();
	}
};

static shared_ptr<CryptoContext<Poly>> GenerateTestCryptoContext(const string& parmsetName) {
	BigInteger modulusP(256);
	shared_ptr<CryptoContext<Poly>> cc = CryptoContextHelper::getNewContext(parmsetName,
			shared_ptr<EncodingParams>(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP),8)));
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

static shared_ptr<CryptoContext<DCRTPoly>> GenerateTestDCRTCryptoContext(const string& parmsetName, usint nTower, usint pbits) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextHelper::getNewDCRTContext(parmsetName, nTower, pbits);
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	return cc;
}

TEST_F(UTPKESer, LTV_Context_Factory) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("LTV5");
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 0) << "Contexts not cleared";

	cc = GenerateTestCryptoContext("LTV5");
	shared_ptr<CryptoContext<Poly>> cc2 = GenerateTestCryptoContext("LTV5");
	EXPECT_EQ(cc.get(), cc2.get()) << "Context mismatch";
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "Context count error";
}

template<typename T>
void UnitTestContext(shared_ptr<CryptoContext<T>> cc) {

	LPKeyPair<T> kp = cc->KeyGen();
	try {
		cc->EvalMultKeyGen(kp.secretKey);
	} catch(...) {}
	try {
		cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
	} catch(...) {}

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( cc->Serialize(&ser) ) << "Serialization failed";

	shared_ptr<CryptoContext<T>> newcc = CryptoContextFactory<T>::DeserializeAndCreateContext(ser);
	ASSERT_TRUE( newcc ) << "Deserialization failed";

	EXPECT_EQ( cc->GetEncryptionAlgorithm()->GetEnabled(), (usint)(ENCRYPTION|SHE) ) << "Enabled features mismatch after ser/deser";

	EXPECT_EQ( *cc->GetCryptoParameters(), *newcc->GetCryptoParameters() ) << "Mismatch after ser/deser";

	Serialized serK;
	ASSERT_TRUE( kp.publicKey->Serialize(&serK) ) << "Key serialization failed";
	shared_ptr<LPPublicKey<T>> newPub = cc->deserializePublicKey(serK);
	ASSERT_TRUE( newPub ) << "Key deserialize failed";

	EXPECT_EQ( *kp.publicKey, *newPub ) << "Key mismatch";

	shared_ptr<CryptoContext<T>> newccFromkey = CryptoContextFactory<T>::DeserializeAndCreateContext(serK);
	ASSERT_TRUE( newccFromkey ) << "Deserialization from key failed";

	shared_ptr<LPPublicKey<T>> finalPub = newccFromkey->deserializePublicKey(serK);
	ASSERT_TRUE( finalPub ) << "Key deserialize in new ctx failed";
	EXPECT_EQ( *newPub, *finalPub ) << "Key mismatch from new ctx";
}

TEST_F(UTPKESer, LTV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("LTV5");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, LTV_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("LTV5", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, StSt_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("StSt6");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, StSt_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("StSt6", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, BV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("BV2");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, BV_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("BV2", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, Null_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("Null");
	UnitTestContext<Poly>(cc);
}

TEST_F(UTPKESer, Null_DCRTPoly_Serial) {
	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("Null", 3, 20);
	UnitTestContext<DCRTPoly>(cc);
}

TEST_F(UTPKESer, FV_Poly_Serial) {
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("FV2");
	UnitTestContext<Poly>(cc);
}

//TEST_F(UTPKESer, FV_DCRTPoly_Serial) {
//	shared_ptr<CryptoContext<DCRTPoly>> cc = GenerateTestDCRTCryptoContext("FV2", 3, 20);
//	UnitTestContext<DCRTPoly>(cc);
//}

// REMAINDER OF THE TESTS USE LTV AS A REPRESENTITIVE CONTEXT
TEST_F(UTPKESer, LTV_keys_and_ciphertext) {
        bool dbg_flag = true;
	shared_ptr<CryptoContext<Poly>> cc = GenerateTestCryptoContext("LTV5");
	LPKeyPair<Poly> kp = cc->KeyGen();
	LPKeyPair<Poly> kpnew;

	DEBUG("step 1");
	{
		Serialized ser;

		ser.SetObject();

		DEBUG("step 1.1");
		ASSERT_TRUE( kp.publicKey->Serialize(&ser) ) << "Public Key serialization failed";

		DEBUG("step 1.2");
		ASSERT_TRUE( (kpnew.publicKey = cc->deserializePublicKey(ser)) ) << "Public key deserialization failed";
		DEBUG("step 1.3");
		EXPECT_EQ( *kp.publicKey, *kpnew.publicKey ) << "Public key mismatch after ser/deser";
	}
	DEBUG("step 2");
	{
		Serialized ser;
		ser.SetObject();
		ASSERT_TRUE( kp.secretKey->Serialize(&ser) ) << "Secret Key serialization failed";

		ASSERT_TRUE( (kpnew.secretKey = cc->deserializeSecretKey(ser)) ) << "Secret key deserialization failed";

		EXPECT_EQ( *kp.secretKey, *kpnew.secretKey ) << "Secret key mismatch after ser/deser";
	}
	DEBUG("step 3");
	BytePlaintextEncoding plaintextShort("This is just a little test");
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort, true);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( ciphertext[0]->Serialize(&ser) ) << "Ciphertext serialize failed";
	DEBUG("step 4");
	shared_ptr<Ciphertext<Poly>> newC;
	ASSERT_TRUE( (newC = cc->deserializeCiphertext(ser)) ) << "Ciphertext deserialization failed";

	EXPECT_EQ( *ciphertext[0], *newC ) << "Ciphertext mismatch";

	DEBUG("step 5");
	ciphertext[0] = newC;
	BytePlaintextEncoding plaintextShortNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "Decrypted deserialize failed";

	DEBUG("step 6");
	shared_ptr<CryptoContext<Poly>> cc2 = GenerateTestCryptoContext("LTV4");
	LPKeyPair<Poly> kp2 = cc->KeyGen();
	LPKeyPair<Poly> kp3 = cc2->KeyGen();

	cc->EvalMultKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp2.secretKey);
	cc2->EvalMultKeyGen(kp3.secretKey);

	Serialized ser0;
	CryptoContext<Poly>::SerializeEvalMultKey(&ser0, kp.secretKey->GetKeyTag());
	Serialized ser2a;
	Serialized ser2b;
	CryptoContext<Poly>::SerializeEvalMultKey(&ser2a, cc);
	CryptoContext<Poly>::SerializeEvalMultKey(&ser2b, cc2);
	Serialized ser3;
	CryptoContext<Poly>::SerializeEvalMultKey(&ser3);

	CryptoContext<Poly>::ClearEvalMultKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	CryptoContext<Poly>::DeserializeEvalMultKey(ser0);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-key deser, context";
	EXPECT_EQ(CryptoContext<Poly>::GetEvalMultKeys().size(), 1U) << "one-key deser, keys";

	CryptoContext<Poly>::ClearEvalMultKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	CryptoContext<Poly>::DeserializeEvalMultKey(ser2a);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser, context";
	EXPECT_EQ(CryptoContext<Poly>::GetEvalMultKeys().size(), 2U) << "one-ctx deser, keys";

	CryptoContext<Poly>::ClearEvalMultKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	CryptoContext<Poly>::DeserializeEvalMultKey(ser2b);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 1) << "one-ctx deser2, context";
	EXPECT_EQ(CryptoContext<Poly>::GetEvalMultKeys().size(), 1U) << "one-ctx deser2, keys";

	CryptoContext<Poly>::ClearEvalMultKeys();
	CryptoContextFactory<Poly>::ReleaseAllContexts();
	CryptoContext<Poly>::DeserializeEvalMultKey(ser3);
	EXPECT_EQ(CryptoContextFactory<Poly>::GetContextCount(), 2) << "all-key deser, context";
	EXPECT_EQ(CryptoContext<Poly>::GetEvalMultKeys().size(), 3U) << "all-key deser, keys";
}
