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

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;



template <class T>
class UTSHE : public ::testing::Test {

public:
	const usint m = 16;

protected:
	UTSHE() {}

	virtual void SetUp() {
	}

	virtual void TearDown() {

	}

	virtual ~UTSHE() {  }

};

// NOTE the SHE tests are all based on these
static const usint ORDER = 16;
static const usint PTM = 64;
static const usint TOWERS = 3;

template<class Element>
void UnitTest_Add(const CryptoContext<Element>& cc) {

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	{
		// EVAL ADD
		IntPlaintextEncoding intArray1(vectorOfInts1);

		IntPlaintextEncoding intArray2(vectorOfInts2);

		IntPlaintextEncoding intArrayExpected(vectorOfIntsAdd);

		////////////////////////////////////////////////////////////
		//Perform the key generation operation.
		////////////////////////////////////////////////////////////
		LPKeyPair<Element> kp = cc.KeyGen();

		vector<shared_ptr<Ciphertext<Element>>> ciphertext1 =
				cc.Encrypt(kp.publicKey, intArray1,false);

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 =
				cc.Encrypt(kp.publicKey, intArray2,false);

		vector<shared_ptr<Ciphertext<Element>>> cResult;

		cResult.insert( cResult.begin(), cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0)));

		IntPlaintextEncoding results;

		cc.Decrypt(kp.secretKey, cResult, &results,false);

		results.resize(intArrayExpected.size());

		EXPECT_EQ(intArrayExpected, results) << "EvalAdd fails";
	}
}

/// add
TEST(UTSHE, LTV_ILVector2n_Add) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(ORDER, PTM);
	UnitTest_Add<ILVector2n>(cc);
}

TEST(UTSHE, LTV_ILVectorArray2n_Add) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM, 30);
	UnitTest_Add<ILDCRT2n>(cc);
}

TEST(UTSHE, StSt_ILVector2n_Add) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementStSt(ORDER, PTM);
	UnitTest_Add<ILVector2n>(cc);
}

TEST(UTSHE, StSt_ILVectorArray2n_Add) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM, 30);
	UnitTest_Add<ILDCRT2n>(cc);
}

TEST(UTSHE, Null_ILVector2n_Add) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(ORDER, PTM);
	UnitTest_Add<ILVector2n>(cc);
}

TEST(UTSHE, Null_ILVectorArray2n_Add) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
	UnitTest_Add<ILDCRT2n>(cc);
}

TEST(UTSHE, BV_ILVector2n_Add) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
	UnitTest_Add<ILVector2n>(cc);
}

TEST(UTSHE, BV_ILVectorArray2n_Add) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM, 30);
	UnitTest_Add<ILDCRT2n>(cc);
}

TEST(UTSHE, FV_ILVector2n_Add) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementFV(ORDER, PTM);
	UnitTest_Add<ILVector2n>(cc);
}

//TEST(UTSHE, FV_ILVectorArray2n_Add) {
//	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
//	UnitTest_Add<ILDCRT2n>(cc);
//}

///
template<class Element>
void UnitTest_Mult(const CryptoContext<Element>& cc) {
	bool dbg_flag = false;
  
	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsMultLong = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	std::vector<uint32_t> vectorOfIntsMult = { 47, 53, 2, 0, 5, 9, 16, 12 };

	{
		// EVAL MULT
		IntPlaintextEncoding intArray1(vectorOfInts1);

		IntPlaintextEncoding intArray2(vectorOfInts2);

		IntPlaintextEncoding intArrayExpected(cc.GetCyclotomicOrder() == 16 ? vectorOfIntsMult : vectorOfIntsMultLong);

		DEBUG("intArray1 "<<intArray1);
		DEBUG("intArray2 "<<intArray2);
		DEBUG("intArrayExpected "<<intArrayExpected);

		// Initialize the public key containers.
		LPKeyPair<Element> kp = cc.KeyGen();

		DEBUG("kp.publicKey "<<kp.publicKey);
		DEBUG("kp.secretKey "<<kp.secretKey);

		vector<shared_ptr<Ciphertext<Element>>> ciphertext1 =
			cc.Encrypt(kp.publicKey, intArray1,false);

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 =
			cc.Encrypt(kp.publicKey, intArray2,false);


		cc.EvalMultKeyGen(kp.secretKey);

		for (size_t i = 0; i<ciphertext1.at(0)->GetElements().size(); i++){
			DEBUG("ciphertext1.at(0) "<<i<<" "<<ciphertext1.at(0)->GetElements().at(i));
			DEBUG("ciphertext2.at(0) "<<i<<" "<<ciphertext2.at(0)->GetElements().at(i));

		}
		vector<shared_ptr<Ciphertext<Element>>> cResult;
		
		cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)));

		for (size_t i = 0; i<cResult.at(0)->GetElements().size(); i++){
			DEBUG("cResult.at(0) "<<i<<" "<<cResult.at(0)->GetElements().at(i));
		}
		IntPlaintextEncoding results;

		cc.Decrypt(kp.secretKey, cResult, &results,false);

		DEBUG("reults first "<<results);
		results.resize(intArrayExpected.size());
		DEBUG("reults second "<<results);		
		EXPECT_EQ(intArrayExpected, results) << "EvalMult fails";

	}

}


TEST(UTSHE, LTV_ILVector2n_Mult) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(ORDER, PTM);
	UnitTest_Mult<ILVector2n>(cc);
}

#if !defined(_MSC_VER)
TEST(UTSHE, LTV_ILVectorArray2n_Mult) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
	UnitTest_Mult<ILDCRT2n>(cc);
}
#endif

//TEST(UTSHE, StSt_ILVector2n_Mult) {
//	CryptoContext<ILVector2n> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTest_Mult<ILVector2n>(cc);
//}
//
//TEST(UTSHE, StSt_ILVectorArray2n_Mult) {
//	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTest_Mult<ILDCRT2n>(cc);
//}

TEST(UTSHE, Null_ILVector2n_Mult) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(ORDER, PTM);
	UnitTest_Mult<ILVector2n>(cc);
}

TEST(UTSHE, Null_ILVectorArray2n_Mult) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
	UnitTest_Mult<ILDCRT2n>(cc);
}

TEST(UTSHE, BV_ILVector2n_Mult) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
	UnitTest_Mult<ILVector2n>(cc);
}

#if !defined(_MSC_VER)
TEST(UTSHE, BV_ILVectorArray2n_Mult) {
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
	UnitTest_Mult<ILDCRT2n>(cc);
}
#endif

TEST(UTSHE, FV_ILVector2n_Mult) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementFV(ORDER, PTM);
	UnitTest_Mult<ILVector2n>(cc);
}

//TEST(UTSHE, FV_ILVectorArray2n_Mult) {
//	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
//	UnitTest_Mult<ILDCRT2n>(cc);
//}


TEST(UTSHE, keyswitch_sparse_key_SingleCRT_byteplaintext) {

	usint m = 512;
	usint plaintextModulus = 2;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");

	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(m, plaintextModulus);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, plaintext);

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext.push_back(newCt);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);
}

TEST(UTSHE, keyswitch_sparse_key_SingleCRT_intArray) {

	//ILVector2n::DestroyPreComputedSamples();
	usint m = 16;
	usint ptm = 2;
	float stdDev = 4;

	BigBinaryInteger q(1);
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger(ptm), m, BigBinaryInteger(40), BigBinaryInteger(4));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	shared_ptr<ILVector2n::Params> params( new ILVector2n::Params(m, q, rootOfUnity) );

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(params, ptm, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);
	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	//this step is needed because there is no marker for padding in the case of IntPlaintextEncoding
	intArrayNew.resize(intArray.size());

	EXPECT_EQ(intArray, intArrayNew);
}

TEST(UTSHE, keyswitch_SingleCRT) {

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	shared_ptr<ILVector2n::Params> params = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(m, 30);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(params, 2, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);
	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.KeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNew);

	EXPECT_EQ(plaintext, plaintextNew);
}

TEST(UTSHE, sparsekeygen_single_crt_encrypt_decrypt) {

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;

	shared_ptr<ILVector2n::Params> params = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(m, 30);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(params, 2, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.SparseKeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	ILVector2n privateElement(kp.secretKey->GetPrivateElement());
	privateElement.SwitchFormat();

	for (usint i = 1; i < privateElement.GetLength(); i += 2) {
		EXPECT_EQ(BigBinaryInteger(0), privateElement.GetValAtIndex(i));
	}
}

TEST(UTSHE, keyswitch_ModReduce_DCRT) {

	usint m = 512;

	BytePlaintextEncoding plaintext("I am good, what are you?! 32 ch");
	float stdDev = 4;
	usint size = 4;
	usint plaintextmodulus = 2;
	usint relinWindow = 1;

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params = GenerateDCRTParams( m, plaintextmodulus, size, 30 );

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, plaintextmodulus, relinWindow, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> newCiphertext(1);

	LPKeyPair<ILDCRT2n> kp2 = cc.KeyGen();

	shared_ptr<LPEvalKey<ILDCRT2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILDCRT2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	BytePlaintextEncoding plaintextNewKeySwitch;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNewKeySwitch);

	EXPECT_EQ(plaintext, plaintextNewKeySwitch) << "Key-Switched Decrypt fails";

	/**************************KEYSWITCH TEST END******************************/
	/**************************MODREDUCE TEST BEGIN******************************/

	newCiphertext[0] = cc.ModReduce(newCiphertext[0]);
	ILDCRT2n sk2PrivateElement(kp2.secretKey->GetPrivateElement());
	sk2PrivateElement.DropLastElement();
	kp2.secretKey->SetPrivateElement(sk2PrivateElement);

	BytePlaintextEncoding plaintextNewModReduce;

	cc.Decrypt(kp2.secretKey, newCiphertext, &plaintextNewModReduce);
	
	EXPECT_EQ(plaintext, plaintextNewModReduce) << "Mod Reduced Decrypt fails";
}

TEST(UTSHE, ringreduce_single_crt) {
	usint m = 16;

	float stdDev = 4;

	shared_ptr<ILVector2n::Params> params = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(m, 30);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(params, 2, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILVector2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint;
	keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	shared_ptr<Ciphertext<ILVector2n>> newCt = cc.KeySwitch(keySwitchHint, ciphertext[0]);
	newCiphertext[0] = newCt;

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	ciphertext = cc.RingReduce(ciphertext, keySwitchHint);

	ILVector2n skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	cc.Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR, false);

	IntPlaintextEncoding intArrayExpected = {1,1,1,1};

	EXPECT_EQ(intArrayNewRR, intArrayExpected);
}

TEST(UTSHE, ringreduce_double_crt) {

	usint m = 16;
	float stdDev = 4;
	usint plaintextmodulus = 2;
	usint relinWindow = 1;
	usint size = 3;

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params = GenerateDCRTParams( m, plaintextmodulus, size, 32 );

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, plaintextmodulus, relinWindow, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);
	cc.Enable(SHE);

	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,1,1,1,1,1,1,1 };
	IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> newCiphertext(ciphertext.size());

	LPKeyPair<ILDCRT2n> kp2 = cc.SparseKeyGen();

	shared_ptr<LPEvalKey<ILDCRT2n>> keySwitchHint = cc.KeySwitchGen(kp.secretKey, kp2.secretKey);

	newCiphertext[0] = cc.KeySwitch(keySwitchHint, ciphertext[0]);

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp2.secretKey, newCiphertext, &intArrayNew, false);

	ciphertext = cc.RingReduce(ciphertext, keySwitchHint);

	ILDCRT2n skSparseElement(kp2.secretKey->GetPrivateElement());
	skSparseElement.SwitchFormat();
	skSparseElement.Decompose();
	skSparseElement.SwitchFormat();

	kp2.secretKey->SetPrivateElement(skSparseElement);

	IntPlaintextEncoding intArrayNewRR;

	cc.Decrypt(kp2.secretKey, ciphertext, &intArrayNewRR, false);

	IntPlaintextEncoding intArrayExpected({ 1,1,1,1 });

	EXPECT_EQ(intArrayNewRR, intArrayExpected);

	ILVector2n::DestroyPreComputedSamples();

}

TEST(UTSHE, canringreduce) {
	BigBinaryInteger m1("17729");
	BigBinaryInteger m2("17761");
	std::vector<BigBinaryInteger> moduli;
	moduli.reserve(2);
	moduli.push_back(m1);
	moduli.push_back(m2);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);
	algorithm.Enable(SHE);

	EXPECT_TRUE(algorithm.CanRingReduce(4096, moduli, 1.006));
	EXPECT_TRUE(algorithm.CanRingReduce(2048, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(1024, moduli, 1.006));
	EXPECT_FALSE(algorithm.CanRingReduce(512, moduli, 1.006));

}

TEST(UTSHE, decomposeMult) {
  bool dbg_flag = false;
	usint m1 = 16;

	BigBinaryInteger modulus("1");
	NextQ(modulus, BigBinaryInteger("2"), m1, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
	shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );
	DEBUG("1");

	ILVector2n x1(params, Format::COEFFICIENT);
	DEBUG("x1 format "<<x1.GetFormat());
	x1 = { 0,0,0,0,0,0,1,0 };

	ILVector2n x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();
	DEBUG("2");
	x1.Decompose();
	x2.Decompose();

	ILVector2n resultsEval(params2, Format::EVALUATION);
	DEBUG("resultsEval format "<<resultsEval.GetFormat());
	x1.SwitchFormat();
	x2.SwitchFormat();
	DEBUG("x1 format "<<x1.GetFormat());
	DEBUG("x2 format "<<x2.GetFormat());
	DEBUG("3");
	resultsEval = x1*x2;

	resultsEval.SwitchFormat();
	DEBUG("4");

	//note now need to do this or else x3 has not data, and when SetFormat is called it tries to switch from EVALUATION and calls CRT on empty vector
	x1.SwitchFormat();

	ILVector2n x3(x1.CloneParametersOnly());


	DEBUG("x1 format "<<x1.GetFormat());
	DEBUG("x3 format "<<x3.GetFormat());
	x3.SetFormat(Format::COEFFICIENT);
	DEBUG("x3 format "<<x3.GetFormat());
	x3 = { 0,0,0,1 };

	ILVector2n x4(x1.CloneParametersOnly());
	x4.SetFormat(Format::COEFFICIENT);
	x4 = { 0,0,0,1 };

	x3.SwitchFormat();
	x4.SwitchFormat();
	DEBUG("5");
	ILVector2n resultsTest(x4.CloneParametersOnly());

	resultsTest = x3 * x4;

	resultsTest.SwitchFormat();
	DEBUG("6");
}
