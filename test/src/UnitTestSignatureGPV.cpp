/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
K.Doruk Gur, kg365@njit.edu
Description:
This code exercises the GPV signature methods of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../include/gtest/gtest.h"
#include "../../src/lib/crypto/signature/lwesign.h"
#include "../../src/lib/crypto/signature/lwesign.cpp"
#include "../../src/lib/encoding/byteplaintextencoding.h"

using namespace lbcrypto;

class UnitTestSignatureGPV : public ::testing::Test {
protected:
	virtual void SetUp() {
	}

	virtual void TearDown() {
		// Code here will be called immediately after each test
		// (right before the destructor).
	}
};
/*---------------------------------------	TESTING METHODS OF SIGNATURE  --------------------------------------------*/

//TEST FOR BASIC SIGNING & VERIFICATION PROCESS
TEST(UTSignatureGPV,simple_sign_verify) {
  bool dbg_flag = false;

  DEBUG("Step 1");
	DiscreteGaussianGenerator dgg(4);
	usint sm = 16;
	BigBinaryInteger smodulus("1152921504606847009");
	BigBinaryInteger srootOfUnity("405107564542978792");
	shared_ptr<ILParams> silParams( new ILParams(sm, smodulus, srootOfUnity) );
  DEBUG("Step 2");
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
  DEBUG("Step 3");
	ILVector2n::PreComputeDggSamples(dgg, silParams);
  DEBUG("Step 4");
	LPSignatureParameters signParams(silParams, dgg);
  DEBUG("Step 5");
	LPSignKeyGPV<ILVector2n> s_k(signParams);
  DEBUG("Step 6");
	LPVerificationKeyGPV<ILVector2n> v_k(signParams);
  DEBUG("Step 7");
	LPSignatureSchemeGPV<ILVector2n> scheme;
  DEBUG("Step 8");
	scheme.KeyGen(&s_k, &v_k);
  DEBUG("Step 9");
	Signature<Matrix<ILVector2n>> signature;
  DEBUG("Step 10");
	BytePlaintextEncoding text("Since hashing is integrated now");
  DEBUG("Step 11");

	scheme.Sign(s_k, text, &signature);

	EXPECT_EQ(true, scheme.Verify(v_k, signature, text))
		<<"Failed verification";

	DEBUG("Step 12");
	ILVector2n::DestroyPreComputedSamples();
	DEBUG("Step 13");
}
//TEST FOR SIGNING AND VERIFYING SIGNATURES GENERATED FROM MULTIPLE TEXTS. ONLY SIGNATURES CORRESPONDING TO THEIR RESPECTIVE TEXT SHOULD VERIFY
TEST(UTSignatureGPV, sign_verify_multiple_texts) {
	DiscreteGaussianGenerator dgg(4);
	usint sm = 16;
	BigBinaryInteger smodulus("1152921504606847009");
	BigBinaryInteger srootOfUnity("405107564542978792");
	shared_ptr<ILParams> silParams( new ILParams(sm, smodulus, srootOfUnity) );
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	LPSignatureParameters signParams(silParams, dgg);
	LPSignKeyGPV<ILVector2n> s_k(signParams);
	LPVerificationKeyGPV<ILVector2n> v_k(signParams);
	
	LPSignatureSchemeGPV<ILVector2n> scheme;
	scheme.KeyGen(&s_k, &v_k);

	Signature<Matrix<ILVector2n>> signature, signature2;
	BytePlaintextEncoding text("We can use arbitrary sized texts");
	BytePlaintextEncoding text2("Which looks cool");



	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);

	EXPECT_EQ(true, scheme.Verify(v_k, signature, text))
			<<"Failed signature 1 - text 1 verification";
	EXPECT_EQ(true, scheme.Verify(v_k, signature2, text2))
			<< "Failed signature 2 - text 2 verification";
	EXPECT_EQ(false, scheme.Verify(v_k, signature2, text))
			<< "Failed signature 2 - text 1 verification";
	EXPECT_EQ(false, scheme.Verify(v_k, signature, text2))
			<< "Failed signature 1 - text 2 verification";

	ILVector2n::DestroyPreComputedSamples();

}

//TEST FOR SIGNING AND VERIFYING SIGNATURES GENERATED FROM MULTIPLE KEYS. ONLY SIGNATURES CORRESPONDING TO THEIR RESPECTIVE SPECIFIC KEY SHOULD VERIFY
TEST(UTSignatureGPV, sign_verify_multiple_keys) {
	DiscreteGaussianGenerator dgg(4);
	usint sm = 16;
	BigBinaryInteger smodulus("1152921504606847009");
	BigBinaryInteger srootOfUnity("405107564542978792");
	shared_ptr<ILParams> silParams( new ILParams(sm, smodulus, srootOfUnity) );
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	LPSignatureParameters signParams(silParams, dgg);
	LPSignKeyGPV<ILVector2n> s_k(signParams),s_k2(signParams);
	LPVerificationKeyGPV<ILVector2n> v_k(signParams),v_k2(signParams);

	LPSignatureSchemeGPV<ILVector2n> scheme;
	scheme.KeyGen(&s_k, &v_k);
	scheme.KeyGen(&s_k2, &v_k2);

	Signature<Matrix<ILVector2n>> signature, signature2;
	BytePlaintextEncoding text("But there are still issues to fix");

	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k2, text, &signature2);

	EXPECT_EQ(true, scheme.Verify(v_k, signature, text))
		<< "Failed signature 1 - key 1 verification";
	EXPECT_EQ(true, scheme.Verify(v_k2, signature2, text))
		<< "Failed signature 2 - key 2 verification";
	EXPECT_EQ(false, scheme.Verify(v_k, signature2, text))
		<< "Failed signature 2 - key 1 verification";
	EXPECT_EQ(false, scheme.Verify(v_k2, signature, text))
		<< "Failed signature 1 - key 2 verification";

	ILVector2n::DestroyPreComputedSamples();

}
/*
int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
*/


