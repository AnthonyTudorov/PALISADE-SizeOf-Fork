/**
 * @file UnitTestIBE.cpp - Unit test file for identity based encryption

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

#include "../lib/math/backend.h"
#include "../lib/abecontext.h"


using namespace std;
using namespace lbcrypto;

template <class T>
class UTIBE : public ::testing::Test {

public:


protected:
	UTIBE() {}

	virtual void SetUp() {

	}

	virtual void TearDown() {

	}

	virtual ~UTIBE() {  }

};
template <class Element>
void UnitTestIBE(int32_t base, usint k, usint ringDimension){
	
    ABEContext<Element> context;
    context.GenerateIBEContext(ringDimension,k,base,SIGMA,false);
    IBEMasterPublicKey<Element> mpk;
	IBEMasterSecretKey<Element> msk;
    context.Setup(&mpk,&msk);
    IBEUserIdentifier<Element> id(context.GenerateRandomElement());
    IBESecretKey<Element> sk;
	context.KeyGen(msk,mpk,id,&sk);
    IBEPlaintext<Element> pt(context.GenerateRandomBinaryElement());
    IBECiphertext<Element> ct;
	context.Encrypt(mpk,id,pt,&ct);
    IBEPlaintext<Element> dt;
	context.Decrypt(id,id,sk,ct,&dt);

	EXPECT_EQ(pt.GetPText(),dt.GetPText());
}
TEST(UTIBE, ibe_base_32_poly) {
	UnitTestIBE<Poly>(32,32,1024);
}

TEST(UTIBE, ibe_base_32_native) {
	UnitTestIBE<NativePoly>(32,32,1024);
}