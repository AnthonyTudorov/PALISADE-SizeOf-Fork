/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
  v00.01
Last Edited:
  12/22/2015 2:37PM
List of Authors:
  TPOC:
    Dr. Kurt Rohloff, rohloff@njit.edu
  Programmers:
    Dr. Yuriy Polyakov, polyakov@njit.edu
    Gyana Sahu, grs22@njit.edu
    Nishanth Pasham, np386@njit.edu
Description:
  This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../include/gtest/gtest.h"
#include <iostream>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/math/nbtheory.h"
#include "../../src/lib/lattice/elemparams.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/lattice/ilelement.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/crypto/lwepre.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"
#include "../../src/lib/utils/utilities.h"

#include "../../src/lib/crypto/lwecrypt.cpp"
#include "../../src/lib/crypto/ciphertext.cpp"

using namespace std;
using namespace lbcrypto;

template <class T>
ElemParams* CreateParams(usint m);

template <class T>
LPCryptoParametersLTV<T>* CreateCryptoParams();

template <>
ElemParams* CreateParams<ILVector2n>(usint m) {
  BigBinaryInteger q("1");
  lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4")); 
  BigBinaryInteger rootOfUnity(RootOfUnity(m,q));
  ILParams ilParams(m,q,rootOfUnity);
  return &ilParams;
}

template <>
ElemParams* CreateParams<ILVectorArray2n>(usint m) {
  usint size = 3;
  // ByteArrayPlaintextEncoding ctxtd;

  vector<BigBinaryInteger> moduli(size);
  vector<BigBinaryInteger> rootsOfUnity(size);

  BigBinaryInteger q("1");
  BigBinaryInteger modulus("1");

  for(int i=0; i < size;i++){
    lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
    moduli[i] = q;
    rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
    modulus = modulus* moduli[i];
  }
  // DiscreteGaussianGenerator dgg(modulus,stdDev);
  ILDCRTParams ildcrtParams(rootsOfUnity, m, moduli);
  return &ildcrtParams;
}

template <class T>
LPCryptoParametersLTV<T>* CreateCryptoParams<ILVector2n>(){
	BigBinaryInteger q("1");
	lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4")); 
	BigBinaryInteger rootOfUnity(RootOfUnity(m,q));
	ILParams ilParams(m,q,rootOfUnity);
	return null;
}

template <class T>
class UnitTestSHE : public ::testing::Test {
  
  public:
static const usint m = 16;

  protected:
	  UnitTestSHE() : params(CreateParams<T>(UnitTestSHE::m)) {}

    virtual void SetUp() {
    }

    virtual void TearDown() {
      // Code here will be called immediately after each test
      // (right before the destructor).
    }

    // virtual ~UnitTestSHE() { delete params; }

    ElemParams* params;
	LPCryptoParametersLTV<T>* cryptoParams;

};

#if GTEST_HAS_TYPED_TEST

typedef ::testing::Types<ILVector2n, ILVectorArray2n> Implementations; 

TYPED_TEST_CASE(UnitTestSHE, Implementations);

// Use TYPED_TEST(TestCaseName, TestName) to define a typed test,
// similar to TEST_F.

TYPED_TEST(UnitTestSHE, eval_add_correction_test){
	  EXPECT_EQ(1, 1); 
}

TYPED_TEST(UnitTestSHE, keyswitch_modReduce_ringReduce_tests){
  
  float stdDev = 4;
  ByteArrayPlaintextEncoding ctxtd;
  const ByteArray plaintext = "M";
  
  ByteArrayPlaintextEncoding ptxt(plaintext);
  ptxt.Pad<ZeroPad>((UnitTestSHE::m)/16);

  LPCryptoParametersLTV<TypeParam> cryptoParams;
  cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
  cryptoParams.SetDistributionParameter(stdDev);
  cryptoParams.SetRelinWindow(1);
  cryptoParams.SetElementParams(*(this->params));

  Ciphertext<TypeParam> cipherText;
  cipherText.SetCryptoParameters(&cryptoParams);

  LPPublicKeyLTV<TypeParam> pk(cryptoParams);
  LPPrivateKeyLTV<TypeParam> sk(cryptoParams);

  std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
  LPPublicKeyEncryptionSchemeLTV<TypeParam> algorithm(mask);
  // TODO - Nishanth/ Yuriy: Some issue here with the way clean up happens with algorithm that it results in core dump while running this test class! Need to fix it.

  algorithm.KeyGen(&pk, &sk);
  algorithm.Encrypt(pk, ptxt, &cipherText);
  algorithm.Decrypt(sk, cipherText, &ctxtd);

  cout << "Decrypted value BEFORE any operations: \n" << endl;
  cout << ctxtd<< "\n" << endl;
  {
    LPPublicKeyLTV<TypeParam> pk2(cryptoParams);
    LPPrivateKeyLTV<TypeParam> sk2(cryptoParams);
    algorithm.KeyGen(&pk2, &sk2);

    LPKeySwitchHintLTV<TypeParam> keySwitchHint;
    algorithm.m_algorithmLeveledSHE->KeySwitchHintGen(sk, sk2, &keySwitchHint);
    Ciphertext<TypeParam> cipherText2;
    cipherText2 = algorithm.m_algorithmLeveledSHE->KeySwitch(keySwitchHint, cipherText);
    algorithm.Decrypt(sk2, cipherText2, &ctxtd);

    cout << "Decrypted value AFTER KeySwitch: \n" << endl;
    cout << ctxtd<< "\n" << endl;
    EXPECT_EQ(ctxtd.GetData(), plaintext) << "keyswitch_test_single_crt failed.\n";
  }

  {
    algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText);
    algorithm.Decrypt(sk, cipherText, &ctxtd);

    cout << "Decrypted value AFTER ModReduce: \n" << endl;
    cout << ctxtd<< "\n" << endl;
    EXPECT_EQ(ctxtd.GetData(), plaintext) << "mod_reduce_test_single_crt failed.\n" ;
  }

  /*{
    algorithm.m_algorithmLeveledSHE->RingReduce(&cipherText, &sk);
    algorithm.Decrypt(sk, cipherText, &ctxtd);
    cout << "Decrypted value after RING Reduce: \n" << endl;
    cout << ctxtd<< "\n" << endl;
  }*/
  
}

#endif