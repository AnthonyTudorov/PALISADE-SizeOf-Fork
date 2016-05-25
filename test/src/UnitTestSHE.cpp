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

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/elemparams.h"
#include "../../src/lattice/ilparams.h"
#include "../../src/lattice/ildcrtparams.h"
#include "../../src/lattice/ilelement.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/ilvector2n.h"
#include "../../src/lattice/ilvectorarray2n.h"
#include "../../src/utils/utilities.h"

#include "../../src/crypto/lwecrypt.cpp"
#include "../../src/crypto/lwefhe.cpp"
#include "../../src/crypto/lweshe.cpp"
#include "../../src/crypto/lweautomorph.cpp"
#include "../../src/crypto/lweahe.cpp"
#include "../../src/crypto/lwepre.cpp"
#include "../../src/crypto/ciphertext.cpp"

using namespace std;
using namespace lbcrypto;

template <class T>
class UnitTestSHE : public ::testing::Test {
  protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
      // Code here will be called immediately after each test
      // (right before the destructor).
    }

    // LPCryptoParametersLTV<ILVectorArray2n>* const cryptoParams;
};

typedef ::testing::Types<ILVectorArray2n> Implementations;

TYPED_TEST_CASE(UnitTestSHE, Implementations);

// Then use TYPED_TEST(TestCaseName, TestName) to define a typed test,
// similar to TEST_F.
TYPED_TEST(UnitTestSHE, keyswitch_test_double_crt) {
  usint m = 16;
  const ByteArray plaintext = "M";
  ByteArrayPlaintextEncoding ptxt(plaintext);
  ptxt.Pad<ZeroPad>(m/16);

  float stdDev = 4;
  usint size = 3;
  ByteArrayPlaintextEncoding ctxtd;

  vector<BigBinaryInteger> moduli(size);
  vector<BigBinaryInteger> rootsOfUnity(size);

  BigBinaryInteger q("1");
  BigBinaryInteger temp;
  BigBinaryInteger modulus("1");

  for(int i=0; i < size;i++){
    lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
    moduli[i] = q;
    rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
    modulus = modulus* moduli[i];
  }

  DiscreteGaussianGenerator dgg(modulus,stdDev);
  ILDCRTParams params(rootsOfUnity, m, moduli);

  LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
  cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
  cryptoParams.SetDistributionParameter(stdDev);
  cryptoParams.SetRelinWindow(1);
  cryptoParams.SetElementParams(params);
  cryptoParams.SetDiscreteGaussianGenerator(dgg);

  Ciphertext<ILVectorArray2n> cipherText;
  cipherText.SetCryptoParameters(cryptoParams);

  LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
  LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

  std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
  LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);

  algorithm.KeyGen(&pk, &sk);
  algorithm.Encrypt(pk, ptxt, &cipherText);
  ctxtd.Unpad<ZeroPad>();
  algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText, &sk);
  algorithm.Decrypt(sk, cipherText, &ctxtd);
  
  EXPECT_EQ(plaintext, ctxtd.GetData());
}

/*--------------------------------------- TESTING METHODS OF TRANSFORM    --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

/*TEST(SHEOperations_test, keyswitch_test_single_crt){
  
}

TEST(SHEOperations_test, keyswitch_test_double_crt){
  
}

TEST(SHEOperations_test, mod_reduce_test_single_crt){

}

TEST(SHEOperations_test, mod_reduce_test_double_crt){

}

TEST(SHEOperations_test, ring_reduce_test_single_crt){

}

TEST(SHEOperations_test, ring_reduce_test_double_crt){

}

TEST(SHEOperations_test, decompose_test_single_crt){

}

TEST(SHEOperations_test, decompose_test_double_crt){

}*/

