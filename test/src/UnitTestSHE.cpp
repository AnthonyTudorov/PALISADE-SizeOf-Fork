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

using namespace std;
using namespace lbcrypto;

//https://github.com/google/googletest/blob/master/googletest/samples/sample6_unittest.cc

template <class T>
class UnitTestSHE : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*--------------------------------------- TESTING METHODS OF TRANSFORM    --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

TEST(SHEOperations_test, keyswitch_test_single_crt){

}

TEST(SHEOperations_test, keyswitch_test_double_crt){

  usint m = 16;
  const ByteArray plaintext = "M";
  ByteArrayPlaintextEncoding ptxt(plaintext);
  ptxt.Pad<ZeroPad>(m/16);
//  ptxt.Pad<ZeroPad>(m/8);

  float stdDev = 4;

  usint size = 3;

  std::cout << "tower size: " << size << std::endl;

  ByteArrayPlaintextEncoding ctxtd;

  vector<BigBinaryInteger> moduli(size);

  vector<BigBinaryInteger> rootsOfUnity(size);

  BigBinaryInteger q("1");
  BigBinaryInteger temp;
  BigBinaryInteger modulus("1");

  for(int i=0; i < size;i++){
        lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
    moduli[i] = q;
    cout << moduli[i] << endl;
    rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
    cout << rootsOfUnity[i] << endl;
    modulus = modulus* moduli[i];
  
  }

  cout << "big modulus: " << modulus << endl;
  DiscreteGaussianGenerator dgg(modulus,stdDev);

  ILDCRTParams params(rootsOfUnity, m, moduli);

  // LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
// //  BigBinaryInteger plaintextm("8");
//   cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
// //  cryptoParams2.SetPlaintextModulus(plaintextm);
//   cryptoParams2.SetDistributionParameter(stdDev);
//   cryptoParams2.SetRelinWindow(1);
//   cryptoParams2.SetElementParams(params);
//   cryptoParams2.SetDiscreteGaussianGenerator(dgg);

//   Ciphertext<ILVectorArray2n> cipherText2;
//   cipherText2.SetCryptoParameters(cryptoParams2);


//   LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
//   LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);

//   LPPublicKeyLTV<ILVectorArray2n> pk3(cryptoParams2);
//   LPPrivateKeyLTV<ILVectorArray2n> sk3(cryptoParams2);

//   std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
//   LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

//   //LPAlgorithmLTV<ILVectorArray2n> algorithm2;

//   algorithm2.KeyGen(&pk2, &sk2);
//   algorithm2.KeyGen(&pk3, &sk3);

//   algorithm2.Encrypt(pk2, ptxt, &cipherText2);

//   algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

  
//   cout << "Decrypted value ILVectorArray2n: \n" << endl;
//   cout << ctxtd<< "\n" << endl;

//   LPKeySwitchHintLTV<ILVectorArray2n> keySwitchHint;

//   algorithm2.m_algorithmLeveledSHE->KeySwitchHintGen(sk2,sk3, &keySwitchHint);
//   Ciphertext<ILVectorArray2n> cipherText3(algorithm2.m_algorithmLeveledSHE->KeySwitch(keySwitchHint, cipherText2));

//   algorithm2.Decrypt(sk3, cipherText3, &ctxtd);

//   cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
  
//   cout << ctxtd<< "\n" << endl;
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

}

