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
#include <vector>

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

class UnitTestLatticeElements : public ::testing::Test {
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

TEST(method_ILVector2n, ensures_mod_operation_during_operations_on_two_ILVector2ns){

  usint order = 8; 
  usint nBits = 7;
  
  BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(order, nBits);
  BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(order, primeModulus);

  ILParams ilparams(order, primeModulus, primitiveRootOfUnity);

  DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(primeModulus);
  
  ILVector2n ilv1(distrUniGen, ilparams);
  BigBinaryVector bbv1 (ilv1.GetValues());

  ILVector2n ilv2(distrUniGen, ilparams);
  BigBinaryVector bbv2(ilv2.GetValues());
  
  {
    ILVector2n ilvResult = ilv1 + ilv2;
    BigBinaryVector bbvResult(ilvResult.GetValues());

    for (usint i=0; i<order/2; i++) {
      EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) + bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "ILVector2n + operation returns incorrect results.";
    }
  }

  {
    ILVector2n ilvResult = ilv1 * ilv2;
    BigBinaryVector bbvResult(ilvResult.GetValues());

    for (usint i=0; i<order/2; i++) {
      EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) * bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "ILVector2n * operation returns incorrect results.";
    }
  }

}

TEST(method_ILVectorArray2n, ensures_mod_operation_during_operations_on_two_ILVectorArray2ns){

  usint order = 16;
  usint nBits = 24;
  usint towersize = 1;

  std::vector<BigBinaryInteger> moduli(towersize);
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  std::vector<ILParams> ilparams(towersize);

  std::vector<ILVector2n> ilvector2n1(towersize);
  std::vector<BigBinaryVector> bbv1(towersize);
  std::vector<ILVector2n> ilvector2n2(towersize);
  std::vector<BigBinaryVector> bbv2(towersize);

  BigBinaryInteger q("1");
  BigBinaryInteger modulus("1");

  for(usint i=0; i < towersize;i++){
      lbcrypto::NextQ(q, BigBinaryInteger::TWO, order, BigBinaryInteger("4"), BigBinaryInteger("4"));
      moduli[i] = q;
      rootsOfUnity[i] = RootOfUnity(order,moduli[i]);
      modulus = modulus* moduli[i];
      
      ILParams ilparamsi(order, moduli[i], rootsOfUnity[i]);
      ilparams.push_back(ilparamsi);

      DiscreteUniformGenerator distrUniGeni = lbcrypto::DiscreteUniformGenerator(moduli[i]);

      ILVector2n ilv1(distrUniGeni, ilparamsi);
      ilvector2n1[i] = ilv1;
      bbv1[i] = (ilv1.GetValues());

      ILVector2n ilv2(distrUniGeni, ilparamsi);
      ilvector2n2[i] = ilv2;
      bbv2[i] = (ilv2.GetValues());
  }

  ILDCRTParams ildcrtparams(rootsOfUnity, order, moduli);

  ILVectorArray2n ilvectorarray2n1(ilvector2n1);
  ILVectorArray2n ilvectorarray2n2(ilvector2n2);

  {
    ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 + ilvectorarray2n2;

    for(usint i=0; i<towersize; i++) {
      for(usint j=0; j<order/2; j++) {
        BigBinaryInteger actualResult(ilvectorarray2nResult.GetTowerAtIndex(i).GetValAtIndex(j));
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) + bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n + operation returns incorrect results.";
      }
    }
    
  }

  {
    ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 * ilvectorarray2n2;

    for(usint i=0; i<towersize; i++) {
      for(usint j=0; j<order/2; j++) {
        BigBinaryInteger actualResult(ilvectorarray2nResult.GetTowerAtIndex(i).GetValAtIndex(j));
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) * bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n * operation returns incorrect results.";
      }
    }

  }

}