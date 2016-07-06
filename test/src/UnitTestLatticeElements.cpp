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

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"

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

 public:
  static const usint test = 1;
};

/*--------------------------------------- TESTING METHODS OF LATTICE ELEMENTS    --------------------------------------------*/

TEST(method_ILVector2n, operators_tests) {
  usint m = 8;

  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilvector2n1(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1.SetValAtIndex(0, "1");
  bbv1.SetValAtIndex(1, "2");
  bbv1.SetValAtIndex(2, "0");
  bbv1.SetValAtIndex(3, "1");
  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

  ILVector2n ilvector2n2(ilparams);
  BigBinaryVector bbv2(m/2, primeModulus);
  bbv2.SetValAtIndex(0, "1");
  bbv2.SetValAtIndex(1, "2");
  bbv2.SetValAtIndex(2, "0");
  bbv2.SetValAtIndex(3, "1");
  ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

  {
    ILVector2n ilv1(ilvector2n1);
    EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) << "ILVector2n_copy_constructor: copy_constructor operation is incorrect.\n";
    EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) << "ILVector2n_operator=: copy_constructor operation is incorrect.\n";
  }

  {
    ILVector2n ilv1 = ilvector2n1;
    EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) << "ILVector2n_operator=: Operator= is incorrect in Format comparision.\n";
    EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) << "ILVector2n_operator=: Operator= is incorrect in comparing values.\n";
  }

  {
    EXPECT_EQ(ilvector2n1, ilvector2n2) << "ILVector2n_operator==: Operator== is incorrect.\n";
  }

  {
    ILVector2n ilv1 = ilvector2n1;
    ilv1.SwitchModulus(BigBinaryInteger("123467"), BigBinaryInteger("1234"));
    EXPECT_NE(ilvector2n1, ilv1) << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare modulus properly.\n";

    ILVector2n ilv2 = ilvector2n1;
    ilv2.SetValAtIndex(2, 2);
    EXPECT_NE(ilvector2n1, ilv2) << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare values properly.\n";
  }

  {
    ILVector2n ilv1 = ilvector2n1;
    ilv1 -= ilvector2n1;
    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(i)) << "ILVector2n_operator-=: Operator-= is incorrect.\n";
    }
  }

  {
     ILVector2n ilv1 = ilvector2n1;
     ilv1 += ilvector2n1;
     for (usint i = 0; i < m/2; ++i)
     {
        EXPECT_EQ(BigBinaryInteger::TWO * ilvector2n1.GetValAtIndex(i), ilv1.GetValAtIndex(i)) << "ILVector2n_operator+=: Operator+= is incorrect.\n";
     }
  }

}

TEST(method_ILVector2n, getters_tests) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilvector2n(ilparams);
  // std::cout << "GetCyclotomicOrder = " << ilvector2n.GetCyclotomicOrder() << std::endl;
  BigBinaryVector bbv(m/2, primeModulus);
  bbv.SetValAtIndex(0, "1");
  bbv.SetValAtIndex(1, "2");
  bbv.SetValAtIndex(2, "0");
  bbv.SetValAtIndex(3, "1");
  ilvector2n.SetValues(bbv, ilvector2n.GetFormat());

  {
    EXPECT_EQ(primeModulus, ilvector2n.GetModulus()) << "ILVector2n.GetModulus is incorrect.\n";
  }

  {
    EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder()) << "ILVector2n.GetCyclotomicOrder is incorrect.\n";
  }

  {
    EXPECT_EQ(primitiveRootOfUnity, ilvector2n.GetRootOfUnity()) << "ILVector2n.GetRootOfUnity is incorrect.\n";
  }

  {
    EXPECT_EQ(bbv, ilvector2n.GetValues()) << "ILVector2n.GetValues is incorrect.\n";
  }

  {
    EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat()) << "ILVector2n.GetFormat is incorrect.\n";
  }

  {
    EXPECT_EQ(m/2, ilvector2n.GetLength()) << "ILVector2n.GetLength is incorrect.\n";
  }

  {
    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(bbv.GetValAtIndex(i), ilvector2n.GetValAtIndex(i)) << "ILVector2n.GetValAtIndex is incorrect.\n";
    }
  }

}

TEST(method_ILVector2n, setters_tests) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilvector2n(ilparams);
  // std::cout << "GetCyclotomicOrder = " << ilvector2n.GetCyclotomicOrder() << std::endl;
  BigBinaryVector bbv(m/2, primeModulus);
  bbv.SetValAtIndex(0, "3");
  bbv.SetValAtIndex(1, "0");
  bbv.SetValAtIndex(2, "0");
  bbv.SetValAtIndex(3, "0");
  ilvector2n.SetValues(bbv, Format::COEFFICIENT);

  ILVector2n ilvector2nInEval(ilparams);
  // std::cout << "GetCyclotomicOrder = " << ilvector2n.GetCyclotomicOrder() << std::endl;
  BigBinaryVector bbvEval(m/2, primeModulus);
  bbvEval.SetValAtIndex(0, "3");
  bbvEval.SetValAtIndex(1, "3");
  bbvEval.SetValAtIndex(2, "3");
  bbvEval.SetValAtIndex(3, "3");
  ilvector2nInEval.SetValues(bbvEval, Format::EVALUATION);

  {
    ILVector2n ilv(ilvector2n);
    
    ilv.SetFormat(Format::COEFFICIENT);
    EXPECT_EQ(ilvector2n, ilv) << "ILVector2n.SetFormat is incorrect. Setting the format to COEFFICIENT is incorrect.\n";
    
    ilv.SetFormat(Format::EVALUATION);
    EXPECT_EQ(ilvector2nInEval, ilv) << "ILVector2n.SetFormat is incorrect. Setting the format to EVALUATION is incorrect.\n";
  }

}

TEST(method_ILVector2n, binary_operations) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilvector2n1(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1.SetValAtIndex(0, "2");
  bbv1.SetValAtIndex(1, "1");
  bbv1.SetValAtIndex(2, "1");
  bbv1.SetValAtIndex(3, "1");
  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

  ILVector2n ilvector2n2(ilparams);
  BigBinaryVector bbv2(m/2, primeModulus);
  bbv2.SetValAtIndex(0, "1");
  bbv2.SetValAtIndex(1, "0");
  bbv2.SetValAtIndex(2, "1");
  bbv2.SetValAtIndex(3, "1");
  ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Plus(ilvector2n2);

    EXPECT_EQ(BigBinaryInteger::THREE, ilv2.GetValAtIndex(0)) << "ILVector2n.Plus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ONE, ilv2.GetValAtIndex(1)) << "ILVector2n.Plus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::TWO, ilv2.GetValAtIndex(2)) << "ILVector2n.Plus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::TWO, ilv2.GetValAtIndex(3)) << "ILVector2n.Plus is incorrect.\n";
  }

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Minus(ilvector2n2);

    EXPECT_EQ(BigBinaryInteger::ONE, ilv2.GetValAtIndex(0)) << "ILVector2n.Minus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ONE, ilv2.GetValAtIndex(1)) << "ILVector2n.Minus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv2.GetValAtIndex(2)) << "ILVector2n.Minus is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv2.GetValAtIndex(3)) << "ILVector2n.Minus is incorrect.\n";
  }

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Times(ilvector2n2);

    EXPECT_EQ(BigBinaryInteger::TWO, ilv2.GetValAtIndex(0)) << "ILVector2n.Times is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv2.GetValAtIndex(1)) << "ILVector2n.Times is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ONE, ilv2.GetValAtIndex(2)) << "ILVector2n.Times is incorrect.\n";
    EXPECT_EQ(BigBinaryInteger::ONE, ilv2.GetValAtIndex(3)) << "ILVector2n.Times is incorrect.\n";
  }

}

TEST(method_ILVector2n, clone_operations) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilv(ilparams);
  BigBinaryVector bbv(m/2, primeModulus);
  bbv.SetValAtIndex(0, "2");
  bbv.SetValAtIndex(1, "1");
  bbv.SetValAtIndex(2, "1");
  bbv.SetValAtIndex(3, "1");
  ilv.SetValues(bbv, ilv.GetFormat());

  {
    ILVector2n ilvClone = ilv.CloneWithParams();

    EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder());
    EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus());
    EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity());
    EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat());
  }

  {
    float stdDev = 4;
    DiscreteGaussianGenerator dgg(stdDev);
    ILVector2n ilvClone = ilv.CloneWithNoise(dgg, ilv.GetFormat());

    EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder());
    EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus());
    EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity());
    EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat());
  }

}

TEST(method_ILVector2n, arithmetic_operations_element) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilv(ilparams);
  BigBinaryVector bbv(m/2, primeModulus);
  bbv.SetValAtIndex(0, "2");
  bbv.SetValAtIndex(1, "1");
  bbv.SetValAtIndex(2, "4");
  bbv.SetValAtIndex(3, "1");
  ilv.SetValues(bbv, ilv.GetFormat());

  BigBinaryInteger element("1");

  {
    ILVector2n ilvector2n = ilv.Plus(element);

    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::FOUR, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(3));
  }

  {
    ILVector2n ilvector2n = ilv.Minus(element);

    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(3));
  }

  //TODO-Nishanth: Uncomment when DividedBy is implemented for ILVector2n
  /*{
    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "2");
    bbv1.SetValAtIndex(1, "8");
    bbv1.SetValAtIndex(2, "4");
    bbv1.SetValAtIndex(3, "6");
    ilv1.SetValues(bbv1, Format::COEFFICIENT);

    BigBinaryInteger ele("2");

    ILVector2n ilvector2n = ilv1.DividedBy(ele);

    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::FOUR, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(3));
  }*/

  {
    ILVector2n ilvector2n = ilv.Times(element);
    BigBinaryInteger ele("2");

    EXPECT_EQ(BigBinaryInteger::FOUR, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("8"), ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(3));
  }

  {
    ILVector2n ilvector2n(ilv);
    ilvector2n += element;

    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::FOUR, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(3));
  }

  {
    ILVector2n ilvector2n = ilv.Minus(element);

    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(3));
  }

  {
    ILVector2n ilvector2n(ilv);
    ilvector2n -= element;

    EXPECT_EQ(BigBinaryInteger::ONE, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilvector2n.GetValAtIndex(3));
  }

}


TEST(method_ILVector2n, arithmetic_operators_tests_between_ilvector2ns) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(m, primeModulus, primitiveRootOfUnity);

  ILVector2n ilvector2n1(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1.SetValAtIndex(0, "2");
  bbv1.SetValAtIndex(1, "1");
  bbv1.SetValAtIndex(2, "1");
  bbv1.SetValAtIndex(3, "1");
  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

}

TEST(method_ILVector2n, decompose_test) {
  usint order = 8;
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  ILParams ilparams(order, primeModulus, primitiveRootOfUnity);

  float stdDev = 4;
  DiscreteGaussianGenerator dgg(stdDev);

  ILVector2n ilVector2n(dgg, ilparams, Format::COEFFICIENT);

  BigBinaryVector bbv1 (ilVector2n.GetValues());

  ilVector2n.Decompose();

  BigBinaryVector bbv2 (ilVector2n.GetValues());

  EXPECT_EQ(bbv2.GetLength(), bbv1.GetLength()/2);

  for(usint i=0; i<bbv2.GetLength(); i++) {
    EXPECT_EQ(bbv2.GetValAtIndex(i), bbv1.GetValAtIndex(2*i)) << "ILVector2n_decompose: Values do not match between original and decomposed elements.";
  }

}

TEST(method_ILVectorArray2n, decompose_test) {
  usint order = 16;
  usint nBits = 24;
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  std::vector<ILParams> ilparams(towersize);

  std::vector<ILVector2n> ilvector2n1(towersize);
  std::vector<BigBinaryVector> bbv1(towersize);

  BigBinaryInteger q("1");
  BigBinaryInteger modulus("1");

  for(usint i=0; i < towersize;i++){
      lbcrypto::NextQ(q, BigBinaryInteger::TWO, order, BigBinaryInteger("4"), BigBinaryInteger("4"));
      moduli[i] = q;
      rootsOfUnity[i] = RootOfUnity(order,moduli[i]);
      modulus = modulus* moduli[i];
  }

  float stdDev = 4;
  DiscreteGaussianGenerator dgg(stdDev);

  ILDCRTParams params(rootsOfUnity, order, moduli);
  ILVectorArray2n ilVectorArray2n(dgg, params, Format::COEFFICIENT);

  ILVectorArray2n ilvectorarray2nOriginal(ilVectorArray2n);
  ilVectorArray2n.Decompose();

  EXPECT_EQ(ilvectorarray2nOriginal.GetTowerLength(), ilVectorArray2n.GetTowerLength()) << "ILVectorArray2n_decompose: Mismatch in the number of towers after decompose.";

  for(usint i=0; i<ilVectorArray2n.GetTowerLength(); i++) {
    ILVector2n ilTowerOriginal(ilvectorarray2nOriginal.GetTowerAtIndex(i));
    ILVector2n ilTowerDecomposed(ilVectorArray2n.GetTowerAtIndex(i));
    
    EXPECT_EQ(ilTowerDecomposed.GetLength(), ilTowerOriginal.GetLength()/2)  << "ILVectorArray2n_decompose: ilVector2n element in ilVectorArray2n is not half the length after decompose.";
    
    for(usint j=0; j<ilTowerDecomposed.GetLength(); j++) {
      EXPECT_EQ(ilTowerDecomposed.GetValAtIndex(j), ilTowerOriginal.GetValAtIndex(2*j)) << "ILVectorArray2n_decompose: Values do not match between original and decomposed elements.";
    }
  }

}

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
  usint towersize = 3;

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