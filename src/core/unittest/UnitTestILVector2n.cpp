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
  Dr. David Bruce Cousins dave.cousins@raytheon.com

  Description: 
  This code tests the ideal lattice vector 2b feature of the PALISADE
  lattice encryption library.

  License Information:
  Copyright (c)  2015, New Jersey  Institute of Technology  (NJIT) All
  rights reserved.  
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"

using namespace std;
using namespace lbcrypto;

class UnitTestILVector2n : public ::testing::Test {
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

/*- TESTING METHODS OF IDEAL LATTICE VECTOR2N    ---*/

TEST(UTILVector2n, operators_tests) {
  bool dbg_flag = false;
  usint m = 8;

  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n1(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1 = {1, 2, 0, 1};

  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

  ILVector2n ilvector2n2(ilparams);
  BigBinaryVector bbv2(m/2, primeModulus);
  bbv2 = {1, 2, 0, 1};
  ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

  {
    ILVector2n ilv1(ilvector2n1);
    EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) 
      << "ILVector2n_copy_constructor: copy_constructor operation is incorrect.\n";
    EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) 
      << "ILVector2n_operator=: copy_constructor operation is incorrect.\n";
  }

  {
    ILVector2n ilv1 = ilvector2n1;
    EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) 
      << "ILVector2n_operator=: Operator= is incorrect in Format comparision.\n";
    EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) 
      << "ILVector2n_operator=: Operator= is incorrect in comparing values.\n";
  }

  EXPECT_EQ(ilvector2n1, ilvector2n2) 
    << "ILVector2n_operator==: Operator== is incorrect.\n";

  {
    ILVector2n ilv1 = ilvector2n1;
    ilv1.SwitchModulus(BigBinaryInteger("123467"), BigBinaryInteger("1234"));
    EXPECT_NE(ilvector2n1, ilv1) 
      << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare modulus properly.\n";

    ILVector2n ilv2 = ilvector2n1;
    ilv2.SetValAtIndex(2, 2);
    EXPECT_NE(ilvector2n1, ilv2) 
      << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare values properly.\n";
  }

  {
    ILVector2n ilv1 = ilvector2n1;
    ilv1 -= ilvector2n1;
    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(i)) 
	<< "ILVector2n_operator-=: Operator-= is incorrect @ index "<<i;
    }
  }
  DEBUG("1");
  {
    ILVector2n ilv1 = ilvector2n1;
    ilv1 += ilvector2n1;
    DEBUG("ilv1 "<<ilv1);
    BigBinaryInteger tmp(ilv1.GetValAtIndex(0));
    DEBUG("TMP "<< tmp);
    DEBUG("ilv1(0) "<< ilv1.GetValAtIndex(0));
    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(BigBinaryInteger::TWO * ilvector2n1.GetValAtIndex(i), ilv1.GetValAtIndex(i)) 
	<< "ILVector2n_operator+=: Operator+= is incorrect @ index "<<i;
    }
  }
}

TEST(UTILVector2n, getters_tests) {
  bool dbg_flag = false;
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n(ilparams);

  BigBinaryVector bbv(m/2, primeModulus);
  bbv = {1, 2, 0, 1};
  ilvector2n.SetValues(bbv, ilvector2n.GetFormat());
  
  EXPECT_EQ(primeModulus, ilvector2n.GetModulus()) 
    << "ILVector2n.GetModulus is incorrect.\n";
  EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder()) 
    << "ILVector2n.GetCyclotomicOrder is incorrect.\n";
  EXPECT_EQ(primitiveRootOfUnity, ilvector2n.GetRootOfUnity()) 
    << "ILVector2n.GetRootOfUnity is incorrect.\n";
  EXPECT_EQ(bbv, ilvector2n.GetValues()) 
    << "ILVector2n.GetValues is incorrect.\n";
  EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat()) 
    << "ILVector2n.GetFormat is incorrect.\n";
  EXPECT_EQ(m/2, ilvector2n.GetLength()) 
    << "ILVector2n.GetLength is incorrect.\n";
  EXPECT_EQ(bbv, ilvector2n.GetValues())
    <<"ILVector2n.GetValues is incorrect.\n";
  for (usint i = 0; i < m/2; ++i) {
    EXPECT_EQ(bbv.GetValAtIndex(i), ilvector2n.GetValAtIndex(i)) 
      << "ILVector2n.GetValAtIndex i:"<<i<< "is incorrect.\n";
  }
}

TEST(UTILVector2n, rounding_operations) {
  usint m = 8;

  BigBinaryInteger q("73");
  BigBinaryInteger primitiveRootOfUnity("22");
  BigBinaryInteger p("8");

  shared_ptr<ILParams> ilparams( new ILParams(m, q, primitiveRootOfUnity) );

  //temporary larger modulus that is used for polynomial multiplication before rounding
  BigBinaryInteger q2("16417");
  BigBinaryInteger primitiveRootOfUnity2("13161");

  shared_ptr<ILParams> ilparams2( new ILParams(m, q2, primitiveRootOfUnity2) );

  //ilparams = ilparams2;

  ILVector2n ilvector2n1(ilparams,COEFFICIENT);
  ilvector2n1 = { 31,21,15,34};
  //ilvector2n1.SwitchFormat();

  ILVector2n ilvector2n2(ilparams,COEFFICIENT);
  ilvector2n2 = { 21,11,35,32 };
  //ilvector2n2.SwitchFormat();

  //unit test for MultiplyAndRound

  ILVector2n roundingCorrect1(ilparams, COEFFICIENT);
  roundingCorrect1 = { 3,2,2,4 };

  ILVector2n rounding1 = ilvector2n1.MultiplyAndRound(p, q);

  EXPECT_EQ(roundingCorrect1, rounding1) 
    << "Rounding p*polynomial/q is incorrect.\n";

  //unit test for MultiplyAndRound after a polynomial multiplication using the larger modulus

  ILVector2n roundingCorrect2(ilparams2, COEFFICIENT);
  roundingCorrect2 = { 16316, 16320, 60, 286 };

  ilvector2n1.SwitchModulus(q2, primitiveRootOfUnity2);
  ilvector2n2.SwitchModulus(q2, primitiveRootOfUnity2);

  ilvector2n1.SwitchFormat();
  ilvector2n2.SwitchFormat();

  ILVector2n rounding2 = ilvector2n1 * ilvector2n2;
  rounding2.SwitchFormat();

  rounding2 = rounding2.MultiplyAndRound(p, q);

  EXPECT_EQ(roundingCorrect2, rounding2) 
    << "Rounding p*polynomial1*polynomial2/q is incorrect.\n";

  //makes sure the result is correct after going back to the original modulus

  rounding2.SwitchModulus(q, primitiveRootOfUnity);

  ILVector2n roundingCorrect3(ilparams, COEFFICIENT);
  roundingCorrect3 = { 45, 49, 60, 67 };

  EXPECT_EQ(roundingCorrect3, rounding2) 
    << "Rounding p*polynomial1*polynomial2/q (mod q) is incorrect.\n";
}

TEST(UTILVector2n, setters_tests) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n(ilparams);
  // std::cout << "GetCyclotomicOrder = " << ilvector2n.GetCyclotomicOrder() << std::endl;
  BigBinaryVector bbv(m/2, primeModulus);
  bbv = {3, 0, 0, 0};
  ilvector2n.SetValues(bbv, Format::COEFFICIENT);

  ILVector2n ilvector2nInEval(ilparams);
  // std::cout << "GetCyclotomicOrder = " << ilvector2n.GetCyclotomicOrder() << std::endl;
  BigBinaryVector bbvEval(m/2, primeModulus);
  bbvEval = {3, 3, 3, 3};
  ilvector2nInEval.SetValues(bbvEval, Format::EVALUATION);

  {
    ILVector2n ilv(ilvector2n);
    
    ilv.SetFormat(Format::COEFFICIENT);
    EXPECT_EQ(ilvector2n, ilv) 
      << "ILVector2n.SetFormat is incorrect. Setting the format to COEFFICIENT is incorrect.\n";
    
    ilv.SetFormat(Format::EVALUATION);
    EXPECT_EQ(ilvector2nInEval, ilv) 
      << "ILVector2n.SetFormat is incorrect. Setting the format to EVALUATION is incorrect.\n";
  }
}

TEST(UTILVector2n, binary_arithmetic_operations) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n1(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1 = {2, 1, 1, 1};  
  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

  ILVector2n ilvector2n2(ilparams);
  BigBinaryVector bbv2(m/2, primeModulus);
  bbv2 = {1, 0, 1, 1};
  ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

  ILVector2n ilvector2n3(ilparams, COEFFICIENT);
  BigBinaryVector bbv3(m / 2, primeModulus);
  bbv3 = {2, 1, 1, 1};
  ilvector2n3.SetValues(bbv3, ilvector2n3.GetFormat());

  ILVector2n ilvector2n4(ilparams, COEFFICIENT);
  BigBinaryVector bbv4(m / 2, primeModulus);
  bbv4= {1, 0, 1, 1};
  ilvector2n4.SetValues(bbv4, ilvector2n4.GetFormat());

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Plus(ilvector2n2);
    BigBinaryVector expected(4, primeModulus);
    expected = {3,1,2,2};
    EXPECT_EQ(expected, ilv2.GetValues())<<"Failure: Plus()";
  }

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Minus(ilvector2n2);
    BigBinaryVector expected(4, primeModulus);
    expected = {1,1,0,0};
    EXPECT_EQ(expected, ilv2.GetValues())<<"Failure: Minus()";
  }

  {
    ILVector2n ilv1(ilvector2n1);
    ILVector2n ilv2 = ilv1.Times(ilvector2n2);
    BigBinaryVector expected(4, primeModulus);
    expected = {2,0,1,1};
    EXPECT_EQ(expected, ilv2.GetValues())<<"Failure: Times()";
  }

  {
    ilvector2n3.SwitchFormat();
    ilvector2n4.SwitchFormat();
	  
    ILVector2n ilv3(ilvector2n3);
    ILVector2n ilv4 = ilv3.Times(ilvector2n4);

    ilv4.SwitchFormat();
    BigBinaryVector expected(4, primeModulus);
    expected = {0,72,2,4};
    EXPECT_EQ(expected, ilv4.GetValues())<<"Failure: Times() using NTT";
  }

}

TEST(UTILVector2n, clone_operations) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilv(ilparams);
  BigBinaryVector bbv(m/2, primeModulus);
  bbv = {2,1,1,1};
  ilv.SetValues(bbv, ilv.GetFormat());

  {
    ILVector2n ilvClone = ilv.CloneParametersOnly();

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
  ILVector2n::DestroyPreComputedSamples();
}

TEST(UTILVector2n, arithmetic_operations_element) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilv(ilparams);
  BigBinaryVector bbv(m/2, primeModulus);
  bbv = {2,1,4,1};
  ilv.SetValues(bbv, ilv.GetFormat());

  BigBinaryInteger element("1");

  {
    ILVector2n ilvector2n(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {1,3,4,1};
    ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

    ilvector2n = ilvector2n.Plus(element);

    BigBinaryVector expected(4, primeModulus);
    expected = {2,3,4,1};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: Plus()";
  }

  {
    ILVector2n ilvector2n = ilv.Minus(element);
    BigBinaryVector expected(4, primeModulus);
    expected = {1,0,3,0};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: Minus()";
  }

  {
    BigBinaryInteger ele("2");
    ILVector2n ilvector2n = ilv.Times(ele);
    BigBinaryVector expected(4, primeModulus);
    expected = {4,2,8,2};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: Times()";
  }

  {
    ILVector2n ilvector2n(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {1,3,4,1};
    ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

    ilvector2n += element;
    BigBinaryVector expected(4, primeModulus);
    expected = {2,3,4,1};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: op+=";
  }

  {
    ILVector2n ilvector2n = ilv.Minus(element);
    BigBinaryVector expected(4, primeModulus);
    expected = {1,0,3,0};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: Minus()";
  }

  {
    ILVector2n ilvector2n(ilv);
    ilvector2n -= element;
    BigBinaryVector expected(4, primeModulus);
    expected = {1,0,3,0};
    EXPECT_EQ(expected, ilvector2n.GetValues())<<"Failure: op-=";
  }

}

TEST(UTILVector2n, other_methods) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  float stdDev = 4.0;
  DiscreteGaussianGenerator dgg(stdDev);
  BinaryUniformGenerator bug;
  DiscreteUniformGenerator dug(primeModulus);

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n(ilparams);
  BigBinaryVector bbv1(m/2, primeModulus);
  bbv1 = {2,1,3,2};
  ilvector2n.SetValues(bbv1, Format::EVALUATION);

  {
    ILVector2n ilv(ilvector2n);
    ilv.AddILElementOne();
    BigBinaryVector expected(4, primeModulus);
    expected = {3,2,4,3};
    EXPECT_EQ(expected, ilv.GetValues())<<"Failure: AddILElementOne()";
  }

  {
    ILVector2n ilv(ilvector2n);
    ilv = ilv.ModByTwo();
    BigBinaryVector expected(4, primeModulus);
    expected = {0,1,1,0};
    EXPECT_EQ(expected, ilv.GetValues())<<"Failure: ModByTwo()";
  }

  {
    ILVector2n ilv(ilvector2n);
    ilv.MakeSparse(BigBinaryInteger::TWO);
    BigBinaryVector expected(4, primeModulus);
    expected = {2,0,3,0};
    EXPECT_EQ(expected, ilv.GetValues())<<"Failure: MakeSparse(TWO)";

    ILVector2n ilv1(ilvector2n);
    ilv1.MakeSparse(BigBinaryInteger::THREE);
    expected = {2,0,0,2};
    EXPECT_EQ(expected, ilv1.GetValues())<<"Failure: MakeSparse(THREE)";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {2,1,3,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);
    ilv.Decompose();
    EXPECT_EQ(2, ilv.GetLength())<<"Failure: Decompose() length";
    EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(0)) 
      << "Failure: Decompose(): Values do not match between original and decomposed elements.";
    EXPECT_EQ(BigBinaryInteger::THREE, ilv.GetValAtIndex(1)) 
      << "Failure Decompose(): Values do not match between original and decomposed elements.";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    BigBinaryVector expected(4, primeModulus);
    bbv = {2,1,3,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ilv.SwitchFormat();
    EXPECT_EQ(primeModulus, ilv.GetModulus())
      <<"Failure: SwitchFormat() ilv modulus";
    EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity())
      <<"Failure: SwitchFormat() ilv rootOfUnity";
    EXPECT_EQ(Format::EVALUATION, ilv.GetFormat())
      <<"Failure: SwitchFormat() ilv format";;
    expected = {69, 44, 65, 49};
    EXPECT_EQ(expected, ilv.GetValues())<<"Failure: ivl.SwitchFormat()";

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {2,1,3,2};
    ilv1.SetValues(bbv1, Format::EVALUATION);

    ilv1.SwitchFormat();

    EXPECT_EQ(primeModulus, ilv1.GetModulus())
      <<"Failure: SwitchFormat() ilv1 modulus";
    EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity())
      <<"Failure: SwitchFormat() ilv1 rootOfUnity";
    EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat())
      <<"Failure: SwitchFormat() ilv1 format";
    expected = {2, 3, 50, 3};
    EXPECT_EQ(expected, ilv1.GetValues())<<"Failure: ivl1.SwitchFormat()";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {2,1,3,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilvector2n1(ilparams);
    ILVector2n ilvector2n2(ilparams);
    ILVector2n ilvector2n3(ilv);
    ILVector2n ilvector2n4(dgg, ilparams);
    ILVector2n ilvector2n5(bug, ilparams);
    ILVector2n ilvector2n6(dug, ilparams);
    ILVector2n::DestroyPreComputedSamples();

    EXPECT_EQ(true, ilvector2n1.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n1";
    EXPECT_EQ(true, ilvector2n2.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n2";
    EXPECT_EQ(false, ilvector2n3.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n3";
    EXPECT_EQ(false, ilvector2n4.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n4";
    EXPECT_EQ(false, ilvector2n5.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n5";
    EXPECT_EQ(false, ilvector2n6.IsEmpty())
      <<"Failure: DestroyPreComputedSamples() 2n6";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {56,1,37,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    BigBinaryInteger modulus("17");
    BigBinaryInteger rootOfUnity("15");

    ilv.SwitchModulus(modulus, rootOfUnity);

    BigBinaryVector expected(4, modulus);
    expected = {0,1,15,2};
    EXPECT_EQ(expected, ilv.GetValues())<<"Failure: SwitchModulus()";

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {56,43,35,28};
    ilv1.SetValues(bbv1, Format::COEFFICIENT);

    BigBinaryInteger modulus1("193");
    BigBinaryInteger rootOfUnity1("150");

    ilv1.SwitchModulus(modulus1, rootOfUnity1);
    expected.SetModulus(modulus1);
    expected = {176,163,35,28};
    EXPECT_EQ(expected, ilv1.GetValues())<<"Failure: SwitchModulus()";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {2,4,3,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {2,0,3,2};
    ilv1.SetValues(bbv1, Format::COEFFICIENT);

    ILVector2n ilv2(ilparams);
    BigBinaryVector bbv2(m/2, primeModulus);
    bbv1 = {2,1,3,2};
    ilv2.SetValues(bbv2, Format::COEFFICIENT);

    EXPECT_EQ(true, ilv.InverseExists())<<"Failure: ilv.InverseExists()";
    EXPECT_EQ(false, ilv1.InverseExists())<<"Failure: ilv1.InverseExists()";
    EXPECT_EQ(false, ilv2.InverseExists())<<"Failure: ilv2.InverseExists()";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {2,4,3,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilvInverse = ilv.MultiplicativeInverse();
    ILVector2n ilvProduct = ilv * ilvInverse;

    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(BigBinaryInteger::ONE, ilvProduct.GetValAtIndex(i))
	<<"Failure ilvProduct.MultiplicativeInverse() @ index "<<i;
    }
    
    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1 = {2,4,3,2};
    ilv1.SetValues(bbv1, Format::EVALUATION);

    ILVector2n ilvInverse1 = ilv1.MultiplicativeInverse();
    ILVector2n ilvProduct1 = ilv1 * ilvInverse1;

    for (usint i = 0; i < m/2; ++i) {
      EXPECT_EQ(BigBinaryInteger::ONE, ilvProduct1.GetValAtIndex(i))
      <<"Failure ilvProduct1.MultiplicativeInverse() @ index "<<i;
    }
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {56,1,37,1};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    EXPECT_EQ(36, ilv.Norm())<<"Failiure Norm()";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv = {56,1,37,2};
    ilv.SetValues(bbv, Format::COEFFICIENT);

    usint index = 3;
    ILVector2n ilvAuto(ilv.AutomorphismTransform(index));
    BigBinaryVector expected(4, primeModulus);
    expected = {1,56,2,37};
    EXPECT_EQ(expected, ilvAuto.GetValues())
      <<"Failure: AutomorphismTransform()";
  }

}

TEST(UTILVector2n, cyclotomicOrder_test) {
  usint m = 8;
  shared_ptr<ILParams> ilparams0( new ILParams(m, BigBinaryInteger("17661"), BigBinaryInteger("8765")) );
  // std::cout << "ilparams0.GetCyclotomicOrder()  = " << ilparams0.GetCyclotomicOrder() << std::endl;
  ILVector2n ilv0(ilparams0);
  // std::cout << "ilv0.GetCyclotomicOrder()  = " << ilv0.GetCyclotomicOrder() << std::endl;
  EXPECT_EQ(ilparams0->GetCyclotomicOrder(), ilv0.GetCyclotomicOrder());
}


// Signed mod must handle the modulo operation for both positive and negative numbers
// It is used in decoding/decryption of homomorphic encryption schemes
TEST(UTILVector2n, signed_mod_tests) {

  usint m = 8;

  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilvector2n1(ilparams,COEFFICIENT);
  BigBinaryVector bbv1(m / 2, primeModulus);
  bbv1 = {62,7,65,8};
  ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

  {
    ILVector2n ilv1(ilparams, COEFFICIENT);
    ilv1 = ilvector2n1.SignedMod(BigBinaryInteger::TWO);

    BigBinaryVector expected(4, primeModulus);
    expected = {1,1,0,0};
    EXPECT_EQ(expected, ilv1.GetValues())
      <<"Failure: ilv1.SignedMod()";
  }

  {
    ILVector2n ilv1(ilparams, COEFFICIENT);
    ilv1 = ilvector2n1.SignedMod(BigBinaryInteger("5"));

    BigBinaryVector expected(4, primeModulus);
    expected = {4,2,2,3};
    EXPECT_EQ(expected, ilv1.GetValues())
      <<"Failure: SignedMod()";
  }

}

TEST(UTILVector2n, transposition_test) {
  usint m = 8;

  BigBinaryInteger q("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams(new ILParams(m, q, primitiveRootOfUnity));

  ILVector2n ilvector2n1(ilparams, COEFFICIENT);
  ilvector2n1 = { 31,21,15,34 };
	
  // converts to evaluation representation
  ilvector2n1.SwitchFormat();

  ilvector2n1 = ilvector2n1.Transpose();

  // converts back to coefficient representation
  ilvector2n1.SwitchFormat();

  ILVector2n ilvector2n2(ilparams);
  BigBinaryVector bbv0(m / 2, q);
  bbv0 = {31,39,58,52};
  ilvector2n2.SetValues(bbv0, Format::COEFFICIENT);
		
  EXPECT_EQ(ilvector2n2, ilvector2n1)
    <<"Failure transposition test";
}



TEST(UTILVector2n, ensures_mod_operation_during_operations_on_two_ILVector2ns){

  usint order = 8; 
  usint nBits = 7;
  
  BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus<BigBinaryInteger>(order, nBits);
  BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity<BigBinaryInteger>(order, primeModulus);

  shared_ptr<ILParams> ilparams( new ILParams(order, primeModulus, primitiveRootOfUnity) );

  DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(primeModulus);
  
  ILVector2n ilv1(distrUniGen, ilparams);
  BigBinaryVector bbv1 (ilv1.GetValues());

  ILVector2n ilv2(distrUniGen, ilparams);
  BigBinaryVector bbv2(ilv2.GetValues());
  
  {
    ILVector2n ilvResult = ilv1 + ilv2;
    BigBinaryVector bbvResult(ilvResult.GetValues());

    for (usint i=0; i<order/2; i++) {
      EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) + bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "Failure: + operation returns incorrect results.";
    }
  }

  {
    ILVector2n ilvResult = ilv1 * ilv2;
    BigBinaryVector bbvResult(ilvResult.GetValues());

    for (usint i=0; i<order/2; i++) {
      EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) * bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "Failure: * operation returns incorrect results.";
    }
  }
}
