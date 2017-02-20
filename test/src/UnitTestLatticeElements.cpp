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

void testILVectorArray2nConstructorNegative(std::vector<ILVector2n> &towers);

/*--------------------------------------- TESTING METHODS OF LATTICE ELEMENTS    --------------------------------------------*/

TEST(UTILVector2n, operators_tests) {
  usint m = 8;

  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

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

TEST(UTILVector2n, getters_tests) {
  bool dbg_flag = true;
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

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
  DEBUG("il2vector2n "<<ilvector2n.GetValues());
  DEBUG("il2vector2n "<<ilvector2n.GetValues());
  DEBUG("il2vector2n "<<ilvector2n.GetValues().GetValAtIndex(0));
  DEBUG("il2vector2n "<<ilvector2n.GetValues().GetValAtIndex(1));
  DEBUG("il2vector2n "<<ilvector2n.GetValues().GetValAtIndex(2));
  DEBUG("il2vector2n "<<ilvector2n.GetValues().GetValAtIndex(3));
  EXPECT_EQ(bbv, ilvector2n.GetValues())<<"ILVector2n.GetValues is incorrect.\n";

  BigBinaryVector foo;
  DEBUG("m "<<m);
  foo = ilvector2n.GetValues(); //try this
  for (usint i = 0; i < m/2; ++i) {  
    DEBUG("i "<<i);
    DEBUG("foo "<<foo.GetValAtIndex(i));
    //    DEBUG("il  "<<ilvector2n.GetValAtIndex(i));
    std::cout<<"il  ";
    std::cout<<ilvector2n.GetValAtIndex(i);
    std::cout<<endl;
    
  }
  {
    for (usint i = 0; i < m/2; ++i) {
      DEBUG("i "<<i);
      DEBUG("bbv "<<bbv.GetValAtIndex(i));
      DEBUG("ilvector2n " << ilvector2n.GetValues());
      DEBUG("foo" << foo);
      DEBUG("fooget" << foo.GetValAtIndex(i));
      DEBUG("ilvector2n" << ilvector2n.GetValAtIndex(i));
      DEBUG("foo");
      EXPECT_EQ(bbv.GetValAtIndex(i), ilvector2n.GetValAtIndex(i)) << "ILVector2n.GetValAtIndex is incorrect.\n";
    }
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

	EXPECT_EQ(roundingCorrect1, rounding1) << "Rounding p*polynomial/q is incorrect.\n";

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

	EXPECT_EQ(roundingCorrect2, rounding2) << "Rounding p*polynomial1*polynomial2/q is incorrect.\n";

	//makes sure the result is correct after going back to the original modulus

	rounding2.SwitchModulus(q, primitiveRootOfUnity);

	ILVector2n roundingCorrect3(ilparams, COEFFICIENT);
	roundingCorrect3 = { 45, 49, 60, 67 };

	EXPECT_EQ(roundingCorrect3, rounding2) << "Rounding p*polynomial1*polynomial2/q (mod q) is incorrect.\n";

}

TEST(UTILVector2n, setters_tests) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

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

TEST(UTILVector2n, binary_operations) {
  usint m = 8; 
  
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

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

  ILVector2n ilvector2n3(ilparams, COEFFICIENT);
  BigBinaryVector bbv3(m / 2, primeModulus);
  bbv3.SetValAtIndex(0, "2");
  bbv3.SetValAtIndex(1, "1");
  bbv3.SetValAtIndex(2, "1");
  bbv3.SetValAtIndex(3, "1");
  ilvector2n3.SetValues(bbv3, ilvector2n3.GetFormat());

  ILVector2n ilvector2n4(ilparams, COEFFICIENT);
  BigBinaryVector bbv4(m / 2, primeModulus);
  bbv4.SetValAtIndex(0, "1");
  bbv4.SetValAtIndex(1, "0");
  bbv4.SetValAtIndex(2, "1");
  bbv4.SetValAtIndex(3, "1");
  ilvector2n4.SetValues(bbv4, ilvector2n4.GetFormat());

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

  {
	  ilvector2n3.SwitchFormat();
	  ilvector2n4.SwitchFormat();
	  
	  ILVector2n ilv3(ilvector2n3);
	  ILVector2n ilv4 = ilv3.Times(ilvector2n4);

	  ilv4.SwitchFormat();

	  EXPECT_EQ(BigBinaryInteger("0"), ilv4.GetValAtIndex(0)) << "ILVector2n.Times using NTT is incorrect.\n";
	  EXPECT_EQ(BigBinaryInteger("72"), ilv4.GetValAtIndex(1)) << "ILVector2n.Times using NTT is incorrect.\n";
	  EXPECT_EQ(BigBinaryInteger("2"), ilv4.GetValAtIndex(2)) << "ILVector2n.Times using NTT is incorrect.\n";
	  EXPECT_EQ(BigBinaryInteger("4"), ilv4.GetValAtIndex(3)) << "ILVector2n.Times using NTT is incorrect.\n";
  }

}

TEST(UTILVector2n, clone_operations) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

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
  ILVector2n::DestroyPreComputedSamples();
}

TEST(UTILVector2n, arithmetic_operations_element) {
  usint m = 8;
  BigBinaryInteger primeModulus("73");
  BigBinaryInteger primitiveRootOfUnity("22");

  shared_ptr<ILParams> ilparams( new ILParams(m, primeModulus, primitiveRootOfUnity) );

  ILVector2n ilv(ilparams);
  BigBinaryVector bbv(m/2, primeModulus);
  bbv.SetValAtIndex(0, "2");
  bbv.SetValAtIndex(1, "1");
  bbv.SetValAtIndex(2, "4");
  bbv.SetValAtIndex(3, "1");
  ilv.SetValues(bbv, ilv.GetFormat());

  BigBinaryInteger element("1");

  {
    ILVector2n ilvector2n(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "1");
    bbv1.SetValAtIndex(1, "3");
    bbv1.SetValAtIndex(2, "4");
    bbv1.SetValAtIndex(3, "1");
    ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

    ilvector2n = ilvector2n.Plus(element);

    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(1));
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
    BigBinaryInteger ele("2");
    ILVector2n ilvector2n = ilv.Times(ele);

    EXPECT_EQ(BigBinaryInteger::FOUR, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("8"), ilvector2n.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(3));
  }

  {
    ILVector2n ilvector2n(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "1");
    bbv1.SetValAtIndex(1, "3");
    bbv1.SetValAtIndex(2, "4");
    bbv1.SetValAtIndex(3, "1");
    ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

    ilvector2n += element;

    EXPECT_EQ(BigBinaryInteger::TWO, ilvector2n.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::THREE, ilvector2n.GetValAtIndex(1));
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
  bbv1.SetValAtIndex(0, "2");
  bbv1.SetValAtIndex(1, "1");
  bbv1.SetValAtIndex(2, "3");
  bbv1.SetValAtIndex(3, "2");
  ilvector2n.SetValues(bbv1, Format::EVALUATION);

  {
    ILVector2n ilv(ilvector2n);

    ilv.AddILElementOne();

    EXPECT_EQ(BigBinaryInteger::THREE, ilv.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::FOUR, ilv.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::THREE, ilv.GetValAtIndex(3));
  }

  {
    ILVector2n ilv(ilvector2n);
    ilv = ilv.ModByTwo();

    EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));
  }

  {
    ILVector2n ilv(ilvector2n);
    ilv.MakeSparse(BigBinaryInteger::TWO);

    EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::THREE, ilv.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));

    ILVector2n ilv1(ilvector2n);
    ilv1.MakeSparse(BigBinaryInteger::THREE);

    EXPECT_EQ(BigBinaryInteger::TWO, ilv1.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::TWO, ilv1.GetValAtIndex(3));
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "2");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "3");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ilv.Decompose();

    EXPECT_EQ(2, ilv.GetLength());

    EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(0)) << "ILVector2n_decompose: Values do not match between original and decomposed elements.";
    EXPECT_EQ(BigBinaryInteger::THREE, ilv.GetValAtIndex(1)) << "ILVector2n_decompose: Values do not match between original and decomposed elements.";
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "2");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "3");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ilv.SwitchFormat();

    EXPECT_EQ(primeModulus, ilv.GetModulus());
    EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity());
    EXPECT_EQ(Format::EVALUATION, ilv.GetFormat());
    EXPECT_EQ(BigBinaryInteger("69"), ilv.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("44"), ilv.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("65"), ilv.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("49"), ilv.GetValAtIndex(3));


    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "2");
    bbv1.SetValAtIndex(1, "1");
    bbv1.SetValAtIndex(2, "3");
    bbv1.SetValAtIndex(3, "2");
    ilv1.SetValues(bbv1, Format::EVALUATION);

    ilv1.SwitchFormat();

    EXPECT_EQ(primeModulus, ilv1.GetModulus());
    EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity());
    EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat());
    EXPECT_EQ(BigBinaryInteger::TWO, ilv1.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::THREE, ilv1.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("50"), ilv1.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::THREE, ilv1.GetValAtIndex(3));
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "2");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "3");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilvector2n1(ilparams);
    ILVector2n ilvector2n2(ilparams);
    ILVector2n ilvector2n3(ilv);
    ILVector2n ilvector2n4(dgg, ilparams);
    ILVector2n ilvector2n5(bug, ilparams);
    ILVector2n ilvector2n6(dug, ilparams);
	ILVector2n::DestroyPreComputedSamples();


    EXPECT_EQ(true, ilvector2n1.IsEmpty());
    EXPECT_EQ(true, ilvector2n2.IsEmpty());
    EXPECT_EQ(false, ilvector2n3.IsEmpty());
    EXPECT_EQ(false, ilvector2n4.IsEmpty());
    EXPECT_EQ(false, ilvector2n5.IsEmpty());
    EXPECT_EQ(false, ilvector2n6.IsEmpty());
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "56");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "37");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    BigBinaryInteger modulus("17");
    BigBinaryInteger rootOfUnity("15");

    ilv.SwitchModulus(modulus, rootOfUnity);

    EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("15"), ilv.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "56");
    bbv1.SetValAtIndex(1, "43");
    bbv1.SetValAtIndex(2, "35");
    bbv1.SetValAtIndex(3, "28");
    ilv1.SetValues(bbv1, Format::COEFFICIENT);

    BigBinaryInteger modulus1("193");
    BigBinaryInteger rootOfUnity1("150");

    ilv1.SwitchModulus(modulus1, rootOfUnity1);

    EXPECT_EQ(BigBinaryInteger("176"), ilv1.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("163"), ilv1.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("35"), ilv1.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("28"), ilv1.GetValAtIndex(3));
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "2");
    bbv.SetValAtIndex(1, "4");
    bbv.SetValAtIndex(2, "3");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "2");
    bbv1.SetValAtIndex(1, "0");
    bbv1.SetValAtIndex(2, "3");
    bbv1.SetValAtIndex(3, "2");
    ilv1.SetValues(bbv1, Format::COEFFICIENT);

    ILVector2n ilv2(ilparams);
    BigBinaryVector bbv2(m/2, primeModulus);
    bbv2.SetValAtIndex(0, "2");
    bbv2.SetValAtIndex(1, "1");
    bbv2.SetValAtIndex(2, "3");
    bbv2.SetValAtIndex(3, "2");
    ilv2.SetValues(bbv2, Format::COEFFICIENT);

    EXPECT_EQ(true, ilv.InverseExists());
    EXPECT_EQ(false, ilv1.InverseExists());
    EXPECT_EQ(false, ilv1.InverseExists());
  }

   {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "2");
    bbv.SetValAtIndex(1, "4");
    bbv.SetValAtIndex(2, "3");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    ILVector2n ilvInverse = ilv.MultiplicativeInverse();
    ILVector2n ilvProduct = ilv * ilvInverse;

    for (usint i = 0; i < m/2; ++i)
    {
      EXPECT_EQ(BigBinaryInteger::ONE, ilvProduct.GetValAtIndex(i));
    }

    ILVector2n ilv1(ilparams);
    BigBinaryVector bbv1(m/2, primeModulus);
    bbv1.SetValAtIndex(0, "2");
    bbv1.SetValAtIndex(1, "4");
    bbv1.SetValAtIndex(2, "3");
    bbv1.SetValAtIndex(3, "2");
    ilv1.SetValues(bbv1, Format::EVALUATION);

    ILVector2n ilvInverse1 = ilv1.MultiplicativeInverse();
    ILVector2n ilvProduct1 = ilv1 * ilvInverse1;

    for (usint i = 0; i < m/2; ++i)
    {
      EXPECT_EQ(BigBinaryInteger::ONE, ilvProduct1.GetValAtIndex(i));
    }

  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "56");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "37");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    EXPECT_EQ(36, ilv.Norm());
  }

  {
    ILVector2n ilv(ilparams);
    BigBinaryVector bbv(m/2, primeModulus);
    bbv.SetValAtIndex(0, "56");
    bbv.SetValAtIndex(1, "1");
    bbv.SetValAtIndex(2, "37");
    bbv.SetValAtIndex(3, "2");
    ilv.SetValues(bbv, Format::COEFFICIENT);

    usint index = 3;
    ILVector2n ilvAuto(ilv.AutomorphismTransform(index));
    
    EXPECT_EQ(BigBinaryInteger::ONE, ilvAuto.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("56"), ilvAuto.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger::TWO, ilvAuto.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("37"), ilvAuto.GetValAtIndex(3));
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

TEST(UTILVectorArray2n, constructors_test) {
	  bool dbg_flag = false;
  usint m = 8;
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  moduli = {BigBinaryInteger("8353"), BigBinaryInteger("8369"), BigBinaryInteger("8513")};
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  rootsOfUnity = {BigBinaryInteger("8163"), BigBinaryInteger("6677"), BigBinaryInteger("156")};

  BigBinaryInteger modulus(BigBinaryInteger::ONE);
  for (usint i = 0; i < towersize; ++i)
  {
    modulus = modulus * moduli[i];
  }

  shared_ptr<ILParams> ilparams0( new ILParams(m, moduli[0], rootsOfUnity[0]) );
  shared_ptr<ILParams> ilparams1( new ILParams(m, moduli[1], rootsOfUnity[1]) );
  shared_ptr<ILParams> ilparams2( new ILParams(m, moduli[2], rootsOfUnity[2]) );
  
  ILVector2n ilv0(ilparams0);
  BigBinaryVector bbv0(m/2, moduli[0]);
  bbv0.SetValAtIndex(0, "2");
  bbv0.SetValAtIndex(1, "4");
  bbv0.SetValAtIndex(2, "3");
  bbv0.SetValAtIndex(3, "2");
  ilv0.SetValues(bbv0, Format::EVALUATION);

  ILVector2n ilv1(ilv0);
  ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);
  
  ILVector2n ilv2(ilv0);
  ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

  shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );
    
  std::vector<ILVector2n> ilvector2nVector(towersize);
  ilvector2nVector[0] = ilv0;
  ilvector2nVector[1] = ilv1;
  ilvector2nVector[2] = ilv2;

  DEBUG("1");
  float stdDev = 4.0;
  DiscreteGaussianGenerator dgg(stdDev);

  {
    ILVectorArray2n ilva(ildcrtparams);

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
    EXPECT_EQ(towersize, ilva.GetNumOfElements());
  }

  DEBUG("2");
  {
    ILVectorArray2n ilva(ilvector2nVector);
    
    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    //TODO-Nishanth: Uncomment once UTILVector2n.cyclotomicOrder_test passes.
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
    EXPECT_EQ(towersize, ilva.GetNumOfElements());

    DEBUG("2.1");
	std::vector<ILVector2n> ilvector2nVectorInconsistent(towersize);
	shared_ptr<ILParams> ilparamsNegativeTestCase( new ILParams(128, BigBinaryInteger("1231"), BigBinaryInteger("213")) );
	ILVector2n ilvNegative(ilparamsNegativeTestCase);
	ilvector2nVectorInconsistent[0] = ilvNegative;
	ilvector2nVectorInconsistent[1] = ilv1;
	ilvector2nVectorInconsistent[2] = ilv2;

    DEBUG("2.2");
    for( int ii=0; ii<ilvector2nVectorInconsistent.size(); ii++ ) {
    	DEBUG(ii << " item " << ilvector2nVectorInconsistent.at(ii).GetParams().use_count());
    }
	EXPECT_THROW(testILVectorArray2nConstructorNegative(ilvector2nVectorInconsistent), std::logic_error);
  }

  DEBUG("3");
  {
    ILVectorArray2n ilva(ilv0, ildcrtparams);

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
    EXPECT_EQ(towersize, ilva.GetNumOfElements());
    for (usint i = 0; i < towersize; ++i)
    {
      EXPECT_EQ(ilvector2nVector[i], ilva.GetElementAtIndex(i));
    }
  }

  DEBUG("4");
  {
    ILVectorArray2n ilva0;
    ILVectorArray2n ilva1(ildcrtparams);
    ILVectorArray2n ilva2(ilv0, ildcrtparams);
    ILVectorArray2n ilva3(ilvector2nVector);

    std::vector<ILVectorArray2n> ilvaVector(4);
    ilvaVector[0] = ilva0;
    ilvaVector[1] = ilva1;
    ilvaVector[2] = ilva2;
    ilvaVector[3] = ilva3;

    //copy constructor
    ILVectorArray2n ilva0Copy(ilva0);
    ILVectorArray2n ilva1Copy(ilva1);
    ILVectorArray2n ilva2Copy(ilva2);
    ILVectorArray2n ilva3Copy(ilva3);

    std::vector<ILVectorArray2n> ilvaCopyVector(4);
    ilvaCopyVector[0] = ilva0Copy;
    ilvaCopyVector[1] = ilva1Copy;
    ilvaCopyVector[2] = ilva2Copy;
    ilvaCopyVector[3] = ilva3Copy;

    for (usint i = 0; i < 4; ++i)
    {
      EXPECT_EQ(ilvaVector[i].GetFormat(), ilvaCopyVector[i].GetFormat());
      EXPECT_EQ(ilvaVector[i].GetModulus(), ilvaCopyVector[i].GetModulus());
      EXPECT_EQ(ilvaVector[i].GetCyclotomicOrder(), ilvaCopyVector[i].GetCyclotomicOrder());
      EXPECT_EQ(ilvaVector[i].GetNumOfElements(), ilvaCopyVector[i].GetNumOfElements());
      if(i==0 || i==1) // to ensure that GetElementAtIndex is not called on uninitialized ILVectorArray2n objects.
        continue;
      for (usint j = 0; j < towersize; ++j)
      {
        EXPECT_EQ(ilvaVector[i].GetElementAtIndex(j), ilvaCopyVector[i].GetElementAtIndex(j));
      }
    }
  }

  DEBUG("5");
  {
    ILVectorArray2n ilva(dgg, ildcrtparams);

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
    EXPECT_EQ(towersize, ilva.GetNumOfElements());
  }

  DEBUG("6");
  {
    ILVectorArray2n ilva(ilv0, ildcrtparams);
    ILVectorArray2n ilvaClone(ilva.CloneWithParams());

    std::vector<ILVector2n> towersInClone = ilvaClone.GetAllElements();
    

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
  }

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
	bbv1.SetValAtIndex(0, "62");
	bbv1.SetValAtIndex(1, "7");
	bbv1.SetValAtIndex(2, "65");
	bbv1.SetValAtIndex(3, "8");
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	{
		ILVector2n ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(BigBinaryInteger::TWO);

		EXPECT_EQ(BigBinaryInteger::ONE, ilv1.GetValAtIndex(0)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::ONE, ilv1.GetValAtIndex(1)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(2)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::ZERO, ilv1.GetValAtIndex(3)) << "ILVector2n.SignedMod fails.\n";

	}

	{
		ILVector2n ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(BigBinaryInteger("5"));

		EXPECT_EQ(BigBinaryInteger::FOUR, ilv1.GetValAtIndex(0)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::TWO, ilv1.GetValAtIndex(1)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::TWO, ilv1.GetValAtIndex(2)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(BigBinaryInteger::THREE, ilv1.GetValAtIndex(3)) << "ILVector2n.SignedMod fails.\n";

	}

}

TEST(UTILVectorArray2n, getters_tests) {
  usint m = 8; //16
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  moduli = {BigBinaryInteger("8353"), BigBinaryInteger("8369"), BigBinaryInteger("8513")};
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  rootsOfUnity = {BigBinaryInteger("8163"), BigBinaryInteger("6677"), BigBinaryInteger("156")};

  BigBinaryInteger modulus(BigBinaryInteger::ONE);
  for (usint i = 0; i < towersize; ++i)
  {
    modulus = modulus * moduli[i];
  }

  shared_ptr<ILParams> ilparams0( new ILParams(m, moduli[0], rootsOfUnity[0]) );
  shared_ptr<ILParams> ilparams1( new ILParams(m, moduli[1], rootsOfUnity[1]) );
  shared_ptr<ILParams> ilparams2( new ILParams(m, moduli[2], rootsOfUnity[2]) );

  ILVector2n ilv0(ilparams0);
  BigBinaryVector bbv0(m/2, moduli[0]);
  bbv0.SetValAtIndex(0, "2");
  bbv0.SetValAtIndex(1, "4");
  bbv0.SetValAtIndex(2, "3");
  bbv0.SetValAtIndex(3, "2");
  ilv0.SetValues(bbv0, Format::EVALUATION);

  ILVector2n ilv1(ilv0);
  ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);
  
  ILVector2n ilv2(ilv0);
  ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

  shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );
    
  std::vector<ILVector2n> ilvector2nVector(towersize);
  // ilvector2nVector = {ilv0, ilv1, ilv2};
  ilvector2nVector[0] = ilv0;
  ilvector2nVector[1] = ilv1;
  ilvector2nVector[2] = ilv2;

  {
    ILVectorArray2n ilva(ildcrtparams);

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
    EXPECT_EQ(towersize, ilva.GetNumOfElements());
  }

}

TEST(UTILVectorArray2n, operator_test) {
  usint m = 8;
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  moduli = {BigBinaryInteger("8353"), BigBinaryInteger("8369"), BigBinaryInteger("8513")};
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  rootsOfUnity = {BigBinaryInteger("8163"), BigBinaryInteger("6677"), BigBinaryInteger("156")};

  BigBinaryInteger modulus(BigBinaryInteger::ONE);
  for (usint i = 0; i < towersize; ++i)
  {
    modulus = modulus * moduli[i];
  }

  shared_ptr<ILParams> ilparams0( new ILParams(m, moduli[0], rootsOfUnity[0]) );
  shared_ptr<ILParams> ilparams1( new ILParams(m, moduli[1], rootsOfUnity[1]) );
  shared_ptr<ILParams> ilparams2( new ILParams(m, moduli[2], rootsOfUnity[2]) );
  
  ILVector2n ilv0(ilparams0);
  BigBinaryVector bbv0(m/2, moduli[0]);
  bbv0.SetValAtIndex(0, "2");
  bbv0.SetValAtIndex(1, "4");
  bbv0.SetValAtIndex(2, "3");
  bbv0.SetValAtIndex(3, "2");
  ilv0.SetValues(bbv0, Format::EVALUATION);

  ILVector2n ilv1(ilv0);
  ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);
  
  ILVector2n ilv2(ilv0);
  ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

  shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );
    
  std::vector<ILVector2n> ilvector2nVector(towersize);
  ilvector2nVector[0] = ilv0;
  ilvector2nVector[1] = ilv1;
  ilvector2nVector[2] = ilv2;

  ILVectorArray2n ilva(ilvector2nVector);

  {
    ILVectorArray2n ilva1(ilva);
    EXPECT_TRUE(ilva == ilva1);
  }

  {
    ILVectorArray2n ilva1 = ilva;
    EXPECT_EQ(ilva, ilva1);
  }

  {
    ILVectorArray2n ilva1(ildcrtparams);
    ilva1 = {2, 4, 3, 2};
    EXPECT_EQ(ilva, ilva1);
  }

  {
    ILVector2n ilvect0(ilparams0);
    BigBinaryVector bbv1(m/2, moduli[0]);
    bbv1.SetValAtIndex(0, "2");
    bbv1.SetValAtIndex(1, "1");
    bbv1.SetValAtIndex(2, "3");
    bbv1.SetValAtIndex(3, "2");
    ilvect0.SetValues(bbv1, Format::EVALUATION);

    ILVector2n ilvect1(ilvect0);
    ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);
    
    ILVector2n ilvect2(ilvect0);
    ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);
      
    std::vector<ILVector2n> ilvector2nVector1(towersize);
    ilvector2nVector1[0] = ilvect0;
    ilvector2nVector1[1] = ilvect1;
    ilvector2nVector1[2] = ilvect2;

    ILVectorArray2n ilva1(ilvector2nVector1);

    EXPECT_TRUE(ilva!=ilva1);
  }

}

TEST(UTILVectorArray2n, arithmetic_operations_element) {
  usint m = 8;
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  moduli = {BigBinaryInteger("8353"), BigBinaryInteger("8369"), BigBinaryInteger("8513")};
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  rootsOfUnity = {BigBinaryInteger("8163"), BigBinaryInteger("6677"), BigBinaryInteger("156")};

  BigBinaryInteger modulus(BigBinaryInteger::ONE);
  for (usint i = 0; i < towersize; ++i)
  {
    modulus = modulus * moduli[i];
  }

  shared_ptr<ILParams> ilparams0( new ILParams(m, moduli[0], rootsOfUnity[0]) );
  shared_ptr<ILParams> ilparams1( new ILParams(m, moduli[1], rootsOfUnity[1]) );
  shared_ptr<ILParams> ilparams2( new ILParams(m, moduli[2], rootsOfUnity[2]) );
  
  ILVector2n ilv0(ilparams0);
  BigBinaryVector bbv0(m/2, moduli[0]);
  bbv0.SetValAtIndex(0, "2");
  bbv0.SetValAtIndex(1, "4");
  bbv0.SetValAtIndex(2, "3");
  bbv0.SetValAtIndex(3, "2");
  ilv0.SetValues(bbv0, Format::EVALUATION);

  ILVector2n ilv1(ilv0);
  ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);
  
  ILVector2n ilv2(ilv0);
  ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);
    
  std::vector<ILVector2n> ilvector2nVector(towersize);
  ilvector2nVector[0] = ilv0;
  ilvector2nVector[1] = ilv1;
  ilvector2nVector[2] = ilv2;

  ILVectorArray2n ilva(ilvector2nVector);

  ILVector2n ilvect0(ilparams0);
  BigBinaryVector bbv1(m/2, moduli[0]);
  bbv1.SetValAtIndex(0, "2");
  bbv1.SetValAtIndex(1, "1");
  bbv1.SetValAtIndex(2, "2");
  bbv1.SetValAtIndex(3, "0");
  ilvect0.SetValues(bbv1, Format::EVALUATION);

  ILVector2n ilvect1(ilvect0);
  ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);
  
  ILVector2n ilvect2(ilvect0);
  ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);
    
  std::vector<ILVector2n> ilvector2nVector1(towersize);
  ilvector2nVector1[0] = ilvect0;
  ilvector2nVector1[1] = ilvect1;
  ilvector2nVector1[2] = ilvect2;

  ILVectorArray2n ilva1(ilvector2nVector1);

  {
    ILVectorArray2n ilvaCopy(ilva.Plus(ilva1));
    // ilvaCopy = ilvaCopy + ilva1;

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0));
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(2));
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaCopy(ilva);
    ilvaCopy += ilva1;

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

       EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0));
       EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1));
       EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(2));
       EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaCopy(ilva.Minus(ilva1));

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(2));
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaResult(ilva);
    ilvaResult -= ilva1;

    for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

       EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
       EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(1));
       EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(2));
       EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaResult(ilva.Times(ilva1));

    for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0));
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger("6"), ilv.GetValAtIndex(2));
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaCopy(ilva);
    ilvaCopy.AddILElementOne();

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(0));
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(2));
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(3));
    }
  }

  {
    ILVectorArray2n ilvaInv(ilva.MultiplicativeInverse());

    ILVector2n ilvectInv0 = ilvaInv.GetElementAtIndex(0);
    ILVector2n ilvectInv1 = ilvaInv.GetElementAtIndex(1);
    ILVector2n ilvectInv2 = ilvaInv.GetElementAtIndex(2);

    EXPECT_EQ(BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("6265"), ilvectInv0.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("5569"), ilvectInv0.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("8353"), ilvectInv0.GetModulus());
    EXPECT_EQ(BigBinaryInteger("8163"), ilvectInv0.GetRootOfUnity());

    EXPECT_EQ(BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("6277"), ilvectInv1.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("2790"), ilvectInv1.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("8369"), ilvectInv1.GetModulus());
    EXPECT_EQ(BigBinaryInteger("6677"), ilvectInv1.GetRootOfUnity());

    EXPECT_EQ(BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("6385"), ilvectInv2.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("2838"), ilvectInv2.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("8513"), ilvectInv2.GetModulus());
    EXPECT_EQ(BigBinaryInteger("156"), ilvectInv2.GetRootOfUnity());

    EXPECT_THROW(ilva1.MultiplicativeInverse(), std::logic_error);
  }

  {
    ILVectorArray2n ilvaCopy(ilva);

    ilvaCopy.MakeSparse(BigBinaryInteger::TWO);

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));
    }
  }

  {
    EXPECT_TRUE(ilva.InverseExists());
    EXPECT_FALSE(ilva1.InverseExists());
  }

  {
    ILVector2n ilvS0(ilparams0);
    BigBinaryVector bbvS0(m/2, moduli[0]);
    bbvS0.SetValAtIndex(0, "23462");
    bbvS0.SetValAtIndex(1, "467986");
    bbvS0.SetValAtIndex(2, "33863");
    bbvS0.SetValAtIndex(3, "2113");
    ilvS0.SetValues(bbvS0, Format::EVALUATION);

    ILVector2n ilvS1(ilvS0);
    ilvS1.SwitchModulus(moduli[1], rootsOfUnity[1]);
    
    ILVector2n ilvS2(ilvS0);
    ilvS2.SwitchModulus(moduli[2], rootsOfUnity[2]);
      
    std::vector<ILVector2n> ilvector2nVectorS(towersize);
    ilvector2nVectorS[0] = ilvS0;
    ilvector2nVectorS[1] = ilvS1;
    ilvector2nVectorS[2] = ilvS2;

    ILVectorArray2n ilvaS(ilvector2nVectorS);
    BigBinaryInteger modulus2("113");
    BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity(m, modulus2));

    ilvaS.SwitchModulus(modulus2, rootOfUnity2);

    ILVector2n ilvectS0 = ilvaS.GetElementAtIndex(0);
    ILVector2n ilvectS1 = ilvaS.GetElementAtIndex(1);
    ILVector2n ilvectS2 = ilvaS.GetElementAtIndex(2);

    EXPECT_EQ(BigBinaryInteger("80"), ilvectS0.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("62"), ilvectS0.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("85"), ilvectS0.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS0.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS0.GetModulus());
    EXPECT_EQ(rootOfUnity2, ilvectS0.GetRootOfUnity());

    EXPECT_EQ(BigBinaryInteger("66"), ilvectS1.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("16"), ilvectS1.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("64"), ilvectS1.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS1.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS1.GetModulus());
    EXPECT_EQ(rootOfUnity2, ilvectS1.GetRootOfUnity());

    EXPECT_EQ(BigBinaryInteger("4"), ilvectS2.GetValAtIndex(0));
    EXPECT_EQ(BigBinaryInteger("44"), ilvectS2.GetValAtIndex(1));
    EXPECT_EQ(BigBinaryInteger("84"), ilvectS2.GetValAtIndex(2));
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS2.GetValAtIndex(3));
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS2.GetModulus());
    EXPECT_EQ(rootOfUnity2, ilvectS2.GetRootOfUnity());
  }

  {
    ILVectorArray2n ilvaCopy(ilva);
    BigBinaryInteger modulus2("113");
    BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity(m, modulus2));
    ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(0));
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(1));
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(2));
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3));

      if(i==0){
        EXPECT_EQ(modulus2, ilv.GetModulus());
        EXPECT_EQ(rootOfUnity2, ilv.GetRootOfUnity());
      }
    }
  }

}

TEST(UTILVectorArray2n, decompose_test) {
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

  shared_ptr<ILDCRTParams> params( new ILDCRTParams(order, moduli, rootsOfUnity) );
  ILVectorArray2n ilVectorArray2n(dgg, params, Format::COEFFICIENT);

  ILVectorArray2n ilvectorarray2nOriginal(ilVectorArray2n);
  ilVectorArray2n.Decompose();

  EXPECT_EQ(ilvectorarray2nOriginal.GetNumOfElements(), ilVectorArray2n.GetNumOfElements()) << "ILVectorArray2n_decompose: Mismatch in the number of towers after decompose.";

  for(usint i=0; i<ilVectorArray2n.GetNumOfElements(); i++) {
    ILVector2n ilTowerOriginal(ilvectorarray2nOriginal.GetElementAtIndex(i));
    ILVector2n ilTowerDecomposed(ilVectorArray2n.GetElementAtIndex(i));
    
    EXPECT_EQ(ilTowerDecomposed.GetLength(), ilTowerOriginal.GetLength()/2)  << "ILVectorArray2n_decompose: ilVector2n element in ilVectorArray2n is not half the length after decompose.";
    
    for(usint j=0; j<ilTowerDecomposed.GetLength(); j++) {
      EXPECT_EQ(ilTowerDecomposed.GetValAtIndex(j), ilTowerOriginal.GetValAtIndex(2*j)) << "ILVectorArray2n_decompose: Values do not match between original and decomposed elements.";
    }
  }

}

TEST(UTILVector2n, ensures_mod_operation_during_operations_on_two_ILVector2ns){

  usint order = 8; 
  usint nBits = 7;
  
  BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(order, nBits);
  BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(order, primeModulus);

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

TEST(UTILVectorArray2n, ensures_mod_operation_during_operations_on_two_ILVectorArray2ns){

  usint order = 16;
  usint nBits = 24;
  usint towersize = 3;

  std::vector<BigBinaryInteger> moduli(towersize);
  std::vector<BigBinaryInteger> rootsOfUnity(towersize);
  std::vector<shared_ptr<ILParams>> ilparams(towersize);

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
      
      shared_ptr<ILParams> ilparamsi( new ILParams(order, moduli[i], rootsOfUnity[i]) );
      ilparams.push_back(ilparamsi);

      DiscreteUniformGenerator distrUniGeni = lbcrypto::DiscreteUniformGenerator(moduli[i]);

      ILVector2n ilv1(distrUniGeni, ilparamsi);
      ilvector2n1[i] = ilv1;
      bbv1[i] = (ilv1.GetValues());

      ILVector2n ilv2(distrUniGeni, ilparamsi);
      ilvector2n2[i] = ilv2;
      bbv2[i] = (ilv2.GetValues());
  }

  shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(order, moduli, rootsOfUnity) );

  ILVectorArray2n ilvectorarray2n1(ilvector2n1);
  ILVectorArray2n ilvectorarray2n2(ilvector2n2);

  {
    ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 + ilvectorarray2n2;

    for(usint i=0; i<towersize; i++) {
      for(usint j=0; j<order/2; j++) {
        BigBinaryInteger actualResult(ilvectorarray2nResult.GetElementAtIndex(i).GetValAtIndex(j));
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) + bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n + operation returns incorrect results.";
      }
    }
    
  }

  {
    ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 * ilvectorarray2n2;

    for(usint i=0; i<towersize; i++) {
      for(usint j=0; j<order/2; j++) {
        BigBinaryInteger actualResult(ilvectorarray2nResult.GetElementAtIndex(i).GetValAtIndex(j));
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) * bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n * operation returns incorrect results.";
      }
    }

  }

}

void testILVectorArray2nConstructorNegative(std::vector<ILVector2n> &towers) {
	ILVectorArray2n expectException(towers);
}
