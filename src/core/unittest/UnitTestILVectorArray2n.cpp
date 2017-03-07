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
    Dr. David Bruce Cousins BBN
Description:

  This code tests the transform feature of the PALISADE lattice
  encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
#include "lattice/ilvectorarray2n.h"

using namespace std;
using namespace lbcrypto;

class UnitTestILVectorArray2n : public ::testing::Test {
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

//forward declaration of helper function
void testILVectorArray2nConstructorNegative(std::vector<ILVector2n> &towers);

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
    
  std::vector<ILVector2n> ilvector2nVector;
  ilvector2nVector.push_back(ilv0);
  ilvector2nVector.push_back(ilv1);
  ilvector2nVector.push_back(ilv2);

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
    ILVectorArray2n ilvaClone(ilva.CloneParametersOnly());

    std::vector<ILVector2n> towersInClone = ilvaClone.GetAllElements();
    

    EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
    EXPECT_EQ(modulus, ilva.GetModulus());
    EXPECT_EQ(m, ilva.GetCyclotomicOrder());
  }

}

void testILVectorArray2nConstructorNegative(std::vector<ILVector2n> &towers);

/*--------------------------------------- TESTING METHODS OF LATTICE ELEMENTS    --------------------------------------------*/

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
  bool dbg_flag = true;
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
      
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0))<<"Failure: Plus()";
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1))<<"Failure: Plus()";
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(2))<<"Failure: Plus()";
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3))<<"Failure: Plus()";
    }
  }
  {
    ILVectorArray2n ilvaCopy(ilva);
    ilvaCopy += ilva1;

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

       EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0))<<"Failure: +=";
       EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1))<<"Failure: +=";
       EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(2))<<"Failure: +=";
       EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3))<<"Failure: +=";
    }
  }
  {
    ILVectorArray2n ilvaCopy(ilva.Minus(ilva1));

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0))<<"Failure: Minus";
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(1))<<"Failure: Minus";
      EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(2))<<"Failure: Minus";
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3))<<"Failure: Minus";
    }
  }
  {
    ILVectorArray2n ilvaResult(ilva);
    ilvaResult -= ilva1;

    for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

       EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(0))<<"Failure: -=";
       EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(1))<<"Failure: -=";
       EXPECT_EQ(BigBinaryInteger::ONE, ilv.GetValAtIndex(2))<<"Failure: -=";
       EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3))<<"Failure: -=";
    }
  }
  {
    ILVectorArray2n ilvaResult(ilva.Times(ilva1));

    for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(0))<<"Failure: Times";
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(1))<<"Failure: Times";
      EXPECT_EQ(BigBinaryInteger("6"), ilv.GetValAtIndex(2))<<"Failure: Times";
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3))<<"Failure: Times";
    }
  }

  {
    ILVectorArray2n ilvaCopy(ilva);
    ilvaCopy.AddILElementOne();

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(0))
<<"Failure: AddILElementOne";
      EXPECT_EQ(BigBinaryInteger("5"), ilv.GetValAtIndex(1))
<<"Failure: AddILElementOne";
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(2))
<<"Failure: AddILElementOne";
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(3))
<<"Failure: AddILElementOne";
    }
  }
  {
    ILVectorArray2n ilvaInv(ilva.MultiplicativeInverse());

    ILVector2n ilvectInv0 = ilvaInv.GetElementAtIndex(0);
    ILVector2n ilvectInv1 = ilvaInv.GetElementAtIndex(1);
    ILVector2n ilvectInv2 = ilvaInv.GetElementAtIndex(2);

    EXPECT_EQ(BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(0))
      <<"Failure: ilvectInv0 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("6265"), ilvectInv0.GetValAtIndex(1))
      <<"Failure: ilvectInv0 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("5569"), ilvectInv0.GetValAtIndex(2))
      <<"Failure: ilvectInv0 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(3))
      <<"Failure: ilvectInv0 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("8353"), ilvectInv0.GetModulus())
      <<"Failure: ilvectInv0 MultiplicativeInverse() modulus";
    EXPECT_EQ(BigBinaryInteger("8163"), ilvectInv0.GetRootOfUnity())
      <<"Failure: ilvectInv0 MultiplicativeInverse() rootOfUnity";

    EXPECT_EQ(BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(0))
      <<"Failure: ilvectInv1 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("6277"), ilvectInv1.GetValAtIndex(1))
      <<"Failure: ilvectInv1 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("2790"), ilvectInv1.GetValAtIndex(2))
      <<"Failure: ilvectInv1 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(3))
      <<"Failure: ilvectInv1 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("8369"), ilvectInv1.GetModulus())
      <<"Failure: ilvectInv1 MultiplicativeInverse() modulus";
    EXPECT_EQ(BigBinaryInteger("6677"), ilvectInv1.GetRootOfUnity())
      <<"Failure: ilvectInv1 MultiplicativeInverse() rootOfUnity";

    EXPECT_EQ(BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(0))
      <<"Failure: ilvectInv2 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("6385"), ilvectInv2.GetValAtIndex(1))
      <<"Failure: ilvectInv2 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("2838"), ilvectInv2.GetValAtIndex(2))
      <<"Failure: ilvectInv2 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(3))
      <<"Failure: ilvectInv2 MultiplicativeInverse()";
    EXPECT_EQ(BigBinaryInteger("8513"), ilvectInv2.GetModulus())
      <<"Failure: ilvectInv2 MultiplicativeInverse() modulus";
    EXPECT_EQ(BigBinaryInteger("156"), ilvectInv2.GetRootOfUnity())
      <<"Failure: ilvectInv2 MultiplicativeInverse() rootOfUnity";

    EXPECT_THROW(ilva1.MultiplicativeInverse(), std::logic_error)
      <<"Failure: throw MultiplicativeInverse()";
  }

  {
    ILVectorArray2n ilvaCopy(ilva);

    ilvaCopy.MakeSparse(BigBinaryInteger::TWO);

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(1))
	<<"Failure MakeSparse() index 1";
      EXPECT_EQ(BigBinaryInteger::ZERO, ilv.GetValAtIndex(3))
	<<"Failure MakeSparse() index 3";
    }
  }

  {
    EXPECT_TRUE(ilva.InverseExists())<<"Failure: ilva.InverseExists()";
    EXPECT_FALSE(ilva1.InverseExists())<<"Failure: ilva1.InverseExists()";
  }

  {
    ILVector2n ilvS0(ilparams0);
    //DEBUG("ilvS0.GetModulus():"<<ilvS0.GetModulus());

    BigBinaryVector bbvS0(m/2, moduli[0]);
    //DEBUG("bbvS0 Modulus:"<<moduli[0]);

    bbvS0.SetValAtIndexWithoutMod(0, "23462");
    bbvS0.SetValAtIndexWithoutMod(1, "467986");
    bbvS0.SetValAtIndexWithoutMod(2, "33863");
    bbvS0.SetValAtIndexWithoutMod(3, "2113");

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

    EXPECT_EQ(BigBinaryInteger("80"), ilvectS0.GetValAtIndex(0))
      <<"Failure S0 SwitchModulus i=0";
    EXPECT_EQ(BigBinaryInteger("62"), ilvectS0.GetValAtIndex(1))
      <<"Failure S0 SwitchModulus i=1";
    EXPECT_EQ(BigBinaryInteger("85"), ilvectS0.GetValAtIndex(2))
      <<"Failure S0 SwitchModulus i=2";
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS0.GetValAtIndex(3))
      <<"Failure S0 SwitchModulus i=3";
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS0.GetModulus())
      <<"Failure S0 SwitchModulus modulus";
    EXPECT_EQ(rootOfUnity2, ilvectS0.GetRootOfUnity())
      <<"Failure S0 rootOfUnity";

    EXPECT_EQ(BigBinaryInteger("66"), ilvectS1.GetValAtIndex(0))
      <<"Failure S1 SwitchModulus i=0";
    EXPECT_EQ(BigBinaryInteger("16"), ilvectS1.GetValAtIndex(1))
      <<"Failure S1 SwitchModulus i=1";
    EXPECT_EQ(BigBinaryInteger("64"), ilvectS1.GetValAtIndex(2))
      <<"Failure S1 SwitchModulus i=2";
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS1.GetValAtIndex(3))
      <<"Failure S1 SwitchModulus i=3";
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS1.GetModulus())
      <<"Failure S1 SwitchModulus modulus";
    EXPECT_EQ(rootOfUnity2, ilvectS1.GetRootOfUnity())
      <<"Failure S1 rootOfUnity2";

    EXPECT_EQ(BigBinaryInteger("4"), ilvectS2.GetValAtIndex(0))
      <<"Failure S2 SwitchModulus i=0";
    EXPECT_EQ(BigBinaryInteger("44"), ilvectS2.GetValAtIndex(1))
      <<"Failure S2 SwitchModulus i=1";
    EXPECT_EQ(BigBinaryInteger("84"), ilvectS2.GetValAtIndex(2))
      <<"Failure S2 SwitchModulus i=2";
    EXPECT_EQ(BigBinaryInteger("79"), ilvectS2.GetValAtIndex(3))
      <<"Failure S2 SwitchModulus i=3";
    EXPECT_EQ(BigBinaryInteger("113"), ilvectS2.GetModulus())
      <<"Failure S2 SwitchModulus modulus";
    EXPECT_EQ(rootOfUnity2, ilvectS2.GetRootOfUnity())
      <<"Failure S2 rootOfUnity";
  }
  {
    ILVectorArray2n ilvaCopy(ilva);
    BigBinaryInteger modulus2("113");
    BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity(m, modulus2));
    ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

    for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
    {
      ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(0))
	<<"Failure: SwitchModulusAtIndex";
      EXPECT_EQ(BigBinaryInteger("4"), ilv.GetValAtIndex(1))
	<<"Failure: SwitchModulusAtIndex";
      EXPECT_EQ(BigBinaryInteger("3"), ilv.GetValAtIndex(2))
	<<"Failure: SwitchModulusAtIndex";
      EXPECT_EQ(BigBinaryInteger::TWO, ilv.GetValAtIndex(3))
	<<"Failure: SwitchModulusAtIndex";

      if(i==0){
        EXPECT_EQ(modulus2, ilv.GetModulus())
	<<"Failure: SwitchModulusAtIndex modulus";
        EXPECT_EQ(rootOfUnity2, ilv.GetRootOfUnity())
	<<"Failure: SwitchModulusAtIndex rootOfUnity";
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
	//mubint::init(moduli[i]); this gets it to work
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) + bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n + operation returns incorrect results. i "<< i << " j "<<j;
      }
    }
    
  }

  {
    ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 * ilvectorarray2n2;

    for(usint i=0; i<towersize; i++) {
      for(usint j=0; j<order/2; j++) {
        BigBinaryInteger actualResult(ilvectorarray2nResult.GetElementAtIndex(i).GetValAtIndex(j));
	//mubint::init(moduli[i]);
        BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) * bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
        EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n * operation returns incorrect results. i "<< i << " j "<<j;
      }
    }

  }

}

void testILVectorArray2nConstructorNegative(std::vector<ILVector2n> &towers) {
	ILVectorArray2n expectException(towers);
}
