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

#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilelement.h"
#include "utils/utilities.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestTransform : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*---------------------------------------	TESTING METHODS OF TRANSFORM	  --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication){

	BigBinaryInteger primeModulus("113"); //65537
	usint cycloOrder = 8;
	usint n = cycloOrder / 2;

	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);

	BigBinaryVector a(4, primeModulus);
	a.SetValAtIndex(0, "1");
	a.SetValAtIndex(1, "2");
	a.SetValAtIndex(2, "4");
	a.SetValAtIndex(3, "1");
	BigBinaryVector b(a);

	BigBinaryVector A = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector B = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector AB = A*B;

	BigBinaryVector InverseFFTAB = ChineseRemainderTransformFTT::GetInstance().InverseTransform(AB, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector expectedResult(4, primeModulus);
	expectedResult.SetValAtIndex(0, "94");
	expectedResult.SetValAtIndex(1, "109");
	expectedResult.SetValAtIndex(2, "11");
	expectedResult.SetValAtIndex(3, "18");

	EXPECT_EQ(expectedResult, InverseFFTAB);

}
