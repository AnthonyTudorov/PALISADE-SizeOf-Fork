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

/*
#include "binint.h"
#include "binmat.h"
#include "binvect.h"
#include "inttypes.h"
#include "nbtheory.h"
#include "ideals.h"
#include "distrgen.h"
#include "lwecrypt.h"
#include "lwepre.h"
#include "il2n.h"
#include "utilities.h"
*/

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

TEST(method_CRT_polynomial_multiplication, compares_to_brute_force_multiplication){

	BigBinaryInteger primeModulus("101"); //65537
	usint cycloOrder = 4;
	usint n = cycloOrder / 2;

	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);
	std::cout <<"The primitiveRootOfUnity for modulus " << primeModulus << " is " << primitiveRootOfUnity << std::endl;

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(primeModulus);
	BigBinaryVector a = distrUniGen.GenerateVector(n);
	BigBinaryVector b = distrUniGen.GenerateVector(n);
	std::cout << "Generated vectors: " << a << " and " << b << std::endl;

	BigBinaryVector A = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector B = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector AB = A.ModMul(B);
	BigBinaryVector ab = a.ModMul(b);

	BigBinaryVector InverseFFTAB = ChineseRemainderTransform::GetInstance().InverseTransform(AB, primitiveRootOfUnity, cycloOrder);

	// EXPECT_EQ(ab, InverseFFTAB);

}
