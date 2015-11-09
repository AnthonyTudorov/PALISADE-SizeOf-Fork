/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	11/05/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
Description:
	This code exercises the math libraries of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <iostream>

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/ideals.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/il2n.h"
#include "../../src/utils/utilities.h"

using namespace std;
using namespace lbcrypto;

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/
class UnitTestDistrGen : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*
EXPECT_EQ (expected, actual) verifies expected == actual.
Compares two integer values
*/


/*---------------------------------------	TESTING METHODS OF NBTHEORY	  --------------------------------------------*/

// TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH SMALL MODULUS

TEST(method_generate_uniform_big_binary_integer_small_modulus,with_in_small_modulus){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator dug = lbcrypto::DiscreteUniformGenerator(modulus);
	BigBinaryInteger uniRandNum = dug.GenerateInteger();

	EXPECT_LT(uniRandNum, modulus);
}

// TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS

TEST(method_generate_uniform_big_binary_integer_large_modulus,with_in_large_modulus){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
	BigBinaryInteger uniRandNum = distrUniGen.GenerateInteger();

	EXPECT_LT(uniRandNum, modulus);
}

//TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS

TEST(method_generate_uniform_big_binary_vector_small_modulus,vector_uniform){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 10;
	BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size);

	EXPECT_EQ(uniRandVector.GetLength(), size);

	for(int i=0; i<size; i++) {
		EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus);
	}
}

//TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS

TEST(method_generate_uniform_big_binary_vector_large_modulus,vector_uniform){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 100;
	BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size);

	EXPECT_EQ(uniRandVector.GetLength(), size);

	for(int i=0; i<size; i++) {
		EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus);
	}
}

TEST(method_generate_uniform_big_binary_vector_mean,vector_uniform){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 10000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size);

	BigBinaryInteger mean("0");
	BigBinaryInteger length(randBigBinaryVector.GetLength());
	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		mean += randBigBinaryVector.GetValAtIndex(index);
	}
	BigBinaryInteger computedMean = mean.DividedBy(length);
	BigBinaryInteger expectedMean = modulus.DividedBy(BigBinaryInteger::TWO);
	BigBinaryInteger diff = (expectedMean>computedMean) ? (expectedMean.Minus(computedMean)) : (computedMean.Minus(expectedMean));

	BigBinaryInteger acceptableDiff("10");

	EXPECT_LT(diff, acceptableDiff);
}

TEST(method_generate_binary_uniform_big_binary_integer,equals){
	BinaryUniformGenerator bug = lbcrypto::BinaryUniformGenerator();
	BigBinaryInteger binUniRandNum = bug.GenerateInteger();

	EXPECT_LT(binUniRandNum, BigBinaryInteger("2"));
	EXPECT_GE(binUniRandNum, BigBinaryInteger("0"));
}

// a large sample. Max of them should be less than q
