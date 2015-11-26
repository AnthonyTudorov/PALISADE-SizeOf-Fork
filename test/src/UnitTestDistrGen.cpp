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

#include "../include/gtest/gtest.h"
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
	DiscreteUniformGenerator dug = lbcrypto::DiscreteUniformGenerator();
	//dug.SetModulus(&modulus);
	BigBinaryInteger uniRandNum = dug.GenerateInteger(modulus);

	EXPECT_LT(uniRandNum, modulus);
}

// TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS

TEST(method_generate_uniform_big_binary_integer_large_modulus,with_in_large_modulus){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();
	BigBinaryInteger uniRandNum = distrUniGen.GenerateInteger(modulus);

	EXPECT_LT(uniRandNum, modulus);
}

//TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS

TEST(method_generate_uniform_big_binary_vector_small_modulus,vector_uniform){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 10;
	BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size,modulus);

	EXPECT_EQ(uniRandVector.GetLength(), size);

	for(int i=0; i<size; i++) {
		EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus);
	}
}

//TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS

TEST(method_generate_uniform_big_binary_vector_large_modulus,vector_uniform){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 100;
	BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size,modulus);

	EXPECT_EQ(uniRandVector.GetLength(), size);

	for(int i=0; i<size; i++) {
		EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus);
	}
}

TEST(method_generate_uniform_big_binary_vector_mean_big_modulus,vector_uniform){
	//999999999961, 999998869, 998443, 4294991873, 100019, 10403
	BigBinaryInteger modulus("100019");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size,modulus);

	BigBinaryInteger mean("0");
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));

	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		mean += randBigBinaryVector.GetValAtIndex(index);
	}
	BigBinaryInteger computedMean = mean.DividedBy(length);
	BigBinaryInteger expectedMean = modulus.DividedBy(BigBinaryInteger::TWO);
	
	BigBinaryInteger diff = (expectedMean>computedMean) ? (expectedMean.Minus(computedMean)) : (computedMean.Minus(expectedMean));

	//within 0.1% of expected mean
	BigBinaryInteger acceptableDiff("100");

	EXPECT_LT(diff, acceptableDiff);
}

TEST(method_generate_uniform_big_binary_vector_mean_small_modulus,vector_uniform){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size,modulus);

	BigBinaryInteger mean("0");
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));
	
	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		mean += randBigBinaryVector.GetValAtIndex(index);
	}

	BigBinaryInteger computedMean = mean.DividedBy(length);
	BigBinaryInteger expectedMean = modulus.DividedBy(BigBinaryInteger::TWO);
	BigBinaryInteger diff = (expectedMean>computedMean) ? (expectedMean.Minus(computedMean)) : (computedMean.Minus(expectedMean));
	
	//within 0.1% of expected mean
	BigBinaryInteger acceptableDiff("10");

	EXPECT_LT(diff, acceptableDiff);
}

TEST(method_generate_uniform_big_binary_vector_mean_smaller_modulus,vector_uniform){
	BigBinaryInteger modulus("7919");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size,modulus);

	BigBinaryInteger mean("0");
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));
	
	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		mean += randBigBinaryVector.GetValAtIndex(index);
	}

	BigBinaryInteger computedMean = mean.DividedBy(length);
	BigBinaryInteger expectedMean = modulus.DividedBy(BigBinaryInteger::TWO);
	BigBinaryInteger diff = (expectedMean>computedMean) ? (expectedMean.Minus(computedMean)) : (computedMean.Minus(expectedMean));
	
	//within 0.1% of expected mean
	BigBinaryInteger acceptableDiff("8");

	EXPECT_LE(diff, acceptableDiff);
}

TEST(method_generate_uniform_big_binary_vector_variance_smaller_modulus,vector_uniform){
	BigBinaryInteger modulus("7919"), twelve("12"), expectedVariance((modulus.Minus(BigBinaryInteger::ONE)*modulus.Minus(BigBinaryInteger::ONE)).DividedBy(twelve));

	BigBinaryInteger expectedMean = modulus.DividedBy(BigBinaryInteger::TWO);

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator();

	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size,modulus);

	BigBinaryInteger mean("0");
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));
	
	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		mean += randBigBinaryVector.GetValAtIndex(index);
	}

	BigBinaryInteger computedMean = mean.DividedBy(length);

	// std::cout << "The computedMean is " << computedMean << std::endl;
	// std::cout << "The expectedMean is " << expectedMean << std::endl;
	
	BigBinaryInteger varianceComputedUsingComputedMean("0"), varianceComputedUsingExpectedMean("0");
	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		BigBinaryInteger tempForComputedMean(randBigBinaryVector.GetValAtIndex(index)), tempForExpectedMean(randBigBinaryVector.GetValAtIndex(index));
		
		tempForComputedMean = (tempForComputedMean>computedMean) ? tempForComputedMean.Minus(computedMean) : computedMean.Minus(tempForComputedMean);
		varianceComputedUsingComputedMean += (tempForComputedMean * tempForComputedMean);

		tempForExpectedMean = (tempForExpectedMean>expectedMean) ? tempForExpectedMean.Minus(expectedMean) : expectedMean.Minus(tempForExpectedMean);
		varianceComputedUsingExpectedMean += (tempForExpectedMean * tempForExpectedMean);		
	}
	varianceComputedUsingComputedMean = varianceComputedUsingComputedMean.DividedBy(length);
	// std::cout << "The varianceComputedUsingComputedMean is " << varianceComputedUsingComputedMean << std::endl;
	EXPECT_GE(varianceComputedUsingComputedMean, BigBinaryInteger::ZERO);

	varianceComputedUsingExpectedMean = varianceComputedUsingExpectedMean.DividedBy(length);
	// std::cout << "The varianceComputedUsingExpectedMean is " << varianceComputedUsingExpectedMean << std::endl;
	EXPECT_GE(varianceComputedUsingExpectedMean, BigBinaryInteger::ZERO);

	// std::cout << "The expectedVariance is " << expectedVariance << std::endl;
}

TEST(method_generate_binary_uniform_big_binary_integer,greater_than_0)
{

	BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();

	BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();

	//EXPECT_LT(binUniRandNum.ConverToInt(), 2);

	//std::cout << "Running Test." << std::endl;
	EXPECT_GE(binUniRandNum.ConvertToInt(), 0)
	<< "Result is less than 0";
	//EXPECT_LE(binUniRandNum.ConvertToInt(), 1);
}

TEST(method_generate_binary_uniform_big_binary_integer,less_than_1) 
{

	BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();

	BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();

	//EXPECT_LT(binUniRandNum.ConverToInt(), 2);
	//EXPECT_GE(binUniRandNum.ConvertToInt(), 0);
	//std::cout << "Running Test." << std::endl;
	EXPECT_LE(binUniRandNum.ConvertToInt(), 1)
	<< "Result is greater than 1";
}

TEST(method_generate_binary_uniform_big_binary_integer,mean) 
{

	BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();

	usint length = 100000;
	BigBinaryVector randBigBinaryVector = binaryUniGen.GenerateVector(length);

	usint sum = 0;

	for(usint index=0; index<randBigBinaryVector.GetLength(); index++) {
		sum += randBigBinaryVector.GetValAtIndex(index).ConvertToInt();
	}
	//std::cout << "Observed sum is " << sum << std::endl;
	//std::cout << "Length is " << length << std::endl;
	float computedMean = (float)sum/(float)length;
	//std::cout << "The computedMean is " << computedMean << std::endl;
	float expectedMean = 0.5;
	float dif = abs(computedMean-expectedMean);
	//std::cout << "The difference is " << dif << std::endl;
	
	//std::cout << "Running Test." << std::endl;
	EXPECT_LT(dif,0.01)
	<< "Mean is incorrect";
}
// a large sample. Max of them should be less than q
