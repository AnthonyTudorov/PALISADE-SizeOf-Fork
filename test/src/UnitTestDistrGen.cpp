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

TEST(method_generate_uniform_big_binary,with_in_small_modulus_integer_small_modulus){
	BigBinaryInteger modulus("10403");
	DiscreteUniformGenerator dug = lbcrypto::DiscreteUniformGenerator(modulus);
	BigBinaryInteger uniRandNum = dug.GenerateInteger();

	EXPECT_LT(uniRandNum, modulus);
}

// TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS

TEST(method_generate_uniform_big_binary,with_in_large_modulus_integer_large_modulus){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
	BigBinaryInteger uniRandNum = distrUniGen.GenerateInteger();

	EXPECT_LT(uniRandNum, modulus);
}

//TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS

TEST(method_generate_uniform_big_binary,vector_uniform_vector_small_modulus){
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

TEST(method_generate_uniform_big_binary,vector_uniform_vector_large_modulus){
	BigBinaryInteger modulus("10402635286389262637365363");
	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 100;
	BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size);

	EXPECT_EQ(uniRandVector.GetLength(), size);

	for(int i=0; i<size; i++) {
		EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus);
	}
}

TEST(method_generate_uniform_big_binary, first_moment_test_convertToDouble_small_modulus){
	BigBinaryInteger modulus("7919");

	double modulusInDouble = modulus.ConvertToDouble();
	double expectedMeanInDouble = modulusInDouble / 2.0;

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size);

	double sum = 0;
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));

	for(usint index=0; index<size; index++) {
		sum += (randBigBinaryVector.GetValAtIndex(index)).ConvertToDouble();
	}

	double computedMeanInDouble = sum/size;
	double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);

	//within 1% of expected mean
	EXPECT_LT(diffInMeans, 0.01*modulusInDouble);
}

TEST(method_generate_uniform_big_binary, second_moment_test_convertToDouble_small_modulus){
	BigBinaryInteger modulus("7919");

	double modulusInDouble = modulus.ConvertToDouble();
	double expectedMeanInDouble = modulusInDouble / 2.0;
	double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0;
	double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
	usint size = 500000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size);

	double sum=0, temp;
	for(usint index=0; index<size; index++) {
		temp = (randBigBinaryVector.GetValAtIndex(index)).ConvertToDouble() - expectedMeanInDouble;
		temp *= temp;
		sum += temp;
	}

	double computedVariance = (sum/size);
	double computedStdDev = sqrt(computedVariance);

	double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);

	//within 1% of expected std dev
	EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble);
}

TEST(method_generate_uniform_big_binary, first_moment_test_convertToDouble_big_modulus){
	//999999999961, 999998869, 998443, 4294991873, 100019, 10403
	BigBinaryInteger modulus("100019");

	double modulusInDouble = modulus.ConvertToDouble();
	double expectedMeanInDouble = modulusInDouble / 2.0;

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

	usint size = 50000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size);

	double sum=0;
	BigBinaryInteger length(std::to_string(randBigBinaryVector.GetLength()));

	for(usint index=0; index<size; index++) {
		sum += (randBigBinaryVector.GetValAtIndex(index)).ConvertToDouble();
	}

	double computedMeanInDouble = sum/size;
	double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);

	//within 1% of expected mean
	EXPECT_LT(diffInMeans, 0.01*modulusInDouble);
}

TEST(method_generate_uniform_big_binary, second_moment_test_convertToDouble_big_modulus){
	//999999999961, 999998869, 998443, 4294991873, 100019, 10403
	BigBinaryInteger modulus("100019");

	double modulusInDouble = modulus.ConvertToDouble();
	double expectedMeanInDouble = modulusInDouble / 2.0;
	double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0;
	double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
	usint size = 50000;
	BigBinaryVector randBigBinaryVector = distrUniGen.GenerateVector(size);

	double sum=0, temp;
	for(usint index=0; index<size; index++) {
		temp = (randBigBinaryVector.GetValAtIndex(index)).ConvertToDouble() - expectedMeanInDouble;
		temp *= temp;
		sum += temp;
	}

	double computedVariance = (sum/size);
	double computedStdDev = sqrt(computedVariance);

	double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);

	//within 1% of expected std dev
	EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble);
}

TEST(method_generate_binary_uniform_big_binary_integer,greater_than_0)
{
	BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
	BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();
	EXPECT_GE(binUniRandNum.ConvertToInt(), 0)
	<< "Result is less than 0";
}

TEST(method_generate_binary_uniform_big_binary_integer,less_than_1)
{
	BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
	BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();
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


TEST(method_test_guassian_rand_generator, generate_char_vector_mean_test) {
	sint stdev = 5;
	usint size = 10000;
  BigBinaryInteger modulus("10403");
	DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(modulus, stdev);
	schar* dggCharVector = dgg.GenerateCharVector(size);

	double mean = 0;
	for(usint i=0; i<size; i++) {
		mean += (double) dggCharVector[i];
		// std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
	}
	mean /= size;
	// std::cout << "The mean of the values is " << mean << std::endl;

	EXPECT_LE(mean, 0.1);
	EXPECT_GE(mean, -0.1);
}

TEST(method_test_guassian_rand_generator, generate_vector_mean_test) {
	sint stdev = 5;
	usint size = 100000;
	BigBinaryInteger modulus("10403");
	BigBinaryInteger modulusByTwo(modulus.DividedBy(BigBinaryInteger::TWO));
	DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(modulus, stdev);
	BigBinaryVector dggBigBinaryVector = dgg.GenerateVector(size);

	usint countOfZero = 0;
	double mean = 0, current = 0;

	for(usint i=0; i<size; i++) {
		current = std::stod(dggBigBinaryVector.GetValAtIndex(i).ToString());
		if(current == 0)
			countOfZero++;
		mean += current;
	}

	mean /= (size - countOfZero);
	// std::cout << "The mean of the values is " << mean << std::endl;

	double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

	double diff = abs(modulusByTwoInDouble - mean);
	EXPECT_LT(diff, 104);
}
