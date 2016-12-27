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
  Dr. David B. Cousins, dcousins@bbn.com

  Description: 
  This code exercises the random number distribution generator libraries
  of the PALISADE lattice encryption library.

  4/22/2016 DBC: modified to new UT format. Adding validity checks for parallelization code.

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

#include <omp.h>
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
//////////////////////////////////////////////////////////////////
// Testing Methods of BigBinaryInteger DiscreteUniformGenerator
//////////////////////////////////////////////////////////////////

// helper functions defined later
void testDiscreteUniformGenerator(BigBinaryInteger &modulus, std::string test_name);
void testParallelDiscreteUniformGenerator(BigBinaryInteger &modulus, std::string test_name);


TEST(UTDistrGen, DiscreteUniformGenerator_LONG ) {

  // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH SMALL MODULUS
  {
    BigBinaryInteger modulus("10403");
    DiscreteUniformGenerator dug = lbcrypto::DiscreteUniformGenerator(modulus);
    BigBinaryInteger uniRandNum = dug.GenerateInteger();

    EXPECT_LT(uniRandNum, modulus) << "Failure testing with_in_small_modulus_integer_small_modulus";
  }

  // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS
  {
    BigBinaryInteger modulus("10402635286389262637365363");
    DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
    BigBinaryInteger uniRandNum = distrUniGen.GenerateInteger();

    EXPECT_LT(uniRandNum, modulus) << "Failure testing with_in_large_modulus_integer_large_modulus";
  }

  //TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS
  {
    BigBinaryInteger modulus("10403");
    DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
    
    usint size = 10;
    BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size);
    // test length
    EXPECT_EQ(uniRandVector.GetLength(), size) << "Failure testing vector_uniform_vector_small_modulus wrong length";
    // test content
    for(int i=0; i<size; i++) {
      EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus)
	<< "Failure testing vector_uniform_vector_small_modulus value greater than modulus at index "<< i;
    }
  }
  
  //TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS
  
  {
    BigBinaryInteger modulus("10402635286389262637365363");
    DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

    usint size = 100;
    BigBinaryVector uniRandVector = distrUniGen.GenerateVector(size);
    // test length
    EXPECT_EQ(uniRandVector.GetLength(), size) << "Failure testing vector_uniform_vector_large_modulus";
    // test content
    for(int i=0; i<size; i++) {
      EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus) 
	<< "Failure testing vector_uniform_vector_large_modulus value greater than modulus at index "<< i;
    }
  }

  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS SMALL MODULUS
    BigBinaryInteger small_modulus("7919");
    testDiscreteUniformGenerator(small_modulus, "small_modulus");
  }
  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS LARGE MODULUS
    BigBinaryInteger large_modulus("100019");
    testDiscreteUniformGenerator(large_modulus, "large_modulus");
  }
  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS HUGE MODULUS
    BigBinaryInteger huge_modulus("10402635286389262637365363");
    testDiscreteUniformGenerator(huge_modulus, "huge_modulus");
  }

  //TEST CASE TO RECREATE OVERFLOW ISSUE CAUSED WHEN CALCULATING MEAN OF BBI's
  //Issue#73
  {
    int caught_error = 0;
    try {
      BigBinaryInteger modulus("10402635286389262637365363"); //10402635286389262637365363
      DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);

      usint eachIterationSize = 1000, noOfIterations = 100;
      BigBinaryInteger sum, mean, N(eachIterationSize);
	
      BigBinaryVector uniRandVector = distrUniGen.GenerateVector(eachIterationSize * noOfIterations);
	
      for(usint i=0; i<noOfIterations; i++) {
	sum = BigBinaryInteger::ZERO;
	mean = BigBinaryInteger::ZERO;
	for(int j=i*eachIterationSize; j<(i+1)*eachIterationSize; j++) {
	  sum += uniRandVector.GetValAtIndex(j);
	}
	mean = sum.DividedBy(N);
      }
    }
    catch (...) {
      caught_error = 1;
    }
    EXPECT_EQ(caught_error, 0)<< "Failure recreate_overflow_issue threw an error";
  } 
} //end TEST(UTDistrGen, DiscreteUniformGenerator)

//
// helper function to test first and second central moment of discrete uniform generator
// single thread case
void testDiscreteUniformGenerator(BigBinaryInteger &modulus, std::string test_name){
  // TEST CASE ON FIRST CENTRAL MOMENT

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
    EXPECT_LT(diffInMeans, 0.01*modulusInDouble) << 
      "Failure testing first_moment_test_convertToDouble " << test_name;


    // TEST CASE ON SECOND CENTRAL MOMENT
    double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0;
    double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);

    sum=0;
    double temp;
    for(usint index=0; index<size; index++) {
      temp = (randBigBinaryVector.GetValAtIndex(index)).ConvertToDouble() - expectedMeanInDouble;
      temp *= temp;
      sum += temp;
    }

    double computedVariance = (sum/size);
    double computedStdDev = sqrt(computedVariance);
    double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);

    EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble) << 
      "Failure testing second_moment_test_convertToDouble "<< test_name;
}


TEST(UTDistrGen, ParallelDiscreteUniformGenerator_LONG ) {

  //BUILD SEVERAL VECTORS OF BBI IN PARALLEL, CONCATENATE THEM TO ONE LARGE VECTOR AND TEST
  //THE RESULT OF THE FIRST AND SECOND CENTRAL MOMENTS

  BigBinaryInteger small_modulus("7919"); // test small modulus
  testParallelDiscreteUniformGenerator(small_modulus, "small_modulus");

  BigBinaryInteger large_modulus("100019");// test large modulus
  testParallelDiscreteUniformGenerator(large_modulus, "large_modulus");

  BigBinaryInteger huge_modulus("10402635286389262637365363");
  testParallelDiscreteUniformGenerator(huge_modulus, "huge_modulus");

}

//
// helper function to test first and second central moment of discrete uniform generator
// multi thread case
void testParallelDiscreteUniformGenerator(BigBinaryInteger &modulus, std::string test_name){
  double modulusInDouble = modulus.ConvertToDouble();
  // we expect the mean to be modulus/2 (the mid range of the min-max data);
  double expectedMeanInDouble = modulusInDouble / 2.0;
  usint size = 500000;
  //usint size = omp_get_max_threads() * 4;

  bool dbg_flag = false;
  vector <BigBinaryInteger> randBigBinaryVector;
#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <BigBinaryInteger> randBigBinaryVectorPvt;
    DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus);
    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      randBigBinaryVectorPvt.push_back(distrUniGen.GenerateInteger());
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
    	{
      DEBUG("thread #" << omp_get_thread_num() << " moving "
	    << (int)randBigBinaryVectorPvt.size()  << " to starting point "
	    << (int)randBigBinaryVector.size() );
      randBigBinaryVector.insert(randBigBinaryVector.end(), randBigBinaryVectorPvt.begin(), randBigBinaryVectorPvt.end());
      DEBUG("thread #" << omp_get_thread_num() << " moved");
    	}
    }

  }

  // now compute the sum over the entire vector
  double sum = 0;
  BigBinaryInteger length(std::to_string(randBigBinaryVector.size()));
  
  for(usint index=0; index<size; index++) {
    sum += (randBigBinaryVector[index]).ConvertToDouble();
  }
  // divide by the size (i.e. take mean)
  double computedMeanInDouble = sum/size;
  // compute the difference between the expected and actual
  double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);
  
  //within 1% of expected mean
  EXPECT_LT(diffInMeans, 0.01*modulusInDouble) << "Failure testing parallel_first_central_moment_test " << test_name;
  
  // TEST CASE ON SECOND CENTRAL MOMENT SMALL MODULUS
  double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0; // var = ((b-a)^2) /12
  double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);
  
  sum=0;
  double temp;
  for(usint index=0; index<size; index++) {
    temp = (randBigBinaryVector[index]).ConvertToDouble() - expectedMeanInDouble;
    temp *= temp;
    sum += temp;
  }
  
  double computedVariance = (sum/size);
  double computedStdDev = sqrt(computedVariance);
  
  double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);
  
  //within 1% of expected std dev
  EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble) << "Failure testing second_central_moment_test " << test_name;
}

// TEST(UTDistrGen, DiscreteUniformGeneratorSeed ) {
//   BigBinaryInteger modulus("7919"); // test small modulus
//   double sum1=0;
//   usint size = 10;
//   {
//     DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus, 12345);
  
//     BigBinaryVector randBigBinaryVector1 = distrUniGen.GenerateVector(size);
  
  
//     for(usint index=0; index<size; index++) {
//       sum1 += (randBigBinaryVector1.GetValAtIndex(index)).ConvertToDouble();
//     }
//   }
//   DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus, 12345);
//   BigBinaryVector randBigBinaryVector2 = distrUniGen.GenerateVector(size);
//   double sum2=0;

//   for(usint index=0; index<size; index++) {
//     sum2 += (randBigBinaryVector2.GetValAtIndex(index)).ConvertToDouble();
//   }
  
//   EXPECT_EQ(sum1, sum2) << "Failure, summs are different";
  
// }


////////////////////////////////////////////////
// Testing Methods of BigBinaryInteger BinaryUniformGenerator
////////////////////////////////////////////////


 TEST(UTDistrGen, BinaryUniformGenerator ) {


  // fail if less than 0
  {
    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
    BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();
    EXPECT_GE(binUniRandNum.ConvertToInt(), 0)
      << "Failure less than 0";
  }

  // fail if gt 1
  {
    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
    BigBinaryInteger binUniRandNum = binaryUniGen.GenerateInteger();
    EXPECT_LE(binUniRandNum.ConvertToInt(), 1)
      << "Failure greater than 1";
  }

  // mean test
  {

    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();

    usint length = 100000;
    BigBinaryInteger modulus = BigBinaryInteger("1041");
    BigBinaryVector randBigBinaryVector = binaryUniGen.GenerateVector(length, modulus);

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
      << "Failure Mean is incorrect";
    // a large sample. Max of them should be less than q

  }
} // end TEST(

 // mean test
 TEST(UTDistrGen, TernaryUniformGenerator) {
	 
	 TernaryUniformGenerator ternaryUniGen = lbcrypto::TernaryUniformGenerator();

	 usint length = 100000;
	 BigBinaryInteger modulus = BigBinaryInteger("1041");
	 BigBinaryVector randBigBinaryVector = ternaryUniGen.GenerateVector(length, modulus);

	 int32_t sum = 0;

	 for (usint index = 0; index<randBigBinaryVector.GetLength(); index++) {
		 if (randBigBinaryVector[index] == modulus - BigBinaryInteger::ONE)
			 sum -= 1;
		 else
			 sum += randBigBinaryVector[index].ConvertToInt();
	 }

	 float computedMean = (double)sum / (double)length;

	 float expectedMean = 0;
	 float dif = abs(computedMean - expectedMean);

	 //std::cout << "Running Test." << std::endl;
	 EXPECT_LT(dif, 0.01)
		 << "Ternary Uniform Distribution Failure Mean is incorrect";
	 // a large sample. Max of them should be less than q

 }


////////////////////////////////////////////////
// Testing Methods of BigBinaryInteger DiscreteGaussianGenerator
////////////////////////////////////////////////


TEST(UTDistrGen, DiscreteGaussianGenerator) {
  //mean test

  {
    std::cout<<"note this sometimes fails. are limits set correctly?"<<std::endl;
    sint stdev = 5;
    usint size = 10000;
    BigBinaryInteger modulus("10403");
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    sint* dggCharVector = dgg.GenerateIntVector(size);

    double mean = 0;
    for(usint i=0; i<size; i++) {
      mean += (double) dggCharVector[i];
      // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
    }
    mean /= size;
    // std::cout << "The mean of the values is " << mean << std::endl;

    EXPECT_LE(mean, 0.1) << "Failure generate_char_vector_mean_test mean > 0.1";
    EXPECT_GE(mean, -0.1) << "Failure generate_char_vector_mean_test mean < -0.1";;
  }

  // generate_vector_mean_test
  {
    sint stdev = 5;
    usint size = 100000;
    BigBinaryInteger modulus("10403");
    BigBinaryInteger modulusByTwo(modulus.DividedBy(BigBinaryInteger::TWO));
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    BigBinaryVector dggBigBinaryVector = dgg.GenerateVector(size,modulus);

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
    EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";
  }

}


TEST(UTDistrGen, ParallelDiscreteGaussianGenerator) {
  //mean test
  bool dbg_flag = false;

  {
    sint stdev = 5;
    usint size = 10000;
    BigBinaryInteger modulus("10403");


    vector<sint>dggCharVector;
    //    sint* dggCharVector = dgg.GenerateIntVector(size);

#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <sint> dggCharVectorPvt;
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      dggCharVectorPvt.push_back(dgg.GenerateInt());
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
    	{
      DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
	    << (int)dggCharVectorPvt.size()  << " to starting point" 
	    << (int)dggCharVector.size() );
      dggCharVector.insert(dggCharVector.end(), dggCharVectorPvt.begin(), dggCharVectorPvt.end());
    	}
    }

  }

  double mean = 0;
  for(usint i=0; i<size; i++) {
    mean += (double) dggCharVector[i];
    // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
  }
    mean /= size;
    // std::cout << "The mean of the values is " << mean << std::endl;
    
    EXPECT_LE(mean, 0.1) << "Failure parallel generate_char_vector_mean_test mean > 0.1";
    EXPECT_GE(mean, -0.1) << "Failure parallel generate_char_vector_mean_test mean < -0.1";;
  }

  // generate_vector_mean_test
  {
    sint stdev = 5;
    usint size = 100000;
    BigBinaryInteger modulus("10403");
    BigBinaryInteger modulusByTwo(modulus.DividedBy(BigBinaryInteger::TWO));
    //BigBinaryVector dggBigBinaryVector = dgg.GenerateVector(size,modulus);
    vector<BigBinaryInteger> dggBigBinaryVector;
#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <BigBinaryInteger> dggBigBinaryVectorPvt;
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      dggBigBinaryVectorPvt.push_back(dgg.GenerateInteger(modulus));
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
      DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
	    << (int)dggBigBinaryVectorPvt.size()  << " to starting point" 
	    << (int)dggBigBinaryVector.size() );
      dggBigBinaryVector.insert(dggBigBinaryVector.end(), dggBigBinaryVectorPvt.begin(), dggBigBinaryVectorPvt.end());
    }
  }

    usint countOfZero = 0;
    double mean = 0, current = 0;

    for(usint i=0; i<size; i++) {
      current = std::stod(dggBigBinaryVector[i].ToString());
      if(current == 0)
	countOfZero++;
      mean += current;
    }

    mean /= (size - countOfZero);
    // std::cout << "The mean of the values is " << mean << std::endl;

    double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

    double diff = abs(modulusByTwoInDouble - mean);
    EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";
  }

}
