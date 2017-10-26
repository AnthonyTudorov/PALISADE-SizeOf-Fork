/**
 * @file discretegaussiangenerator.h This code provides generation of gaussian distibutions of discrete values.
 * Discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*Seperate base sampler from generic
 * Look at Michael's code
 * Base samplers should containt one single probability table
 * Handle seperate cosets as seperate sampler pointers in sampling
 * Replace NTL with Bernoulli distribution
 * */

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_

#define MAX_SMP 4

#include <math.h>
#include <random>
#include <memory>

#include "backend.h"
#include "distributiongenerator.h"

namespace lbcrypto {

enum BaseSamplerType {KNUTH_YAO = 0, PEIKERT = 1};

class DiscreteGaussianGeneratorGeneric;
class BaseSampler;
class SamplerCombiner;
class BitGenerator;

class BitGenerator{
public:
	BitGenerator(){}
	short Generate(){
		if (counter % 31 == 0) {
			sequence = (PseudoRandomNumberGenerator::GetPRNG())();
			sequence = sequence << 1;
			counter = 0;
		}
		short bit = (sequence >> (32 - counter)) & 1;
		counter++;
		return bit;
	}
	~BitGenerator(){}
private:
	uint32_t sequence = 0;
	char counter = 0;
};

class BaseSampler{
public:
	BaseSampler(double mean,double std,BitGenerator* generator,BaseSamplerType bType);
	BaseSampler(){};
	virtual int64_t GenerateInteger();
	virtual ~BaseSampler(){
		if (DDGColumn != nullptr) {
			delete[] DDGColumn;
		}
	}
	short RandomBit(){
		return bg->Generate();
	}
private:
	// all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
	double b_a;

	/**
	 *Mean of the distribution used
	 */
	double b_mean;

	/**
	 * The standard deviation of the distribution.
	 */
	float b_std;

	/**
		 * Generator used for creating random bits through sampling
		 */
	BitGenerator* bg;
	/**
	 * Type of the base sampler (Knuth Yao or Peikert's Inversion)
	 */
	BaseSamplerType b_type;



	/**
	 *The probability matrix used in Knuth-Yao sampling
	 */
	std::vector<uint64_t> probMatrix;

	std::vector<std::vector<short>> DDGTree;

	short *DDGColumn = nullptr;

	/**
	 *Array that stores the Hamming Weights of the probability matrix used in Knuth-Yao sampling
	 */
	std::vector<uint32_t> hammingWeights;
	/**
	 *Size of probability matrix used in Knuth-Yao
	 */
	int32_t b_matrixSize;



	/**
	 *Index of first bit with non zero Hamming weight in the probability table
	 */
	int32_t firstNonZero;


	std::vector<double> m_vals;
	usint FindInVector(const std::vector<double> &S, double search) const;
	/**
	 * @brief Generates DDG tree used through the sampling in Knuth-Yao
	 */
	void GenerateDDGTree();
	/**
	 * @brief Initializes the generator used for Peikert's Inversion method.
	 * @param mean Mean of the distribution that the sampler will be using
	 *
	 */
	void Initialize(double mean);

	/**
	 * @brief Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	 * @param sttdev standard deviation of Discrete Gaussian Distribution
	 * @param mean Center of the distribution
	 * @param tableCount Number of probability tables to be generated
	 */
	void GenerateProbMatrix(double stddev, double mean);
	/**
	 * @ brief Returns a generated integer. Uses Naive Knuth-Yao method
	 * @ return A random value within the Discrete Gaussian Distribution
	 */
	int64_t GenerateIntegerKnuthYaoAlt();
	/**
	 * @ brief Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	 * @ return A random value within the Discrete Gaussian Distribution
	 */
	int64_t GenerateIntegerKnuthYao();
	/**
	 * @brief Returns a generated integer. Uses Peikert's inversion method.
	 */
	int64_t GenerateIntegerPeikert() const;

};
class SamplerCombiner: public BaseSampler{
public:
	SamplerCombiner(BaseSampler* s1,BaseSampler* s2,int64_t z1,int64_t z2):sampler1(s1),sampler2(s1),x1(z1),x2(z2){}
	int64_t GenerateInteger(){
		return x1*sampler1->GenerateInteger() + x2*sampler2->GenerateInteger();
	}
	~SamplerCombiner(){}
private:
	BaseSampler *sampler1, *sampler2;
	int64_t x1,x2;

};

/**
 * @brief The class for Generic Discrete Gaussion Distribution generator.
 */
class DiscreteGaussianGeneratorGeneric: public DistributionGenerator<BigInteger,BigVector>{
public:
	/**
	 * @brief Basic constructor which does the precomputations.
	 */
	DiscreteGaussianGeneratorGeneric(BaseSampler** samplers, const double std,const int b, const int max_slevels, const int precision, const int flips);

	/**
	 * @ brief Returns a generated integer. Uses generic algorithm in UCSD paper, based on Sample Z
	 * @ param mean Mean of the distribution
	 * @ param variance Variance of the desired distribution
	 * @ return A random value within the Discrete Gaussian Distribution
	 */
	int64_t GenerateInteger(double mean, double std);
	int64_t GenerateInteger(){
		return base_samplers[0]->GenerateInteger();
	}
	~DiscreteGaussianGeneratorGeneric();
private:
	 int64_t flipAndRound(double center);
	 int64_t SampleC(int64_t center);

	    BaseSampler* wide_sampler;
	    BaseSampler** base_samplers;
	    BaseSampler* combiners[MAX_SMP];
	    long double wide_sigma2, rr_sigma2, sigma2_0;
	    double x, c, ci;
	    int k, flips, max_slevels, log_base;
	    uint64_t mask;
	 /**
	  * @ brief Method to return the nth bit of a number
	  * @ param number The number that the bit of desired
	  * @ param n Desired bit number
	  * @ return The nth bit of the number starting from 0 being the LSB
	  */
	 short extractBit(int64_t number,int n){
		 return (number>>n) & 1;
	 }

};

}  // namespace lbcrypto
#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
