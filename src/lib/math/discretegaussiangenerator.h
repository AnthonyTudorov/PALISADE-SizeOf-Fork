/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
* @section DESCRIPTION
* This code provides generation of discrete gaussian distributions.
*/

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_

#define _USE_MATH_DEFINES // added for Visual Studio support

#include <math.h>
#include <random>

#include "backend.h"
#include "distributiongenerator.h"
#include "largefloat.h"

namespace lbcrypto {

/**
* @brief The class for Discrete Gaussion Distribution generator.
*/
class DiscreteGaussianGenerator : DistributionGenerator {

public:
	/**
	* Default constructor.
	*/
	DiscreteGaussianGenerator();

	/**
	* @brief         Basic constructor for specifying distribution parameter and modulus.
	* @param modulus The modulus to use to generate discrete values.
	* @param std     The standard deviation for this Gaussian Distribution.
	*/
	DiscreteGaussianGenerator (const sint std);

	/**
	* @brief Initializes the generator.
	*/
	void Initialize ();

	/**
	* @brief  Returns the standard deviation of the generator.
	* @return The analytically obtained standard deviation of the generator.
	*/
	sint GetStd () const;

	/**
	* @brief     Sets the standard deviation of the generator.
	* @param std The analytic standard deviation of the generator.
	*/
	void SetStd (const sint std);

	//BigBinaryVector DiscreteGaussianGenerator::GenerateIdentity(usint size, const BigBinaryInteger &modulus);

	/**
	* @brief      Returns a generated char.
	* @return     an schar value generated with the distribution.
	*/
	sint GenerateInt () const;

	/**
	* @brief      Returns a generated char vector.
	* @param size The number of values to return.
	* @return     A pointer to an array of schar values generated with the distribution.
	*/
	sint * GenerateIntVector (usint size) const;

	/**
	* @brief  Returns a generated integer. Uses Peikert's inversion method.
	* @return A random value within this Discrete Gaussian Distribution.
	*/
	BigBinaryInteger GenerateInteger (const BigBinaryInteger &modulus) const;

	/**
	* @brief           Generates a vector of random values within this Discrete Gaussian Distribution. Uses Peikert's inversion method.
	*
	* @param  size     The number of values to return.
	* @param  modulus  modulus of the polynomial ring.
	* @return          The vector of values within this Discrete Gaussian Distribution.
	*/
	BigBinaryVector GenerateVector (usint size, const BigBinaryInteger &modulus) const;

	/**
	* @brief  Returns a generated integer. Uses rejection method.
	* @param mean center of discrete Gaussian distribution.
	* @param stddev standard deviatin of discrete Gaussian distribution.
	* @param n is ring dimension
	* param modulus modulus
	* @return A random value within this Discrete Gaussian Distribution.
	*/
	BigBinaryInteger GenerateInteger (double mean, double stddev, size_t n, const BigBinaryInteger &modulus) const;

	/**
	* @brief  Returns a generated integer. Uses rejection method.
	* @param mean center of discrete Gaussian distribution.
	* @param stddev standard deviatin of discrete Gaussian distribution.
	* @param n is ring dimension
	* @return A random value within this Discrete Gaussian Distribution.
	*/
	int32_t GenerateInteger (double mean, double stddev, size_t n) const;

	/**
	* @brief  Returns a generated integer. Uses rejection method. Works with large floating numbers.
	* @param mean center of discrete Gaussian distribution.
	* @param stddev standard deviatin of discrete Gaussian distribution.
	* @param n is ring dimension
	* @return A random value within this Discrete Gaussian Distribution.
	*/
	static int32_t GenerateInteger (const LargeFloat &mean, const LargeFloat &stddev, size_t n);

	/**
	* @brief  Returns a generated integer (int32_t). Uses rejection method.
	* @param mean center of discrecte Gaussian distribution.
	* @param stddev standard deviatin of discrete Gaussian distribution.
	* @return A random value within this Discrete Gaussian Distribution.
	*/
	//int32_t GenerateInt32 (double mean, double stddev);
	//will be defined later

	/**
	* @brief Generates the probability matrix of given distribution, which is used in Knuth-Yao method
	* @param sttdev standard deviation of Discrete Gaussian Distribution
	* @param mean Center of the distribution
	*/
	void GenerateProbMatrix(double stddev, double mean);

	/**
	* @ brief Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
	* @ return A random value within the Discrete Gaussian Distribution
	*/
	int32_t GenerateIntegerKnuthYao();
	/**
	* @brief Destructor
	*/
	~DiscreteGaussianGenerator() { if (probMatrix != nullptr) { delete[] probMatrix;} }

private:
	usint FindInVector (const std::vector<double> &S, double search) const;

	static double UnnormalizedGaussianPDF(const double &mean, const double &sigma, int32_t x) {
		return pow(M_E, -pow(x - mean, 2)/(2. * sigma * sigma));
	}

	static inline LargeFloat UnnormalizedGaussianPDF(const LargeFloat &mean, const LargeFloat &sigma, int32_t x) {
		return pow(M_E, -pow(x - mean, 2)/(2. * sigma * sigma));
	}

	// Gyana to add precomputation methods and data members
	// all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
	double m_a;

	std::vector<double> m_vals;

	/**
	* The standard deviation of the distribution.
	*/
	sint m_std;
	
	/**
	*The probability matrix used in Knuth-Yao sampling
	*/
	uint32_t * probMatrix = nullptr;
	
	/**
	*Array that stores the Hamming Weights of the probability matrix used in Knuth-Yao sampling
	*/
	//uint32_t hammingWeights[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	/**
	*Size of probability matrix
	*/
	uint32_t probMatrixSize;
	
	/**
	*Mean of the distribution used for Knuth-Yao probability table
	*/
	double probMean;
};

}  // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
