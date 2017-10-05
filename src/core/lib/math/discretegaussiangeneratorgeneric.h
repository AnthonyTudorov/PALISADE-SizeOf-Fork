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

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_

#define _USE_MATH_DEFINES // added for Visual Studio support

#include <math.h>
#include <random>
#include <memory>

#include "backend.h"
#include "distributiongenerator.h"

namespace lbcrypto {

	enum BaseSamplerType { KNUTH_YAO = 0, PEIKERT = 1 };

	class DiscreteGaussianGeneratorGeneric;

	/**
	* @brief The class for Discrete Gaussion Distribution generator.
	*/
	class DiscreteGaussianGeneratorGeneric : public DistributionGenerator<BigInteger,BigVector> {

	public:
		/**
		* @brief         Basic constructor for specifying distribution parameter and modulus.
		* @param modulus The modulus to use to generate discrete values.
		* @param std     The standard deviation for this Gaussian Distribution.
		*/
		DiscreteGaussianGeneratorGeneric(float std = 1,BaseSamplerType type = PEIKERT);

		/**
		* @brief Initializes the generator.
		*/
		void Initialize();

		/**
		* @brief  Returns the standard deviation of the generator.
		* @return The analytically obtained standard deviation of the generator.
		*/
		float GetStd() const;

		/**
		* @brief     Sets the standard deviation of the generator.
		* @param std The analytic standard deviation of the generator.
		*/
		void SetStd(float std);


		/**
		* @brief Generates the probability matrix of given distribution, which is used in Knuth-Yao method
		* @param sttdev standard deviation of Discrete Gaussian Distribution
		* @param mean Center of the distribution
		* @param tableCount Number of probability tables to be generated
		*/
		void GenerateProbMatrix(double stddev, double mean, int tableCount);


		/**
		* @ brief Returns a generated integer. Uses Naive Knuth-Yao method
		* @ param tableID Identifier for the probability table
		* @ return A random value within the Discrete Gaussian Distribution
		*/
		int32_t GenerateIntegerKnuthYaoAlt(int tableID);


		/**
		* @ brief Returns a generated integer. Uses Knuth-Yao method defined as Algorithm 1 in http://link.springer.com/chapter/10.1007%2F978-3-662-43414-7_19#page-1
		* @ param tableID Identifier for the probability table
		* @ return A random value within the Discrete Gaussian Distribution
		*/
		int32_t GenerateIntegerKnuthYao(int tableID);
		/**
		* @brief Destructor
		*/
		~DiscreteGaussianGeneratorGeneric() {
			if (DDGColumn != nullptr) { delete[] DDGColumn;}
		}

		void PreCompute(int32_t b, int32_t k, double stddev);
		/**
		* @ brief Returns a generated integer. Uses generic algorithm in UCSD paper
		* @ param mean Mean of the distribution
		* @ param stddev Standard deviation of the distribution
		* @ return A random value within the Discrete Gaussian Distribution
		*/
		int32_t GenerateInteger(double mean, double stddev);


		/**
		* @brief  Returns a generated integer. Uses Peikert's inversion method.
		* @param b The index of the table to be sampled from
		* @return A random value within this Discrete Gaussian Distribution.
		*/
		int32_t GenerateIntegerPeikert(int b) const;

	private:

		// Gyana to add precomputation methods and data members
		// all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
		double m_a;

		/**
		* The standard deviation of the distribution.
		*/
		float m_std;

		/**
		*The probability matrix used in Knuth-Yao sampling
		*/
		//uint64_t ** probMatrix = nullptr;
		std::vector<std::vector<uint64_t>>  probMatrix;

		std::vector<std::vector<std::vector<short>>> DDGTree;
		//short *** DDGTree = nullptr;

		short *DDGColumn = nullptr;

		/**
		*Array that stores the Hamming Weights of the probability matrix used in Knuth-Yao sampling
		*/
		std::vector<std::vector<uint32_t>> hammingWeights;
		//uint32_t** hammingWeights =nullptr;
		/**
		*Size of probability matrix
		*/
		int32_t probMatrixSize;
		uint32_t tableCount;

		/**
		*Mean of the distribution used for Knuth-Yao probability table
		*/
		std::vector<double> probMean;

		/**
		 *Index of first bit with non zero Hamming weight in the probability table
		 */
		std::vector<int32_t> firstNonZero;



		int32_t SampleI(int32_t i);
		double SampleC(double c, int32_t k);

		double m_K=0;

		std::vector<double> m_sigma;
		//double* m_sigma = nullptr;
		std::vector<int32_t> m_z;
		//int32_t* m_z = nullptr;

		int32_t m_Sample_b = 0;
		int32_t m_Sample_k = 0;
		int32_t m_Sample_max = 0;
		double m_prev_std=0;
		double m_SigmaBar = 0;

		uint32_t ky_seed = 0;
		char ky_counter = 0;



		BaseSamplerType bType;

		std::vector<std::vector<double>> m_vals;

		usint FindInVector(const std::vector<double> &S, double search) const;

		/**
		* @brief Generates DDG tree used through the sampling in Knuth-Yao
		* @param tableID identifier for probability table
		*/
		void GenerateDDGTree(int tableID);

		/**
		* @brief Initializes the generator.
		*/
		void Initialize(int b);

	};

}  // namespace lbcrypto
#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATORGENERIC_H_
