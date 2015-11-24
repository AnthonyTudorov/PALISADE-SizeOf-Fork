/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham, np386@njit.edu
 * @version 00_04
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
 *
 * This code provides basic noise generation functionality.
 */

#ifndef LBCRYPTO_MATH_DISTRGEN_H
#define LBCRYPTO_MATH_DISTRGEN_H

#include "backend.h"
#include <math.h>
#include <random>

 #include <bitset>
 #include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief The class for random number distribution generator
 */
class DistributionGenerator
{
public:

	/**
	 * Basic virtual method.
	 *
	 * @return a return value set to 0.
	 */
	virtual BigBinaryInteger GenerateInteger() const = 0;

	/**
	 * Basic virtual method.
	 *
	 * @return a return value set to 0.
	 */
	virtual BigBinaryVector GenerateVector(usint size, const BigBinaryInteger &modulus) const = 0;

	/**
	 *  Interface requires virtual destructor.
	 */
	virtual ~DistributionGenerator() = 0;
};

inline DistributionGenerator::~DistributionGenerator() { };

//class UniformIntegerGenerator: DistributionGenerator
//{
//public:
//	UniformIntegerGenerator(); //srand(time(NULL)) is called here
//	UniformIntegerGenerator(const BigBinaryInteger& lower, const BigBinaryInteger& upper);
//	~UniformIntegerGenerator();
//
//	//ACCESSORS
//
//    BigBinaryInteger& GetLowerBound() const;
//	BigBinaryInteger& GetUpperBound() const;
//    void SetLowerBound(const BigBinaryInteger& lower);
//	void SetUpperBound(const BigBinaryInteger& upper);
//
//    BigBinaryInteger& GenerateInteger() const;
//    BigBinaryVector& GenerateVector(int size) const;
//
//private:
//    //it is assumed that lower and higher bounds for uniform random distribution can be up to the value of ciphertext modulus
//	BigBinaryInteger m_lowerBound;
//    BigBinaryInteger m_upperBound;
//	//I don't believe we need to store the seed used for the previous case; it can be set to srand (time(NULL));
//	//if it is faster to keep working incrementally with the same seed, we can add it
//	//though in this case, it is not clear how parallelization can be achieved
//};

/**
 * @brief The class for discrete Gaussion distribution generator
 */
class DiscreteGaussianGenerator: DistributionGenerator
{
public:
	/**
	 * Basic constructor.
	 */
	DiscreteGaussianGenerator(); //srand(time(NULL)) is called here

	/**
	 * Basic constructor for specifying distribution parameter and modulus.
	 *
	 * @param std is the distribution parameter.
	 */
	DiscreteGaussianGenerator(sint std);

	/**
	 * Destructor.
	 */
	~DiscreteGaussianGenerator();

	//ACCESSORS

    //int GetMean() const;

	/**
	 * Returns the standard deviation of the generator.
	 *
	 * @return the analytically obtained standard deviation of the generator.
	 */
	sint GetStd() const;
    //int GetUpperBound() const;
    //void SetMean(int mean);

	/**
	 * Sets the standard deviation of the generator.
	 *
	 * @param std the analytic standard deviation of the generator.
	 */
	void SetStd(sint std);
    //void SetUpperBound(int upperBound);

	/*
	 * Sets the modulus of the generator.
	 *
	 * @param &modulus the analytic standard deviation of the generator.
	 */
	//void SetModulus(BigBinaryInteger &modulus);

	/**
	 * Returns a generated char vector.
	 *
	 * @param size the number of values to return.
	 * @return a pointer to an array of schar values generated with the distribution.
	 */
	schar* GenerateCharVector(usint size) const;

	/**
	 * Returns a generated integer.
	 *
	 * @return a generated integer.
	 */
	BigBinaryInteger GenerateInteger() const;

	/**
	 * Returns a generated vector.
	 *
	 * @param size the number of values to return.
	 * @param &modulus the modulus of the returned data.
	 * @return vector of values generated with the distribution.
	 */
	BigBinaryVector GenerateVector(usint size, const BigBinaryInteger &modulus) const;

	/**
	 * Returns a generated vector.
	 *
	 * @param vectorLength the number of values to return.
	 * @param &modValue the number of values to return.
	 * @return vector of values generated with the distribution.
	 */
	static BigBinaryVector DiscreteGaussianPositiveGenerator(usint vectorLength,const BigBinaryInteger &modValue);

private:
	usint FindInVector(const std::vector<double> &S,double search) const;
    //Gyana to add precomputation methods and data members
	//all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
//	int m_mean;
	float m_a;
	void InitiateVals();
	std::vector<double> m_vals;
	sint m_std;
	//BigBinaryInteger m_modulus;
};

/**
 * @brief The class for discrete Uniform distribution generator over Zq.
 */
class DiscreteUniformGenerator: DistributionGenerator
{
public:
	/**
	 * Basic constructor.
	 */
	DiscreteUniformGenerator(); //srand(time(NULL)) is called here

	/**
	 * Basic constructor for specifying distribution modulus.
	 *
	 * @param &mod is the distirbution modulus.
	 */
	DiscreteUniformGenerator(BigBinaryInteger &mod);

	/**
	 * Destructor.
	 */
	~DiscreteUniformGenerator();

	//ACCESSORS

    //int GetMean() const;

	/**
	 * Returns the modulus of the generator.
	 *
	 * @return the modulus of the generator.
	 */
	const BigBinaryInteger& GetModulus() const;

	/**
	 * Sets the modulus of the generator.
	 *
	 * @param &mod is the distirbution modulus.
	 */
	void SetModulus(BigBinaryInteger &mod);

	/**
	 * Returns a generated integer.
	 *
	 * @return a generated integer.
	 */
	BigBinaryInteger GenerateInteger() const;

	/**
	 * Returns a generated vector.
	 *
	 * @param size the number of values to return.
	 * @return vector of values generated with the distribution.
	 */
	BigBinaryVector GenerateVector(usint size) const;

private:
	BigBinaryInteger m_modulus;

	static const usint MINVAL = 0;
	//This code does not work in VS 2012 - need to find a solution
	//static const usint LENOFMAX = std::numeric_limits<usint>::digits;
	//static const usint MAXVAL = std::numeric_limits<usint>::max();

	static const usint LENOFMAX = 16;
	static const usint MAXVAL = 65535;
	//2^16-1 = 65535

	usint moduloLength;
	usint noOfIter;
	usint remainder;
	void InitializeVals();
};



/**
 * @brief The class for binary uniform distribution generator.
 */
class BinaryUniformGenerator: DistributionGenerator
{
public:
	/**
	 * Basic constructor.
	 */
	BinaryUniformGenerator(); //srand(time(NULL)) is called here

	/**
	 * Destructor.
	 */
	~BinaryUniformGenerator() { };

	/**
	 * Returns a generated integer.
	 *
	 * @return a generated integer.
	 */
	BigBinaryInteger GenerateInteger() const;

	/**
	 * Returns a generated vector.
	 *
	 * @param size the number of values to return.
	 * @return vector of values generated with the distribution.
	 */
	BigBinaryVector GenerateVector(usint size) const;

};


} // namespace lbcrypto ends

#endif
