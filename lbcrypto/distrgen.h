/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.
 *
 * This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
 *
 * @section DESCRIPTION
 *
 * This code provides basic noise generation functionality.
 */

#ifndef LBCRYPTO_DISTRGEN_H
#define LBCRYPTO_DISTRGEN_H

#include "binint.h"
#include "binvect.h"
#include <math.h>
#include <random>

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
	virtual BigBinaryInteger GenerateInteger() const = 0;
	virtual BigBinaryVector GenerateVector(usint size) const = 0;
};

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
	 * @param std is the distirbution parameter.
	 * @param &mod is the distirbution modulus.  	  
	 */
	DiscreteGaussianGenerator(sint std,BigBinaryInteger &mod);

	/**
	 * Destructor.	  
	 */
	~DiscreteGaussianGenerator();

	//ACCESSORS

    //int GetMean() const;
	sint GetStd() const;
    //int GetUpperBound() const;
    //void SetMean(int mean);
	void SetStd(sint std);
    //void SetUpperBound(int upperBound);
	void SetModulus(BigBinaryInteger &modulus);

	schar* GenerateCharVector(usint size) const;

	BigBinaryInteger GenerateInteger() const;

	BigBinaryVector GenerateVector(usint size) const;

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
	BigBinaryInteger m_modulus;
};

} // namespace lbcrypto ends

#endif
