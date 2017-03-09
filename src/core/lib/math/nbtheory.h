/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham, np386@njit.edu
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
 *
 * 	NBTHEORY is set set of functions that will be used to calculate following:
 *		- If two numbers are coprime.
 *		- GCD of two numbers 
 *		- If number i Prime
 *		- witnesss function to test if number is prime
 *		- Roots of unit for provided cyclotomic integer
 *		- Eulers Totient function phin(n)
 *		- Generator algorithm
 */

#ifndef LBCRYPTO_MATH_NBTHEORY_H
#define LBCRYPTO_MATH_NBTHEORY_H

#include "backend.h"
#include <vector>
#include <set>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	const usint PRIMALITY_NO_OF_ITERATIONS = 100;  //!< @brief Number of iterations used for primality testing.

	/**
	 * Finds roots of unity for given input.  Assumes the the input is a power of two. 
	 * Mostly likely does not give correct results otherwise.
	 *
	 * @param m as number which is cyclotomic(in format of int).
	 * @param &modulo which is used to find generator.
	 * 
	 * @return a root of unity.  	  
	 */
	template<typename IntType>
	IntType RootOfUnity(usint m, const IntType &modulo);

	/**
	 * Finds roots of unity for given input.  Assumes the the input cyclotomicorder is a power of two. 
	 * Mostly likely does not give correct results otherwise.
	 *
	 * @param m as number which is cyclotomic(in format of int).
	 * @param moduli vector of modulus
	 * 
	 * @returns a vector of roots of unity corresponding to each modulus.  	  
	 */
	template<typename IntType>
	std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType> moduli);

	/**
	 * Method to reverse bits of num and return an unsigned int, for all bits up to an including the designated most significant bit.
	 *
	 * @param input an unsigned int
	 * @param msb the most significant bit.  All larger bits are disregarded.
	 * 
	 * @return an unsigned integer that represents the reversed bits.	  
	 */
	usint ReverseBits(usint input, usint msb);

//	/*
//	 * Method that converts signed char to BigBinaryInteger
//	 *
//	 * @param input an unsigned int
//	 * @param msb the most significant bit.  All larger bits are disregarded.
//	 * 
//	 * @return an unsigned integer that represents the reversed bits.	  
//	 */
//	BigBinaryInteger scharToBigBinaryInteger(schar, const BigBinaryInteger &modulus);

	/**
	 * Get MSB of an unisigned integer.
	 *
	 * @param x the input to find MSB of.
	 * 
	 * @return the index of the MSB bit location.	  
	 */
	usint GetMSB32(usint x);

	/**
	 * Return greatest common divisor of two big binary integers.
	 *
	 * @param a one integer to find greatest common divisor of.
	 * @param b another integer to find greatest common divisor of.
	 * 
	 * @return the greatest common divisor.	  
	 */
	BigBinaryInteger GreatestCommonDivisor(const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Return result of MillerRabin primality test of a BigBinaryInteger.
	 * This approach to primality testing is iterative and randomized.  It returns false if evidence of non-primality is found, and true if no evidence is found after multiple rounds of testing.  The const parameter PRIMALITY_NO_OF_ITERATIONS determines how many rounds are used.
	 *
	 * @param p the candidate prime to test.
	 * 
	 * @return false if evidence of non-primality is found.  True is no evidence of non-primality is found.	  
	 */
	bool MillerRabinPrimalityTest(const BigBinaryInteger& p);

	/**
	 * Return result of PollardRho factorization of a BigBinaryInteger.
	 * Returns BigBinaryInteger::ONE if no factorization is found.
	 *
	 * @param n the value to perform a factorization on.
	 * 
	 * @return a factor of n, and BigBinaryInteger::ONE if no other factor is found.	  
	 */
	const BigBinaryInteger PollardRhoFactorization(const BigBinaryInteger &n);

	/**
	 * Recursively factorizes and find the distinct primefactors of a number.
	 * Clears the input set and returns factors in the set.
	 *
	 * @param &n the value to factorize.
	 * @param &primeFactors the input set which is cleared and then results are returned in.  
	 */
	void PrimeFactorize(const BigBinaryInteger &n, std::set<BigBinaryInteger> &primeFactors);

	/**
	 * Finds a Prime Modulus Corresponding to a Given Cyclotomic Number.
	 * Assumes that GCD((2^n)-1, M) == M, but this property is not currently tested.
	 *
	 * @param m the the ring parameter.
	 * @param nBits the number of bits needed to be in q.
	 *
	 * @return the candidate prime modulus.  
	 */
	BigBinaryInteger FindPrimeModulus(usint m, usint nBits);

	/**
	 * Finds the next number that is a prime number matching the methods criteria. Sigma and alpha are required to calculate a minimum bound. The prime number generated will equal to one modulus the cyclotomic order and the plaintext modulus.
	 *
	 * @param &q is the place holder for the new prime. The original value of q will be set a minimum unless it is less than the minimum bound which is dependant on sigma and alpha.
	 * @param &plainTextModulus is the plaintext modulus the prime number will be used on.
	 * @param &ringDimension is the plaintext ringDimension the prime number will be used on.
	 * @param &sigma is parameter used for setting the minimum bound.
	 * @param &alpha is parameter used for setting the minimum bound.
	 *
	 * @return the next prime modulus.  
	 */

	void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint &ringDimension, const BigBinaryInteger &sigma, const BigBinaryInteger &alpha);

	/**
	 * Multiplicative inverse for primitive unsigned integer data types
	 *
	 * @param a the number we need the inverse of.
	 * @param b the modulus we are working with.
	 *
	 * @return the multiplicative inverse  
	 */
	usint ModInverse(usint a, usint b);


//private:
//
//	BigBinaryInteger RNG(const BigBinaryInteger& n);
//
//	bool WitnessFunction(const BigBinaryInteger& a, const BigBinaryInteger& d, usint s, const BigBinaryInteger& p);
//
//	BigBinaryInteger FindGenerator(const BigBinaryInteger& q);

} // namespace lbcrypto ends

#endif
