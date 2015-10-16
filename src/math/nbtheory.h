//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
Description:	

Description:	
	NBTHEORY is set set of functions that will be used to calculate following:
		- If two numbers are coprime.
		- GCD of two numbers 
		- If number i Prime
		- witnesss function to test if number is prime
		- Roots of unit for provided cyclotomic integer
		- Eulers Totient function phin(n)
		- Generator algorithm

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
*/

#ifndef LBCRYPTO_NBTHEORY_H
#define LBCRYPTO_NBTHEORY_H

#include "backend.h"
#include <vector>
#include <set>
#include <string>

using namespace cpu8bit;

namespace lbcrypto {

const usint PRIMALITY_NO_OF_ITERATIONS = 100;

BigBinaryInteger RootOfUnity(int m, const BigBinaryInteger& modulo);

BigBinaryInteger intToBigBinaryInteger(usint m);

usint ReverseBits(usint input, usint msb);

//converts signed char generated using GDG to BigBinaryInteger for polynomial operations
BigBinaryInteger scharToBigBinaryInteger(schar, const BigBinaryInteger &modulus);

usint GetMSB32(usint x);

BigBinaryInteger GCD(const BigBinaryInteger& a, const BigBinaryInteger& b);

bool PrimalityTest(const BigBinaryInteger& p);

BigBinaryInteger FindGenerator(const BigBinaryInteger& q);

BigBinaryInteger RNG(const BigBinaryInteger& n);

const BigBinaryInteger PollardRho(const BigBinaryInteger &n);

void Factorize(const BigBinaryInteger &n, std::set<BigBinaryInteger> &primeFactors);

bool witnessFunction(const BigBinaryInteger& a, const BigBinaryInteger& d, usint s, const BigBinaryInteger& p);

} // namespace lbcrypto ends

#endif
