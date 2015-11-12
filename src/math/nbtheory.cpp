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

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "nbtheory.h"
#include <math.h>
#include <time.h>
#include <sstream>

//#define DEBUG_NBTHEORY //used to print step by step values in debug mode
//define DEBUG_ROOTS_OF_UNITY


namespace lbcrypto {

/*
	Generates a random number between 0 and n.
	Input: BigBinaryInteger n.
	Output: Randomly generated BigBinaryInteger between 0 and n.
*/
 static BigBinaryInteger RNG(const BigBinaryInteger& n)
 {
	// std::cout << " \n********WARNING: This code is calling an incorrect random number generator that is intended for temporary use ONLY!!!!!  This function, RNG(const BigBinaryInteger& n), is in nbtheory.cpp*********" << std::endl;

	std::string rand1 = std::to_string(rand());
	std::string rand2 = std::to_string(rand());
	std::string randstr = rand1 + rand2;
	return BigBinaryInteger(randstr).Mod(n);
}

/*
	A witness function used for the Miller-Rabin Primality test.
	Inputs: a is a randomly generated witness between 2 and p-1,
			p is the number to be tested for primality,
			s and d satisfy p-1 = ((2^s) * d), d is odd.
	Output: true if p is composite,
			false if p is likely prime
*/
static bool WitnessFunction(const BigBinaryInteger& a, const BigBinaryInteger& d, usint s, const BigBinaryInteger& p)
{
	BigBinaryInteger mod = a.ModExp(d, p);
	bool prevMod = false;
	for(int i=1; i<s+1; i++) {
		if(mod != BigBinaryInteger::ONE && mod != p-BigBinaryInteger::ONE)
			prevMod = true;
		else
			prevMod = false;
		mod = mod.ModExp(BigBinaryInteger::TWO, p);
		if(mod == BigBinaryInteger::ONE && prevMod) return true;
	}
	return (mod != BigBinaryInteger::ONE);
}

/*
	A helper function to RootOfUnity function. This finds a generator for a given prime q.
	Input: BigBinaryInteger q which is a prime.
	Output: A generator of prime q
*/
static BigBinaryInteger FindGenerator(const BigBinaryInteger& q)
 {
 	std::set<BigBinaryInteger> primeFactors;
 	PrimeFactorize(q-BigBinaryInteger::ONE, primeFactors);
 	bool generatorFound = false;
 	BigBinaryInteger gen;
 	while(!generatorFound) {
 		usint count = 0;
 		gen = RNG(q-BigBinaryInteger::TWO).ModAdd(BigBinaryInteger::ONE, q);
 		for(std::set<BigBinaryInteger>::iterator it = primeFactors.begin(); it != primeFactors.end(); ++it) {
 			BigBinaryInteger exponent = (q-BigBinaryInteger::ONE).DividedBy(*it);
 			if(gen.ModExp(exponent, q) == BigBinaryInteger::ONE) break;
 			else count++;
 		}
 		if(count == primeFactors.size()) generatorFound = true;
 	}
 	return gen;
 }

/*
	finds roots of unity for given input.  Assumes the the input is a power of two.  Mostly likely does not give correct results otherwise.
	input:	m as number which is cyclotomic(in format of int),
			modulo which is used to find generator (in format of BigBinaryInteger)
	
	output:	root of unity (in format of BigBinaryInteger)
*/
BigBinaryInteger RootOfUnity(int m, const BigBinaryInteger& modulo) 
{
	BigBinaryInteger result;
	BigBinaryInteger M(std::to_string(m));
	BigBinaryInteger gen = FindGenerator(modulo);
	result = gen.ModExp((modulo-BigBinaryInteger::ONE).DividedBy(M), modulo);
	if(result == BigBinaryInteger::ONE) {
		return RootOfUnity(m, modulo);
	}
	return result;
}


/*
	This method can be used to convert int to BigBinaryInteger
*/
BigBinaryInteger UintToBigBinaryInteger(usint m)
{
	/*
	std::ostringstream s;
	s << m;
	BigBinaryInteger result(s.str());
	return result;
	*/
	
	return BigBinaryInteger::intToBigBinaryInteger(m);
	
}

/* Function to reverse bits of num */
usint ReverseBits(usint num, usint msb)
{
    usint reverse_num = 0, i, temp;
 
    for (i = 0; i < msb; i++)
    {
        temp = (num & (1 << i));
        if(temp)
            reverse_num |= (1 << ((msb - 1) - i));
    }
  
    return reverse_num;
}

//gets MSB for an unsigned integer
usint GetMSB32(usint x)
{
    static const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    usint r = 0;
    if (x & 0xFFFF0000) { r += 16/1; x >>= 16/1; }
    if (x & 0x0000FF00) { r += 16/2; x >>= 16/2; }
    if (x & 0x000000F0) { r += 16/4; x >>= 16/4; }
    return r + bval[x];
}

/*usint GetMSB32(usint v) {
  static const int pos[32] = {0, 1, 28, 2, 29, 14, 24, 3,
    30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19,
    16, 7, 26, 12, 18, 6, 11, 5, 10, 9};
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v = (v >> 1) + 1;
  return pos[(v * 0x077CB531UL) >> 27];
}*/

/*
	A recurise function used to find the Greatest Common Divisor (GCD) of two BigBinaryIntegers.
	Input: BigBinaryInteger's a and b.
	Output: A BigBinaryInteger which is GCD of a and b.
*/
 BigBinaryInteger GreatestCommonDivisor(const BigBinaryInteger& a, const BigBinaryInteger& b)
 {
 	BigBinaryInteger m_rkminus2, m_rkminus1, m_rk;
 	m_rkminus2 = a;
 	m_rkminus1 = b;
 	while(m_rkminus2 >= m_rkminus1) {
 		m_rkminus2 -= m_rkminus1;
 	}
 	m_rk = m_rkminus2;
	if(m_rk == BigBinaryInteger::ZERO) {
		return m_rkminus1;
	}
 	return GreatestCommonDivisor(m_rkminus1, m_rk);
 }

/*
	The Miller-Rabin Primality Test
	Input: p the number to be tested for primality.
	Output: true if p is prime,
			false if p is not prime
*/
 bool MillerRabinPrimalityTest(const BigBinaryInteger& p)
 {
 	if(p < BigBinaryInteger::TWO || ((p != BigBinaryInteger::TWO) && (p.Mod(BigBinaryInteger::TWO) == BigBinaryInteger::ZERO)))
 		return false;
 	if(p == BigBinaryInteger::TWO || p == BigBinaryInteger::THREE || p == BigBinaryInteger::FIVE)
 		return true;
 	BigBinaryInteger d = p-BigBinaryInteger::ONE;
 	usint s = 0;
 	while(d.Mod(BigBinaryInteger::TWO) == BigBinaryInteger::ZERO) {
 		d = d.DividedBy(BigBinaryInteger::TWO);
 		s++;
 	}
 	bool composite = true;
 	for(int i=0; i<PRIMALITY_NO_OF_ITERATIONS; i++) {
 		BigBinaryInteger a = RNG(p-BigBinaryInteger::THREE).ModAdd(BigBinaryInteger::TWO, p);
 		composite = (WitnessFunction(a, d, s, p));
		if(composite)
			break;
	}
	return (!composite);
 }

/*
	The Pollard Rho factorization of a number n.
	Input: n the number to be factorized.
	Output: a factor of n.
*/
 const BigBinaryInteger PollardRhoFactorization(const BigBinaryInteger &n)
 {
 	BigBinaryInteger divisor(BigBinaryInteger::ONE);
 	
 	BigBinaryInteger c(RNG(n));
 	BigBinaryInteger x(RNG(n));
 	BigBinaryInteger xx(x);
 	
 	//check divisibility by 2
 	if(n.Mod(BigBinaryInteger::TWO) == BigBinaryInteger::ZERO)
 		return BigBinaryInteger(BigBinaryInteger::TWO);

 	do {
 		x = (x.ModMul(x, n) + c).Mod(n);
 		xx = (xx.ModMul(xx, n) + c).Mod(n);
 		xx = (xx.ModMul(xx, n) + c).Mod(n);
 		divisor = GreatestCommonDivisor(((x-xx) > BigBinaryInteger::ZERO) ? x-xx : xx-x, n);
 	} while (divisor == BigBinaryInteger::ONE);
 	
 	return divisor;
 }

/*
	Recursively factorizes and find the distinct primefactors of a number
	Input: n is the number to be prime factorized,
		   primeFactors is a set of prime factors of n. All initial values are cleared.
*/
 void PrimeFactorize(const BigBinaryInteger &n, std::set<BigBinaryInteger> &primeFactors)
 {
	// primeFactors.clear();
 	if(n == BigBinaryInteger::ONE) return;
 	if(MillerRabinPrimalityTest(n)) {
 		primeFactors.insert(n);
 		return;
 	}
 	BigBinaryInteger divisor(PollardRhoFactorization(n));
 	PrimeFactorize(divisor, primeFactors);
 	BigBinaryInteger reducedN(n.DividedBy(divisor));
 	PrimeFactorize(reducedN, primeFactors);
 }

/*
	Finds a Prime Modulus Corresponding to a Given Cyclotomic Number
	Assuming that "GreatestCommonDivisor(twoTonBitsminusone, M) == M"
*/
BigBinaryInteger FindPrimeModulus(usint m, usint nBits)
{
	BigBinaryInteger twoTonBitsminusone("1"), M(std::to_string(m)), q;
	for(usint i=0; i<nBits-1; i++)	// Iterating until initial search condition.
		twoTonBitsminusone = twoTonBitsminusone * BigBinaryInteger::TWO;
	//if(GreatestCommonDivisor(twoTonBitsminusone, M) != M)  // Implementing a guard to make sure assumptions are satisfied.
		// throw error
	q = twoTonBitsminusone + M + BigBinaryInteger::ONE;
	bool found = false;
	while(!found) {  //Looping over invariant until test condition satisfied.
		if((q-BigBinaryInteger::ONE).Mod(M) != BigBinaryInteger::ZERO) {
			q += M;
			continue;
		}
		if(!MillerRabinPrimalityTest(q)) {
			q += M;
			continue;
		}
		found = true;
	}
	return q;
}

}
