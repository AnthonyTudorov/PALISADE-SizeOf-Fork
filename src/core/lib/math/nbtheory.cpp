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

#include "time.h"
#include <chrono>

#include "../utils/debug.h"


#define _USE_MATH_DEFINES 
#include <cmath>
#include <time.h>
#include <sstream>

//#define DEBUG_NBTHEORY //used to print step by step values in debug mode
//define DEBUG_ROOTS_OF_UNITY

namespace lbcrypto {
  //todo: more substitutions here

template BigBinaryInteger RootOfUnity<BigBinaryInteger>(usint m, const BigBinaryInteger& modulo);
template std::vector<BigBinaryInteger> RootsOfUnity(usint m, const std::vector<BigBinaryInteger> moduli);
template BigBinaryInteger GreatestCommonDivisor(const BigBinaryInteger& a, const BigBinaryInteger& b);
  template bool MillerRabinPrimalityTest(const BigBinaryInteger& p, const usint niter);
template const BigBinaryInteger PollardRhoFactorization(const BigBinaryInteger &n);
template void PrimeFactorize( BigBinaryInteger n, std::set<BigBinaryInteger> &primeFactors);
template BigBinaryInteger FindPrimeModulus(usint m, usint nBits);
template void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint cyclotomicOrder, const BigBinaryInteger &sigma, const BigBinaryInteger &alpha);
template BigBinaryVector PolyMod(const BigBinaryVector &dividend, const BigBinaryVector &divisor, const BigBinaryInteger &modulus);
template BigBinaryVector PolynomialMultiplication(const BigBinaryVector &a, const BigBinaryVector &b);
template BigBinaryVector GetCyclotomicPolynomial(usint m, const BigBinaryInteger &modulus);


template std::vector<usint> GetTotientList(const usint &n);
// FIXME the MATH_BACKEND check is a hack and needs to go away
#if MATHBACKEND != 7
#ifndef NO_MATHBACKEND_7
template native64::BigBinaryInteger RootOfUnity<native64::BigBinaryInteger>(usint m, const native64::BigBinaryInteger& modulo);
template std::vector<native64::BigBinaryInteger> RootsOfUnity(usint m, const std::vector<native64::BigBinaryInteger> moduli);
template native64::BigBinaryInteger GreatestCommonDivisor(const native64::BigBinaryInteger& a, const native64::BigBinaryInteger& b);
  template bool MillerRabinPrimalityTest(const native64::BigBinaryInteger& p, const usint niter);
template const native64::BigBinaryInteger PollardRhoFactorization(const native64::BigBinaryInteger &n);
template void PrimeFactorize( native64::BigBinaryInteger n, std::set<native64::BigBinaryInteger> &primeFactors);
template native64::BigBinaryInteger FindPrimeModulus(usint m, usint nBits);
template void NextQ(native64::BigBinaryInteger &q, const native64::BigBinaryInteger &plainTextModulus, const usint cyclotomicOrder, const native64::BigBinaryInteger &sigma, const native64::BigBinaryInteger &alpha);
//template native64::BigBinaryInteger GetTotient(const native64::BigBinaryInteger &n);
template std::vector<native64::BigBinaryInteger> GetTotientList(const native64::BigBinaryInteger &n);
template native64::BigBinaryVector PolyMod(const native64::BigBinaryVector &dividend, const native64::BigBinaryVector &divisor, const native64::BigBinaryInteger &modulus);
template native64::BigBinaryVector PolynomialMultiplication(const native64::BigBinaryVector &a, const native64::BigBinaryVector &b);
template native64::BigBinaryVector GetCyclotomicPolynomial(usint m, const native64::BigBinaryInteger &modulus);

#endif
#endif
}

namespace lbcrypto {

/*
	Generates a random number between 0 and n.
	Input: BigBinaryInteger n.
	Output: Randomly generated BigBinaryInteger between 0 and n.
*/


template<typename IntType>
static IntType RNG(const IntType& modulus)
 {
	// static parameters for the 32-bit unsigned integers used for multiprecision random number generation
	static const usint chunk_min = 0;
	static const usint chunk_width = std::numeric_limits<uint32_t>::digits;
	static const usint chunk_max = std::numeric_limits<uint32_t>::max();

	static std::uniform_int_distribution<uint32_t> distribution(chunk_min, chunk_max);

	// Update values that depend on modulus.
	usint modulusWidth = modulus.GetMSB();
	// Get the number of chunks in the modulus
	// 1 is subtracted to make sure the last chunk is fully used by the modulus
	usint chunksPerValue = (modulusWidth - 1) / chunk_width;

	// result is initialized to 0
	IntType result;

	//temp is used for intermediate multiprecision computations
	IntType temp;

	//stores current random number generated by built-in C++ 11 uniform generator (used for 32-bit unsigned integers)
	uint32_t value;

	do {

		result = 0;

		// Generate random uint32_t "limbs" of the BigBinaryInteger
		for (usint i = 0; i < chunksPerValue; i++) {
			//Generate an unsigned long integer
			value = distribution(PseudoRandomNumberGenerator::GetPRNG());
			// converts value into IntType
			temp = value;
			//Move it to the appropriate chunk of the big integer
			temp <<= i*chunk_width;
			//Add it to the current big integer storing the result
			result += temp;
		}

		//work with the remainder - after all 32-bit chunks were processed
		temp = modulus >> chunksPerValue*chunk_width;

		// Generate a uniform number for the remainder
		// If not 1, i.e., the modulus is either 1 or a power of 2*CHUNK_WIDTH
		if (temp.GetMSB() != 1)
 {
			uint32_t bound = temp.ConvertToInt();

			// default generator for the most significant chunk of the multiprecision number
			std::uniform_int_distribution<uint32_t>  distribution2 = std::uniform_int_distribution<uint32_t>(chunk_min, bound);

			value = distribution2(PseudoRandomNumberGenerator::GetPRNG());
			// converts value into IntType
			temp = value;
			//Move it to the appropriate chunk of the big integer
			temp <<= chunksPerValue*chunk_width;
			//Add it to the current big integer storing the result
			result += temp;

		}

	} while (result > modulus); // deals with the rare scenario when the bits in the most significant chunk are the same
	// and the bits in the following chunk of the result are larger than in the modulus

	return result;
 }
#if MATHBACKEND ==6
//native NTL version
  static NTL::myZZ RNG(const NTL::myZZ& modulus)
  {
    
    return RandomBnd(modulus);
    
  }
#endif
/*
	A witness function used for the Miller-Rabin Primality test.
	Inputs: a is a randomly generated witness between 2 and p-1,
			p is the number to be tested for primality,
			s and d satisfy p-1 = ((2^s) * d), d is odd.
	Output: true if p is composite,
			false if p is likely prime
*/
template<typename IntType>
static bool WitnessFunction(const IntType& a, const IntType& d, usint s, const IntType& p)
{
	IntType mod = a.ModExp(d, p);
	bool prevMod = false;
	for(usint i=1; i<s+1; i++) {
		if(mod != 1 && mod != p-1)
			prevMod = true;
		else
			prevMod = false;
		mod = mod.ModMul(mod,p);
		if(mod == 1 && prevMod) return true;
	}
	return (mod != 1);
}

/*
	A helper function to RootOfUnity function. This finds a generator for a given prime q.
	Input: BigBinaryInteger q which is a prime.
	Output: A generator of prime q
*/
template<typename IntType>
static IntType FindGenerator(const IntType& q)
 {
	bool dbg_flag = false;
 	std::set<IntType> primeFactors;
	DEBUG("calling PrimeFactorize");

	IntType qm1 = q - 1;
	IntType qm2 = q - 2;
 	PrimeFactorize<IntType>(qm1, primeFactors);
	DEBUG("done");
 	bool generatorFound = false;
 	IntType gen;
 	while(!generatorFound) {
 		usint count = 0;
		DEBUG("count "<<count);
 		//gen = RNG(qm2).ModAdd(IntType::ONE, q); //modadd note needed
		gen = RNG(qm2)+1;

 		for(auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
		  DEBUG("in set");
		  DEBUG("divide "<< qm1 <<" by "<< *it);

		  if(gen.ModExp(qm1/(*it), q) == 1) break;
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
template<typename IntType>
IntType RootOfUnity(usint m, const IntType& modulo)
{
	bool dbg_flag = false;
	DEBUG("in Root of unity m :"<<m<<" modulo "<<modulo.ToString());
	IntType M(m);
	if((modulo-1).Mod(M) != 0) {
		std::string errMsg = "Please provide a primeModulus(q) and a cyclotomic number(m) satisfying the condition: (q-1)/m is an integer. The values of primeModulus = " + modulo.ToString() + " and m = " + std::to_string(m) + " do not satisfy this condition";
		throw std::runtime_error(errMsg);
	}
	IntType result;
	DEBUG("calling FindGenerator");	
	IntType gen = FindGenerator(modulo);
	DEBUG("gen = "<<gen.ToString());

	DEBUG("calling gen.ModExp( " <<((modulo-1).DividedBy(M)).ToString() << ", modulus "<< modulo.ToString());
	result = gen.ModExp((modulo-1).DividedBy(M), modulo);
	DEBUG("result = "<<result.ToString());
	if(result == 1) {
	  DEBUG("LOOP?");
		return RootOfUnity(m, modulo);
	}
	return result;
}

template<typename IntType>
std::vector<IntType> RootsOfUnity(usint m, const std::vector<IntType> moduli) {
	std::vector<IntType> rootsOfUnity(moduli.size());
	for(usint i=0; i<moduli.size(); i++) {
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
	}
	return rootsOfUnity;
}

// precomputed reverse of a byte

inline static unsigned char reverse_byte(unsigned char x)
{
    static const unsigned char table[] = {
        0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
        0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
        0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
        0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
        0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
        0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
        0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
        0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
        0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
        0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
        0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
        0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
        0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
        0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
        0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
        0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
        0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
        0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
        0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
        0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
        0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
        0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
        0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
        0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
        0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
        0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
        0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
        0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
        0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
        0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
        0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
        0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
    };
    return table[x];
}

static int shift_trick[] = {0, 7, 6, 5, 4, 3, 2, 1};

/* Function to reverse bits of num */
usint ReverseBits(usint num, usint msb)
{
	usint msbb = msb/8 + (msb%8?1:0);

	switch( msbb ) {
	case 1:
		return (reverse_byte( (num)&0xff ) >> shift_trick[msb%8]);

	case 2:
		return (reverse_byte( (num)&0xff ) << 8 |
			reverse_byte( (num >> 8)&0xff ) ) >> shift_trick[msb%8];

	case 3:
		return (reverse_byte( (num)&0xff ) << 16 |
			reverse_byte( (num >> 8)&0xff ) << 8 |
			reverse_byte( (num >> 16)&0xff ) ) >> shift_trick[msb%8];

	case 4:
		return (reverse_byte( (num)&0xff ) << 24 |
			reverse_byte( (num >> 8)&0xff ) << 16 |
			reverse_byte( (num >> 16)&0xff ) << 8 |
			reverse_byte( (num >> 24)&0xff ) ) >> shift_trick[msb%8];
	default:
		throw std::logic_error("msbb value not handled:"+std::to_string(msbb));
	}
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


template<typename IntType>
IntType GreatestCommonDivisor(const IntType& a, const IntType& b)
 {
   bool dbg_flag = false;
   IntType m_a, m_b, m_t;
 	m_a = a;
 	m_b = b;
	DEBUG("GCD a "<<a.ToString()<<" b "<< b.ToString());
	while (m_b != 0) {
		m_t = m_b;
		DEBUG("GCD m_a.Mod(b) "<<m_a.ToString() <<"( "<<m_b.ToString()<<")");
		m_b = m_a.Mod(m_b);
		
		m_a = m_t;
		DEBUG("GCD m_a "<<m_b.ToString() <<" m_b "<<m_b.ToString());
	}
	DEBUG("GCD ret "<<m_a.ToString());		  
	return m_a;
 }
  
#if MATHBACKEND ==6
  //define an NTL native implementation 
  NTL::myZZ GreatestCommonDivisor(const NTL::myZZ& a, const NTL::myZZ& b)
  {
  bool dbg_flag = false;
  DEBUG("NTL::GCD a "<<a<<" b "<< b);   
  return GCD(a,b);
}
#endif
  
  /*
    The Miller-Rabin Primality Test
    Input: p the number to be tested for primality.
    Output: true if p is prime,
    false if p is not prime
  */
  template<typename IntType>
  bool MillerRabinPrimalityTest(const IntType& p, const usint niter)
  {
 	if(p < 2 || ((p != 2) && (p.Mod(2) == 0)))
 		return false;
 	if(p == 2 || p == 3 || p == 5)
 		return true;

 	IntType d = p-1;
 	usint s = 0;
 	while(d.Mod(2) == 0) {
 		d = d.DividedBy(2);
 		s++;
 	}
 	bool composite = true;
 	for(usint i=0; i<niter; i++) {
 		IntType a = RNG(p-3).ModAdd(2, p);
 		composite = (WitnessFunction(a, d, s, p));
		if(composite)
			break;
	}
	return (!composite);
 }


#if MATHBACKEND ==6
  //NTL native version
bool MillerRabinPrimalityTest(const NTL::myZZ& p, const usint niter)
 {
 	if(p < NTL::myZZ::TWO || ((p != NTL::myZZ::TWO) && 
	(p.Mod(NTL::myZZ::TWO) == NTL::myZZ::ZERO)))
 		return false;
 	if(p == NTL::myZZ::TWO || p == NTL::myZZ::THREE || p == NTL::myZZ::FIVE)
 		return true;

	return (bool) ProbPrime(p, niter); //TODO: check to see if niter >maxint
}
#endif

/*
	The Pollard Rho factorization of a number n.
	Input: n the number to be factorized.
	Output: a factor of n.
*/
template<typename IntType>
const IntType PollardRhoFactorization(const IntType &n)
 {
   bool dbg_flag = false;
   IntType divisor(1);
 	
   IntType c(RNG(n));
   IntType x(RNG(n));
   IntType xx(x);
 	
 	//check divisibility by 2
 	if(n.Mod(2) == 0)
 		return IntType(2);

#if MATHBACKEND == 6 || MATHBACKEND == 7
	IntType mu(1);
#else
	//Precompute the Barrett mu parameter
	IntType temp(1);
	temp <<= 2 * n.GetMSB() + 3;
	IntType mu = temp.DividedBy(n);
#endif

 	do {
		x = (x*x + c).ModBarrett(n,mu);
		xx = (xx*xx + c).ModBarrett(n,mu);
		xx = (xx*xx + c).ModBarrett(n,mu);
 		divisor = GreatestCommonDivisor(((x-xx) > 0) ? x-xx : xx-x, n);
		DEBUG("PRF divisor "<<divisor.ToString());
		
 	} while (divisor == 1);
 	
 	return divisor;
 }

/*
	Recursively factorizes and find the distinct primefactors of a number
	Input: n is the number to be prime factorized,
		   primeFactors is a set of prime factors of n.
*/
template<typename IntType>
void PrimeFactorize( IntType n, std::set<IntType> &primeFactors)
 {
   bool dbg_flag = false;
   DEBUG("PrimeFactorize "<<n);
#if 1 
	// primeFactors.clear();
        DEBUG("In PrimeFactorize n " <<n);
	DEBUG("set size "<< primeFactors.size());

 	if(n == 0 || n == 1) return;
 	if(MillerRabinPrimalityTest(n)) {
	        DEBUG("Miller true");
 		primeFactors.insert(n);
 		return;
 	}

	DEBUG("calling PrFact n "<<n);
	IntType divisor(PollardRhoFactorization(n));

	DEBUG("calling PF "<<divisor);
 	PrimeFactorize(divisor, primeFactors);

	DEBUG("calling div "<<divisor);
	//IntType reducedN = n.DividedBy(divisor);
	n /= divisor;

	DEBUG("calling PF reduced n "<<n);
	PrimeFactorize(n, primeFactors);
#else
	//do not take a recursive approach -- therein lies memory issues.
	//do it iteratively.
	howevere this may be way slower!!!!

	IntType n(nin); //because nin is const!
	//first check if prime
	if(nin == IntType::ONE) return;
 	if(MillerRabinPrimalityTest(nin)) {
	        DEBUG("Miller true");
 		primeFactors.insert(nin);
 		return;
 	}
	while (n%IntType::TWO ==IntType::ZERO) {
	  primeFactors.insert(IntType::TWO); //note may have to only insert one. 
	  DEBUG(IntType::TWO);
	  n >>=1; //n = n/2;
	}
	// n must be odd at this point.  So we can skip 
	// one element (Note i = i +2)

	IntType stopval = n; //should be sqrt(n) 

	usint nbits = n.GetMSB();
	nbits /=2;
	stopval = IntType::ONE<<nbits;
	for (IntType i = IntType::THREE; i <= stopval; i += IntType::TWO){
	  
	  if(MillerRabinPrimalityTest(nin)) {
	    DEBUG("Miller true");
	    primeFactors.insert(nin);
	    return;
	  }

	  // While i divides n, print i and divide n
	  //note we can use a remdiv() function
	  while (n%i == IntType::ZERO) {
	    primeFactors.insert(i);
	    DEBUG(i);
	    n /= i;
	  }
	}
	
	// This condition is to handle the case when n 
	// is a prime number greater than 2
	if (n > IntType::TWO){
	  primeFactors.insert(n);
	  DEBUG(n);
	}
	DEBUG("returning primeFactors ");	
	for (auto it=primeFactors.begin(); it!=primeFactors.end(); ++it)
	  DEBUG(*it);

	return;

#endif


 }

/*
	Finds a Prime Modulus Corresponding to a Given Cyclotomic Number
	Assuming that "GreatestCommonDivisor(twoTonBitsminusone, M) == M"
*/
template<typename IntType>
IntType FindPrimeModulus(usint m, usint nBits)
{
	IntType twoTonBitsminusone(1), M(m), q;
	
	for(usint i=0; i<nBits-1; i++)	// Iterating until initial search condition.
		twoTonBitsminusone = twoTonBitsminusone * 2;
	
	q = twoTonBitsminusone + M + 1;
	bool found = false;
	while(!found) {  //Looping over invariant until test condition satisfied.
		if((q-1).Mod(M) != 0) {
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

template<typename IntType>
void NextQ(IntType &q, const IntType &plainTextModulus, const usint cyc, const IntType &sigma, const IntType &alpha) {
	IntType bigSixteen("16");
	IntType lowerBound;
	IntType cyclotomicOrder(cyc);

	lowerBound = bigSixteen * cyclotomicOrder * sigma  * sigma * alpha;
	if (!(q >= lowerBound)) {
		q = lowerBound;
	}
	else {
		q = q + 1;
	}

	while (q.Mod(plainTextModulus) != 1) {
		q = q + 1;
	}

	//IntType cyclotomicOrder = ringDimensions * IntType::TWO;

	while (q.Mod(cyclotomicOrder) != 1) {
		q = q + plainTextModulus;
	}

	IntType productValue = cyclotomicOrder * plainTextModulus;

	while (!MillerRabinPrimalityTest(q)) {
		q = q + productValue;
	}

	IntType gcd;
	gcd = GreatestCommonDivisor(q - 1, cyclotomicOrder);

	if(!(cyclotomicOrder == gcd)){
		q = q + 1;
	  	NextQ(q, plainTextModulus, cyc, sigma, alpha);
	}
		
}


/*
	Finds multiplicative inverse using the Extended Euclid Algorithms
*/
usint ModInverse(usint a, usint b)
{

	//usint b0 = b;
	usint t, q;
	usint x0 = 0, x1 = 1;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	//if (x1 < 0) x1 += b0;
	//TODO: x1 is never < 0

	return x1;
}

template<>
usint GreatestCommonDivisor(const usint& a, const usint& b)
{
	bool dbg_flag = false;
	usint m_a, m_b, m_t;
	m_a = a;
	m_b = b;
	DEBUG("GCD a " << a << " b " << b);
	while (m_b != 0) {
		m_t = m_b;
		DEBUG("GCD m_a.Mod(b) " << m_a << "( " << m_b << ")");
		m_b = m_a % (m_b);

		m_a = m_t;
		DEBUG("GCD m_a " << m_b << " m_b " << m_b);
	}
	DEBUG("GCD ret " << m_a);
	return m_a;
}

template<typename IntType>
IntType NextPowerOfTwo(const IntType &n) {
	usint result = ceil(log2(n));
	return result;
}

uint64_t GetTotient(const uint64_t n) {

	std::set<native64::BigBinaryInteger> factors;
	native64::BigBinaryInteger enn(n);
	PrimeFactorize(enn, factors);

	native64::BigBinaryInteger primeProd(1);
	native64::BigBinaryInteger numerator(1);
	for (auto &r : factors) {
		numerator = numerator * (r - 1);
		primeProd = primeProd * r;
	}

	primeProd = (enn / primeProd) * numerator;
	return primeProd.ConvertToInt();
}

/*Naive Loop to find coprimes to n*/
template<typename IntType>
std::vector<IntType> GetTotientList(const IntType &n) {

	std::vector<IntType> result;
	IntType one(1);
	for (IntType i = IntType(1); i < n; i = i + 1) {
		if (GreatestCommonDivisor(i, n) == one)
			result.push_back(i);
	}

	return std::move(result);
}

/* Calculate the remainder from polynomial division */
template<typename IntVector, typename IntType>
IntVector PolyMod(const IntVector &dividend, const IntVector &divisor, const IntType &modulus) {

	usint divisorLength = divisor.GetLength();
	usint dividendLength = dividend.GetLength();

	IntVector result(divisorLength - 1, modulus);
	usint runs = dividendLength - divisorLength + 1; //no. of iterations

	auto mat = [](const IntType &x, const IntType &y, const IntType &z, const IntType &mod) {
		IntType result(z.ModSub(x*y, mod));
		return result;
	};

	IntVector runningDividend(dividend);

	int  divisorPtr;
	for (usint i = 0; i < runs; i++) {
		IntType divConst(runningDividend.GetValAtIndex(dividendLength - 1));//get the highest degree coeff
		divisorPtr = divisorLength - 1;
		for (usint j = 0; j < dividendLength - i - 1; j++) {
			if (divisorPtr > j) {
				runningDividend.SetValAtIndex(dividendLength - 1 - j, mat(divisor.GetValAtIndex(divisorPtr - 1 - j), divConst, runningDividend.GetValAtIndex(dividendLength - 2 - j), modulus));
			}
			else
				runningDividend.SetValAtIndex(dividendLength - 1 - j, runningDividend.GetValAtIndex(dividendLength - 2 - j));

		}
	}

	for (usint i = 0, j = runs; i < divisorLength - 1; i++, j++) {
		result.SetValAtIndex(i, runningDividend.GetValAtIndex(j));
	}


	return result;
}

std::vector<int> GetCyclotomicPolynomialRecursive(usint m) {
	std::vector<int> result;
	if (m == 1) {
		result = { -1,1 };
		return result;
	}
	if (m == 2) {
		result = { 1,1 };
		return result;
	}
	auto IsPrime = [](usint m) {
		bool flag = true;
		for (usint i = 2; i < m; i++) {
			if (m%i == 0) {
				flag = false;
				return flag;
			}
		}
		return flag;
	};
	if (IsPrime(m)) {
		result = std::vector<int>(m, 1);
		return result;
	}

	auto GetDivisibleNumbers = [](usint m) {
		std::vector<usint> div;
		for (usint i = 1; i < m; i++) {
			if (m%i == 0) {
				div.push_back(i);
			}
		}
		return div;
	};

	auto PolyMult = [](const std::vector<int> &a, const std::vector<int> &b) {
		usint degreeA = a.size() - 1;
		usint degreeB = b.size() - 1;

		usint degreeResultant = degreeA + degreeB;

		std::vector<int> result(degreeResultant + 1, 0);

		for (usint i = 0; i < a.size(); i++) {

			for (usint j = 0; j < b.size(); j++) {
				const auto &valResult = result.at(i + j);
				const auto &valMult = a.at(i)*b.at(j);
				result.at(i + j) = valMult + valResult;
			}
		}

		return result;
	};

	auto PolyQuotient = [](const std::vector<int> &dividend, const std::vector<int> &divisor) {
		usint divisorLength = divisor.size();
		usint dividendLength = dividend.size();

		usint runs = dividendLength - divisorLength + 1; //no. of iterations
		std::vector<int> result(runs + 1);

		auto mat = [](const int x, const int y, const int z) {
			int result = z - (x*y);
			return result;
		};

		std::vector<int> runningDividend(dividend);

		int  divisorPtr;
		for (usint i = 0; i < runs; i++) {
			int divConst = (runningDividend.at(dividendLength - 1));//get the highest degree coeff
			divisorPtr = divisorLength - 1;
			for (usint j = 0; j < dividendLength - i - 1; j++) {
				if (divisorPtr > j) {
					runningDividend.at(dividendLength - 1 - j) = mat(divisor.at(divisorPtr - 1 - j), divConst, runningDividend.at(dividendLength - 2 - j));
				}
				else
					runningDividend.at(dividendLength - 1 - j) = runningDividend.at(dividendLength - 2 - j);

			}
			result.at(i + 1) = runningDividend.at(dividendLength - 1);
		}
		result.at(0) = 1;//under the assumption that both dividend and divisor are monic
		result.pop_back();

		return result;
	};
	auto divisibleNumbers = GetDivisibleNumbers(m);

	std::vector<int> product(1, 1);

	for (usint i = 0; i < divisibleNumbers.size(); i++) {
		auto P = GetCyclotomicPolynomialRecursive(divisibleNumbers[i]);
		product = PolyMult(product, P);
	}

	//make big poly = x^m - 1
	std::vector<int> bigPoly(m + 1, 0);
	bigPoly.at(0) = -1;
	bigPoly.at(m) = 1;

	result = PolyQuotient(bigPoly, product);

	return result;
}

template<typename IntVector>
IntVector PolynomialMultiplication(const IntVector &a, const IntVector &b) {

	usint degreeA = a.GetLength() - 1;
	usint degreeB = b.GetLength() - 1;

	usint degreeResultant = degreeA + degreeB;

	const auto &modulus = a.GetModulus();

	IntVector result(degreeResultant + 1, modulus);

	for (usint i = 0; i < a.GetLength(); i++) {

		for (usint j = 0; j < b.GetLength(); j++) {
			const auto &valResult = result.GetValAtIndex(i + j);
			const auto &valMult = a.GetValAtIndex(i)*b.GetValAtIndex(j);
			result.SetValAtIndex(i + j, (valMult + valResult).Mod(modulus));
		}
	}

	return result;

}

template<typename IntVector, typename IntType>
IntVector GetCyclotomicPolynomial(usint m, const IntType &modulus) {

	auto intCP = GetCyclotomicPolynomialRecursive(m);
	IntVector result(intCP.size(), modulus);
	for (usint i = 0; i < intCP.size(); i++) {
		auto val = intCP.at(i);
		if (intCP.at(i) > -1)
			result.SetValAtIndex(i, IntType(val));
		else {
			val *= -1;
			result.SetValAtIndex(i, modulus - IntType(val));
		}

	}

	return result;

}



}
