/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	9/29/2015 4:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
Description:	
	This code benchmarks the math libraries of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "benchmark/benchmark_api.h"

#include <iostream>

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/elemparams.h"
#include "../../src/lattice/ilparams.h"
#include "../../src/lattice/ildcrtparams.h"
#include "../../src/lattice/ilelement.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/ilvector2n.h"
#include "../../src/lattice/ilvectorarray2n.h"
#include "../../src/utils/utilities.h"


using namespace std;
using namespace lbcrypto;

// TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO SMALL NUMBERS

//static void method_greatest_common_divisor_equals_small_numbers(void) {
static int greatest_common_divisor_equals_small_numbers(void) {
  BigBinaryInteger a("10403"), b("103");
  BigBinaryInteger c = lbcrypto::GreatestCommonDivisor(a, b);
  return(c.ConvertToInt());
}

static int greatest_common_divisor_equals_powers_of_two_numbers(void) {
  BigBinaryInteger a("1048576"), b("4096");
  BigBinaryInteger c(lbcrypto::GreatestCommonDivisor(a, b));
  return(c.ConvertToInt());
}

static bool miller_rabin_primality_is_prime_small_prime(void){
  BigBinaryInteger prime("24469");
  return( lbcrypto::MillerRabinPrimalityTest(prime));
}
static bool miller_rabin_primality_is_prime_big_prime(void){
  BigBinaryInteger prime("952229140957");
  return( lbcrypto::MillerRabinPrimalityTest(prime));
}

static bool miller_rabin_primality_is_not_prime_small_composite_number(void){
  BigBinaryInteger isNotPrime("10403");
  return(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

static bool miller_rabin_primality_is_not_prime_big_composite_number(void){
  BigBinaryInteger isNotPrime("952229140959");
  return(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

static int factorize_returns_factors(void){
  BigBinaryInteger comp("53093040");
  std::set<BigBinaryInteger> factors;
  lbcrypto::PrimeFactorize(comp, factors);
  int done = 1;
  return (done); //prevent optimizing out
}

static int prime_modulus_foundPrimeModulus(void){
  usint m = 2048;
  usint nBits = 30;
  int done = 1;
  lbcrypto::FindPrimeModulus(m, nBits);
  return (done);
}

static int prime_modulus_returns_higher_bit_length(void){
	usint m=4096; 
	usint nBits=49;
  int done = 1;
	BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(m, nBits);
	return(done);
}


static void BM_GCD1(benchmark::State& state) {
  
  int out =0;
  while (state.KeepRunning()) {
    out = greatest_common_divisor_equals_small_numbers();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}


static void BM_GCD2(benchmark::State& state) {
  
  int out =0;
  while (state.KeepRunning()) {
    out = greatest_common_divisor_equals_powers_of_two_numbers();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}

static void BM_MR1(benchmark::State& state) {
    
  int out =0;
  while (state.KeepRunning()) {
    out = miller_rabin_primality_is_prime_small_prime();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}

static void BM_MR2(benchmark::State& state) {
  
  bool out =0;
  while (state.KeepRunning()) {
    out = miller_rabin_primality_is_prime_big_prime();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}

static void BM_MR3(benchmark::State& state) {
  
  bool out =0;
  while (state.KeepRunning()) {
    out = miller_rabin_primality_is_not_prime_small_composite_number();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}

static void BM_MR4(benchmark::State& state) {
  
  bool out =0;
  while (state.KeepRunning()) {
    out = miller_rabin_primality_is_not_prime_big_composite_number();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}
static void BM_FACT1(benchmark::State& state) {
  
  bool out =0;
  while (state.KeepRunning()) {
    out = factorize_returns_factors();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}

static void BM_PM1(benchmark::State& state) {
    
  int out =0;
  while (state.KeepRunning()) {
    out = prime_modulus_foundPrimeModulus();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}
static void BM_PM2(benchmark::State& state) {
    
  int out =0;
  while (state.KeepRunning()) {
    out = prime_modulus_returns_higher_bit_length();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str());
}


BENCHMARK(BM_GCD1);
BENCHMARK(BM_GCD2);
BENCHMARK(BM_MR1);
BENCHMARK(BM_MR2);
BENCHMARK(BM_MR3);
BENCHMARK(BM_MR4);
BENCHMARK(BM_FACT1);
BENCHMARK(BM_PM1);
BENCHMARK(BM_PM2);

BENCHMARK_MAIN()
