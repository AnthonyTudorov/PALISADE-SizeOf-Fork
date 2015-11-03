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
Description:	
	This code exercises the math libraries of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <iostream>

#include "../../src/math/backend.h"
#include "../../src/utils/inttypes.h"
#include "../../src/math/nbtheory.h"
#include "../../src/lattice/ideals.h"
#include "../../src/math/distrgen.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/lattice/il2n.h"
#include "../../src/utils/utilities.h"

/*
#include "binint.h"
#include "binmat.h"
#include "binvect.h"
#include "inttypes.h"
#include "nbtheory.h"
#include "ideals.h"
#include "distrgen.h"
#include "lwecrypt.h"
#include "lwepre.h"
#include "il2n.h"
#include "utilities.h"
*/

using namespace std;
using namespace lbcrypto;

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/
class UnitTestBinInt : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*
EXPECT_EQ (expected, actual) verifies expected == actual.
Compares two integer values
*/


/*---------------------------------------	TESTING METHODS OF NBTHEORY	  --------------------------------------------*/

// TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO SMALL NUMBERS

TEST(method_greatest_common_divisor_small_numbers,equals){
	BigBinaryInteger a("10403"), b("103");
	BigBinaryInteger c = lbcrypto::GreatestCommonDivisor(a, b);

	int expectedResult = 103;

	EXPECT_EQ(expectedResult, c.ConvertToInt());
}

// TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO POWERS OF 2 NUMBERS

TEST(method_greatest_common_divisor_powers_of_two_numbers,equals){
	BigBinaryInteger a("1099511627776"), b("4096");
	BigBinaryInteger c(lbcrypto::GreatestCommonDivisor(a, b));
	
	BigBinaryInteger expectedResult(b);

	EXPECT_EQ(expectedResult, c);
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL PRIME

TEST(method_miller_rabin_primality_small_prime, is_prime){
	BigBinaryInteger prime("24469");
	EXPECT_TRUE(lbcrypto::MillerRabinPrimalityTest(prime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG PRIME

TEST(method_miller_rabin_primality_big_prime, is_prime){
	BigBinaryInteger prime("952229140957");

	EXPECT_TRUE(lbcrypto::MillerRabinPrimalityTest(prime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL COMPOSITE NUMBER

TEST(method_miller_rabin_primality_small_composite_number, is_not_prime){
	BigBinaryInteger isNotPrime("10403");

	EXPECT_FALSE(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG COMPOSITE NUMBER

TEST(method_miller_rabin_primality_big_composite_number, is_not_prime){
	BigBinaryInteger isNotPrime("952229140959");

	EXPECT_FALSE(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

// TEST CASE FOR FACTORIZATION

TEST(method_factorize, returns_factors){
	BigBinaryInteger comp("30");
	std::set<BigBinaryInteger> factors;
	lbcrypto::PrimeFactorize(comp, factors);

	for(std::set<BigBinaryInteger>::iterator it = factors.begin(); it != factors.end(); ++it) {
		// ASSERT_THAT(*it, ElementsAre(2, 3, 5));
	}
}

//TEST CASE TO FIND PRIME MODULUS

TEST(method_Find_Prime_Modulus, foundPrimeModulus){
	usint m = 2048;
	usint nBits = 30;

	BigBinaryInteger expectedResult("536881153");

	EXPECT_EQ(expectedResult, lbcrypto::FindPrimeModulus(m, nBits));
}

//TEST CASE TO FIND ROOTS OF UNITY FOR SMALL CYCLOTOMIC NUMBERS

// TEST(method_root_of_unity, foundRootOfUnity){
// 	int m = 8;
// 	BigBinaryInteger prime("17");

// 	BigBinaryInteger expectedResult("15");

// 	ASSERT_EQ(expectedResult, lbcrypto::RootOfUnity(m, prime));
// }

// TEST(random_number_generator, less_than) {
// 	BigBinaryInteger prime("101");
// 	ASSERT_EQ(lbcrypto::RNG(prime), prime);
// }

// TEST(method_witness_function, is_composite){
// 	BigBinaryInteger prime("101");
// 	const BigBinaryInteger a = lbcrypto::RNG(prime);
// 	BigBinaryInteger d("25");
// 	std::cout << " witnessFunction result for " << prime << " is " << lbcrypto::witnessFunction(a, d, 2, prime) << std::endl;
// }

// TEST(method_pollard_rho_factorization, factors){
// 	BigBinaryInteger comp("124");
// 	std::cout << "A factor of " << comp << " is " << lbcrypto::PollardRho(comp) << std::endl;
// }

