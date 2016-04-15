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
		Dr. David Bruce Cousins, dcousins@bbn.com
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

#include "../include/gtest/gtest.h"
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

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/
class UnitTestNbTheory : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};


/*----------------------------	TESTING METHODS OF NBTHEORY	  --------------------------------------------*/

// TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO SMALL NUMBERS

TEST(method_greatest_common_divisor,equals_small_numbers){
	BigBinaryInteger a("10403"), b("103");
	BigBinaryInteger c = lbcrypto::GreatestCommonDivisor(a, b);

	int expectedResult = 103;

	EXPECT_EQ(expectedResult, c.ConvertToInt());
}

// TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO POWERS OF 2 NUMBERS

TEST(method_greatest_common_divisor,equals_powers_of_two_numbers){
	BigBinaryInteger a("1048576"), b("4096");
	BigBinaryInteger c(lbcrypto::GreatestCommonDivisor(a, b));
	
	BigBinaryInteger expectedResult(b);

	EXPECT_EQ(expectedResult, c);
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL PRIME

TEST(method_miller_rabin_primality, is_prime_small_prime){
	BigBinaryInteger prime("24469");
	EXPECT_TRUE(lbcrypto::MillerRabinPrimalityTest(prime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG PRIME

TEST(method_miller_rabin_primality, is_prime_big_prime){
	BigBinaryInteger prime("952229140957");

	EXPECT_TRUE(lbcrypto::MillerRabinPrimalityTest(prime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL COMPOSITE NUMBER

TEST(method_miller_rabin_primality, is_not_prime_small_composite_number){
	BigBinaryInteger isNotPrime("10403");

	EXPECT_FALSE(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

// TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG COMPOSITE NUMBER

TEST(method_miller_rabin_primality, is_not_prime_big_composite_number){
	BigBinaryInteger isNotPrime("952229140959");

	EXPECT_FALSE(lbcrypto::MillerRabinPrimalityTest(isNotPrime));
}

// TEST CASE FOR FACTORIZATION

TEST(method_factorize, returns_factors){
	BigBinaryInteger comp("53093040");
	std::set<BigBinaryInteger> factors;
	lbcrypto::PrimeFactorize(comp, factors);

	for(std::set<BigBinaryInteger>::iterator it = factors.begin(); it != factors.end(); ++it) {
		// std::cout << *it << std::endl;
		// ASSERT_THAT(*it, ElementsAre(2, 3, 5));
	}
}

//TEST CASE TO FIND PRIME MODULUS

TEST(method_prime_modulus, foundPrimeModulus){
	usint m = 2048;
	usint nBits = 30;

	BigBinaryInteger expectedResult("536881153");

	EXPECT_EQ(expectedResult, lbcrypto::FindPrimeModulus(m, nBits));
}

// TEST CASE TO FIND PRIME MODULUS FOR A HIGHER BIT LENGTH 

//TEST(method_prime_modulus, returns_higher_bit_length){
	
//	usint m=4096; 
//	usint nBits=49;
	
//	BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(m, nBits);
//	BigBinaryInteger expectedResult("281474976768001");
//	EXPECT_EQ(expectedResult, primeModulus);
//}

//TEST CASE TO ENSURE THE ROOT OF UNITY THAT IS FOUND IS A PRIMITIVE ROOT OF UNTIY

TEST(method_primitive_root_of_unity, equals_m_not_equals_mbytwo){
	
	usint m=4096; 
	usint nBits=33;
	
	BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(m, nBits);
	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(m, primeModulus);

	BigBinaryInteger M(std::to_string(m)), MbyTwo(M.DividedBy(BigBinaryInteger::TWO));

	BigBinaryInteger wpowerm = primitiveRootOfUnity.ModExp(M, primeModulus);
	EXPECT_EQ(wpowerm, BigBinaryInteger::ONE);

	BigBinaryInteger wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
	EXPECT_NE(wpowermbytwo, BigBinaryInteger::ONE);
}

//TEST CASE TO ENSURE THE ROOTS OF UNITY THAT ARE FOUND ARE CONSISTENTLY THE PRIMITIVE ROOTS OF UNTIY

TEST(method_primitive_root_of_unity, equals_m_not_equals_mbytwo_mbyfour_single_input){

	const usint n=2048;
	const usint m=2*n;
	const usint nBits=43;
	const int ITERATIONS = m*2;

	BigBinaryInteger M(std::to_string(m)), MbyTwo(M.DividedBy(BigBinaryInteger::TWO)), MbyFour(MbyTwo.DividedBy(BigBinaryInteger::TWO));

	BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(m, nBits);

	for(int i=0; i<ITERATIONS; i++) {
		BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(m, primeModulus);

		BigBinaryInteger wpowerm = primitiveRootOfUnity.ModExp(M, primeModulus);
		EXPECT_EQ(wpowerm, BigBinaryInteger::ONE);

		BigBinaryInteger wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
		EXPECT_NE(wpowermbytwo, BigBinaryInteger::ONE);

		BigBinaryInteger wpowermbyfour = primitiveRootOfUnity.ModExp(MbyFour, primeModulus);
		EXPECT_NE(wpowermbyfour, BigBinaryInteger::ONE);
	}
}

//TEST CASE TO ENSURE THE ROOTS OF UNITY FOUND FOR MULTIPLE CYCLOTOMIC NUMBERS ARE ALL PRIMITIVE ROOTS OF UNTIY

TEST(method_primitive_root_of_unity, equals_m_not_equals_mbytwo_mbyfour_multiple_inputs){
	// ofstream fout;
	// fout.open ("primitiveRootsBug.log");
	usint nqBitsArray[] = {
		1, 1 
		,2, 4
		,8, 20
		,1024, 30
		,2048, 31 
		,2048, 33
		,2048, 40
		,2048, 41 
		//NOTE: To test for prime modulus greater than bit length of 50, set the following two constants in binint.h and dtstruct.h: 
		// const usint BIT_LENGTH = 200 and const usint FRAGMENTATION_FACTOR = 27
		// ,2048, 51
		,4096, 32 
		,4096, 43 
		// ,4096, 53 
		,8192, 33 
		,8192, 44 
		// ,8192, 55 
		,16384, 34 
		,16384, 46 
		// ,16384, 57 
		,32768, 35 
		,32768, 47 
		// ,32768, 59 
	};
	int length = sizeof(nqBitsArray)/sizeof(nqBitsArray[0]);
	// double diff, start, finish;
	usint n, qBits, m;
	// BigBinaryInteger M(std::to_string(m)), MbyTwo(M.DividedBy(BigBinaryInteger::TWO)), MbyFour(MbyTwo.DividedBy(BigBinaryInteger::TWO));

	for(int i=2; i<length; i += 2) {
		// fout << "----------------------------------------------------------------------------------------------------------------------------------" << endl;
		// fout << "i = " << i << endl;
		n = nqBitsArray[i];
		qBits = nqBitsArray[i+1];
		m = 2 * n;

		BigBinaryInteger M(std::to_string(m)), MbyTwo(M.DividedBy(BigBinaryInteger::TWO)), MbyFour(MbyTwo.DividedBy(BigBinaryInteger::TWO));

		// start = currentDateTime();
		// fout << "m=" << m << ", qBits=" << qBits << ", M=" << M << ", MbyTwo=" << MbyTwo << endl;
		BigBinaryInteger primeModulus = lbcrypto::FindPrimeModulus(m, qBits);
		// fout << "Prime modulus for n = " << n << " and qbits = " << qBits << " is " << primeModulus << endl;

		BigBinaryInteger primitiveRootOfUnity(lbcrypto::RootOfUnity(m, primeModulus));

		// fout << "The primitiveRootOfUnity is " << primitiveRootOfUnity << endl;

		// std::set<BigBinaryInteger> rootsOfUnity = testRootsOfUnity(m, primeModulus);

		// fout << "Roots of unity for prime modulus " << primeModulus << " are: " << endl;
		// for(std::set<BigBinaryInteger>::iterator it = rootsOfUnity.begin(); it != rootsOfUnity.end(); ++it) {
		// 	fout << (*it) << ", ";
		// }
		// fout << endl;
		// finish = currentDateTime();
		// diff = finish - start;
		// fout << "Computation time: " << "\t" << diff << " ms" << endl;
		// fout << "----------------------------------------------------------------------------------------------------------------------------------" << endl;

		BigBinaryInteger wpowerm = primitiveRootOfUnity.ModExp(M, primeModulus);
		// fout << "w^m = " << wpowerm << endl;
		EXPECT_EQ(wpowerm, BigBinaryInteger::ONE);

		BigBinaryInteger wpowermbytwo = primitiveRootOfUnity.ModExp(MbyTwo, primeModulus);
		// fout << "w^(m/2) = " << wpowermbytwo << endl;
		EXPECT_NE(wpowermbytwo, BigBinaryInteger::ONE);

		BigBinaryInteger wpowermbyfour = primitiveRootOfUnity.ModExp(MbyFour, primeModulus);
		// fout << "w^(m/4) = " << wpowermbyfour << endl;
		EXPECT_NE(wpowermbyfour, BigBinaryInteger::ONE);
		// fout << "----------------------------------------------------------------------------------------------------------------------------------" << endl;
		// fout << endl;
	}
	// fout << "End of Computation" << endl;
	// fout.close();

}

TEST(method_primitive_root_of_unity, exception_handling) {
	
	int m = 32;
	BigBinaryInteger modulus1("67108913"), modulus2("17729"), modulus3("2097169"), modulus4("8353"), modulus5("8369");

	//note this example shows two ways of testing for an exception throw
	BigBinaryInteger primitiveRootOfUnity1;

	//the first way is to catch the error and expect the result. 
	int caught_error = 0;
	try{
	  primitiveRootOfUnity1 = lbcrypto::RootOfUnity(m, modulus1); 
	}
	catch(...) {
	  caught_error = 1;
	}
	EXPECT_EQ(caught_error, 1)<<"RootOfUnity did not throw an error and should have";
	
	// the second way is to directly expect the throw. 
	EXPECT_ANY_THROW(	// this call should throw 
	  primitiveRootOfUnity1 = lbcrypto::RootOfUnity(m, modulus1); 
	)<<"RootOfUnity did not throw an error and should have";

	BigBinaryInteger primitiveRootOfUnity2;
	EXPECT_NO_THROW(	// this call should NOT throw 
	  primitiveRootOfUnity2 = lbcrypto::RootOfUnity(m, modulus2); 
	)<<"RootOfUnity threw an error and should not have";

	std::cout << "RootOfUnity for " << modulus1 << " is " << primitiveRootOfUnity1 << std::endl;
	std::cout << "RootOfUnity for " << modulus2 << " is " << primitiveRootOfUnity2 << std::endl;

}

// TEST(random_number_generator_small_modulus, less_than) {
// 	BigBinaryInteger prime("101");
// 	const int ITERATIONS = 101;
// 	for(int i=0; i<ITERATIONS; i++)
// 		ASSERT_LT(lbcrypto::RNG(prime), prime);
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
