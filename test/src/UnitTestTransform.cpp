/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	12/22/2015 2:37PM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
Description:
	This code tests the transform feature of the PALISADE lattice encryption library.

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

class UnitTestTransform : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

void printBBV(const BigBinaryVector &b);
void printRootsOfUnity(const BigBinaryInteger &primitiveRootOfUnity, const BigBinaryInteger &primeModulus, usint n);
void printBinMatrix(const BigBinaryMatrix &b);

/*---------------------------------------	TESTING METHODS OF TRANSFORM	  --------------------------------------------*/

// TEST CASE TO TEST BASIC FUNCTIONALITY OF CHINESE REMAINDER TRANSFORM

TEST(method_test_CRT, basic_input_output_compares){
	BigBinaryInteger primeModulus("17"); //65537
	usint cycloOrder = 8;
	usint n = cycloOrder / 2;

	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);
	// std::cout <<"The primitiveRootOfUnity for modulus " << primeModulus << " is " << primitiveRootOfUnity << std::endl;
	// printRootsOfUnity(primitiveRootOfUnity, primeModulus, n);

	BigBinaryVector crt[n];
	for(int i=0; i<n; i++) {
		crt[i] = BigBinaryVector(n, primeModulus);
		for(int j=0; j<n; j++) {
			crt[i].SetValAtIndex(j, BigBinaryInteger(primitiveRootOfUnity.ModExp(BigBinaryInteger(i*j), primeModulus)));
		}
	}

	BigBinaryVector a(n, primeModulus);
	a.SetValAtIndex(0, BigBinaryInteger::ONE);
	a.SetValAtIndex(1, BigBinaryInteger::ZERO);
	a.SetValAtIndex(2, BigBinaryInteger::ZERO);
	a.SetValAtIndex(3, BigBinaryInteger::ZERO);
	BigBinaryVector A = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector expectedA(n, primeModulus);
	for(int i=0; i<n; i++) {
		expectedA.SetValAtIndex(i, BigBinaryInteger::ONE);
	}
	EXPECT_EQ(expectedA, A);

	BigBinaryVector b(n, primeModulus);
	b.SetValAtIndex(0, BigBinaryInteger::ZERO);
	b.SetValAtIndex(1, BigBinaryInteger::ONE);
	b.SetValAtIndex(2, BigBinaryInteger::ZERO);
	b.SetValAtIndex(3, BigBinaryInteger::ZERO);
	BigBinaryVector B = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector expectedB(n, primeModulus);
	for(int i=0; i<n; i++) {
		expectedB.SetValAtIndex(i, BigBinaryInteger(primitiveRootOfUnity.ModExp(BigBinaryInteger(2*i+1), primeModulus)));
	}
	EXPECT_EQ(expectedB, B);

	/*BigBinaryVector c(n, primeModulus);
	c.SetValAtIndex(0, BigBinaryInteger::ZERO);
	c.SetValAtIndex(1, BigBinaryInteger::ONE);
	c.SetValAtIndex(2, BigBinaryInteger::ONE);
	c.SetValAtIndex(3, BigBinaryInteger::ZERO);
	std::cout << "Vector Before Transform: " << std::endl;
	printBBV(c);

	BigBinaryVector C = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(c, primitiveRootOfUnity, cycloOrder);
	std::cout << "Vector After Transform: " << std::endl;
	printBBV(C);*/

}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM.
// Currently this test case is not complete as there is no code in src/ to multiply two BigBinaryVector's in COEFFICIENT form.

TEST(method_CRT_polynomial_multiplication, compares_to_brute_force_multiplication){

	BigBinaryInteger primeModulus("101"); //65537
	usint cycloOrder = 4;
	usint n = cycloOrder / 2;

	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);
	std::cout <<"The primitiveRootOfUnity for modulus " << primeModulus << " is " << primitiveRootOfUnity << std::endl;

	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(primeModulus);
	BigBinaryVector a = distrUniGen.GenerateVector(n);
	BigBinaryVector b = distrUniGen.GenerateVector(n);
	std::cout << "Generated vectors: " << a << " and " << b << std::endl;

	BigBinaryVector A = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector B = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector AB = A.ModMul(B);
	BigBinaryVector ab = a.ModMul(b);

	BigBinaryVector InverseFFTAB = ChineseRemainderTransform::GetInstance().InverseTransform(AB, primitiveRootOfUnity, cycloOrder);
	// EXPECT_EQ(ab, InverseFFTAB);
}

void printBBV(const BigBinaryVector &b){
	std::cout << "Printing BBV values:" << std::endl;
	for(usint i=0; i<b.GetLength(); i++) {
		std::cout << i << "		" << b.GetValAtIndex(i) << std::endl;
	}
	std::cout << std::endl;
}

void printRootsOfUnity(const BigBinaryInteger &primitiveRootOfUnity, const BigBinaryInteger &primeModulus, usint n){
	std::cout << "Printing roots of unity: " << std::endl;
	for(usint i=0; i<n; i++){
		std::cout << i << "		" << primitiveRootOfUnity.ModExp(BigBinaryInteger(i), primeModulus) << std::endl;
	}
}

void printBinMatrix(const BigBinaryMatrix &b){
	std::cout <<  "Printing the matrix: " << std::endl;
	for(usint i=0; i<b.GetRowSize(); i++){
		for(usint j=0; j<b.GetColumnSize(); j++){
			std::cout << b.GetValAtIndex(i, j) << "	";
		}
		std::cout << std::endl;
	}
}