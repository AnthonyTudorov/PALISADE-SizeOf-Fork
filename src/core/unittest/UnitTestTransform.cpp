/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
 /*
	This code tests the transform feature of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/ildcrt2n.h"
#include "math/backend.h"
#include "../lib/math/transfrm.h"
#include "../lib/math/transfrm.cpp"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilelement.h"
#include "utils/utilities.h"
#include "utils/debug.h"
#include "random"

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

/*---------------------------------------	TESTING METHODS OF TRANSFORM	  --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication){

	BigBinaryInteger primeModulus("113"); //65537
	usint cycloOrder = 8;
	usint n = cycloOrder / 2;

	BigBinaryInteger primitiveRootOfUnity = lbcrypto::RootOfUnity(cycloOrder, primeModulus);

	BigBinaryVector a(n, primeModulus);
	a.SetValAtIndex(0, "1");
	a.SetValAtIndex(1, "2");
	a.SetValAtIndex(2, "4");
	a.SetValAtIndex(3, "1");
	BigBinaryVector b(a);

	BigBinaryVector A = ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().ForwardTransform(a, primitiveRootOfUnity, cycloOrder);
	BigBinaryVector B = ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().ForwardTransform(b, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector AB = A*B;

	BigBinaryVector InverseFFTAB = ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().InverseTransform(AB, primitiveRootOfUnity, cycloOrder);

	BigBinaryVector expectedResult(n, primeModulus);
	expectedResult.SetValAtIndex(0, "94");
	expectedResult.SetValAtIndex(1, "109");
	expectedResult.SetValAtIndex(2, "11");
	expectedResult.SetValAtIndex(3, "18");

	EXPECT_EQ(expectedResult, InverseFFTAB);

}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication_small) {

	bool dbg_flag = false;

	usint m = 22;
	BigBinaryInteger squareRootOfRoot(3750);
	BigBinaryInteger modulus(4621);
	BigBinaryInteger bigModulus("32043581647489");
	BigBinaryInteger bigRoot("31971887649898");
	usint n = GetTotient(m);

	DEBUG("m is " << m << " and n is " << n);
	auto cycloPoly =  GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);
	DEBUG("2");

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);
	DEBUG("3");

	BigBinaryVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);
	DEBUG("4");

	BigBinaryVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);
	DEBUG("5");

	auto C = A*B;
	DEBUG("6");

	auto c = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

	DEBUG("7");
	auto cCheck = PolynomialMultiplication(a, b);

	DEBUG("8");
	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}


// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED USING CHINESE REMAINDER THEOREM

TEST(UTTransform, CRT_polynomial_multiplication_big_ring) {

	usint m = 1800;

	BigBinaryInteger modulus(14401);
	BigBinaryInteger bigModulus("1045889179649");
	BigBinaryInteger bigRoot("864331722621");
	BigBinaryInteger squareRootOfRoot("972");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);

	BigBinaryVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(a, squareRootOfRoot,bigModulus,bigRoot, m);

	BigBinaryVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(b, squareRootOfRoot,bigModulus,bigRoot, m);

	auto C = A*B;

	auto c = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(C, squareRootOfRoot,bigModulus,bigRoot, m);

	auto cCheck = PolynomialMultiplication(a, b);

	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_polynomial_multiplication_big_ring_prime_cyclotomics) {


	//usint m = 1733;
	//usint p = 2 * m + 1;
	//BigBinaryInteger modulusP(p);

	//BigBinaryInteger modulusQ("1152921504606909071");
	//BigBinaryInteger squareRootOfRoot("44343872016735288");

	//BigBinaryInteger bigmodulus("10889035741470030830827987437816582848513");
	//BigBinaryInteger bigroot("5879632101734955395039618227388702592012");

	usint m = 1733;

	BigBinaryInteger modulus("1152921504606909071");
	BigBinaryInteger bigModulus("10889035741470030830827987437816582848513");
	BigBinaryInteger bigRoot("5879632101734955395039618227388702592012");
	BigBinaryInteger squareRootOfRoot("44343872016735288");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigBinaryVector a(n, modulus);
	a = { 1,2,3,4,5,6,7,8,9,10 };
	auto A = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(a, squareRootOfRoot, bigModulus, bigRoot, m);

	BigBinaryVector b(n, modulus);
	b = { 5,6,7,8,9,10,11,12,13,14 };
	auto B = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(b, squareRootOfRoot, bigModulus, bigRoot, m);

	auto C = A*B;

	auto c = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(C, squareRootOfRoot, bigModulus, bigRoot, m);

	auto cCheck = PolynomialMultiplication(a, b);

	cCheck = PolyMod(cCheck, cycloPoly, modulus);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(cCheck.GetValAtIndex(i), c.GetValAtIndex(i));
	}

}


// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC FILED.
//CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

TEST(UTTransform, CRT_CHECK_small_ring) {

	usint m = 22;
	BigBinaryInteger squareRootOfRoot(3750);
	BigBinaryInteger modulus(4621);
	BigBinaryInteger bigModulus("32043581647489");
	BigBinaryInteger bigRoot("31971887649898");
	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);

	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,bigModulus,bigRoot, m);


	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot,bigModulus,bigRoot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC FILED.
//CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

TEST(UTTransform, CRT_CHECK_big_ring) {

	usint m = 1800;

	BigBinaryInteger modulus(14401);
	BigBinaryInteger squareRootOfRoot("972");
	BigBinaryInteger bigModulus("1045889179649");
	BigBinaryInteger bigRoot("864331722621");
	usint n = GetTotient(m);
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly,modulus);


	BigBinaryVector input(n, modulus);
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<> dis(0, 100); //generates a number in [0,100]
	for (usint i = 0; i < n; i++) {
		input.SetValAtIndex(i, BigBinaryInteger(dis(gen)));
	}
	
	auto output = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,bigModulus,bigRoot, m);

	auto recOut = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(output, squareRootOfRoot,bigModulus,bigRoot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), recOut.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_CHECK_small_ring_precomputed) {

	usint m = 22;
	BigBinaryInteger squareRootOfRoot(3750);
	BigBinaryInteger modulus(4621);
	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);
	BigBinaryInteger nttmodulus("32043581647489");
	BigBinaryInteger nttroot("31971887649898");

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetPreComputedNTTModulus(m, modulus, nttmodulus, nttroot);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };

	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot,nttmodulus,nttroot, m);

	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus,nttroot, m);

	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}

TEST(UTTransform, CRT_CHECK_very_big_ring_precomputed) {
	bool dbg_flag = false;
	usint m = 8422;
	DEBUG("1");
	BigBinaryInteger modulus("619578785044668429129510602549015713");//find a modulus that has 2*8422 root of unity and is 120 bit long
	BigBinaryInteger squareRootOfRoot("204851043665385327685783246012876507");
	usint n = GetTotient(m);
	DEBUG("UT GetTotient("<<m<<")= "<<n);

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);
	BigBinaryInteger nttmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigBinaryInteger nttroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetPreComputedNTTModulus(m, modulus, nttmodulus, nttroot);
	DEBUG("2");
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);
	DEBUG("3");
	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	DEBUG("4");
	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);
	DEBUG("5");
	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);
	DEBUG("6");
	for (usint i = 0; i < n; i++) {
		EXPECT_EQ(input.GetValAtIndex(i), inputCheck.GetValAtIndex(i));
	}

}
