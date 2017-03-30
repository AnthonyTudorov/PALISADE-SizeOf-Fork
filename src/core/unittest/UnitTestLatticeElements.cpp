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

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"

using namespace std;
using namespace lbcrypto;

class UnitTestLatticeElements : public ::testing::Test {
protected:
	virtual void SetUp() {
	}

	virtual void TearDown() {
		// Code here will be called immediately after each test
		// (right before the destructor).
	}

public:
	static const usint test = 1;
};

void testILVectorArray2nConstructorNegative(std::vector<native64::ILVector2n> &towers);

/*--------------------------------------- TESTING METHODS OF LATTICE ELEMENTS    --------------------------------------------*/

template<typename IntType, typename VecType, typename ParmType, typename Element>
static void operators_tests() {
	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1.SetValAtIndex(0, "1");
	bbv1.SetValAtIndex(1, "2");
	bbv1.SetValAtIndex(2, "0");
	bbv1.SetValAtIndex(3, "1");
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	Element ilvector2n2(ilparams);
	VecType bbv2(m/2, primeModulus);
	bbv2.SetValAtIndex(0, "1");
	bbv2.SetValAtIndex(1, "2");
	bbv2.SetValAtIndex(2, "0");
	bbv2.SetValAtIndex(3, "1");
	ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

	EXPECT_EQ(ilvector2n1, ilvector2n2) << "Operator == fails";


	{
		Element ilv1(ilvector2n1);
		EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) << "copy constructor fails";
		EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) << "copy constructor fails";
	}

	{
		Element ilv1 = ilvector2n1;
		EXPECT_EQ(ilvector2n1.GetFormat(), ilv1.GetFormat()) << "Get Format fails";
		EXPECT_EQ(ilvector2n1.GetValues(), ilv1.GetValues()) << "Get Format fails";
	}

	{
		Element ilv1 = ilvector2n1;
		ilv1.SwitchModulus(IntType("123467"), IntType("1234"));
		EXPECT_NE(ilvector2n1, ilv1) << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare modulus properly.\n";

		Element ilv2 = ilvector2n1;
		ilv2.SetValAtIndex(2, 2);
		EXPECT_NE(ilvector2n1, ilv2) << "ILVector2n_operator!=: Operator!= is incorrect. It did not compare values properly.\n";
	}

	{
		Element ilv1 = ilvector2n1;
		ilv1 -= ilvector2n1;
		for (usint i = 0; i < m/2; ++i) {
			EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(i)) << "ILVector2n_operator-=: Operator-= is incorrect.\n";
		}
	}

	{
		Element ilv1 = ilvector2n1;
		ilv1 += ilvector2n1;
		for (usint i = 0; i < m/2; ++i)
		{
			EXPECT_EQ(IntType::TWO * ilvector2n1.GetValAtIndex(i), ilv1.GetValAtIndex(i)) << "ILVector2n_operator+=: Operator+= is incorrect.\n";
		}
	}

	{
		Element ilvector2n(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "1");
		bbv.SetValAtIndex(1, "2");
		bbv.SetValAtIndex(2, "0");
		bbv.SetValAtIndex(3, "1");
		ilvector2n.SetValues(bbv, ilvector2n.GetFormat());

		EXPECT_EQ(primeModulus, ilvector2n.GetModulus()) << "ILVector2n.GetModulus is incorrect.\n";
		EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder()) << "ILVector2n.GetCyclotomicOrder is incorrect.\n";
		EXPECT_EQ(primitiveRootOfUnity, ilvector2n.GetRootOfUnity()) << "ILVector2n.GetRootOfUnity is incorrect.\n";
		EXPECT_EQ(bbv, ilvector2n.GetValues()) << "ILVector2n.GetValues is incorrect.\n";
		EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat()) << "ILVector2n.GetFormat is incorrect.\n";
		EXPECT_EQ(m/2, ilvector2n.GetLength()) << "ILVector2n.GetLength is incorrect.\n";
		for (usint i = 0; i < m/2; ++i) {
			EXPECT_EQ(bbv.GetValAtIndex(i), ilvector2n.GetValAtIndex(i)) << "ILVector2n.GetValAtIndex is incorrect.\n";
		}
	}

}

TEST(UTILVector2n, ops_tests) {
	operators_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, ops_tests) {
	operators_tests<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, ops_tests) {
//	operators_tests<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void rounding_operations() {
	usint m = 8;

	IntType q("73");
	IntType primitiveRootOfUnity("22");
	IntType p("8");

	shared_ptr<ParmType> ilparams( new ParmType(m, q, primitiveRootOfUnity) );

	//temporary larger modulus that is used for polynomial multiplication before rounding
	IntType q2("16417");
	IntType primitiveRootOfUnity2("13161");

	shared_ptr<ParmType> ilparams2( new ParmType(m, q2, primitiveRootOfUnity2) );

	Element ilvector2n1(ilparams,COEFFICIENT);
	ilvector2n1 = { 31,21,15,34};

	Element ilvector2n2(ilparams,COEFFICIENT);
	ilvector2n2 = { 21,11,35,32 };

	//unit test for MultiplyAndRound

	Element roundingCorrect1(ilparams, COEFFICIENT);
	roundingCorrect1 = { 3,2,2,4 };

	Element rounding1 = ilvector2n1.MultiplyAndRound(p, q);

	EXPECT_EQ(roundingCorrect1, rounding1) << "Rounding p*polynomial/q is incorrect.\n";

	//unit test for MultiplyAndRound after a polynomial multiplication using the larger modulus

	Element roundingCorrect2(ilparams2, COEFFICIENT);
	roundingCorrect2 = { 16316, 16320, 60, 286 };

	ilvector2n1.SwitchModulus(q2, primitiveRootOfUnity2);
	ilvector2n2.SwitchModulus(q2, primitiveRootOfUnity2);

	ilvector2n1.SwitchFormat();
	ilvector2n2.SwitchFormat();

	Element rounding2 = ilvector2n1 * ilvector2n2;
	rounding2.SwitchFormat();

	rounding2 = rounding2.MultiplyAndRound(p, q);

	EXPECT_EQ(roundingCorrect2, rounding2) << "Rounding p*polynomial1*polynomial2/q is incorrect.\n";

	//makes sure the result is correct after going back to the original modulus

	rounding2.SwitchModulus(q, primitiveRootOfUnity);

	Element roundingCorrect3(ilparams, COEFFICIENT);
	roundingCorrect3 = { 45, 49, 60, 67 };

	EXPECT_EQ(roundingCorrect3, rounding2) << "Rounding p*polynomial1*polynomial2/q (mod q) is incorrect.\n";

}

TEST(UTILVector2n, rounding_operations) {
	rounding_operations<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, rounding_operations) {
	rounding_operations<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, rounding_operations) {
//	rounding_operations<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void setters_tests() {
	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv.SetValAtIndex(0, "3");
	bbv.SetValAtIndex(1, "0");
	bbv.SetValAtIndex(2, "0");
	bbv.SetValAtIndex(3, "0");
	ilvector2n.SetValues(bbv, Format::COEFFICIENT);

	Element ilvector2nInEval(ilparams);
	VecType bbvEval(m/2, primeModulus);
	bbvEval.SetValAtIndex(0, "3");
	bbvEval.SetValAtIndex(1, "3");
	bbvEval.SetValAtIndex(2, "3");
	bbvEval.SetValAtIndex(3, "3");
	ilvector2nInEval.SetValues(bbvEval, Format::EVALUATION);

	{
		Element ilv(ilvector2n);

		ilv.SetFormat(Format::COEFFICIENT);
		EXPECT_EQ(ilvector2n, ilv) << "ILVector2n.SetFormat is incorrect. Setting the format to COEFFICIENT is incorrect.\n";

		ilv.SetFormat(Format::EVALUATION);
		EXPECT_EQ(ilvector2nInEval, ilv) << "ILVector2n.SetFormat is incorrect. Setting the format to EVALUATION is incorrect.\n";
	}

	// this is here because it's a vectors-only test
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "56");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "37");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		EXPECT_EQ(36, ilv.Norm());
	}

}

TEST(UTILVector2n, setters_tests) {
	setters_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, setters_tests) {
	setters_tests<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void binary_operations() {
	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1.SetValAtIndex(0, "2");
	bbv1.SetValAtIndex(1, "1");
	bbv1.SetValAtIndex(2, "1");
	bbv1.SetValAtIndex(3, "1");
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	Element ilvector2n2(ilparams);
	VecType bbv2(m/2, primeModulus);
	bbv2.SetValAtIndex(0, "1");
	bbv2.SetValAtIndex(1, "0");
	bbv2.SetValAtIndex(2, "1");
	bbv2.SetValAtIndex(3, "1");
	ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());

	Element ilvector2n3(ilparams, COEFFICIENT);
	VecType bbv3(m / 2, primeModulus);
	bbv3.SetValAtIndex(0, "2");
	bbv3.SetValAtIndex(1, "1");
	bbv3.SetValAtIndex(2, "1");
	bbv3.SetValAtIndex(3, "1");
	ilvector2n3.SetValues(bbv3, ilvector2n3.GetFormat());

	Element ilvector2n4(ilparams, COEFFICIENT);
	VecType bbv4(m / 2, primeModulus);
	bbv4.SetValAtIndex(0, "1");
	bbv4.SetValAtIndex(1, "0");
	bbv4.SetValAtIndex(2, "1");
	bbv4.SetValAtIndex(3, "1");
	ilvector2n4.SetValues(bbv4, ilvector2n4.GetFormat());

	{
		Element ilv1(ilvector2n1);
		Element ilv2 = ilv1.Plus(ilvector2n2);

		EXPECT_EQ(IntType::THREE, ilv2.GetValAtIndex(0)) << "ILVector2n.Plus is incorrect.\n";
		EXPECT_EQ(IntType::ONE, ilv2.GetValAtIndex(1)) << "ILVector2n.Plus is incorrect.\n";
		EXPECT_EQ(IntType::TWO, ilv2.GetValAtIndex(2)) << "ILVector2n.Plus is incorrect.\n";
		EXPECT_EQ(IntType::TWO, ilv2.GetValAtIndex(3)) << "ILVector2n.Plus is incorrect.\n";
	}

	{
		Element ilv1(ilvector2n1);
		Element ilv2 = ilv1.Minus(ilvector2n2);

		EXPECT_EQ(IntType::ONE, ilv2.GetValAtIndex(0)) << "ILVector2n.Minus is incorrect.\n";
		EXPECT_EQ(IntType::ONE, ilv2.GetValAtIndex(1)) << "ILVector2n.Minus is incorrect.\n";
		EXPECT_EQ(IntType::ZERO, ilv2.GetValAtIndex(2)) << "ILVector2n.Minus is incorrect.\n";
		EXPECT_EQ(IntType::ZERO, ilv2.GetValAtIndex(3)) << "ILVector2n.Minus is incorrect.\n";
	}

	{
		Element ilv1(ilvector2n1);
		Element ilv2 = ilv1.Times(ilvector2n2);

		EXPECT_EQ(IntType::TWO, ilv2.GetValAtIndex(0)) << "ILVector2n.Times is incorrect.\n";
		EXPECT_EQ(IntType::ZERO, ilv2.GetValAtIndex(1)) << "ILVector2n.Times is incorrect.\n";
		EXPECT_EQ(IntType::ONE, ilv2.GetValAtIndex(2)) << "ILVector2n.Times is incorrect.\n";
		EXPECT_EQ(IntType::ONE, ilv2.GetValAtIndex(3)) << "ILVector2n.Times is incorrect.\n";
	}

	{
		ilvector2n3.SwitchFormat();
		ilvector2n4.SwitchFormat();

		Element ilv3(ilvector2n3);
		Element ilv4 = ilv3.Times(ilvector2n4);

		ilv4.SwitchFormat();

		EXPECT_EQ(IntType::ZERO, ilv4.GetValAtIndex(0)) << "ILVector2n.Times using NTT is incorrect.\n";
		EXPECT_EQ(IntType("72"), ilv4.GetValAtIndex(1)) << "ILVector2n.Times using NTT is incorrect.\n";
		EXPECT_EQ(IntType::TWO, ilv4.GetValAtIndex(2)) << "ILVector2n.Times using NTT is incorrect.\n";
		EXPECT_EQ(IntType::FOUR, ilv4.GetValAtIndex(3)) << "ILVector2n.Times using NTT is incorrect.\n";
	}

}

TEST(UTILVector2n, binary_operations) {
	binary_operations<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, binary_operations) {
	binary_operations<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, binary_operations) {
//	binary_operations<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void clone_operations() {
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv.SetValAtIndex(0, "2");
	bbv.SetValAtIndex(1, "1");
	bbv.SetValAtIndex(2, "1");
	bbv.SetValAtIndex(3, "1");
	ilv.SetValues(bbv, ilv.GetFormat());

	{
		Element ilvClone = ilv.CloneParametersOnly();

		EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder());
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus());
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity());
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat());
	}

	{
		float stdDev = 4;
		DiscreteGaussianGeneratorImpl<IntType,VecType> dgg(stdDev);
		Element ilvClone = ilv.CloneWithNoise(dgg, ilv.GetFormat());

		EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder());
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus());
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity());
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat());
	}

	{
		//    float stdDev = 4;
		//    DiscreteGaussianGeneratorImpl<IntType,VecType> dgg(stdDev);
		Element ilvClone = ilv.CloneWithNoise(DiscreteGaussianGen, ilv.GetFormat());

		EXPECT_EQ(ilv.GetCyclotomicOrder(), ilvClone.GetCyclotomicOrder());
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus());
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity());
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat());
	}
}

TEST(UTILVector2n, clone_operations) {
	clone_operations<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, clone_operations) {
	clone_operations<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, clone_operations) {
//	clone_operations<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void arithmetic_operations_element() {
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv.SetValAtIndex(0, "2");
	bbv.SetValAtIndex(1, "1");
	bbv.SetValAtIndex(2, "4");
	bbv.SetValAtIndex(3, "1");
	ilv.SetValues(bbv, ilv.GetFormat());

	IntType element("1");

	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "1");
		bbv1.SetValAtIndex(1, "3");
		bbv1.SetValAtIndex(2, "4");
		bbv1.SetValAtIndex(3, "1");
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n = ilvector2n.Plus(element);

		EXPECT_EQ(IntType::TWO, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::THREE, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType::FOUR, ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::ONE, ilvector2n.GetValAtIndex(3));
	}

	{
		Element ilvector2n = ilv.Minus(element);

		EXPECT_EQ(IntType::ONE, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType::THREE, ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(3));
	}

	{
		IntType ele("2");
		Element ilvector2n = ilv.Times(ele);

		EXPECT_EQ(IntType::FOUR, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::TWO, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType("8"), ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::TWO, ilvector2n.GetValAtIndex(3));
	}

	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "1");
		bbv1.SetValAtIndex(1, "3");
		bbv1.SetValAtIndex(2, "4");
		bbv1.SetValAtIndex(3, "1");
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n += element;

		EXPECT_EQ(IntType::TWO, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::THREE, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType::FOUR, ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::ONE, ilvector2n.GetValAtIndex(3));
	}

	{
		Element ilvector2n = ilv.Minus(element);

		EXPECT_EQ(IntType::ONE, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType::THREE, ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(3));
	}

	{
		Element ilvector2n(ilv);
		ilvector2n -= element;

		EXPECT_EQ(IntType::ONE, ilvector2n.GetValAtIndex(0));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(1));
		EXPECT_EQ(IntType::THREE, ilvector2n.GetValAtIndex(2));
		EXPECT_EQ(IntType::ZERO, ilvector2n.GetValAtIndex(3));
	}

}

TEST(UTILVector2n, arithmetic_operations_element) {
	arithmetic_operations_element<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, arithmetic_operations_element) {
	arithmetic_operations_element<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, arithmetic_operations_element) {
//	arithmetic_operations_element<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void other_methods() {
	bool dbg_flag = false;
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	float stdDev = 4.0;
	DiscreteGaussianGeneratorImpl<IntType,VecType> dgg(stdDev);
	BinaryUniformGeneratorImpl<IntType,VecType> bug;
	DiscreteUniformGeneratorImpl<IntType,VecType> dug(primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1.SetValAtIndex(0, "2");
	bbv1.SetValAtIndex(1, "1");
	bbv1.SetValAtIndex(2, "3");
	bbv1.SetValAtIndex(3, "2");
	ilvector2n.SetValues(bbv1, Format::EVALUATION);

	DEBUG("1");
	{
		Element ilv(ilvector2n);

		ilv.AddILElementOne();

		EXPECT_EQ(IntType::THREE, ilv.GetValAtIndex(0));
		EXPECT_EQ(IntType::TWO, ilv.GetValAtIndex(1));
		EXPECT_EQ(IntType::FOUR, ilv.GetValAtIndex(2));
		EXPECT_EQ(IntType::THREE, ilv.GetValAtIndex(3));
	}

	DEBUG("2");
	{
		Element ilv(ilvector2n);
		ilv = ilv.ModByTwo();

		EXPECT_EQ(IntType::ZERO, ilv.GetValAtIndex(0));
		EXPECT_EQ(IntType::ONE, ilv.GetValAtIndex(1));
		EXPECT_EQ(IntType::ONE, ilv.GetValAtIndex(2));
		EXPECT_EQ(IntType::ZERO, ilv.GetValAtIndex(3));
	}

	DEBUG("3");
	{
		Element ilv(ilvector2n);
		ilv.MakeSparse(2);

		EXPECT_EQ(IntType::TWO, ilv.GetValAtIndex(0));
		EXPECT_EQ(IntType::ZERO, ilv.GetValAtIndex(1));
		EXPECT_EQ(IntType::THREE, ilv.GetValAtIndex(2));
		EXPECT_EQ(IntType::ZERO, ilv.GetValAtIndex(3));

		Element ilv1(ilvector2n);
		ilv1.MakeSparse(3);

		EXPECT_EQ(IntType::TWO, ilv1.GetValAtIndex(0));
		EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(1));
		EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(2));
		EXPECT_EQ(IntType::TWO, ilv1.GetValAtIndex(3));
	}

	DEBUG("4");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "2");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "3");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.Decompose();

		EXPECT_EQ(2, ilv.GetLength());

		EXPECT_EQ(IntType::TWO, ilv.GetValAtIndex(0)) << "ILVector2n_decompose: Values do not match between original and decomposed elements.";
		EXPECT_EQ(IntType::THREE, ilv.GetValAtIndex(1)) << "ILVector2n_decompose: Values do not match between original and decomposed elements.";
	}

	DEBUG("5");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "2");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "3");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv.GetModulus());
		EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity());
		EXPECT_EQ(Format::EVALUATION, ilv.GetFormat());
		EXPECT_EQ(IntType("69"), ilv.GetValAtIndex(0));
		EXPECT_EQ(IntType("44"), ilv.GetValAtIndex(1));
		EXPECT_EQ(IntType("65"), ilv.GetValAtIndex(2));
		EXPECT_EQ(IntType("49"), ilv.GetValAtIndex(3));


		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "2");
		bbv1.SetValAtIndex(1, "1");
		bbv1.SetValAtIndex(2, "3");
		bbv1.SetValAtIndex(3, "2");
		ilv1.SetValues(bbv1, Format::EVALUATION);

		ilv1.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv1.GetModulus());
		EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity());
		EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat());
		EXPECT_EQ(IntType::TWO, ilv1.GetValAtIndex(0));
		EXPECT_EQ(IntType::THREE, ilv1.GetValAtIndex(1));
		EXPECT_EQ(IntType("50"), ilv1.GetValAtIndex(2));
		EXPECT_EQ(IntType::THREE, ilv1.GetValAtIndex(3));
	}

	DEBUG("6");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "2");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "3");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilvector2n1(ilparams);
		Element ilvector2n2(ilparams);
		Element ilvector2n3(ilv);
		Element ilvector2n4(dgg, ilparams);
		Element ilvector2n5(bug, ilparams);
		Element ilvector2n6(dug, ilparams);

		EXPECT_EQ(true, ilvector2n1.IsEmpty());
		EXPECT_EQ(true, ilvector2n2.IsEmpty());
		EXPECT_EQ(false, ilvector2n3.IsEmpty());
		EXPECT_EQ(false, ilvector2n4.IsEmpty());
		EXPECT_EQ(false, ilvector2n5.IsEmpty());
		EXPECT_EQ(false, ilvector2n6.IsEmpty());
	}

	DEBUG("7");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "56");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "37");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		IntType modulus("17");
		IntType rootOfUnity("15");

		ilv.SwitchModulus(modulus, rootOfUnity);

		EXPECT_EQ(IntType::ZERO, ilv.GetValAtIndex(0));
		EXPECT_EQ(IntType::ONE, ilv.GetValAtIndex(1));
		EXPECT_EQ(IntType("15"), ilv.GetValAtIndex(2));
		EXPECT_EQ(IntType::TWO, ilv.GetValAtIndex(3));

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "56");
		bbv1.SetValAtIndex(1, "43");
		bbv1.SetValAtIndex(2, "35");
		bbv1.SetValAtIndex(3, "28");
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		IntType modulus1("193");
		IntType rootOfUnity1("150");

		ilv1.SwitchModulus(modulus1, rootOfUnity1);

		EXPECT_EQ(IntType("176"), ilv1.GetValAtIndex(0));
		EXPECT_EQ(IntType("163"), ilv1.GetValAtIndex(1));
		EXPECT_EQ(IntType("35"), ilv1.GetValAtIndex(2));
		EXPECT_EQ(IntType("28"), ilv1.GetValAtIndex(3));
	}

	DEBUG("8");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "2");
		bbv.SetValAtIndex(1, "4");
		bbv.SetValAtIndex(2, "3");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "2");
		bbv1.SetValAtIndex(1, "0");
		bbv1.SetValAtIndex(2, "3");
		bbv1.SetValAtIndex(3, "2");
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		Element ilv2(ilparams);
		VecType bbv2(m/2, primeModulus);
		bbv2.SetValAtIndex(0, "2");
		bbv2.SetValAtIndex(1, "1");
		bbv2.SetValAtIndex(2, "3");
		bbv2.SetValAtIndex(3, "2");
		ilv2.SetValues(bbv2, Format::COEFFICIENT);

		EXPECT_EQ(true, ilv.InverseExists());
		EXPECT_EQ(false, ilv1.InverseExists());
		EXPECT_EQ(false, ilv1.InverseExists());
	}

	DEBUG("9");
	{
		//	  Multiply is only supposed to work in EVALUATION so this test ought to never work :)

		//	   Element ilv(ilparams);
		//	   VecType bbv(m/2, primeModulus);
		//    bbv.SetValAtIndex(0, "2");
		//    bbv.SetValAtIndex(1, "4");
		//    bbv.SetValAtIndex(2, "3");
		//    bbv.SetValAtIndex(3, "2");
		//    ilv.SetValues(bbv, Format::COEFFICIENT);
		//
		//    Element ilvInverse = ilv.MultiplicativeInverse();
		//    Element ilvProduct = ilv * ilvInverse;
		//
		//    for (usint i = 0; i < m/2; ++i)
		//    {
		//      EXPECT_EQ(IntType::ONE, ilvProduct.GetValAtIndex(i));
		//    }

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1.SetValAtIndex(0, "2");
		bbv1.SetValAtIndex(1, "4");
		bbv1.SetValAtIndex(2, "3");
		bbv1.SetValAtIndex(3, "2");
		ilv1.SetValues(bbv1, Format::EVALUATION);

		Element ilvInverse1 = ilv1.MultiplicativeInverse();
		Element ilvProduct1 = ilv1 * ilvInverse1;

		for (usint i = 0; i < m/2; ++i)
		{
			EXPECT_EQ(IntType::ONE, ilvProduct1.GetValAtIndex(i));
		}

	}

	DEBUG("B");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv.SetValAtIndex(0, "56");
		bbv.SetValAtIndex(1, "1");
		bbv.SetValAtIndex(2, "37");
		bbv.SetValAtIndex(3, "2");
		ilv.SetValues(bbv, Format::COEFFICIENT);

		usint index = 3;
		Element ilvAuto(ilv.AutomorphismTransform(index));

		EXPECT_EQ(IntType::ONE, ilvAuto.GetValAtIndex(0));
		EXPECT_EQ(IntType("56"), ilvAuto.GetValAtIndex(1));
		EXPECT_EQ(IntType::TWO, ilvAuto.GetValAtIndex(2));
		EXPECT_EQ(IntType("37"), ilvAuto.GetValAtIndex(3));
	}

}

TEST(UTILVector2n, other_methods) {
	other_methods<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, other_methods) {
	other_methods<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, other_methods) {
//	other_methods<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void cyclotomicOrder_test() {
	usint m = 8;
	shared_ptr<ParmType> ilparams0( new ParmType(m, IntType("17661"), IntType("8765")) );
	Element ilv0(ilparams0);
	EXPECT_EQ(ilparams0->GetCyclotomicOrder(), ilv0.GetCyclotomicOrder());
}

TEST(UTILVector2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

TEST(UTILVectorArray2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
}

// this test is only for ILVector2n so isn't templated
TEST(UTILVectorArray2n, constructors_test) {

	bool dbg_flag = false;
	usint m = 8;
	usint towersize = 3;

	std::vector<native64::BigBinaryInteger> moduli(towersize);
	moduli = {native64::BigBinaryInteger("8353"), native64::BigBinaryInteger("8369"), native64::BigBinaryInteger("8513")};
	std::vector<native64::BigBinaryInteger> rootsOfUnity(towersize);
	rootsOfUnity = {native64::BigBinaryInteger("8163"), native64::BigBinaryInteger("6677"), native64::BigBinaryInteger("156")};

	BigBinaryInteger modulus(BigBinaryInteger::ONE);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native64::ILParams> ilparams0( new native64::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native64::ILParams> ilparams1( new native64::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native64::ILParams> ilparams2( new native64::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native64::ILVector2n ilv0(ilparams0);
	native64::BigBinaryVector bbv0(m/2, moduli[0]);
	bbv0.SetValAtIndex(0, "2");
	bbv0.SetValAtIndex(1, "4");
	bbv0.SetValAtIndex(2, "3");
	bbv0.SetValAtIndex(3, "2");
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native64::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native64::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );

	std::vector<native64::ILVector2n> ilvector2nVector;
	ilvector2nVector.push_back(ilv0);
	ilvector2nVector.push_back(ilv1);
	ilvector2nVector.push_back(ilv2);

	DEBUG("1");
	//  float stdDev = 4.0;
	//  DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,VecType> dgg(stdDev);

	{
		ILVectorArray2n ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		EXPECT_EQ(towersize, ilva.GetNumOfElements());
	}

	DEBUG("2");
	{
		ILVectorArray2n ilva(ilvector2nVector);

		DEBUG("2.0");
		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		EXPECT_EQ(towersize, ilva.GetNumOfElements());

		DEBUG("2.1");
		std::vector<native64::ILVector2n> ilvector2nVectorInconsistent(towersize);
		shared_ptr<native64::ILParams> ilparamsNegativeTestCase( new native64::ILParams(128, native64::BigBinaryInteger("1231"), native64::BigBinaryInteger("213")) );
		native64::ILVector2n ilvNegative(ilparamsNegativeTestCase);
		ilvector2nVectorInconsistent[0] = ilvNegative;
		ilvector2nVectorInconsistent[1] = ilv1;
		ilvector2nVectorInconsistent[2] = ilv2;

		DEBUG("2.2");
		for( int ii=0; ii<ilvector2nVectorInconsistent.size(); ii++ ) {
			DEBUG(ii << " item " << ilvector2nVectorInconsistent.at(ii).GetParams().use_count());
		}
		EXPECT_THROW(testILVectorArray2nConstructorNegative(ilvector2nVectorInconsistent), std::logic_error);
	}

	DEBUG("3");
	{
		ILVectorArray2n ilva(ilv0, ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		EXPECT_EQ(towersize, ilva.GetNumOfElements());
		for (usint i = 0; i < towersize; ++i)
		{
			EXPECT_EQ(ilvector2nVector[i], ilva.GetElementAtIndex(i));
		}
	}

	DEBUG("4");
	{
		ILVectorArray2n ilva0;
		ILVectorArray2n ilva1(ildcrtparams);
		ILVectorArray2n ilva2(ilv0, ildcrtparams);
		ILVectorArray2n ilva3(ilvector2nVector);

		std::vector<ILVectorArray2n> ilvaVector(4);
		ilvaVector[0] = ilva0;
		ilvaVector[1] = ilva1;
		ilvaVector[2] = ilva2;
		ilvaVector[3] = ilva3;

		//copy constructor
		ILVectorArray2n ilva0Copy(ilva0);
		ILVectorArray2n ilva1Copy(ilva1);
		ILVectorArray2n ilva2Copy(ilva2);
		ILVectorArray2n ilva3Copy(ilva3);

		std::vector<ILVectorArray2n> ilvaCopyVector(4);
		ilvaCopyVector[0] = ilva0Copy;
		ilvaCopyVector[1] = ilva1Copy;
		ilvaCopyVector[2] = ilva2Copy;
		ilvaCopyVector[3] = ilva3Copy;

		for (usint i = 0; i < 4; ++i)
		{
			EXPECT_EQ(ilvaVector[i].GetFormat(), ilvaCopyVector[i].GetFormat());
			EXPECT_EQ(ilvaVector[i].GetModulus(), ilvaCopyVector[i].GetModulus());
			EXPECT_EQ(ilvaVector[i].GetCyclotomicOrder(), ilvaCopyVector[i].GetCyclotomicOrder());
			EXPECT_EQ(ilvaVector[i].GetNumOfElements(), ilvaCopyVector[i].GetNumOfElements());
			if(i==0 || i==1) // to ensure that GetElementAtIndex is not called on uninitialized ILVectorArray2n objects.
				continue;
			for (usint j = 0; j < towersize; ++j)
			{
				EXPECT_EQ(ilvaVector[i].GetElementAtIndex(j), ilvaCopyVector[i].GetElementAtIndex(j));
			}
		}
	}

	DEBUG("5");
	{
		DEBUG("ild mod " << ildcrtparams->GetModulus());
		ILVectorArray2n ilva(DiscreteGaussianGen, ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		EXPECT_EQ(towersize, ilva.GetNumOfElements());
	}

	DEBUG("6");
	{
		ILVectorArray2n ilva(ilv0, ildcrtparams);
		ILVectorArray2n ilvaClone(ilva.CloneParametersOnly());

		std::vector<native64::ILVector2n> towersInClone = ilvaClone.GetAllElements();

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
	}

}

// Signed mod must handle the modulo operation for both positive and negative numbers
// It is used in decoding/decryption of homomorphic encryption schemes
template<typename IntType, typename VecType, typename ParmType, typename Element>
void signed_mod_tests() {

	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams,COEFFICIENT);
	VecType bbv1(m / 2, primeModulus);
	bbv1.SetValAtIndex(0, "62");
	bbv1.SetValAtIndex(1, "7");
	bbv1.SetValAtIndex(2, "65");
	bbv1.SetValAtIndex(3, "8");
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(IntType::TWO);

		EXPECT_EQ(IntType::ONE, ilv1.GetValAtIndex(0)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::ONE, ilv1.GetValAtIndex(1)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(2)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(3)) << "ILVector2n.SignedMod fails.\n";
	}

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(IntType::FIVE);

		EXPECT_EQ(IntType::FOUR, ilv1.GetValAtIndex(0)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::TWO, ilv1.GetValAtIndex(1)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::TWO, ilv1.GetValAtIndex(2)) << "ILVector2n.SignedMod fails.\n";
		EXPECT_EQ(IntType::THREE, ilv1.GetValAtIndex(3)) << "ILVector2n.SignedMod fails.\n";
	}
}

TEST(UTILVector2n, signed_mod_tests) {
	signed_mod_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, signed_mod_tests) {
	signed_mod_tests<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

//TEST(UTILVectorArray2n, signed_mod_tests) {
//	signed_mod_tests<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILVectorArray2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void transposition_test() {
	usint m = 8;

	IntType q("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams(new ParmType(m, q, primitiveRootOfUnity));

	Element ilvector2n1(ilparams, COEFFICIENT);
	ilvector2n1 = { 31,21,15,34 };

	// converts to evaluation representation
	ilvector2n1.SwitchFormat();

	ilvector2n1 = ilvector2n1.Transpose();

	// converts back to coefficient representation
	ilvector2n1.SwitchFormat();

	Element ilvector2n2(ilparams);
	VecType bbv0(m / 2, q);
	bbv0.SetValAtIndex(0, "31");
	bbv0.SetValAtIndex(1, "39");
	bbv0.SetValAtIndex(2, "58");
	bbv0.SetValAtIndex(3, "52");
	ilvector2n2.SetValues(bbv0, Format::COEFFICIENT);

	EXPECT_EQ(ilvector2n2, ilvector2n1);

}

TEST(UTILVector2n, transposition_test) {
	transposition_test<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, transposition_test) {
	transposition_test<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

// ILVectorArray2n Only
TEST(UTILVectorArray2n, getters_and_operators_tests) {
	usint m = 8;
	usint towersize = 3;

	std::vector<native64::BigBinaryInteger> moduli(towersize);
	moduli = {native64::BigBinaryInteger("8353"), native64::BigBinaryInteger("8369"), native64::BigBinaryInteger("8513")};
	std::vector<native64::BigBinaryInteger> rootsOfUnity(towersize);
	rootsOfUnity = {native64::BigBinaryInteger("8163"), native64::BigBinaryInteger("6677"), native64::BigBinaryInteger("156")};

	BigBinaryInteger modulus(BigBinaryInteger::ONE);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native64::ILParams> ilparams0( new native64::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native64::ILParams> ilparams1( new native64::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native64::ILParams> ilparams2( new native64::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native64::ILVector2n ilv0(ilparams0);
	native64::BigBinaryVector bbv0(m/2, moduli[0]);
	bbv0.SetValAtIndex(0, "2");
	bbv0.SetValAtIndex(1, "4");
	bbv0.SetValAtIndex(2, "3");
	bbv0.SetValAtIndex(3, "2");
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native64::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native64::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );

	std::vector<native64::ILVector2n> ilvector2nVector(towersize);
	ilvector2nVector[0] = ilv0;
	ilvector2nVector[1] = ilv1;
	ilvector2nVector[2] = ilv2;

	{
		ILVectorArray2n ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		EXPECT_EQ(towersize, ilva.GetNumOfElements());
	}

	ILVectorArray2n ilva(ilvector2nVector);

	{
		ILVectorArray2n ilva1(ilva);
		EXPECT_TRUE(ilva == ilva1);
	}

	{
		ILVectorArray2n ilva1 = ilva;
		EXPECT_EQ(ilva, ilva1);
	}

	{
		ILVectorArray2n ilva1(ildcrtparams);
		ilva1 = {2, 4, 3, 2};
		EXPECT_EQ(ilva, ilva1);
	}

	{
		native64::ILVector2n ilvect0(ilparams0);
		native64::BigBinaryVector bbv1(m/2, moduli[0]);
		bbv1.SetValAtIndex(0, "2");
		bbv1.SetValAtIndex(1, "1");
		bbv1.SetValAtIndex(2, "3");
		bbv1.SetValAtIndex(3, "2");
		ilvect0.SetValues(bbv1, Format::EVALUATION);

		native64::ILVector2n ilvect1(ilvect0);
		ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

		native64::ILVector2n ilvect2(ilvect0);
		ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<native64::ILVector2n> ilvector2nVector1(towersize);
		ilvector2nVector1[0] = ilvect0;
		ilvector2nVector1[1] = ilvect1;
		ilvector2nVector1[2] = ilvect2;

		ILVectorArray2n ilva1(ilvector2nVector1);

		EXPECT_TRUE(ilva!=ilva1);
	}

}

TEST(UTILVectorArray2n, arithmetic_operations_element_2) {
	usint m = 8;
	usint towersize = 3;

	std::vector<native64::BigBinaryInteger> moduli(towersize);
	moduli = {native64::BigBinaryInteger("8353"), native64::BigBinaryInteger("8369"), native64::BigBinaryInteger("8513")};
	std::vector<native64::BigBinaryInteger> rootsOfUnity(towersize);
	rootsOfUnity = {native64::BigBinaryInteger("8163"), native64::BigBinaryInteger("6677"), native64::BigBinaryInteger("156")};

	BigBinaryInteger modulus(BigBinaryInteger::ONE);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native64::ILParams> ilparams0( new native64::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native64::ILParams> ilparams1( new native64::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native64::ILParams> ilparams2( new native64::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native64::ILVector2n ilv0(ilparams0);
	native64::BigBinaryVector bbv0(m/2, moduli[0]);
	bbv0.SetValAtIndex(0, "2");
	bbv0.SetValAtIndex(1, "4");
	bbv0.SetValAtIndex(2, "3");
	bbv0.SetValAtIndex(3, "2");
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native64::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native64::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(m, moduli, rootsOfUnity) );

	std::vector<native64::ILVector2n> ilvector2nVector(towersize);
	ilvector2nVector[0] = ilv0;
	ilvector2nVector[1] = ilv1;
	ilvector2nVector[2] = ilv2;

	ILVectorArray2n ilva(ilvector2nVector);

	native64::ILVector2n ilvect0(ilparams0);
	native64::BigBinaryVector bbv1(m/2, moduli[0]);
	bbv1.SetValAtIndex(0, "2");
	bbv1.SetValAtIndex(1, "1");
	bbv1.SetValAtIndex(2, "2");
	bbv1.SetValAtIndex(3, "0");
	ilvect0.SetValues(bbv1, Format::EVALUATION);

	native64::ILVector2n ilvect1(ilvect0);
	ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native64::ILVector2n ilvect2(ilvect0);
	ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	std::vector<native64::ILVector2n> ilvector2nVector1(towersize);
	ilvector2nVector1[0] = ilvect0;
	ilvector2nVector1[1] = ilvect1;
	ilvector2nVector1[2] = ilvect2;

	ILVectorArray2n ilva1(ilvector2nVector1);

	{
		ILVectorArray2n ilvaCopy(ilva.Plus(ilva1));
		// ilvaCopy = ilvaCopy + ilva1;

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::FIVE, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::FIVE, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaCopy(ilva);
		ilvaCopy += ilva1;

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::FIVE, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::FIVE, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaCopy(ilva.Minus(ilva1));

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::THREE, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::ONE, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaResult(ilva);
		ilvaResult -= ilva1;

		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::ZERO, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::THREE, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::ONE, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaResult(ilva.Times(ilva1));

		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaResult.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger("6"), ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaCopy(ilva);
		ilvaCopy.AddILElementOne();

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::THREE, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::FIVE, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::THREE, ilv.GetValAtIndex(3));
		}
	}

	{
		ILVectorArray2n ilvaInv(ilva.MultiplicativeInverse());

		native64::ILVector2n ilvectInv0 = ilvaInv.GetElementAtIndex(0);
		native64::ILVector2n ilvectInv1 = ilvaInv.GetElementAtIndex(1);
		native64::ILVector2n ilvectInv2 = ilvaInv.GetElementAtIndex(2);

		EXPECT_EQ(native64::BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("6265"), ilvectInv0.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("5569"), ilvectInv0.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("4177"), ilvectInv0.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("8353"), ilvectInv0.GetModulus());
		EXPECT_EQ(native64::BigBinaryInteger("8163"), ilvectInv0.GetRootOfUnity());

		EXPECT_EQ(native64::BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("6277"), ilvectInv1.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("2790"), ilvectInv1.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("4185"), ilvectInv1.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("8369"), ilvectInv1.GetModulus());
		EXPECT_EQ(native64::BigBinaryInteger("6677"), ilvectInv1.GetRootOfUnity());

		EXPECT_EQ(native64::BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("6385"), ilvectInv2.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("2838"), ilvectInv2.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("4257"), ilvectInv2.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("8513"), ilvectInv2.GetModulus());
		EXPECT_EQ(native64::BigBinaryInteger("156"), ilvectInv2.GetRootOfUnity());

		EXPECT_THROW(ilva1.MultiplicativeInverse(), std::logic_error);
	}

	{
		ILVectorArray2n ilvaCopy(ilva);

		ilvaCopy.MakeSparse(2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::ZERO, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::ZERO, ilv.GetValAtIndex(3));
		}
	}

	{
		EXPECT_TRUE(ilva.InverseExists());
		EXPECT_FALSE(ilva1.InverseExists());
	}

	{
		native64::ILVector2n ilvS0(ilparams0);
		native64::BigBinaryVector bbvS0(m/2, moduli[0]);
		bbvS0.SetValAtIndex(0, "23462");
		bbvS0.SetValAtIndex(1, "467986");
		bbvS0.SetValAtIndex(2, "33863");
		bbvS0.SetValAtIndex(3, "2113");
		ilvS0.SetValues(bbvS0, Format::EVALUATION);

		native64::ILVector2n ilvS1(ilvS0);
		ilvS1.SwitchModulus(moduli[1], rootsOfUnity[1]);

		native64::ILVector2n ilvS2(ilvS0);
		ilvS2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<native64::ILVector2n> ilvector2nVectorS(towersize);
		ilvector2nVectorS[0] = ilvS0;
		ilvector2nVectorS[1] = ilvS1;
		ilvector2nVectorS[2] = ilvS2;

		ILVectorArray2n ilvaS(ilvector2nVectorS);
		BigBinaryInteger modulus2("113");
		BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity<BigBinaryInteger>(m, modulus2));

		ilvaS.SwitchModulus(modulus2, rootOfUnity2);

		native64::ILVector2n ilvectS0 = ilvaS.GetElementAtIndex(0);
		native64::ILVector2n ilvectS1 = ilvaS.GetElementAtIndex(1);
		native64::ILVector2n ilvectS2 = ilvaS.GetElementAtIndex(2);

		EXPECT_EQ(native64::BigBinaryInteger("80"), ilvectS0.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("62"), ilvectS0.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("85"), ilvectS0.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("79"), ilvectS0.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("113"), ilvectS0.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS0.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(native64::BigBinaryInteger("66"), ilvectS1.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("16"), ilvectS1.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("64"), ilvectS1.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("79"), ilvectS1.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("113"), ilvectS1.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS1.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilvectS2.GetValAtIndex(0));
		EXPECT_EQ(native64::BigBinaryInteger("44"), ilvectS2.GetValAtIndex(1));
		EXPECT_EQ(native64::BigBinaryInteger("84"), ilvectS2.GetValAtIndex(2));
		EXPECT_EQ(native64::BigBinaryInteger("79"), ilvectS2.GetValAtIndex(3));
		EXPECT_EQ(native64::BigBinaryInteger("113"), ilvectS2.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS2.GetRootOfUnity().ConvertToInt());
	}

	{
		ILVectorArray2n ilvaCopy(ilva);
		BigBinaryInteger modulus2("113");
		BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity<BigBinaryInteger>(m, modulus2));
		ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native64::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(0));
			EXPECT_EQ(native64::BigBinaryInteger::FOUR, ilv.GetValAtIndex(1));
			EXPECT_EQ(native64::BigBinaryInteger::THREE, ilv.GetValAtIndex(2));
			EXPECT_EQ(native64::BigBinaryInteger::TWO, ilv.GetValAtIndex(3));

			if(i==0){
				EXPECT_EQ(modulus2.ConvertToInt(), ilv.GetModulus().ConvertToInt());
				EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilv.GetRootOfUnity().ConvertToInt());
			}
		}
	}

}

TEST(UTILVectorArray2n, decompose_test) {
	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;

	std::vector<native64::BigBinaryInteger> moduli(towersize);
	std::vector<native64::BigBinaryInteger> rootsOfUnity(towersize);
	std::vector<native64::ILParams> ilparams(towersize);

	std::vector<native64::ILVector2n> ilvector2n1(towersize);
	std::vector<native64::BigBinaryVector> bbv1(towersize);

	native64::BigBinaryInteger q("1");
	BigBinaryInteger modulus("1");

	for(usint i=0; i < towersize;i++){
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, order, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity<native64::BigBinaryInteger>(order,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	//  float stdDev = 4;
	//  DiscreteGaussianGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector> dgg(stdDev);

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(order, moduli, rootsOfUnity) );
	ILVectorArray2n ilVectorArray2n(DiscreteGaussianGen, params, Format::COEFFICIENT);

	ILVectorArray2n ilvectorarray2nOriginal(ilVectorArray2n);
	ilVectorArray2n.Decompose();

	EXPECT_EQ(ilvectorarray2nOriginal.GetNumOfElements(), ilVectorArray2n.GetNumOfElements()) << "ILVectorArray2n_decompose: Mismatch in the number of towers after decompose.";

	for(usint i=0; i<ilVectorArray2n.GetNumOfElements(); i++) {
		native64::ILVector2n ilTowerOriginal(ilvectorarray2nOriginal.GetElementAtIndex(i));
		native64::ILVector2n ilTowerDecomposed(ilVectorArray2n.GetElementAtIndex(i));

		EXPECT_EQ(ilTowerDecomposed.GetLength(), ilTowerOriginal.GetLength()/2)  << "ILVectorArray2n_decompose: ilVector2n element in ilVectorArray2n is not half the length after decompose.";

		for(usint j=0; j<ilTowerDecomposed.GetLength(); j++) {
			EXPECT_EQ(ilTowerDecomposed.GetValAtIndex(j), ilTowerOriginal.GetValAtIndex(2*j)) << "ILVectorArray2n_decompose: Values do not match between original and decomposed elements.";
		}
	}

}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void ensures_mod_operation_during_operations_on_two_ILVector2ns() {

	usint order = 8;
	usint nBits = 7;

	IntType primeModulus = lbcrypto::FindPrimeModulus<IntType>(order, nBits);
	IntType primitiveRootOfUnity = lbcrypto::RootOfUnity<IntType>(order, primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(order, primeModulus, primitiveRootOfUnity) );
//
//	DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(primeModulus);
//

	Element ilv1(DiscreteUniformGen, ilparams);
	VecType bbv1 (ilv1.GetValues());

	Element ilv2(DiscreteUniformGen, ilparams);
	VecType bbv2(ilv2.GetValues());

	{
		Element ilvResult = ilv1 + ilv2;
		VecType bbvResult(ilvResult.GetValues());

		for (usint i=0; i<order/2; i++) {
			EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) + bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "ILVector2n + operation returns incorrect results.";
		}
	}

	{
		Element ilvResult = ilv1 * ilv2;
		VecType bbvResult(ilvResult.GetValues());

		for (usint i=0; i<order/2; i++) {
			EXPECT_EQ(bbvResult.GetValAtIndex(i), (bbv1.GetValAtIndex(i) * bbv2.GetValAtIndex(i)).Mod(primeModulus)) << "ILVector2n * operation returns incorrect results.";
		}
	}

}

TEST(UTILVector2n, ensures_mod_operation_during_operations_on_two_ILVector2ns) {
	ensures_mod_operation_during_operations_on_two_ILVector2ns<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, ensures_mod_operation_during_operations_on_two_ILVector2ns) {
	ensures_mod_operation_during_operations_on_two_ILVector2ns<native64::BigBinaryInteger, native64::BigBinaryVector, native64::ILParams, native64::ILVector2n>();
}

TEST(UTILVectorArray2n, ensures_mod_operation_during_operations_on_two_ILVectorArray2ns){

	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;

	std::vector<native64::BigBinaryInteger> moduli(towersize);
	std::vector<native64::BigBinaryInteger> rootsOfUnity(towersize);
	std::vector<shared_ptr<native64::ILParams>> ilparams(towersize);

	std::vector<native64::ILVector2n> ilvector2n1(towersize);
	std::vector<native64::BigBinaryVector> bbv1(towersize);
	std::vector<native64::ILVector2n> ilvector2n2(towersize);
	std::vector<native64::BigBinaryVector> bbv2(towersize);

	native64::BigBinaryInteger q("1");
	BigBinaryInteger modulus("1");

	for(usint i=0; i < towersize;i++){
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, order, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity<native64::BigBinaryInteger>(order,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());

		shared_ptr<native64::ILParams> ilparamsi( new native64::ILParams(order, moduli[i], rootsOfUnity[i]) );
		ilparams.push_back(ilparamsi);

		auto distrUniGeni = lbcrypto::DiscreteUniformGeneratorImpl<native64::BigBinaryInteger,native64::BigBinaryVector>(moduli[i]);

		native64::ILVector2n ilv1(distrUniGeni, ilparamsi);
		ilvector2n1[i] = ilv1;
		bbv1[i] = (ilv1.GetValues());

		native64::ILVector2n ilv2(distrUniGeni, ilparamsi);
		ilvector2n2[i] = ilv2;
		bbv2[i] = (ilv2.GetValues());
	}

	shared_ptr<ILDCRTParams> ildcrtparams( new ILDCRTParams(order, moduli, rootsOfUnity) );

	ILVectorArray2n ilvectorarray2n1(ilvector2n1);
	ILVectorArray2n ilvectorarray2n2(ilvector2n2);

	{
		ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 + ilvectorarray2n2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<order/2; j++) {
				native64::BigBinaryInteger actualResult(ilvectorarray2nResult.GetElementAtIndex(i).GetValAtIndex(j));
				native64::BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) + bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
				EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n + operation returns incorrect results.";
			}
		}

	}

	{
		ILVectorArray2n ilvectorarray2nResult = ilvectorarray2n1 * ilvectorarray2n2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<order/2; j++) {
				native64::BigBinaryInteger actualResult(ilvectorarray2nResult.GetElementAtIndex(i).GetValAtIndex(j));
				native64::BigBinaryInteger expectedResult((bbv1[i].GetValAtIndex(j) * bbv2[i].GetValAtIndex(j)).Mod(moduli[i]));
				EXPECT_EQ(actualResult, expectedResult) << "ILVectorArray2n * operation returns incorrect results.";
			}
		}

	}

}

void testILVectorArray2nConstructorNegative(std::vector<native64::ILVector2n> &towers) {
	ILVectorArray2n expectException(towers);
}
