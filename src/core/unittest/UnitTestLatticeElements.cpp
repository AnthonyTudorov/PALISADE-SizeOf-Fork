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
#include <vector>

#include "../lib/lattice/ildcrt2n.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "utils/parmfactory.h"

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

void testILVectorArray2nConstructorNegative(std::vector<native_int::ILVector2n> &towers);

/*-TESTING METHODS OF LATTICE ELEMENTS    ----------------*/

// template for operations tests
template<typename IntType, typename VecType, typename ParmType, typename Element>
static void operators_tests(shared_ptr<ParmType> ilparams) {

	Element ilvector2n1(ilparams);
	ilvector2n1 = {1,2,0,1};

	Element ilvector2n2(ilparams);
	ilvector2n2 = {1,2,0,1};

	EXPECT_EQ(ilvector2n1, ilvector2n2) << "Faiure: Operator ==";

	{//test constructor
		Element ilv1(ilvector2n1);
		EXPECT_EQ(ilvector2n1, ilv1) << "Faiure: copy constructor";
	}

	{//test operator=
		Element ilv1 = ilvector2n1;
		EXPECT_EQ(ilvector2n1, ilv1) << "Faiure: operator=";
	}

	{//test SwitchModulus, !=
		Element ilv1 = ilvector2n1;
		try {
			ilv1.SwitchModulus(IntType("123467"), IntType("1234"));
			EXPECT_NE(ilvector2n1, ilv1)
				<< "Faiure: Operator!= switchmodulus comparison";

			Element ilv2 = ilvector2n1;
			ilv2.SetValAtIndex(2, 2);
			EXPECT_NE(ilvector2n1, ilv2)
				<< "Faiure: Operator!= value comparison";
		} catch (std::exception& e) {
			// ignore for vectorarray
		}
	}

#ifdef OUT
	NOTE GetValAtIndex not supported for vectorarray; needs a fix
	{//test operator-=
		Element ilv1 = ilvector2n1;
		ilv1 -= ilvector2n1;
		for (usint i = 0; i < m/2; ++i) {
			EXPECT_EQ(IntType::ZERO, ilv1.GetValAtIndex(i))
				<< "Faiure: Operator-= @ index "<<i;
		}
	}

	{//test operator+=
		Element ilv1 = ilvector2n1;
		ilv1 += ilvector2n1;
		for (usint i = 0; i < m/2; ++i)
			{//we expect a+a == 2*a
			EXPECT_EQ(IntType::TWO * ilvector2n1.GetValAtIndex(i),
				  ilv1.GetValAtIndex(i))
				<< "Faiure: Operator+= @ index "<<i;
		}
	}

	SetValues and GetValues and etc not supported for vectorarray; needs a fix
	{//test getters //todo: this should be in its own test
		Element ilvector2n(ilparams);
		VecType bbv(m/2, ilparams->GetModulus());
		bbv = {"1", "2", "0", "1"};
		ilvector2n.SetValues(bbv, ilvector2n.GetFormat());
		bbv[3] = 11;
		EXPECT_EQ(ilparams->GetModulus(), ilvector2n.GetModulus())
			<< "Failure: GetModulus()";
		EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder())
			<< "Failure: GetCyclotomicOrder()";
		EXPECT_EQ(ilparams->GetRootOfUnity(), ilvector2n.GetRootOfUnity())
			<< "Failure: GetRootOfUnity()";
		EXPECT_EQ(bbv, ilvector2n.GetValues()) 
			<< "Failure: GetValues()";
		EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat())
			<< "Failure: GetFormat()";
		EXPECT_EQ(m/2, ilvector2n.GetLength())
			<< "Failure: GetLength()";

		 for (usint i = 0; i < m/2; ++i) {
		 	EXPECT_EQ(bbv.GetValAtIndex(i), 
		 		  ilvector2n.GetValAtIndex(i)) 
		 		<< " Failure: GetValAtIndex("<<i<< ")";
		 }
	}
#endif


}

//instantiate ops_tests for various backend combos
TEST(UTILVector2n, ops_tests) {
	usint m = 8;
	ILVector2n::Integer primeModulus("73");
	ILVector2n::Integer primitiveRootOfUnity("22");

	operators_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>(
			GenerateTestParams<ILParams,BigBinaryInteger>(m, primeModulus, primitiveRootOfUnity) );
}

TEST(UTILNativeVector2n, ops_tests) {
	usint m = 8;
	native_int::BinaryInteger primeModulus("73");
	native_int::BinaryInteger primitiveRootOfUnity("22");

	operators_tests<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>(
			GenerateTestParams<native_int::ILParams,native_int::BinaryInteger>(m, primeModulus, primitiveRootOfUnity) );
}

TEST(UTILDCRT2n, ops_tests) {
	operators_tests<BigBinaryInteger, BigBinaryVector, ILDCRTParams<BigBinaryInteger>, ILDCRT2n>(
			GenerateDCRTParams(8, 8, 3, 20) );
}

// template for rounding_operations tests
template<typename IntType, typename VecType, typename ParmType, typename Element>
void rounding_operations() {
  bool dbg_flag = false;
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
	ilvector2n1 = { "31","21","15","34"};

	DEBUG("ilvector2n1 a "<<ilvector2n1);

	Element ilvector2n2(ilparams,COEFFICIENT);
	ilvector2n2 = { "21","11","35","32" };

	DEBUG("ilvector2n2 a "<<ilvector2n2);

	//unit test for MultiplyAndRound

	Element roundingCorrect1(ilparams, COEFFICIENT);
	roundingCorrect1 = { "3","2","2","4" };

	DEBUG("ilvector2n1 b "<<ilvector2n1);

	Element rounding1 = ilvector2n1.MultiplyAndRound(p, q);

	EXPECT_EQ(roundingCorrect1, rounding1) 
		<< "Failure: Rounding p*polynomial/q";

	//unit test for MultiplyAndRound after a polynomial
	//multiplication using the larger modulus

	Element roundingCorrect2(ilparams2, COEFFICIENT);
	roundingCorrect2 = { "16316","16320","60","286" };

	ilvector2n1.SwitchModulus(q2, primitiveRootOfUnity2);
	ilvector2n2.SwitchModulus(q2, primitiveRootOfUnity2);
	DEBUG("ilvector2n1 c "<<ilvector2n1);
	DEBUG("ilvector2n2 c "<<ilvector2n2);


	ilvector2n1.SwitchFormat();
	ilvector2n2.SwitchFormat();
	DEBUG("ilvector2n1 d "<<ilvector2n1);
	DEBUG("ilvector2n2 d "<<ilvector2n2);

	Element rounding2 = ilvector2n1 * ilvector2n2;

	DEBUG("rounding2 d "<<rounding2);
	rounding2.SwitchFormat();
	DEBUG("rounding2 e "<<rounding2);
	rounding2 = rounding2.MultiplyAndRound(p, q);
	DEBUG("rounding2 f "<<rounding2);
	EXPECT_EQ(roundingCorrect2, rounding2) 
		<< "Failure: Rounding p*polynomial1*polynomial2/q";

	//makes sure the result is correct after going back to the
	//original modulus

	rounding2.SwitchModulus(q, primitiveRootOfUnity);
	DEBUG("rounding2 g "<<rounding2);

	Element roundingCorrect3(ilparams, COEFFICIENT);
	roundingCorrect3 = { "45","49","60","67" };

	EXPECT_EQ(roundingCorrect3, rounding2) 
		<< "falure p*polynomial1*polynomial2/q (mod q)";
}
// instantiate various test for rounding_operations()
TEST(UTILVector2n, rounding_operations) {
	rounding_operations<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, rounding_operations) {
	rounding_operations<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, rounding_operations) {
//	rounding_operations<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

//template for setters_tests()
template<typename IntType, typename VecType, typename ParmType, typename Element>
void setters_tests() {
	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {	"3","0","0","0"};
	ilvector2n.SetValues(bbv, Format::COEFFICIENT);

	Element ilvector2nInEval(ilparams);
	VecType bbvEval(m/2, primeModulus);
	bbvEval={"3","3","3","3"};
	ilvector2nInEval.SetValues(bbvEval, Format::EVALUATION);

	{// test SetFormat()
		Element ilv(ilvector2n);

		ilv.SetFormat(Format::COEFFICIENT);
		EXPECT_EQ(ilvector2n, ilv) << "Failure: SetFormat() to COEFFICIENT";

		ilv.SetFormat(Format::EVALUATION);
		EXPECT_EQ(ilvector2nInEval, ilv) << "Failure: SetFormat() to EVALUATION";
	}

	// this is here because it's a vectors-only test
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		EXPECT_EQ(36, ilv.Norm())
			<< "Failure: Norm()";
	}
}

// instantiate setters_tests() for various combos
TEST(UTILVector2n, setters_tests) {
	setters_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, setters_tests) {
	setters_tests<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//template for binary_ops()
template<typename IntType, typename VecType, typename ParmType, typename Element>
void binary_ops() {
	bool dbg_flag = false;
	usint m = 8;

	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1 = {"2","1","1","1"};
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());
	DEBUG("ilvector2n1 a "<<ilvector2n1);

	Element ilvector2n2(ilparams);
	VecType bbv2(m/2, primeModulus);
	bbv2 = {"1","0","1","1"};
	ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());
	DEBUG("ilvector2n2 a "<<ilvector2n2);

	Element ilvector2n3(ilparams, COEFFICIENT);
	VecType bbv3(m / 2, primeModulus);
	bbv3 = {"2","1","1","1"};
	ilvector2n3.SetValues(bbv3, ilvector2n3.GetFormat());
	DEBUG("ilvector2n3 a "<<ilvector2n3);

	Element ilvector2n4(ilparams, COEFFICIENT);
	VecType bbv4(m / 2, primeModulus);
	bbv4 = {"1","0","1","1"};
	ilvector2n4.SetValues(bbv4, ilvector2n4.GetFormat());
	DEBUG("ilvector2n4 a "<<ilvector2n4);

	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 a "<<ilv1);
		Element ilv2 = ilv1.Plus(ilvector2n2);
		DEBUG("ilv2 a "<<ilv2);
		VecType expected(4, primeModulus);
		expected = {"3","1","2","2"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<<"Failure: Plus()";
	}
	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 b "<<ilv1);
		Element ilv2 = ilv1.Minus(ilvector2n2);
		VecType expected(4, primeModulus);
		expected = {"1","1","0","0"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<<"Failure: Minus()";
	}
	
	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 c "<<ilv1);
		Element ilv2 = ilv1.Times(ilvector2n2);
		VecType expected(4, primeModulus);
		expected = {"2","0","1","1"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<<"Failure: Times()";
	}

	{
		ilvector2n3.SwitchFormat();
		DEBUG("ilvector2n3 "<<ilvector2n3);
		ilvector2n4.SwitchFormat();
		DEBUG("ilvector2n4 "<<ilvector2n4);

		Element ilv3(ilvector2n3);
		Element ilv4 = ilv3.Times(ilvector2n4);
		DEBUG("ilv3 "<<ilv3);
		DEBUG("ilv4 "<<ilv4);

		ilv4.SwitchFormat();
		DEBUG("ilv4 "<<ilv4);

		VecType expected(4, primeModulus);
		expected = {"0","72","2","4"};
		EXPECT_EQ(expected, ilv4.GetValues())
			<<"Failure: Times() using SwitchFormat()";
	}
}

// Instantiations of binary_ops
TEST(UTILVector2n, binary_ops) {
	binary_ops<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, binary_ops) {
	binary_ops<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, binary_ops) {
//	binary_ops<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

//templet for clone_ops
template<typename IntType, typename VecType, typename ParmType, typename Element>
void clone_ops() {
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {"2","1","1","1"};
	ilv.SetValues(bbv, ilv.GetFormat());
	{
		Element ilvClone = ilv.CloneParametersOnly();

		EXPECT_EQ(ilv.GetCyclotomicOrder(), 
			  ilvClone.GetCyclotomicOrder())
			<< "Failure: CloneParametersOnly GetCyclotomicOrder()";
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus())
			<< "Failure: CloneParametersOnly GetModulus()";
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
			<< "Failure: CloneParametersOnly GetRootOfUnity()";
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat())
			<< "Failure: CloneParametersOnly GetFormat()";
	}
	{
		float stdDev = 4;
		DiscreteGaussianGeneratorImpl<IntType,VecType> dgg(stdDev);
		Element ilvClone = ilv.CloneWithNoise(dgg, ilv.GetFormat());

		EXPECT_EQ(ilv.GetCyclotomicOrder(), 
			  ilvClone.GetCyclotomicOrder())
			<< "Failure: CloneWithNoise GetCyclotomicOrder()";
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus())
			<< "Failure: CloneWithNoise GetModulus()";
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
			<< "Failure: CloneWithNoise GetRootOfUnity()";
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat())
			<< "Failure: CloneWithNoise GetFormat()";
	}
}
//Instantiations of clone_ops()
TEST(UTILVector2n, clone_ops) {
	clone_ops<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, clone_ops) {
	clone_ops<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, clone_ops) {
//	clone_ops<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

//template for arithmetic_ops_element()
template<typename IntType, typename VecType, typename ParmType, typename Element>
void arithmetic_ops_element() {
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {"2","1","4","1"};
	ilv.SetValues(bbv, ilv.GetFormat());

	IntType element("1");

	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"1","3","4","1"};
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n = ilvector2n.Plus(element);
		VecType expected(4, primeModulus);
		expected = {"2","3","4","1"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: Plus()";
	}
	{
		Element ilvector2n = ilv.Minus(element);
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: Minus()";
	}
	{
		IntType ele("2");
		Element ilvector2n = ilv.Times(ele);
		VecType expected(4, primeModulus);
		expected = {"4","2","8","2"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: Times()";
	}
	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"1","3","4","1"};
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n += element;
		VecType expected(4, primeModulus);
		expected = {"2","3","4","1"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: op+=";
	}
	{
		Element ilvector2n = ilv.Minus(element);
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: Minus()";

	}
	{
		Element ilvector2n(ilv);
		ilvector2n -= element;
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<<"Failure: op-=";
	}
}
//instantiations for arithmetic_ops_element()
TEST(UTILVector2n, arithmetic_ops_element) {
	arithmetic_ops_element<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, arithmetic_ops_element) {
	arithmetic_ops_element<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, arithmetic_ops_element) {
//	arithmetic_ops_element<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

//template fore other_methods()
template<typename IntType, typename VecType, typename ParmType, typename Element>
void other_methods() {
	bool dbg_flag = false;
	usint m = 8;
	IntType primeModulus("73");
	IntType primitiveRootOfUnity("22");

	float stdDev = 4.0;
	typename Element::DggType dgg(stdDev);
	typename Element::BugType bug;
	typename Element::DugType dug;
	dug.SetModulus(primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1 = {"2","1","3","2"};
	ilvector2n.SetValues(bbv1, Format::EVALUATION);

	DEBUG("1");
	{
		Element ilv(ilvector2n);

		ilv.AddILElementOne();
		VecType expected(4, primeModulus);
		expected = {"3","2","4","3"};
		EXPECT_EQ(expected, ilv.GetValues())
			<<"Failure: AddILElementOne()";
	}

	DEBUG("2");
	{
		Element ilv(ilvector2n);
		ilv = ilv.ModByTwo();
		VecType expected(4, primeModulus);
		expected = {"0","1","1","0"};
		EXPECT_EQ(expected, ilv.GetValues())
			<<"Failure: ModByTwo()";
	}

	DEBUG("3");
	{
		Element ilv(ilvector2n);
		ilv.MakeSparse(2);
		VecType expected(4, primeModulus);
		expected = {"2","0","3","0"};
		EXPECT_EQ(expected, ilv.GetValues())
			<<"Failure: MakeSparse(2)";

		Element ilv1(ilvector2n);
		ilv1.MakeSparse(3);
		expected = {"2","0","0","2"};

		EXPECT_EQ(expected, ilv1.GetValues())
			<<"Failure: MakeSparse(3)";
	}

	DEBUG("4");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.Decompose();

		EXPECT_EQ(2U, ilv.GetLength())<<"Failure: Decompose() length";

		EXPECT_EQ(ilv.GetValAtIndex(0), 2)
			<< "Failure: Decompose(): mismatch between original and decomposed elements at index 0.";
		
		EXPECT_EQ(ilv.GetValAtIndex(1), 3) 					<< "Failure: Decompose(): mismatch between original and decomposed elements at index 1.";
	}

	DEBUG("5");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv.GetModulus())
			<<"Failure: SwitchFormat() ilv modulus";
		EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity())
			<<"Failure: SwitchFormat() ilv rootOfUnity";
		EXPECT_EQ(Format::EVALUATION, ilv.GetFormat())
			<<"Failure: SwitchFormat() ilv format";
		VecType expected(4, primeModulus);
		expected = {"69","44","65","49"};
		EXPECT_EQ(expected, ilv.GetValues())<<"Failure: ivl.SwitchFormat() values";

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"2","1","3","2"};
		ilv1.SetValues(bbv1, Format::EVALUATION);

		ilv1.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv1.GetModulus())
			<<"Failure: SwitchFormat() ilv1 modulus";
		EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity())
			<<"Failure: SwitchFormat() ilv1 rootOfUnity";
		EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat())
			<<"Failure: SwitchFormat() ilv1 format";
		expected = {"2","3","50","3"};
		EXPECT_EQ(expected, ilv1.GetValues())<<"Failure: ivl1.SwitchFormat() values";
	}
	DEBUG("6");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilvector2n1(ilparams);
		Element ilvector2n2(ilparams);
		Element ilvector2n3(ilv);
		Element ilvector2n4(dgg, ilparams);
		Element ilvector2n5(bug, ilparams);
		Element ilvector2n6(dug, ilparams);

		EXPECT_EQ(true, ilvector2n1.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n1";
		EXPECT_EQ(true, ilvector2n2.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n2";
		EXPECT_EQ(false, ilvector2n3.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n3";
		EXPECT_EQ(false, ilvector2n4.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n4";
		EXPECT_EQ(false, ilvector2n5.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n5";
		EXPECT_EQ(false, ilvector2n6.IsEmpty())
			<<"Failure: DestroyPreComputedSamples() 2n6";
	}

	DEBUG("7");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv ={"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		IntType modulus("17");
		IntType rootOfUnity("15");

		ilv.SwitchModulus(modulus, rootOfUnity);
		VecType expected(4, modulus);
		expected = {"0","1","15","2"};
		EXPECT_EQ(expected, ilv.GetValues())
			<<"Failure: SwitchModulus()";

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 ={"56","43","35","28"};
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		IntType modulus1("193");
		IntType rootOfUnity1("150");

		ilv1.SwitchModulus(modulus1, rootOfUnity1);
		VecType expected2(4, modulus1);
		expected2 = {"176","163","35","28"};
		EXPECT_EQ(expected2, ilv1.GetValues())
			<<"Failure: SwitchModulus()";
	}

	DEBUG("8");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","4","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"2","0","3","2"};
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		Element ilv2(ilparams);
		VecType bbv2(m/2, primeModulus);
		bbv2 = {"2","1","3","2"};
		ilv2.SetValues(bbv2, Format::COEFFICIENT);

		EXPECT_EQ(true, ilv.InverseExists())
			<<"Failure: ilv.InverseExists()";
		EXPECT_EQ(false, ilv1.InverseExists())
			<<"Failure: ilv1.InverseExists()";
		EXPECT_EQ(true, ilv2.InverseExists())
			<<"Failure: ilv2.InverseExists()";
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
		bbv1 = {"2","4","3","2"};
		ilv1.SetValues(bbv1, Format::EVALUATION);

		Element ilvInverse1 = ilv1.MultiplicativeInverse();
		Element ilvProduct1 = ilv1 * ilvInverse1;

		for (usint i = 0; i < m/2; ++i)
		{
			EXPECT_EQ(ilvProduct1.GetValAtIndex(i), 1)
				<<"Failure: ilvProduct1.MultiplicativeInverse() @ index "<<i;
		}
	}

	DEBUG("A");
	{
		std::cout<<"this might fail"<<std::endl;
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","1"};
		ilv.SetValues(bbv, Format::COEFFICIENT);
		
		EXPECT_EQ(36, ilv.Norm())<<"Failure: Norm()";
	}
	DEBUG("B");	
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		usint index = 3;
		Element ilvAuto(ilv.AutomorphismTransform(index));
		VecType expected(4, primeModulus);
		expected = {"1","56","2","37"};
		EXPECT_EQ(expected, ilvAuto.GetValues())
			<<"Failure: AutomorphismTransform()";
	}
}
//Instantiations of other_methods()
TEST(UTILVector2n, other_methods) {
	other_methods<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, other_methods) {
	other_methods<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, other_methods) {
//	other_methods<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void cyclotomicOrder_test() {
	usint m = 8;
	shared_ptr<ParmType> ilparams0( new ParmType(m, IntType("17661"), IntType("8765")) );
	Element ilv0(ilparams0);
	EXPECT_EQ(ilparams0->GetCyclotomicOrder(), ilv0.GetCyclotomicOrder())
		<< "Failure: GetCyclotomicOrder()";
}
//Instantiations of cyclotomicOrder_test()
TEST(UTILVector2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

TEST(UTILDCRT2n, cyclotomicOrder_test) {
	cyclotomicOrder_test<BigBinaryInteger, BigBinaryVector, ILDCRTParams<BigBinaryInteger>, ILDCRT2n>();
}

// this test is only for ILDCRT2n so isn't templated
TEST(UTILDCRT2n, constructors_test) {

	bool dbg_flag = false;
	usint m = 8;
	usint towersize = 3;

	std::vector<native_int::BinaryInteger> moduli(towersize);
	moduli = {native_int::BinaryInteger("8353"), native_int::BinaryInteger("8369"), native_int::BinaryInteger("8513")};
	std::vector<native_int::BinaryInteger> rootsOfUnity(towersize);
	rootsOfUnity = {native_int::BinaryInteger("8163"), native_int::BinaryInteger("6677"), native_int::BinaryInteger("156")};

	BigBinaryInteger modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native_int::ILParams> ilparams0( new native_int::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native_int::ILParams> ilparams1( new native_int::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native_int::ILParams> ilparams2( new native_int::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native_int::ILVector2n ilv0(ilparams0);
	native_int::BinaryVector bbv0(m/2, moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native_int::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native_int::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<BigBinaryInteger>> ildcrtparams( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	std::vector<native_int::ILVector2n> ilvector2nVector;
	ilvector2nVector.push_back(ilv0);
	ilvector2nVector.push_back(ilv1);
	ilvector2nVector.push_back(ilv2);

	DEBUG("1");
	float stdDev = 4.0;
	ILDCRT2n::DggType dgg(stdDev);

	{
		ILDCRT2n ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) 
			<<"Failure: ildcrtparams ctor ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<<"Failure: ildcrtparams ctor ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<<"Failure: ildcrtparams ctor ilva.GetModulus()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())			
			<<"Failure: ildcrtparams ctor ilva.GetNumOfElements()";
	}

	DEBUG("2");
	{
		ILDCRT2n ilva(ilvector2nVector);

		DEBUG("2.0");
		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())			
			<<"Failure: ctor ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<<"Failure: ctor ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<<"Failure: ctor ilva.GetCyclotomicOrder()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
			<<"Failure: ctor ilva.GetNumOfElements()";

		DEBUG("2.1");
		std::vector<native_int::ILVector2n> ilvector2nVectorInconsistent(towersize);
		shared_ptr<native_int::ILParams> ilparamsNegativeTestCase( new native_int::ILParams(128, native_int::BinaryInteger("1231"), native_int::BinaryInteger("213")) );
		native_int::ILVector2n ilvNegative(ilparamsNegativeTestCase);
		ilvector2nVectorInconsistent[0] = ilvNegative;
		ilvector2nVectorInconsistent[1] = ilv1;
		ilvector2nVectorInconsistent[2] = ilv2;

		DEBUG("2.2");
		for( size_t ii=0; ii<ilvector2nVectorInconsistent.size(); ii++ ) {
			DEBUG(ii << " item " << ilvector2nVectorInconsistent.at(ii).GetParams().use_count());			

		}
		EXPECT_THROW(testILVectorArray2nConstructorNegative(ilvector2nVectorInconsistent), std::logic_error)
			<<"Failure: ilvector2nVectorInconsistent";
	}

	DEBUG("4");
	{
		ILDCRT2n ilva0;
		ILDCRT2n ilva1(ildcrtparams);
		ILDCRT2n ilva2(ilvector2nVector);

		std::vector<ILDCRT2n> ilvaVector( { ilva0, ilva1, ilva2 } );

		//copy constructor
		ILDCRT2n ilva0Copy(ilva0);
		ILDCRT2n ilva1Copy(ilva1);
		ILDCRT2n ilva2Copy(ilva2);

		std::vector<ILDCRT2n> ilvaCopyVector( { ilva0Copy, ilva1Copy, ilva2Copy } );

		for (usint i = 0; i < 3; ++i)
		{
			EXPECT_EQ(ilvaVector[i].GetFormat(), ilvaCopyVector[i].GetFormat())
				<<"Failure: ctor ilvaCopyVector["<<i<<"].GetFormat()";
			EXPECT_EQ(ilvaVector[i].GetModulus(), ilvaCopyVector[i].GetModulus())
				<<"Failure: ctor ilvaCopyVector["<<i<<"].GetModulus()";
			EXPECT_EQ(ilvaVector[i].GetCyclotomicOrder(), ilvaCopyVector[i].GetCyclotomicOrder())
				<<"Failure: ctor ilvaCopyVector["<<i<<"].GetCyclotomicOrder()";
			EXPECT_EQ(ilvaVector[i].GetNumOfElements(), ilvaCopyVector[i].GetNumOfElements())
				<<"Failure: ctor ilvaCopyVector["<<i<<"].GetNumOfElements()";
			if(i==0 || i==1) // to ensure that GetElementAtIndex is not called on uninitialized ILDCRT2n objects.
				continue;
			for (usint j = 0; j < towersize; ++j)
			{
				EXPECT_EQ(ilvaVector[i].GetElementAtIndex(j), ilvaCopyVector[i].GetElementAtIndex(j))
					<<"Failure: ctor ilvaCopyVector["<<i<<"].GetElementAtIndex("<<j<<")";
;
			}
		}

	}

	DEBUG("5");
	{
		DEBUG("ild mod " << ildcrtparams->GetModulus());
		ILDCRT2n ilva(dgg, ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())			
			<<"Failure: ctor(dgg, ldcrtparams) ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<<"Failure: ctor(dgg, ildcrtparams) ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<<"Failure: ctor(dgg, ildcrtparams) ilva.GetCyclotomicOrder()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
			<<"Failure: ctor(dgg, ildcrtparams) ilva.GetNumOfElements()";
	}

	DEBUG("6");
	{
		ILDCRT2n ilva(dgg, ildcrtparams);
		ILDCRT2n ilvaClone(ilva.CloneParametersOnly());

		std::vector<native_int::ILVector2n> towersInClone = ilvaClone.GetAllElements();

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat());
		EXPECT_EQ(modulus, ilva.GetModulus());
		EXPECT_EQ(m, ilva.GetCyclotomicOrder());
		//todo: finish this test
		std::cout<<"Not all tests written yet for this function"<<std::endl;
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
	bbv1 = {"62","7","65","8"};
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(2);
		VecType expected(4, primeModulus);
		expected = {"1","1","0","0"};
		EXPECT_EQ(expected, ilv1.GetValues())
			<<"Failure: ilv1.SignedMod(TWO)";
	}

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.SignedMod(5);
		VecType expected(4, primeModulus);
		expected = {"4","2","2","3"};
		EXPECT_EQ(expected, ilv1.GetValues())
			<<"Failure: ilv1.SignedMod(FIVE)";
	}
}
//Instantiations of signed_mod_tests()
TEST(UTILVector2n, signed_mod_tests) {
	signed_mod_tests<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, signed_mod_tests) {
	signed_mod_tests<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

//TEST(UTILDCRT2n, signed_mod_tests) {
//	signed_mod_tests<BigBinaryInteger, BigBinaryVector, ILDCRTParams, ILDCRT2n>();
//}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void transposition_test() {
  bool dbg_flag = false;
	usint m = 8;

	IntType q("73");
	IntType primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams(new ParmType(m, q, primitiveRootOfUnity));

	Element ilvector2n1(ilparams, COEFFICIENT);
	ilvector2n1 = {"31","21","15","34"};

	// converts to evaluation representation
	ilvector2n1.SwitchFormat();
	DEBUG("ilvector2n1 a "<<ilvector2n1);

	ilvector2n1 = ilvector2n1.Transpose();
	DEBUG("ilvector2n1 b "<<ilvector2n1);

	// converts back to coefficient representation
	ilvector2n1.SwitchFormat();

	DEBUG("ilvector2n1 c "<<ilvector2n1);

	Element ilvector2n2(ilparams);

	VecType bbv0(m / 2, q);
	bbv0 = {"31","39","58","52"};
	ilvector2n2.SetValues(bbv0, Format::COEFFICIENT);

	DEBUG("ilvector2n2 a "<<ilvector2n2);

	EXPECT_EQ(ilvector2n2, ilvector2n1)
		<<"Failure: transposition test";
}
//Instantiations of transposition_test()
TEST(UTILVector2n, transposition_test) {
	transposition_test<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, transposition_test) {
	transposition_test<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

// ILDCRT2n Only
TEST(UTILDCRT2n, getters_and_operators) {
	usint m = 8;
	usint towersize = 3;

	std::vector<native_int::BinaryInteger> moduli(towersize);
	moduli = {native_int::BinaryInteger("8353"),
		  native_int::BinaryInteger("8369"),
 		  native_int::BinaryInteger("8513")};

	std::vector<native_int::BinaryInteger> rootsOfUnity(towersize);

	rootsOfUnity = {native_int::BinaryInteger("8163"), 
			native_int::BinaryInteger("6677"), 
			native_int::BinaryInteger("156")};

	BigBinaryInteger modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native_int::ILParams> ilparams0( new native_int::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native_int::ILParams> ilparams1( new native_int::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native_int::ILParams> ilparams2( new native_int::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native_int::ILVector2n ilv0(ilparams0);
	native_int::BinaryVector bbv0(ilparams0->GetRingDimension(), moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native_int::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native_int::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<BigBinaryInteger>> ildcrtparams( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	std::vector<native_int::ILVector2n> ilvector2nVector(towersize);

	ilvector2nVector = {ilv0, ilv1, ilv2};	
	{
		ILDCRT2n ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())
		  <<"Failure: ilva format";
		EXPECT_EQ(modulus, ilva.GetModulus())
		  <<"Failure: ilva modulus";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
		  <<"Failure: ilva cyclotomicOrder";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
		  <<"Failure: ilva number of elements";
	}

	ILDCRT2n ilva(ilvector2nVector);

	{
		ILDCRT2n ilva1(ilva);
		EXPECT_TRUE(ilva == ilva1) << "Failure: ilva CTOR";
	}

	{
		ILDCRT2n ilva1 = ilva;
		EXPECT_EQ(ilva, ilva1) << "Failure: ilva operator=";
	}

	{
		ILDCRT2n ilva1(ildcrtparams);
		ilva1 = {2, 4, 3, 2};
		EXPECT_EQ(ilva, ilva1) << "Failure: ilva CTOR(params)";
	}

	{
		native_int::ILVector2n ilvect0(ilparams0);
		native_int::BinaryVector bbv1(m/2, moduli[0]);
		bbv1 = {"2","1","3","2"};
		ilvect0.SetValues(bbv1, Format::EVALUATION);

		native_int::ILVector2n ilvect1(ilvect0);
		ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

		native_int::ILVector2n ilvect2(ilvect0);
		ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<native_int::ILVector2n> ilvector2nVector1(towersize);
		ilvector2nVector1 = {ilvect0, ilvect1, ilvect2};

		ILDCRT2n ilva1(ilvector2nVector1);

		EXPECT_TRUE(ilva!=ilva1) << "Failure: ilva operator!=";
	}

}

TEST(UTILDCRT2n, arithmetic_ops_element_2) {
	usint m = 8;
	usint towersize = 3;

	std::vector<native_int::BinaryInteger> moduli(towersize);
	moduli = {
		native_int::BinaryInteger("8353"), 
		native_int::BinaryInteger("8369"), 
		native_int::BinaryInteger("8513")
	};
	std::vector<native_int::BinaryInteger> rootsOfUnity(towersize);
	rootsOfUnity = {
		native_int::BinaryInteger("8163"), 
		native_int::BinaryInteger("6677"), 
		native_int::BinaryInteger("156")};

	BigBinaryInteger modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<native_int::ILParams> ilparams0( new native_int::ILParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<native_int::ILParams> ilparams1( new native_int::ILParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<native_int::ILParams> ilparams2( new native_int::ILParams(m, moduli[2], rootsOfUnity[2]) );

	native_int::ILVector2n ilv0(ilparams0);
	native_int::BinaryVector bbv0(m/2, moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	native_int::ILVector2n ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native_int::ILVector2n ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<BigBinaryInteger>> ildcrtparams( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	std::vector<native_int::ILVector2n> ilvector2nVector(towersize);
	ilvector2nVector[0] = ilv0;
	ilvector2nVector[1] = ilv1;
	ilvector2nVector[2] = ilv2;

	ILDCRT2n ilva(ilvector2nVector);

	native_int::ILVector2n ilvect0(ilparams0);
	native_int::BinaryVector bbv1(m/2, moduli[0]);
	bbv1 = {"2","1","2","0"};
	ilvect0.SetValues(bbv1, Format::EVALUATION);

	native_int::ILVector2n ilvect1(ilvect0);
	ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	native_int::ILVector2n ilvect2(ilvect0);
	ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	std::vector<native_int::ILVector2n> ilvector2nVector1(towersize);
	ilvector2nVector1[0] = ilvect0;
	ilvector2nVector1[1] = ilvect1;
	ilvector2nVector1[2] = ilvect2;

	ILDCRT2n ilva1(ilvector2nVector1);

	{
		ILDCRT2n ilvaCopy(ilva.Plus(ilva1));
		// ilvaCopy = ilvaCopy + ilva1;

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"4","5","5","2"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: Plus()";
		}
	}

	{
		ILDCRT2n ilvaCopy(ilva);
		ilvaCopy += ilva1;
	//TODO: clean up <<"Failure: +=";

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"4","5","5","2"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: +=";
		}
	}
	{
		ILDCRT2n ilvaCopy(ilva.Minus(ilva1));
		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"0","3","1","2"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: Minus";
		}
	}
	{
		ILDCRT2n ilvaResult(ilva);
		ilvaResult -= ilva1;
		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaResult.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"0","3","1","2"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: -=";
		}
	}
	{
		ILDCRT2n ilvaResult(ilva.Times(ilva1));
		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaResult.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"4","4","6","0"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: Times()";
		}
	}
	{
		ILDCRT2n ilvaCopy(ilva);
		ilvaCopy.AddILElementOne();

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"3","5","4","3"};
			EXPECT_EQ(expected, ilv.GetValues()) <<"Failure: AddILElementOne";
		}
	}

	{
		ILDCRT2n ilvaInv(ilva.MultiplicativeInverse());

		native_int::ILVector2n ilvectInv0 = ilvaInv.GetElementAtIndex(0);
		//TODO: SHOULD BE ABLE TO SAY native_int::ILVector2n ilvectInv0 = ilvaInv[0];
		native_int::ILVector2n ilvectInv1 = ilvaInv.GetElementAtIndex(1);
		native_int::ILVector2n ilvectInv2 = ilvaInv.GetElementAtIndex(2);
		native_int::BinaryVector expected0 (4, ilvectInv0.GetModulus());
		expected0 = {"4177","6265","5569","4177"};
		EXPECT_EQ(expected0, ilvectInv0.GetValues())
		  <<"Failure: ilvectInv0 MultiplicativeInverse()";
		EXPECT_EQ(native_int::BinaryInteger("8353"), ilvectInv0.GetModulus())
		  <<"Failure: ilvectInv0 MultiplicativeInverse() modulus";
		EXPECT_EQ(native_int::BinaryInteger("8163"), ilvectInv0.GetRootOfUnity())
		  <<"Failure: ilvectInv0 MultiplicativeInverse() rootOfUnity";

		native_int::BinaryVector expected1 (4, ilvectInv1.GetModulus());
		expected1 = {"4185","6277","2790","4185"};
		EXPECT_EQ(expected1, ilvectInv1.GetValues())
		  <<"Failure: ilvectInv1 MultiplicativeInverse()";
		EXPECT_EQ(native_int::BinaryInteger("8369"), ilvectInv1.GetModulus())
		  <<"Failure: ilvectInv1 MultiplicativeInverse() modulus";
		EXPECT_EQ(native_int::BinaryInteger("6677"), ilvectInv1.GetRootOfUnity())
		  <<"Failure: ilvectInv1 MultiplicativeInverse() rootOfUnity";

		native_int::BinaryVector expected2 (4, ilvectInv2.GetModulus());
		expected2 = {"4257","6385","2838","4257"};
		EXPECT_EQ(expected2, ilvectInv2.GetValues())
		  <<"Failure: ilvectInv2 MultiplicativeInverse()";
		EXPECT_EQ(native_int::BinaryInteger("8513"), ilvectInv2.GetModulus())
		  <<"Failure: ilvectInv2 MultiplicativeInverse() modulus";
		EXPECT_EQ(native_int::BinaryInteger("156"), ilvectInv2.GetRootOfUnity())
		  <<"Failure: ilvectInv2 MultiplicativeInverse() rootOfUnity";
		EXPECT_THROW(ilva1.MultiplicativeInverse(), std::logic_error)      
			<<"Failure: throw MultiplicativeInverse()";
	}

	{
		ILDCRT2n ilvaCopy(ilva);

		ilvaCopy.MakeSparse(2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(native_int::BinaryInteger(0), ilv.GetValAtIndex(1))
				<<"Failure MakeSparse() index 1";
			EXPECT_EQ(native_int::BinaryInteger(0), ilv.GetValAtIndex(3))
				<<"Failure MakeSparse() index 3";
		}
	}

	{
	        EXPECT_TRUE(ilva.InverseExists())<<"Failure: ilva.InverseExists()";
		EXPECT_FALSE(ilva1.InverseExists())<<"Failure: ilva1.InverseExists()";
	}

	// this case is NOT used because SwitchModulus is not really defined for an ILDCRT2n, so...
	if( false )
	{
		native_int::ILVector2n ilvS0(ilparams0);
		native_int::BinaryVector bbvS0(m/2, moduli[0]);
		bbvS0 = {"23462","467986","33863","2113"};
		ilvS0.SetValues(bbvS0, Format::EVALUATION);
		std::cout << ilvS0.GetValues() << std::endl;

		native_int::ILVector2n ilvS1(ilvS0);
		native_int::ILVector2n ilvS2(ilvS0);

		ilvS0.SwitchModulus(moduli[0], rootsOfUnity[0]);
		ilvS1.SwitchModulus(moduli[1], rootsOfUnity[1]);
		ilvS2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<native_int::ILVector2n> ilvector2nVectorS(towersize);
		ilvector2nVectorS[0] = ilvS0;
		ilvector2nVectorS[1] = ilvS1;
		ilvector2nVectorS[2] = ilvS2;

		ILDCRT2n ilvaS(ilvector2nVectorS);
		BigBinaryInteger modulus2("113");
		BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity<BigBinaryInteger>(m, modulus2));

		ilvaS.SwitchModulus(modulus2, rootOfUnity2);

		native_int::ILVector2n ilvectS0 = ilvaS.GetElementAtIndex(0);
		native_int::ILVector2n ilvectS1 = ilvaS.GetElementAtIndex(1);
		native_int::ILVector2n ilvectS2 = ilvaS.GetElementAtIndex(2);

		EXPECT_EQ(native_int::BinaryInteger("80"), ilvectS0.GetValAtIndex(0));
		EXPECT_EQ(native_int::BinaryInteger("62"), ilvectS0.GetValAtIndex(1));
		EXPECT_EQ(native_int::BinaryInteger("85"), ilvectS0.GetValAtIndex(2));
		EXPECT_EQ(native_int::BinaryInteger("79"), ilvectS0.GetValAtIndex(3));
		EXPECT_EQ(native_int::BinaryInteger("113"), ilvectS0.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS0.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(native_int::BinaryInteger("66"), ilvectS1.GetValAtIndex(0));
		EXPECT_EQ(native_int::BinaryInteger("16"), ilvectS1.GetValAtIndex(1));
		EXPECT_EQ(native_int::BinaryInteger("64"), ilvectS1.GetValAtIndex(2));
		EXPECT_EQ(native_int::BinaryInteger("79"), ilvectS1.GetValAtIndex(3));
		EXPECT_EQ(native_int::BinaryInteger("113"), ilvectS1.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS1.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(native_int::BinaryInteger(4), ilvectS2.GetValAtIndex(0));
		EXPECT_EQ(native_int::BinaryInteger("44"), ilvectS2.GetValAtIndex(1));
		EXPECT_EQ(native_int::BinaryInteger("84"), ilvectS2.GetValAtIndex(2));
		EXPECT_EQ(native_int::BinaryInteger("79"), ilvectS2.GetValAtIndex(3));
		EXPECT_EQ(native_int::BinaryInteger("113"), ilvectS2.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS2.GetRootOfUnity().ConvertToInt());
	}

	{
		ILDCRT2n ilvaCopy(ilva);
		BigBinaryInteger modulus2("113");
		BigBinaryInteger rootOfUnity2(lbcrypto::RootOfUnity<BigBinaryInteger>(m, modulus2));
		ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			native_int::ILVector2n ilv = ilvaCopy.GetElementAtIndex(i);
			native_int::BinaryVector expected (4, ilv.GetModulus());
			expected = {"2","4","3","2"};
			EXPECT_EQ(expected, ilv.GetValues())
				<<"Failure: ilv.SwitchModulusAtIndex";

			if(i==0){
				EXPECT_EQ(modulus2.ConvertToInt(), ilv.GetModulus().ConvertToInt())
					<<"Failure: SwitchModulusAtIndex modulus";
;
				EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilv.GetRootOfUnity().ConvertToInt())	
				<<"Failure: SwitchModulusAtIndex rootOfUnity";
;
			}
		}
	}

}

TEST(UTILDCRT2n, decompose_test) {
	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;
	usint ptm = 2;

	float stdDev = 4;
	ILDCRT2n::DggType dgg(stdDev);

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params = GenerateDCRTParams(order, ptm, towersize, nBits);
	ILDCRT2n ilVectorArray2n(dgg, params, Format::COEFFICIENT);

	ILDCRT2n ilvectorarray2nOriginal(ilVectorArray2n);
	ilVectorArray2n.Decompose();

	EXPECT_EQ(ilvectorarray2nOriginal.GetNumOfElements(), ilVectorArray2n.GetNumOfElements()) << "Failure ILDCRT2n.Decompose(): Mismatch in the number of towers";

	for(usint i=0; i<ilVectorArray2n.GetNumOfElements(); i++) {
		native_int::ILVector2n ilTowerOriginal(ilvectorarray2nOriginal.GetElementAtIndex(i));
		native_int::ILVector2n ilTowerDecomposed(ilVectorArray2n.GetElementAtIndex(i));

		EXPECT_EQ(ilTowerDecomposed.GetLength(), ilTowerOriginal.GetLength()/2)  << "Failure: ILDCRT2n.Decompose(): ilVector2n element "<<i<<" in ilVectorArray2n is not half the length";

		for(usint j=0; j<ilTowerDecomposed.GetLength(); j++) {
			EXPECT_EQ(ilTowerDecomposed.GetValAtIndex(j), ilTowerOriginal.GetValAtIndex(2*j)) << "Failure: ILDCRT2n.Decompose(): Value mismatch";
		}
	}

}

template<typename IntType, typename VecType, typename ParmType, typename Element>
void ensures_mod_operation_during_ops_on_two_ILVector2ns() {

	usint order = 8;
	usint nBits = 7;

	IntType primeModulus = lbcrypto::FirstPrime<IntType>(nBits, order);
	IntType primitiveRootOfUnity = lbcrypto::RootOfUnity<IntType>(order, primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(order, primeModulus, primitiveRootOfUnity) );

	typename Element::DugType distrUniGen = typename Element::DugType();
	distrUniGen.SetModulus(primeModulus);

	Element ilv1(distrUniGen, ilparams);
	VecType bbv1 (ilv1.GetValues());

	Element ilv2(distrUniGen, ilparams);
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

TEST(UTILVector2n, ensures_mod_operation_during_ops_on_two_ILVector2ns) {
	ensures_mod_operation_during_ops_on_two_ILVector2ns<BigBinaryInteger, BigBinaryVector, ILParams, ILVector2n>();
}

TEST(UTILNativeVector2n, ensures_mod_operation_during_ops_on_two_ILVector2ns) {
	ensures_mod_operation_during_ops_on_two_ILVector2ns<native_int::BinaryInteger, native_int::BinaryVector, native_int::ILParams, native_int::ILVector2n>();
}

TEST(UTILDCRT2n, ensures_mod_operation_during_ops_on_two_ILVectorArray2ns){

	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;
	usint ptm = 2;

	shared_ptr<ILDCRTParams<BigBinaryInteger>> ildcrtparams = GenerateDCRTParams(order, ptm, towersize, nBits);

	ILDCRT2n::DugType dug;

	ILDCRT2n op1(dug, ildcrtparams);
	ILDCRT2n op2(dug, ildcrtparams);

	{
		ILDCRT2n sum = op1 + op2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<ildcrtparams->GetRingDimension(); j++) {
				native_int::BinaryInteger actualResult(sum.GetElementAtIndex(i).GetValAtIndex(j));
				native_int::BinaryInteger expectedResult((op1.GetElementAtIndex(i).GetValAtIndex(j) + op2.GetElementAtIndex(i).GetValAtIndex(j)).Mod(ildcrtparams->GetParams()[i]->GetModulus()));
				EXPECT_EQ(actualResult, expectedResult) << "Failure: ILDCRT2n + operation tower "<<i<<" index "<<j;
			}
		}
	}

	{
		ILDCRT2n prod = op1 * op2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<ildcrtparams->GetRingDimension(); j++) {
				native_int::BinaryInteger actualResult(prod.GetElementAtIndex(i).GetValAtIndex(j));
				native_int::BinaryInteger expectedResult((op1.GetElementAtIndex(i).GetValAtIndex(j) * op2.GetElementAtIndex(i).GetValAtIndex(j)).Mod(ildcrtparams->GetParams()[i]->GetModulus()));
				EXPECT_EQ(actualResult, expectedResult)  << "Failure: ILDCRT2n * operation tower "<<i<<" index "<<j;
			}
		}
	}

}

void testILVectorArray2nConstructorNegative(std::vector<native_int::ILVector2n> &towers) {
	ILDCRT2n expectException(towers);
}
