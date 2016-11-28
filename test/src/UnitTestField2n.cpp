/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
K.Doruk Gur, kg365@njit.edu
Description:
This code exercises the Field2n methods of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../include/gtest/gtest.h"
#include "../../src/lib/lattice/field2n.h"

using namespace lbcrypto;

class UnitTestField2n : public ::testing::Test {
protected:
	virtual void SetUp() {
	}

	virtual void TearDown() {
		// Code here will be called immediately after each test
		// (right before the destructor).
	}
};
/*---------------------------------------	TESTING METHODS OF FIELD2N  --------------------------------------------*/

//TEST FOR GETTER FOR FORMAT
TEST(UTField2n, get_format) {
	bool dbg_flag = false;

	DEBUG("Step 1");
	Field2n test(2, COEFFICIENT, true);
	DEBUG("Step 2");
	EXPECT_EQ(COEFFICIENT, test.GetFormat())
		<< "Failed getter" << std::endl;
}
//TEST FOR INVERSE OF FIELD ELEMENT
TEST(UTField2n, inverse) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n test(2, EVALUATION, true);
	test.at(0) = std::complex<double>(2, 0);
	test.at(1) = std::complex<double>(-4, 0);
	DEBUG("Step 2");
	Field2n inverse(2, EVALUATION, true);
	inverse.at(0) = std::complex<double>(0.5, 0);
	inverse.at(1) = std::complex<double>(-0.25, 0);
	DEBUG("Step 3");
	EXPECT_EQ(inverse, test.Inverse());
}
//TEST FOR ADDITION OPERATION
TEST(UTField2n, plus) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(2, EVALUATION, true);
	a.at(0) = std::complex<double>(2, 1);
	a.at(1) = std::complex<double>(-4, 2);
	DEBUG("Step 2");
	Field2n b(2, EVALUATION, true);
	b.at(0) = std::complex<double>(3, -0.1);
	b.at(1) = std::complex<double>(-4, 3.2);
	DEBUG("Step 3");
	Field2n c(2, EVALUATION, true);
	c.at(0) = std::complex<double>(5, 0.9);
	c.at(1) = std::complex<double>(-8, 5.2);
	EXPECT_EQ(c, a.Plus(b));
}

//TEST FOR SUBSTRACTION OPERATION
TEST(UTField2n, minus) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(2, EVALUATION, true);
	a.at(0) = std::complex<double>(2, 1);
	a.at(1) = std::complex<double>(-4, 2);
	DEBUG("Step 2");
	Field2n b(2, EVALUATION, true);
	b.at(0) = std::complex<double>(3, -0.1);
	b.at(1) = std::complex<double>(-4, 3.2);
	DEBUG("Step 3");
	Field2n c(2, EVALUATION, true);
	c.at(0) = std::complex<double>(-1, 1.1);
	c.at(1) = std::complex<double>(0, -1.2);
	EXPECT_EQ(c, a.Minus(b));
}

//TEST FOR MULTIPLICATION OPERATION
TEST(UTField2n, times) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(2, EVALUATION, true);
	a.at(0) = std::complex<double>(4, 3);
	a.at(1) = std::complex<double>(6, -3);
	DEBUG("Step 2");
	Field2n b(2, EVALUATION, true);
	b.at(0) = std::complex<double>(4, -3);
	b.at(1) = std::complex<double>(4, -2.8);
	DEBUG("Step 3");
	Field2n c(2, EVALUATION, true);
	c.at(0) = std::complex<double>(25, 0);
	c.at(1) = std::complex<double>(15.6, -28.8);
	DEBUG("Step 4");
	EXPECT_EQ(c, a.Times(b));
}

//TEST FOR SHIFT RIGHT OPERATION
TEST(UTField2n, shift_right) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(3, 0);
	a.at(2) = std::complex<double>(2, 0);
	a.at(3) = std::complex<double>(1, 0);
	DEBUG("Step 2");
	Field2n b(4, COEFFICIENT, true);
	b.at(0) = std::complex<double>(-1, 0);
	b.at(1) = std::complex<double>(4, 0);
	b.at(2) = std::complex<double>(3, 0);
	b.at(3) = std::complex<double>(2, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.ShiftRight());
}

//TEST FOR TRANSPOSE OPERATION
TEST(UTField2n, transpose) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(3, 0);
	a.at(2) = std::complex<double>(2, 0);
	a.at(3) = std::complex<double>(1, 0);
	DEBUG("Step 2");
	Field2n b(4, COEFFICIENT, true);
	b.at(0) = std::complex<double>(4, 0);
	b.at(1) = std::complex<double>(-1, 0);
	b.at(2) = std::complex<double>(-2, 0);
	b.at(3) = std::complex<double>(-3, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.Transpose());
}

//TEST FOR EXTRACT ODD OPERATION
TEST(UTField2n, extract_odd) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(3, 0);
	a.at(2) = std::complex<double>(2, 0);
	a.at(3) = std::complex<double>(1, 0);
	DEBUG("Step 2");
	Field2n b(2, COEFFICIENT, true);
	b.at(0) = std::complex<double>(3, 0);
	b.at(1) = std::complex<double>(1, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.ExtractOdd());
}

//TEST FOR EXTRACT EVEN OPERATION
TEST(UTField2n, extract_even) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(3, 0);
	a.at(2) = std::complex<double>(2, 0);
	a.at(3) = std::complex<double>(1, 0);
	DEBUG("Step 2");
	Field2n b(2, COEFFICIENT, true);
	b.at(0) = std::complex<double>(4, 0);
	b.at(1) = std::complex<double>(2, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.ExtractEven());
}

//TEST FOR PERMUTE OPERATION
TEST(UTField2n, permute) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(1, 0);
	a.at(1) = std::complex<double>(2, 0);
	a.at(2) = std::complex<double>(3, 0);
	a.at(3) = std::complex<double>(4, 0);
	DEBUG("Step 2");
	Field2n b(4, COEFFICIENT, true);
	b.at(0) = std::complex<double>(1, 0);
	b.at(1) = std::complex<double>(3, 0);
	b.at(2) = std::complex<double>(2, 0);
	b.at(3) = std::complex<double>(4, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.Permute());
}

//TEST FOR INVERSE PERMUTE OPERATION
TEST(UTField2n, inveres_permute) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, COEFFICIENT, true);
	a.at(0) = std::complex<double>(1, 0);
	a.at(1) = std::complex<double>(3, 0);
	a.at(2) = std::complex<double>(2, 0);
	a.at(3) = std::complex<double>(4, 0);
	DEBUG("Step 2");
	Field2n b(4, COEFFICIENT, true);
	b.at(0) = std::complex<double>(1, 0);
	b.at(1) = std::complex<double>(2, 0);
	b.at(2) = std::complex<double>(3, 0);
	b.at(3) = std::complex<double>(4, 0);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.InversePermute());
}

//TEST FOR SCALAR MULT OPERATION
TEST(UTField2n, scalar_mult) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(4, EVALUATION, true);
	a.at(0) = std::complex<double>(1, -1);
	a.at(1) = std::complex<double>(3, -2);
	a.at(2) = std::complex<double>(2, -3);
	a.at(3) = std::complex<double>(4, -4);
	DEBUG("Step 2");
	Field2n b(4, EVALUATION, true);
	b.at(0) = std::complex<double>(3, -3);
	b.at(1) = std::complex<double>(9, -6);
	b.at(2) = std::complex<double>(6, -9);
	b.at(3) = std::complex<double>(12, -12);
	DEBUG("Step 3");
	EXPECT_EQ(b, a.ScalarMult(3));
}

//TEST FOR COEFFICIENT TO EVALUATION FORMAT CHANGE
TEST(UTField2n, coefficient_evaluation) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n a(8, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(5, 0);
	a.at(2) = std::complex<double>(5, 0);
	a.at(3) = std::complex<double>(4.2, 0);
	a.at(4) = std::complex<double>(5, 0);
	a.at(5) = std::complex<double>(7.1, 0);
	a.at(6) = std::complex<double>(6, 0);
	a.at(7) = std::complex<double>(3, 0);
	DEBUG("Step 2");
	Field2n b(8, EVALUATION, true);
	b.at(0) = std::complex<double>(8.74631, 52.2118);
	b.at(1) = std::complex<double>(17.281, 12.1583);
	b.at(2) = std::complex<double>(3.5474, 1.04558);
	b.at(3) = std::complex<double>(6.42526, 1.09913);
	b.at(4) = std::complex<double>(6.42526, -1.09913);
	b.at(5) = std::complex<double>(3.5474, -1.04558);
	b.at(6) = std::complex<double>(17.281, -12.1583);
	b.at(7) = std::complex<double>(8.74631, -52.2118);
	DEBUG("Step 3");
	a.SwitchFormat();
	EXPECT_EQ(b, a);
}

//TEST FOR EVALUATION TO COEFFICIENT FORMAT CHANGE
TEST(UTField2n, evaluation_coefficient) {
	bool dbg_flag = false;
	DEBUG("Step 1");
	Field2n b(8, EVALUATION, true);
	b.at(0) = std::complex<double>(8.74631, 52.2118);
	b.at(1) = std::complex<double>(17.281, 12.1583);
	b.at(2) = std::complex<double>(3.5474, 1.04558);
	b.at(3) = std::complex<double>(6.42526, 1.09913);
	b.at(4) = std::complex<double>(6.42526, -1.09913);
	b.at(5) = std::complex<double>(3.5474, -1.04558);
	b.at(6) = std::complex<double>(17.281, -12.1583);
	b.at(7) = std::complex<double>(8.74631, -52.2118);
	DEBUG("Step 2");
	Field2n a(8, COEFFICIENT, true);
	a.at(0) = std::complex<double>(4, 0);
	a.at(1) = std::complex<double>(5, 0);
	a.at(2) = std::complex<double>(5, 0);
	a.at(3) = std::complex<double>(4.2, 0);
	a.at(4) = std::complex<double>(5, 0);
	a.at(5) = std::complex<double>(7.1, 0);
	a.at(6) = std::complex<double>(6, 0);
	a.at(7) = std::complex<double>(3, 0);
	
	DEBUG("Step 3");
	b.SwitchFormat();
	EXPECT_EQ(a, b);
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

