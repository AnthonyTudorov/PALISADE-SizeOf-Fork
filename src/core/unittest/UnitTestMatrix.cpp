/*
  PRE SCHEME PROJECT, Crypto Lab, NJIT
  Version:
  v00.01
  Last Edited:
  11/15/2015
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


#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "math/matrix.cpp"
#include "math/matrixstrassen.cpp"

//using namespace std;
using namespace lbcrypto;


class UnitTestMatrix : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF BININT CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

static function<unique_ptr<ILVector2n>()> secureIL2nAlloc() {
    BigBinaryInteger secureModulus("8590983169");
    BigBinaryInteger secureRootOfUnity("4810681236");
    return ILVector2n::MakeAllocator(
        shared_ptr<ILParams>( new ILParams(
        2048, secureModulus, secureRootOfUnity) ),
        EVALUATION
        );
}

static function<unique_ptr<ILVector2n>()> fastIL2nAlloc() {
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
    return ILVector2n::MakeAllocator(
        shared_ptr<ILParams>( new ILParams(
        m, modulus, rootOfUnity) ),
        EVALUATION
        );
}

static function<unique_ptr<ILVector2n>()> fastUniformIL2nAlloc() {
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	return ILVector2n::MakeDiscreteUniformAllocator(
		shared_ptr<ILParams>(new ILParams(
			m, modulus, rootOfUnity)),
		EVALUATION
	);
}

TEST(UTMatrix,serializer) {
	Matrix<int32_t> m([](){return make_unique<int32_t>();}, 3, 5);
}

TEST(UTMatrix,basic_il2n_math){
    Matrix<ILVector2n> z(secureIL2nAlloc(), 2,2);
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    Matrix<ILVector2n> I = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Identity();
    I.SetFormat(COEFFICIENT);
    I.SetFormat(EVALUATION);
    EXPECT_EQ(n, I*n);

    n -= n;
    EXPECT_EQ(n, z);

    //Matrix<ILVector2n> m = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    //m.Fill(2);
    //n.Fill(1);
    //n = n + n;
    //EXPECT_EQ(n, m);
}

TEST(UTMatrix,basic_int_math){
    Matrix<BigBinaryInteger> z(BigBinaryInteger::Allocator, 2,2);
    Matrix<BigBinaryInteger> n = Matrix<BigBinaryInteger>(BigBinaryInteger::Allocator, 2, 2).Ones();
    Matrix<BigBinaryInteger> I = Matrix<BigBinaryInteger>(BigBinaryInteger::Allocator, 2, 2).Identity();
    EXPECT_EQ(n, I*n);
    n -= n;
    EXPECT_EQ(n, z);
}

TEST(UTMatrix,basic_intvec_math){

  bool dbg_flag = false;

    BigBinaryInteger modulus("67108913");
    DEBUG("1");
    auto singleAlloc = [=](){ return make_unique<BigBinaryVector>(1, modulus); };
    DEBUG("2");
    Matrix<BigBinaryVector> z(singleAlloc, 2,2);
    DEBUG("3");
    Matrix<BigBinaryVector> n = Matrix<BigBinaryVector>(singleAlloc, 2, 2).Ones();
    DEBUG("4");
    Matrix<BigBinaryVector> I = Matrix<BigBinaryVector>(singleAlloc, 2, 2).Identity();
    DEBUG("5");
    DEBUG("z mod 00 "<<z(0,0).GetModulus().ToString());
    DEBUG("z mod 01 "<<z(0,1).GetModulus().ToString());
    DEBUG("z mod 10 "<<z(1,0).GetModulus().ToString());
    DEBUG("z mod 1 1 "<<z(1,1).GetModulus().ToString());
    DEBUG("n mod "<<n(0,0).GetModulus().ToString());
    DEBUG("I mod "<<I(0,0).GetModulus().ToString());
    EXPECT_EQ(n, I*n);
    DEBUG("6");
    n -= n;
    DEBUG("7");
    EXPECT_EQ(n, z);
    DEBUG("8");
}

TEST(UTMatrix, transpose){
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    Matrix<ILVector2n> nT = Matrix<ILVector2n>(n).Transpose();
    Matrix<ILVector2n> I = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Identity();
    EXPECT_EQ(nT, I*nT);
}

TEST(UTMatrix, scalar_mult){
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    auto one = secureIL2nAlloc()();
    *one = 1;
    EXPECT_EQ(n, *one*n);
    EXPECT_EQ(n, n**one);

    //auto two = secureIL2nAlloc()();
    //Matrix<ILVector2n> twos = Matrix<ILVector2n>(secureIL2nAlloc(), 4, 2).Fill(2);
    //*two = 2;
    //EXPECT_EQ(*two*n, twos);
    //EXPECT_EQ(n**two, twos);
}

TEST(UTMatrix, ILVector2n_mult_square_matrix) {

	int32_t dimension = 8;

	Matrix<ILVector2n> A = Matrix<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<ILVector2n> B = Matrix<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<ILVector2n> C = Matrix<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	Matrix<ILVector2n> I = Matrix<ILVector2n>(fastIL2nAlloc(), dimension, dimension).Identity();

	EXPECT_EQ(A, A*I) << "Matrix multiplication of two ILVector2Ns: A = AI - failed.\n";
	EXPECT_EQ(A, I*A) << "Matrix multiplication of two ILVector2Ns: A = IA - failed.\n";

	EXPECT_EQ((A*B).Transpose(), B.Transpose()*A.Transpose()) << "Matrix multiplication of two ILVector2Ns: (A*B)^T = B^T*A^T - failed.\n";

	EXPECT_EQ(A*B*C, A*(B*C)) << "Matrix multiplication of two ILVector2Ns: A*B*C = A*(B*C) - failed.\n";
	EXPECT_EQ(A*B*C, (A*B)*C) << "Matrix multiplication of two ILVector2Ns: A*B*C = (A*B)*C - failed.\n";

}



TEST(UTMatrix, ILVector2n_mult_square_matrix_caps) {

	int32_t dimension = 16;

	MatrixStrassen<ILVector2n> A = MatrixStrassen<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<ILVector2n> B = MatrixStrassen<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<ILVector2n> C = MatrixStrassen<ILVector2n>(fastIL2nAlloc(), dimension, dimension, fastUniformIL2nAlloc());
	MatrixStrassen<ILVector2n> I = MatrixStrassen<ILVector2n>(fastIL2nAlloc(), dimension, dimension).Identity();

	//EXPECT_EQ((A.Mult(B))(0, 0), (A.MultiplyCAPS(B, 2))(0, 0)) << "CAPS matrix multiplication of two ILVector2Ns doesn't agree with Mult: A.Mult(B), A.MultiplyCAPS(B,2) - failed.\n";
	EXPECT_EQ(A, A.Mult(I, 2)) << "CAPS matrix multiplication of two ILVector2Ns: A = AI - failed.\n";
	EXPECT_EQ(A, I.Mult(A, 2)) << "Matrix multiplication of two ILVector2Ns: A = IA - failed.\n";

	EXPECT_EQ((A.Mult(B, 2)).Transpose(), B.Transpose().Mult(A.Transpose(), 2)) << "Matrix multiplication of two ILVector2Ns: (A.MultiplyCAPS(B,2)).Transpose(), B.Transpose().MultiplyCAPS(A.Transpose(),2) - failed.\n";

	EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), A.Mult((B.Mult(C, 2)), 2)) << "Matrix multiplication of two ILVector2Ns: A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), A.MultiplyCAPS((B.MultiplyCAPS(C,2)),2) - failed.\n";
	EXPECT_EQ(A.Mult(B, 2).Mult(C, 2), (A.Mult(B, 2)).Mult(C, 2)) << "Matrix multiplication of two ILVector2Ns: A.MultiplyCAPS(B,2).MultiplyCAPS(C,2), (A.MultiplyCAPS(B,2)).MultiplyCAPS(C,2) - failed.\n";

}


inline void expect_close(double a, double b) {
	EXPECT_LE(abs(a - b), 10e-8);
}

TEST(UTMatrix, cholesky) {
	Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 2, 2);
	m(0, 0) = 20;
	m(0, 1) = 4;
	m(1, 0) = 4;
	m(1, 1) = 10;
	auto c = Cholesky(m);
	EXPECT_LE(abs(4.47213595 - c(0, 0)), 1e-8);
	EXPECT_LE(abs(0 - c(0, 1)), 1e-8);
	EXPECT_LE(abs(.89442719 - c(1, 0)), 1e-8);
	EXPECT_LE(abs(3.03315018 - c(1, 1)), 1e-8);
	auto cc = c*c.Transpose();
	EXPECT_LE(abs(m(0, 0) - cc(0, 0)), 1e-8);
	EXPECT_LE(abs(m(0, 1) - cc(0, 1)), 1e-8);
	EXPECT_LE(abs(m(1, 0) - cc(1, 0)), 1e-8);
	EXPECT_LE(abs(m(1, 1) - cc(1, 1)), 1e-8);
}

TEST(UTMatrix, gadget_vector) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 1, 4).GadgetVector();
	auto v = secureIL2nAlloc()();
	*v = 1;
    EXPECT_EQ(*v, n(0,0));
	*v = 2;
    EXPECT_EQ(*v, n(0,1));
	*v = 4;
    EXPECT_EQ(*v, n(0,2));
	*v = 8;
    EXPECT_EQ(*v, n(0,3));
}

TEST(UTMatrix, rotate_vec_result) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(fastIL2nAlloc(), 1, 2).Ones();
    const BigBinaryInteger& modulus = n(0,0).GetModulus();
    n.SetFormat(COEFFICIENT);
	n(0,0).SetValAtIndex(2, 1);
    Matrix<BigBinaryVector> R = RotateVecResult(n);
	EXPECT_EQ(8, R.GetRows());
	EXPECT_EQ(16, R.GetCols());
	EXPECT_EQ(BigBinaryVector::Single(BigBinaryInteger::ONE, modulus), R(0,0));

	BigBinaryInteger negOne = n(0,0).GetModulus() - BigBinaryInteger("1");
    BigBinaryVector negOneVec = BigBinaryVector::Single(negOne, modulus);
	EXPECT_EQ(negOneVec, R(0,6));
	EXPECT_EQ(negOneVec, R(1,7));

    auto singleAlloc = [=](){ return make_unique<BigBinaryVector>(1, modulus); };
	EXPECT_EQ(*singleAlloc(), R(0,6 + 8));
	EXPECT_EQ(*singleAlloc(), R(1,7 + 8));

}

TEST(UTMatrix, rotate) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(fastIL2nAlloc(), 1, 2).Ones();
    const BigBinaryInteger& modulus = n(0,0).GetModulus();
    n.SetFormat(COEFFICIENT);
	n(0,0).SetValAtIndex(2, 1);
    Matrix<BigBinaryInteger> R = Rotate(n);
	EXPECT_EQ(8, R.GetRows());
	EXPECT_EQ(16, R.GetCols());
	EXPECT_EQ(BigBinaryInteger::ONE, R(0,0));

	BigBinaryInteger negOne = n(0,0).GetModulus() - BigBinaryInteger("1");
	EXPECT_EQ(negOne, R(0,6));
	EXPECT_EQ(negOne, R(1,7));

	EXPECT_EQ(BigBinaryInteger::ZERO, R(0,6 + 8));
	EXPECT_EQ(BigBinaryInteger::ZERO, R(1,7 + 8));

}

TEST(UTMatrix, vstack) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    Matrix<ILVector2n> m = Matrix<ILVector2n>(secureIL2nAlloc(), 8, 2).Ones();
    EXPECT_EQ(m, n.VStack(n));
}

TEST(UTMatrix, hstack) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    Matrix<ILVector2n> m = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 4).Ones();
    EXPECT_EQ(m, n.HStack(n));
}

TEST(UTMatrix, norm) {
    Matrix<ILVector2n> n = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    EXPECT_EQ(1.0, n.Norm());
    Matrix<ILVector2n> m = Matrix<ILVector2n>(secureIL2nAlloc(), 2, 2).Identity();
    EXPECT_EQ(1.0, m.Norm());
}

// Checks the implementantation of determinant based on a 3x3 matrix
TEST(UTMatrix, determinant) {
	
	Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 3, 3);
	m(0, 0) = 1;
	m(0, 1) = 2;
	m(0, 2) = 1;
	m(1, 0) = -1;
	m(1, 1) = 1;
	m(1, 2) = 1;
	m(2, 0) = 1;
	m(2, 1) = 2;
	m(2, 2) = 3;

	//int32_t determinant = m.Determinant();
	int32_t determinant = 0;
	m.Determinant(&determinant);
	EXPECT_EQ(6, determinant);

}

// Checks the implementantation of cofactor matrix based on a 3x3 matrix
TEST(UTMatrix, cofactorMatrix) {

	Matrix<int32_t> m([]() { return make_unique<int32_t>(); }, 3, 3);
	m(0, 0) = 1;
	m(0, 1) = 2;
	m(0, 2) = 0;
	m(1, 0) = -1;
	m(1, 1) = 1;
	m(1, 2) = 1;
	m(2, 0) = 1;
	m(2, 1) = 2;
	m(2, 2) = 3;

	Matrix<int32_t> r([]() { return make_unique<int32_t>(); }, 3, 3);
	r(0, 0) = 1;
	r(0, 1) = 4;
	r(0, 2) = -3;
	r(1, 0) = -6;
	r(1, 1) = 3;
	r(1, 2) = 0;
	r(2, 0) = 2;
	r(2, 1) = -1;
	r(2, 2) = 3;

	EXPECT_EQ(r, m.CofactorMatrix());

}
