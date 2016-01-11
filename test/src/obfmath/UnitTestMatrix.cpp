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


#include "../../include/gtest/gtest.h"
#include <iostream>
#include "../../../src/obfmath/largefloat.h"

#include "../../../src/math/backend.h"
#include "../../../src/math/nbtheory.h"
#include "../../../src/math/distrgen.h"
#include "../../../src/lattice/ilvector2n.h"
#include "../../../src/crypto/lwecrypt.h"
#include "../../../src/crypto/lwepre.h"
#include "../../../src/utils/inttypes.h"
#include "../../../src/utils/utilities.h"

#include "../../../src/obfmath/matrix.h"

using namespace std;
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
        ILParams(
        2048, secureModulus, secureRootOfUnity),
        EVALUATION
        );
}

static function<unique_ptr<ILVector2n>()> fastIL2nAlloc() {
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
    return ILVector2n::MakeAllocator(
        ILParams(
        m, modulus, rootOfUnity),
        EVALUATION
        );
}

TEST(UTMatrix,basic_il2n_math){
    ILMat<ILVector2n> z(secureIL2nAlloc(), 2,2);
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    ILMat<ILVector2n> I = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 2).Identity();
    I.SwitchFormat();
    I.SwitchFormat();
    EXPECT_EQ(n, I*n);

    n -= n;
    EXPECT_EQ(n, z);

    //ILMat<ILVector2n> m = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    //m.Fill(2);
    //n.Fill(1);
    //n = n + n;
    //EXPECT_EQ(n, m);
}

TEST(UTMatrix,basic_int_math){
    ILMat<BigBinaryInteger> z(BigBinaryInteger::Allocator, 2,2);
    ILMat<BigBinaryInteger> n = ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, 2, 2).Ones();
    ILMat<BigBinaryInteger> I = ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, 2, 2).Identity();
    EXPECT_EQ(n, I*n);
    n -= n;
    EXPECT_EQ(n, z);

    //ILMat<BigBinaryInteger> m = ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, 2, 2).Ones();
    //m.Fill(2);
    //n.Fill(1);
    //n = n + n;
    //EXPECT_EQ(n, m);
}

TEST(UTMatrix, transpose){
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    ILMat<ILVector2n> nT = ILMat<ILVector2n>(n).Transpose();
    ILMat<ILVector2n> I = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 2).Identity();
    EXPECT_EQ(nT, I*nT);
}

TEST(UTMatrix, scalar_mult){
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    auto one = secureIL2nAlloc()();
    *one = 1;
    EXPECT_EQ(n, *one*n);
    EXPECT_EQ(n, n**one);

    //auto two = secureIL2nAlloc()();
    //ILMat<ILVector2n> twos = ILMat<ILVector2n>(secureIL2nAlloc(), 4, 2).Fill(2);
    //*two = 2;
    //EXPECT_EQ(*two*n, twos);
    //EXPECT_EQ(n**two, twos);
}

inline void expect_close(double a, double b) {
	EXPECT_LE(abs(a - b), 10e-8);
}

TEST(UTMatrix, cholesky) {
	ILMat<int32_t> m([](){ return make_unique<int32_t>(); }, 2, 2);
	m(0,0) = 20;
	m(0,1) = 4;
	m(1,0) = 4;
	m(1,1) = 10;
	auto c = Cholesky(m);
	EXPECT_LE(abs(4.47213595 - c(0,0)), 1e-8);
	EXPECT_LE(abs(0 - c(0,1)), 1e-8);
	EXPECT_LE(abs(.89442719 - c(1,0)), 1e-8);
	EXPECT_LE(abs(3.03315018 - c(1,1)), 1e-8);
	auto cc = c*c.Transpose();
	EXPECT_LE(abs(m(0,0) - cc(0,0)), 1e-8);
	EXPECT_LE(abs(m(0,1)- cc(0,1)), 1e-8);
	EXPECT_LE(abs(m(1,0)- cc(1,0)), 1e-8);
	EXPECT_LE(abs(m(1,1) - cc(1,1)), 1e-8);
}

TEST(UTMatrix, gadget_vector) {
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 1, 4).GadgetVector();
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
TEST(UTMatrix, rotate) {
    ILMat<ILVector2n> n = ILMat<ILVector2n>(fastIL2nAlloc(), 1, 2).Ones();
	n(0,0).SetValAtIndex(2, 1);
    ILMat<BigBinaryInteger> R = Rotate(n);
	EXPECT_EQ(8, R.GetRows());
	EXPECT_EQ(16, R.GetCols());
	EXPECT_EQ(BigBinaryInteger::ONE, R(0,0));
	BigBinaryInteger negOne = n(0,0).GetParams().GetModulus() - BigBinaryInteger("1");
	EXPECT_EQ(negOne, R(0,6));
	EXPECT_EQ(negOne, R(1,7));

	EXPECT_EQ(BigBinaryInteger(), R(0,6 + 8));
	EXPECT_EQ(BigBinaryInteger(), R(1,7 + 8));

}

TEST(UTMatrix, vstack) {
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 4, 2).Ones();
    ILMat<ILVector2n> m = ILMat<ILVector2n>(secureIL2nAlloc(), 8, 2).Ones();
    EXPECT_EQ(m, n.VStack(n));
}

TEST(UTMatrix, hstack) {
    ILMat<ILVector2n> n = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 2).Ones();
    ILMat<ILVector2n> m = ILMat<ILVector2n>(secureIL2nAlloc(), 2, 4).Ones();
    EXPECT_EQ(m, n.HStack(n));
}
