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

#include "../../../src/math/backend.h"
#include "../../../src/math/nbtheory.h"
#include "../../../src/math/distrgen.h"
#include "../../../src/lattice/ilvector2n.h"
#include "../../../src/crypto/lwecrypt.h"
#include "../../../src/crypto/lwepre.h"
#include "../../../src/utils/inttypes.h"
#include "../../../src/utils/utilities.h"

#include "../../../src/lattice/matrix.h"

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
TEST(UTMatrix,basic_math){
    BigBinaryInteger modulus("8590983169");
    BigBinaryInteger rootOfUnity("4810681236");
    ILParams ilParams(2048, modulus, rootOfUnity);
    ILMat<ILVector2n> z(ilParams, EVALUATION, 2,2);
    ILMat<ILVector2n> n = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 2, 2);
    ILMat<ILVector2n> I = ILMat<ILVector2n>::Identity(ilParams, EVALUATION, 2, 2);
    EXPECT_EQ(n, I*n);

    n -= n;
    EXPECT_EQ(n, z);

    ILMat<ILVector2n> m = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 2, 2);
    m.Fill(2);
    n.Fill(1);
    n = n + n;
    EXPECT_EQ(n, m);
}

TEST(UTMatrix, transpose){
    BigBinaryInteger modulus("8590983169");
    BigBinaryInteger rootOfUnity("4810681236");
    ILParams ilParams(2, modulus, rootOfUnity);
    ILMat<ILVector2n> n = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 4, 2);
    ILMat<ILVector2n> nT = ILMat<ILVector2n>(n).Transpose();
    ILMat<ILVector2n> I = ILMat<ILVector2n>::Identity(ilParams, EVALUATION, 2, 2);
    EXPECT_EQ(nT, I*nT);
}

TEST(UTMatrix, vstack) {
    BigBinaryInteger modulus("8590983169");
    BigBinaryInteger rootOfUnity("4810681236");
    ILParams ilParams(2, modulus, rootOfUnity);
    ILMat<ILVector2n> n = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 4, 2);
    ILMat<ILVector2n> m = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 8, 2);
    EXPECT_EQ(m, n.VStack(n));
}

TEST(UTMatrix, hstack) {
    BigBinaryInteger modulus("8590983169");
    BigBinaryInteger rootOfUnity("4810681236");
    ILParams ilParams(2, modulus, rootOfUnity);
    ILMat<ILVector2n> n = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 2, 2);
    ILMat<ILVector2n> m = ILMat<ILVector2n>::Ones(ilParams, EVALUATION, 2, 4);
    EXPECT_EQ(m, n.HStack(n));
}
