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

#include "../../../src/obfmath/randomizedround.h"
#include "../../../src/obfmath/trapdoor.h"

using namespace std;
using namespace lbcrypto;


class UnitTestTrapdoor : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF TRAPDOOR CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/

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

TEST(UTTrapdoor,randomized_round){
    //  It compiles! ...
    //RandomizeRound(0, 4.3, 1024);
}



TEST(UTTrapdoor,sizes){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams fastParams( m, modulus, rootOfUnity);
	pair<RingMat, TrapdoorPair> trapPair = TrapdoorSample(fastParams, stddev);    

	EXPECT_EQ(1,trapPair.first.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(k+2,trapPair.first.GetCols()) 
		<< "Failure testing number of colums";

	EXPECT_EQ(k,trapPair.second.m_r.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(1,trapPair.second.m_r.GetCols()) 
		<< "Failure testing number of colums";

	EXPECT_EQ(k,trapPair.second.m_e.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(1,trapPair.second.m_e.GetCols()) 
		<< "Failure testing number of colums";


}

TEST(UTTrapdoor,TrapDoorPairTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams params( m, modulus, rootOfUnity);
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	pair<RingMat, TrapdoorPair> trapPair = TrapdoorSample(params, stddev);    

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
        RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.HStack(rHat);//).VStack(eyeKK);
	//stackedTrap2.PrintValues();

	EXPECT_EQ(k,stackedTrap1.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(2,stackedTrap1.GetCols()) 
		<< "Failure testing number of colums";

	RingMat stackedTrap2 = stackedTrap1.HStack(eyeKK);//).VStack(eyeKK);

	EXPECT_EQ(k,stackedTrap2.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(k+2,stackedTrap2.GetCols()) 
		<< "Failure testing number of colums";

        //RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();
}

TEST(UTTrapdoor,GadgetTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams params( m, modulus, rootOfUnity);
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

        RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

	EXPECT_EQ(1,g.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(k,g.GetCols()) 
		<< "Failure testing number of colums";
}


TEST(UTTrapdoor,TrapDoorMultTest){
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	float stddev = 4;

	double val = modulus.ConvertToDouble(); //TODO get the next few lines working in a single instance.
	double logTwo = log(val-1.0)/log(2)+1.0;
	usint k = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();

	ILParams params( m, modulus, rootOfUnity);
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

	pair<RingMat, TrapdoorPair> trapPair = TrapdoorSample(params, stddev);    

	RingMat eHat = trapPair.second.m_e;
	RingMat rHat = trapPair.second.m_r;
        RingMat eyeKK = RingMat(zero_alloc, k, k).Identity();

	//eHat.PrintValues();
	//rHat.PrintValues();
	//eyeKK.PrintValues();

	RingMat stackedTrap1 = eHat.HStack(rHat);
	RingMat stackedTrap2 = stackedTrap1.HStack(eyeKK);

	RingMat trapMult = (trapPair.first)*(stackedTrap2);

	EXPECT_EQ(1,trapMult.GetRows()) 
		<< "Failure testing number of rows";
	EXPECT_EQ(k,trapMult.GetCols()) 
		<< "Failure testing number of colums";

        //RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();
}

