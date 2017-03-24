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
Hadi Sajjadpour, ss2959@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Test cases in this file make the following assumptions:
1. All functionatliy of plaintext (both BytePlainTextEncoding and IntPlainTextEncoding) work.
2. Encrypt/Decrypt work
3. Math layer operations such as functions in nbtheory
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;



template <class T>
class UTNTT : public ::testing::Test {

public:
	const usint m = 16;

protected:
	UTNTT() {}

	virtual void SetUp() {
	}

	virtual void TearDown() {

	}

	virtual ~UTNTT() {  }

};



TEST(UTNTT, switch_format_simple_single_crt) {
	usint m1 = 16;

	BigBinaryInteger modulus("1");
	NextQ(modulus, BigBinaryInteger("2"), m1, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	ILParams params(m1, modulus, rootOfUnity);
	ILParams params2(m1 / 2, modulus, rootOfUnity);
	shared_ptr<ILParams> x1p( new ILParams(params) );
	shared_ptr<ILParams> x2p( new ILParams(params2) );

	ILVector2n x1( x1p, Format::COEFFICIENT );
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	ILVector2n x2( x2p, Format::COEFFICIENT );
	x2 = { 4127,9647,1987,5410 };

	ILVector2n x1Clone(x1);
	ILVector2n x2Clone(x2);

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	EXPECT_EQ(x1, x1Clone);
	EXPECT_EQ(x2, x2Clone);
}

TEST(UTNTT, switch_format_simple_double_crt) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

	ILVectorArray2n x1(params, Format::COEFFICIENT);
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	ILVectorArray2n x2(params, Format::COEFFICIENT);
	x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

	ILVectorArray2n x1Clone(x1);
	ILVectorArray2n x2Clone(x2);

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	EXPECT_EQ(x1, x1Clone);
	EXPECT_EQ(x2, x2Clone);
}

TEST(UTNTT, switch_format_decompose_single_crt) {
	usint m1 = 16;

	BigBinaryInteger modulus("1");
	NextQ(modulus, BigBinaryInteger("2"), m1, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
	shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );

	ILVector2n x1(params, Format::COEFFICIENT);
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	ILVector2n x2(params, Format::COEFFICIENT);
	x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

	x1.SwitchFormat(); //EVAL
	x2.SwitchFormat();

	x1.SwitchFormat(); //COEF
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	x1.SwitchFormat(); //COEf
	x2.SwitchFormat();

	x1.SwitchFormat(); //EVAL
	x2.SwitchFormat();

	ILVector2n x1Expected(params2, Format::COEFFICIENT);
	x1Expected = { 431,1234,2145,5471};

	ILVector2n x2Expected(params2, Format::COEFFICIENT);
	x2Expected = { 4127,1987,6541,9741 };

	EXPECT_EQ(x1, x1Expected);
	EXPECT_EQ(x2, x2Expected);
}

TEST(UTNTT, decomposeMult_double_crt) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger temp;
	
	init_moduli[0] = BigBinaryInteger("17729");
	init_moduli[1] = BigBinaryInteger("17761");


	for (int i = 0; i < init_size; i++) {
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

	ILVectorArray2n x1(params, Format::COEFFICIENT);
	x1 = { 0,0,0,0,0,0,1,0 };

	ILVectorArray2n x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	ILVectorArray2n resultsEval(x2.CloneParametersOnly());
	resultsEval = { 0,0,0,0,0,0,0,0 };
	resultsEval.SwitchFormat();

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	x1.SwitchFormat();
	x2.SwitchFormat();

	resultsEval = x1*x2;

	resultsEval.SwitchFormat(); // COEF

	EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(0), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(1), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(2), BigBinaryInteger("17728"));
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(3), BigBinaryInteger::ZERO);

	EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(0), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(1), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(2), BigBinaryInteger("17760"));
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(3), BigBinaryInteger::ZERO);
}

TEST(UTNTT, decomposeMult_single_crt) {
	usint m1 = 16;

	BigBinaryInteger modulus("17729");
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
	shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );

	ILVector2n x1(params, Format::COEFFICIENT);
	x1 = { 0,0,0,0,0,0,1,0 };

	ILVector2n x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	ILVector2n resultsEval(params2, Format::EVALUATION);

	x1.SwitchFormat();
	x2.SwitchFormat();

	resultsEval = x1*x2;

	resultsEval.SwitchFormat(); // COEF	

	EXPECT_EQ(resultsEval.GetValAtIndex(0), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetValAtIndex(1), BigBinaryInteger::ZERO);
	EXPECT_EQ(resultsEval.GetValAtIndex(2), BigBinaryInteger("17728"));
	EXPECT_EQ(resultsEval.GetValAtIndex(3), BigBinaryInteger::ZERO);
}