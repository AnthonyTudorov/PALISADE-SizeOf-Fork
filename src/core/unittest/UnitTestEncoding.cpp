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
  This code exercises the encoding libraries of the PALISADE lattice encryption library.
*/

#define PROFILE
#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/scalarencoding.h"
#include "encoding/stringencoding.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;


class UTEncoding : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST_F(UTEncoding,scalar_encoding) {
	usint m = 8;
	Poly::Integer primeModulus("73");
	Poly::Integer primitiveRootOfUnity("22");

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	shared_ptr<EncodingParams> ep( new EncodingParams(64) );
	ScalarEncoding	se(lp, ep, value);
	se.Encode();
	EXPECT_EQ( se.GetElement().GetValAtIndex(0), value );
	EXPECT_EQ( se.GetElement().GetValAtIndex(1), 0 );

	se.Decode();
	EXPECT_EQ( se.GetScalarValue(), value );
}

TEST_F(UTEncoding,string_encoding) {
	string value = "Hello, world!";
	usint m = 64;

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	shared_ptr<EncodingParams> ep( new EncodingParams(256) );
	StringEncoding	se(lp, ep, value);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetStringValue(), value ) << "string encode/decode";

	// truncate!
	shared_ptr<ILParams> lp2 =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(4);
	shared_ptr<EncodingParams> ep2( new EncodingParams(256) );
	StringEncoding	se2(lp2, ep2, value);
	se2.Encode();
	se2.Decode();
	EXPECT_EQ( se2.GetStringValue(), value ) << "string truncate encode/decode";
}

TEST_F(UTEncoding,binary_polynomial){
	BigInteger b(1);
	b = (b << 70) + 1;
	IntPlaintextEncoding small(9);
	IntPlaintextEncoding medium( ((uint64_t)1<<33) + (uint64_t)1);
	IntPlaintextEncoding large(b);

	EXPECT_EQ( small[0], 1U );
	EXPECT_EQ( small[1], 0U );
	EXPECT_EQ( small[2], 0U );
	EXPECT_EQ( small[3], 1U );

	EXPECT_EQ( medium[0], 1U );
	EXPECT_EQ( medium[33], 1U);
	for( size_t ii=1; ii<33; ii++ )
		EXPECT_EQ( medium[ii], 0U);

	EXPECT_EQ( large[0], 1U );
	EXPECT_EQ( large[70], 1U );
	for( size_t ii=1; ii<70; ii++ )
		EXPECT_EQ( large[ii], 0U);
}


