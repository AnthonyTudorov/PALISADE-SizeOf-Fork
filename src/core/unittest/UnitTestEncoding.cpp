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
#include "encoding/encodings.h"

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
	uint64_t value = 47;
	int64_t	valueSigned = -47;
	usint m = 8;

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	EncodingParams ep( new EncodingParamsImpl( PlaintextModulus(128) ) );
	ScalarEncoding	se(lp, ep, value);
	se.Encode();
	EXPECT_EQ( se.GetElement<Poly>().at(0), value );
	EXPECT_EQ( se.GetElement<Poly>().at(1), 0 );

	se.Decode();
	EXPECT_EQ( se.GetScalarValue(), value ) << "unsigned";

	ScalarEncoding	se2(lp, ep, valueSigned);
	se2.Encode();
	se2.Decode();
	EXPECT_EQ( se2.GetScalarSignedValue(), valueSigned ) << "signed negative";

	ScalarEncoding	se3(lp, ep, (int64_t)value);
	se3.Encode();
	se3.Decode();
	EXPECT_EQ( se3.GetScalarSignedValue(), (int64_t)value ) << "signed positive";
}

TEST_F(UTEncoding,coef_packed_encoding) {
	vector<uint64_t> value = {32, 17, 8};
	vector<int64_t>	valueSigned = { -32, 22, -101, 6 };
	usint m = 8;

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	EncodingParams ep( new EncodingParamsImpl(256) );
	CoefPackedEncoding	se(lp, ep, value);
	se.Encode();
	se.Decode();
	se.SetLength( value.size() );
	EXPECT_EQ( se.GetCoefPackedValue(), value ) << "unsigned";

	CoefPackedEncoding	se2(lp, ep, valueSigned);
	se2.Encode();
	se2.Decode();
	se2.SetLength( valueSigned.size() );
	EXPECT_EQ( se2.GetCoefPackedSignedValue(), valueSigned ) << "signed negative";
}

TEST_F(UTEncoding,packed_int_ptxt_encoding) {
	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedEncoding::SetParams(m, p);

	shared_ptr<ILParams> lp(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
	EncodingParams ep(new EncodingParamsImpl(p,8));

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedEncoding	se(lp, ep, vectorOfInts1);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int";
}

TEST_F(UTEncoding,string_encoding) {
	string value = "Hello, world!";
	usint m = 64;

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	EncodingParams ep( new EncodingParamsImpl(256) );
	StringEncoding	se(lp, ep, value);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetStringValue(), value ) << "string encode/decode";

	// truncate!
	shared_ptr<ILParams> lp2 =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(4);
	StringEncoding	se2(lp2, ep, value);
	se2.Encode();
	se2.Decode();
	EXPECT_EQ( se2.GetStringValue(), value.substr(0, lp2->GetRingDimension()) ) << "string truncate encode/decode";
}

TEST_F(UTEncoding,integer_encoding){
	uint64_t	m = 64;
	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParams,BigInteger>(m);
	EncodingParams ep( new EncodingParamsImpl(64) );

	uint64_t mv = ((uint64_t)1<<33) + (uint64_t)1;

	IntegerEncoding small(lp, ep, 9U);
	IntegerEncoding medium(lp, ep, mv);
	small.Encode();
	medium.Encode();
	small.Decode();
	medium.Decode();

	EXPECT_EQ( small.GetIntegerValue(), 9U ) << "small";

	EXPECT_EQ( medium.GetIntegerValue(), mv ) << "medium";
}


