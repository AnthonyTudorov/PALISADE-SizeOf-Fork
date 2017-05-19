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

#include "../lib/lattice/ildcrt2n.h"
#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilvector2n.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


class UnitTestSerialize : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST(UTSer,cpu_int){
	BigBinaryInteger small(7);
	BigBinaryInteger medium(1ULL<<27 | 1ULL<<22);
	BigBinaryInteger larger(1ULL<<40 | 1ULL<<22);
	BigBinaryInteger yooge("371828316732191777888912");

	string ser;
	BigBinaryInteger deser;

	ser = small.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";

	ser = yooge.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(yooge, deser) << "Yooge integer ser/deser fails";
}

TEST(UTSer,native_int){
	native_int::BigBinaryInteger small(7);
	native_int::BigBinaryInteger medium(1ULL<<27 | 1ULL<<22);
	native_int::BigBinaryInteger larger(1ULL<<40 | 1ULL<<22);

	string ser;
	native_int::BigBinaryInteger deser;

	ser = small.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";
}

TEST(UTSer,vector_of_cpu_int){
	const int vecsize = 100;
	const BigBinaryInteger mod((uint64_t)1<<40);
	BigBinaryVector	testvec(vecsize, mod);
	ILVector2n::DugType	dug;
	dug.SetModulus(mod);
	BigBinaryInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.SetValAtIndex(i, ranval);
	}

	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << "Serialization failed";

	BigBinaryVector newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}

TEST(UTSer,vector_of_native_int){
	const int vecsize = 100;
	const native_int::BigBinaryInteger mod((uint64_t)1<<40);
	native_int::BigBinaryVector	testvec(vecsize, mod);
	native_int::ILVector2n::DugType	dug;
	dug.SetModulus(mod);
	native_int::BigBinaryInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.SetValAtIndex(i, ranval);
	}

	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << "Serialization failed";

	native_int::BigBinaryVector newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilparams_test) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(1024, 40);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	ILVector2n::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}


TEST(UTSer,ildcrtparams_test) {
	shared_ptr<ILDCRTParams> p = GenerateDCRTParams(1024, 64, 5, 40);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	ILDCRT2n::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilvector_test) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(1024, 40);
	ILVector2n::DugType dug;
	ILVector2n vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << "Serialization failed";

	ILVector2n newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( vec, newvec ) << "Mismatch after ser/deser";

}

TEST(UTSer,ilvectorarray_test) {
	shared_ptr<ILDCRTParams> p = GenerateDCRTParams(1024, 64, 5, 40);
	ILVectorArray2n::DugType dug;
	ILVectorArray2n vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << "Serialization failed";

	ILDCRT2n newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( vec, newvec ) << "Mismatch after ser/deser";

}
