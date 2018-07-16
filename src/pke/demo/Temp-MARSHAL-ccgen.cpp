/**
 * @file gen context This file generates cryptocontexts
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

//#define RAPIDJSON_SCHEMA_VERBOSE 1

#include <iostream>
#include <fstream>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/filewritestream.h"
#include "rapidjson/error/en.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/schema.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <map>
#include <iterator>
#include <algorithm>


using namespace rapidjson;

#include <iostream>
#include <string>
#include <cstdio>
using namespace std;
using namespace lbcrypto;

#include "utils/schemavalidator.h"


ostream& operator<<(ostream& out, const rapidjson::Value& v) {
	switch( v.GetType() ) {
	case rapidjson::kNullType:
		break;

	case rapidjson::kFalseType:
		out << "False";
		break;

	case rapidjson::kTrueType:
		out << "True";
		break;


	case rapidjson::kObjectType:
	case rapidjson::kArrayType:
		out << " --- not supported --- ";
		break;

	case rapidjson::kStringType:
		out << v.GetString();
		break;

	case rapidjson::kNumberType:
		out << v.GetInt();
		break;
	}

	return out;
}

// Parms generator

int
main(int argc, char *argv[])
{
	if( argc != 5 ) {
		cout << "Usage is " << argv[0] << " scheme ptm secparm opcount" << endl;
		return 0;
	}

	string scheme(argv[1]);
	PlaintextModulus ptm = stoul(argv[2]);
	float secparm = stof(argv[3]);
	int opcount = stoul(argv[4]);

	CryptoContext<DCRTPoly> cc;

	usint relin = 16;
	float dist = 4;

	if( scheme == "LTV" ) {

		cc = CryptoContextFactory<DCRTPoly>::genCryptoContextLTV(
			ptm, secparm, relin, dist, 0, opcount, 0);

	}

	else if( scheme == "BFV" ) {

		cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFV(
				ptm, secparm, relin, dist,
				0, opcount, 0);

	}

	else if( scheme == "BFVrns" ) {

		cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
				ptm, secparm, dist,
				0, opcount, 0);

	}

	else if( scheme == "BFVrnsB" ) {

		cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrnsB(
				ptm, secparm, dist,
				0, opcount, 0);

	}

	else {

		cerr << "Unknown scheme " << scheme << endl;
		return 1;

	}

	if( cc == 0 ) {

		cerr << "Unable to make scheme" << endl;
		return 1;

	}

	Serialized sch;
	if( cc->Serialize(&sch) != true )
		return 0;

	string ser;
	if( SerializableHelper::SerializationToPrettyString(sch, ser) == false )
		return 0;

	cout << ser << endl;

	return 0;
}
