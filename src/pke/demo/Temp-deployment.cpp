/**
 * @file schemavalidator.h This file contains code to validate serializations against schema
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

#define RAPIDJSON_NO_SIZETYPEDEFINE

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

// configurator

int
main(int argc, char *argv[])
{
	if( argc != 4 ) {
		cout << "Usage is " << argv[0] << " config-schema app-profile serialized-output" << endl;
		return 0;
	}

	Serialized sch;
	if( SerializableHelper::ReadSerializationFromFile(argv[1], &sch, true) == false )
		return 0;

	SchemaDocument schema(sch);

	cout << "Parsed config-schema" << endl;

	Serialized ser;
	if( SerializableHelper::ReadSerializationFromFile(argv[2], &ser, true) == false )
		return 0;

	SchemaValidator validator(schema);
	if (!ser.Accept(validator)) {
		// Input JSON is invalid according to the schema
		// Output diagnostic information

		StringBuffer sb;
		validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
		cout << "Schema: " << sb.GetString() << endl;

		cout << "Invalid keyword " << validator.GetInvalidSchemaKeyword() << endl;

		sb.Clear();
		validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
		cout << "Document " << sb.GetString() << endl;

		return 0;
	}

	cout << "Validated app-profile" << endl;

	const auto& dep = ser["deployment"];
	const auto& ct = dep["controls"];
	cout << ct["scheme"].GetString() << endl;

	CryptoContext<DCRTPoly> cc = CryptoContextHelper::ContextFromDeployment<DCRTPoly>(ct);

	Serialized outSer;
	cc->Serialize(&outSer);

	if( SerializableHelper::WriteSerializationToFile(outSer, argv[3]) == false )
		return 0;

	cout << "Completed serialized-output... Done!" << endl;

	return 0;
}
