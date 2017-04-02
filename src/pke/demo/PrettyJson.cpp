/*
 * @file PrettyJson.cpp -- JSON operations in PALISADE library.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 */


#include <iostream>
#include <fstream>
#include <string>
using namespace std;

#define RAPIDJSON_HAS_STDSTRING 1

#include "utils/serializablehelper.h"

void
usage(const string& cmd, const string& msg) {
	cout << msg << endl;
	cout << "Usage is: " << cmd << " filename1 filename2 ..." << endl;
	cout << "to read from standard input, do not specify any filenames" << endl;
}

int
main( int argc, char *argv[] )
{
	istream *br = &cin;
	ifstream fil;

	if( argc > 1 && string(argv[1]) == "-help" ) {
		usage(argv[0], "");
		return 0;
	}

	for( int i = 1; i <= argc; i++ ) {
		if( argc > 1 ) {
			fil.open(argv[i]);
			if( !fil.is_open() ) {
				cout << "File '" << argv[i] << "' could not be opened, skipping" << endl;
				continue;
			}

			br = &fil;
		}

		// set up to read from br and write to stdout

		lbcrypto::IStreamWrapper is(*br);

		rapidjson::Document doc;

		while( br->good() ) {
			lbcrypto::OStreamWrapper oo(cout);
			rapidjson::PrettyWriter<lbcrypto::OStreamWrapper> ww(oo);

			doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(is);

			if( !br->good() )
				break;

			if( doc.HasParseError() && doc.GetParseError() != rapidjson::kParseErrorDocumentEmpty ) {
				cout << "Parse error " << doc.GetParseError() << " at " << doc.GetErrorOffset() << endl;
				break;
			}

			doc.Accept(ww);
			cout << endl;
		}

		fil.close();
	}

	return 0;
}
