/*
 * PrettyJson.cpp
 *
 *  Created on: May 23, 2016
 *      Author: gwryan
 */


#include <iostream>
#include <fstream>
#include <string>
using namespace std;

#define RAPIDJSON_HAS_STDSTRING 1
#include "../../../include/rapidjson/document.h"
#include "../../../include/rapidjson/pointer.h"
#include "../../../include/rapidjson/reader.h"
#include "../../../include/rapidjson/writer.h"
#include "../../../include/rapidjson/filereadstream.h"
#include "../../../include/rapidjson/filewritestream.h"
#include "../../../include/rapidjson/error/en.h"
#include "../../../include/rapidjson/prettywriter.h"
#include "../../../include/rapidjson/stringbuffer.h"
#include "../../../src/lib/utils/serializablehelper.h"

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
			if( doc.HasParseError() && doc.GetParseError() != rapidjson::kParseErrorDocumentEmpty ) {
				cout << "Parse error " << doc.GetParseError() << " at " << doc.GetErrorOffset() << endl;
				break;
			}

			doc.Accept(ww);
			cout << endl;
		}

	}

	return 0;
}
