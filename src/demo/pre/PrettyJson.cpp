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

void
usage(const string& cmd, const string& msg) {
	cout << msg << endl;
	cout << "Usage is: " << cmd << " [filename]" << endl;
}

int
main( int argc, char *argv[] )
{
	istream *br = &cin;
	ifstream fil;

	if( argc == 2 ) {
		fil.open(argv[1]);
		if( !fil.is_open() ) {
			usage(argv[0], "Cannot open " + string(argv[1]));
			return 1;
		}
		br = &fil;
	}

	else if( argc != 1 ){
		usage(argv[0], "Too many file name arguments specified");
		return 1;
	}

	rapidjson::Document doc;

	string inBuf;
	char ch;

	do {
		inBuf = "";
		while( (ch = br->get()) != EOF && ch != '$' )
			inBuf += ch;

		doc.Parse(inBuf.c_str());

		if( doc.HasParseError() ) {
			usage( argv[0], "Parse error");
			return 1;
		}

		char writeBuffer[32768];
		rapidjson::FileWriteStream os(stdout, writeBuffer, sizeof(writeBuffer));

		rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);

		doc.Accept(writer);
		cout << endl << endl;

	} while( br->good() );

	return 0;
}
