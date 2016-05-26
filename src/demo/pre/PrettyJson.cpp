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
	FILE *br = stdin;

	if( argc == 2 ) {
		br = fopen(argv[1], "r");
		if( br == 0 ) {
			usage(argv[0], "Cannot open " + string(argv[1]));
			return 1;
		}
	}
	else if( argc != 1 ){
		usage(argv[0], "Too many file name arguments specified");
		return 1;
	}

	rapidjson::Document doc;

	char readBuffer[32768];
	rapidjson::FileReadStream is(br, readBuffer, sizeof(readBuffer));

	doc.ParseStream(is);

	if( doc.HasParseError() ) {
		usage( argv[0], "Parse error");
		return 1;
	}

	char writeBuffer[32768];
	rapidjson::FileWriteStream os(stdout, writeBuffer, sizeof(writeBuffer));

	rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);

	doc.Accept(writer);
	cout << endl;

	return 0;
}
